from twisted.internet import protocol

from txeap import packet, eap, backends


class RadiusServer(protocol.DatagramProtocol):
    def __init__(self, config):
        self.config = config
        self.secret = config.get('main', 'secret')

        # Special processors
        self.eapProcessor = eap.EAPProcessor(self)
        
        # Setup all available auth backends
        self.registeredBackends = []
        for b in backends.backends:
            self.registeredBackends.append(
                b(config)
            )

    def datagramReceived(self, datagram, hp):
        "Creates a packet object for received datagrams"
        print hp, repr(datagram)
        pkt = packet.RadiusPacket(datagram=datagram)
        self.processPacket(pkt, hp)

    def processPacket(self, pkt, host):
        print host, pkt.attributes
        if pkt.rad_code == packet.AccessRequest:
            rp = pkt.createReply(packet.AccessReject)

            ma = pkt.get('Message-Authenticator')
            # Do something with the MA

            # Hand packet off to EAP if we have the message attribute
            eapm = pkt.get('EAP-Message')
            if eapm:
                rp = self.eapProcessor.processMessage(pkt, host)

            # Encode and write the response
            self.transport.write(
                rp.encodeDatagram(self.secret), 
                host
            )
