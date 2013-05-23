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
        pkt = packet.RadiusPacket(datagram=datagram)
        self.processPacket(pkt, hp)

    def processPacket(self, pkt, host):
        if pkt.rad_code == packet.AccessRequest:
            rp = pkt.createReply(packet.AccessReject)

            ma = pkt.get('Message-Authenticator')
            # Do something with the MA

            # Hand packet off to EAP if we have the attribute
            eapm = pkt.get('EAP-Message')
            print eapm
            if eapm:
                rp = self.eapProcessor.processMessage(pkt, host)
    
            # Encode and write the response
            self.transport.write(
                rp.encodeDatagram(self.secret), 
                host
            )

    def processEAPResponse(self, message):
        r = EAPMD5ChallengeRequest(message.pkt, self.secret)

        return r.createPacket()
