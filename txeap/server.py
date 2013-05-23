from twisted.internet import protocol

from txeap import packet, eap


class RadiusServer(protocol.DatagramProtocol):
    def __init__(self, config):
        self.config = config
        self.secret = config['secret']

    def datagramReceived(self, datagram, hp):
        print repr(datagram)
        pkt = packet.RadiusPacket(datagram=datagram)
        print pkt.attributes
        self.processPacket(pkt)

    def processPacket(self, pkt):
        if pkt.rad_code == packet.AccessRequest:

            mac = pkt.get('Message-Authenticator')[0]
            eapm = pkt.get('EAP-Message')[0]
            user = pkt.get('User-Name')[0]

            rp = packet.RadiusPacket(packet.AccessReject)

            if eapm:
                message = EAPMessage(pkt, self.secret, data=eapm)

                # This useless pyrad module doesn't even have a way to sanely authenticate requests

                if message.eap_code == EAPRequest:
                    pass

                if message.eap_code == EAPResponse:
                    print "EAP Response", repr(eapm)
                    rp = self.processEAPResponse(message)
                    print "Send", repr(rp)

                if message.eap_code == EAPSuccess:
                    pass

                if message.eap_code == EAPFail:
                    pass
            
            self.transport.write(rp, pkt.source)

    def processEAPResponse(self, message):
        r = EAPMD5ChallengeRequest(message.pkt, self.secret)

        return r.createPacket()
