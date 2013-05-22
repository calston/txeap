from twisted.internet import protocol

from txeap import packet

import os
import hmac
import struct
import uuid
import hashlib

EAPRequest = 1
EAPResponse = 2 
EAPSuccess = 3 
EAPFail = 4 

class EAPMessage(object):
    eap_code = 0 
    eap_type = 0
    eap_id = 0

    def __init__(self, pkt, secret, data=None):
        self.pkt = pkt
        self.secret = secret

        if data:
            self.decodeEAPMessage(data)

    def createReplyPacket(self, data):
        "Build a reply packet for this message"
        reply=self.pkt.CreateReply()
        print reply
        reply.source=self.pkt.source
        reply.secret=self.secret
        reply.code = self.packet_type

        print "EAPR", repr(self.encodeEAPMessage(data))
        reply.AddAttribute('EAP-Message', self.encodeEAPMessage(data))
        reply.AddAttribute('Message-Authenticator', self.encodeEAPMessage(data))

        return reply.ReplyPacket()

    def decodeMessage(self, data):
        "Decode this EAP message type"
        pass

    def decodeEAPMessage(self, data):
        self.eap_code, self.eap_id, eap_len = struct.unpack('!BBH', data[:4])
        eap_data = data[4:]
        return self.decodeMessage(eap_data)

    def encodeEAPMessage(self, data):
        l = len(data)+4
        pkt_hdr = struct.pack('!BBH', self.eap_code, self.eap_id, l)
        return pkt_hdr + data


class EAPMD5ChallengeRequest(EAPMessage):
    eap_code = 1
    eap_type = 4
    eap_id = 1
    packet_type = packet.AccessChallenge

    def createPacket(self):
        self.randstr = uuid.uuid1().bytes
        data_hdr = struct.pack('!BB', self.eap_type, 16)
        data = hashlib.md5(self.randstr).digest()
        
        return self.createReplyPacket(data_hdr + data)

class RadiusServer(protocol.DatagramProtocol):
    def __init__(self, config):
        self.config = config
        self.secret = config['secret']
        
        cwd = os.path.dirname(__file__)

        mydict = dictionary.Dictionary(
            os.path.join(cwd, 'dictionary')
        )

        curved.RADIUS.__init__(self, hosts=hosts, dict=mydict)

    def datagramReceived(self, datagram, hp):
        packet = packet.RadiusPacket(datagram=datagramA)
        self.proccessPacket(packet)

    def createReplyPacket(self, code, pkt):
        reply=pkt.CreateReply()
        print reply
        reply.source=pkt.source
        reply.secret=self.secret
        reply.code = code
        return reply.ReplyPacket()

    def processPacket(self, pkt):
        if pkt.code == packet.AccessRequest:
            pdict = {}
            for attr in pkt.keys():
                pdict[attr] = pkt[attr][0]

            print pdict

            mac = pdict.get('Message-Authenticator', None)
            eapm = pdict.get('EAP-Message', None)
            user = pdict.get('User-Name', None)

            rp = self.createReplyPacket(packet.AccessReject, pkt)

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
