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

class EAPProcessor(object):
    def __init__(self, server):
        self.server = server

    def processMessage(self, pkt, host):
        # Long EAP messages are sent as multiple attributes so just join them
        eap_data = ''.join(pkt.get('EAP-Message'))

        message = EAPMessage(pkt, self.server.secret, data=eap_data)

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
        reply = packet.RadiusPacket(self.packet_type, secret=self.secret)

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

