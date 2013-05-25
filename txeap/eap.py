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

EAPRequestIdentity = 1

class EAPException(Exception):
    "EAP Exception"

class EAPProcessor(object):
    def __init__(self, server):
        self.server = server

    def processEAPResponse(self, message):

        if message.eap_type == EAPRequestIdentity:
            r = EAPMD5ChallengeRequest(message.pkt, self.server.secret)

        return r.createPacket()

    def processMessage(self, pkt, host):
        # Long EAP messages are sent as multiple attributes so just join them
        eap_data = ''.join(pkt.get('EAP-Message'))

        message = EAPMessage(pkt, self.server.secret, data=eap_data)

        if message.eap_code == EAPRequest:
            pass

        if message.eap_code == EAPResponse:
            print "EAP Response", repr(eap_data)
            return self.processEAPResponse(message)

        if message.eap_code == EAPSuccess:
            pass

        if message.eap_code == EAPFail:
            pass


class EAPMessage(object):
    def __init__(self, pkt, secret, code=0, id=0, type=0, data=None):
        self.pkt = pkt
        self.secret = secret

        self.eap_code = code
        self.eap_type = type
        self.eap_id = id

        if data:
            self.decodeEAPMessage(data)

    def createReplyPacket(self, type, data):
        "Build a reply packet for this message"
        reply = self.pkt.createReply(type)

        reply.addAttribute('EAP-Message', self.encodeEAPMessage(data))

        return reply

    def decodeEAPMessage(self, data):
        # Decode EAP message
        (self.eap_code, self.eap_id, 
            eap_len, self.eap_type) = struct.unpack('!BBHB', data[:5])

        self.eap_data = data[5:]

    def encodeEAPMessage(self, data):
        "Encode this object and some data back into an EAP-Message"
        l = len(data)+4

        pkt_hdr = struct.pack('!BBHB', self.eap_code, 
                                self.eap_id, l, self.eap_type)
        return pkt_hdr + data


class EAPMD5ChallengeRequest(EAPMessage):

    def __init__(self, pkt, secret):
        self.eap_code = 1
        self.eap_type = 4
        self.eap_id = 1
        self.pkt = pkt
        self.secret = secret

    def createPacket(self):
        "Create an MD5 challenge EAP message"
        self.randstr = uuid.uuid1().bytes
        data_hdr = struct.pack('!BB', self.eap_type, 16)
        data = hashlib.md5(self.randstr).digest()

        return self.createReplyPacket(packet.AccessChallenge, data_hdr + data)

