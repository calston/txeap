from txeap import packet

import os
import hmac
import struct
import uuid
import hashlib
import time

# EAP codes
EAPRequest = 1
EAPResponse = 2 
EAPSuccess = 3 
EAPFail = 4 

# Types
EAPRequestIdentity = 1
EAPMD5Challenge = 4

class EAPException(Exception):
    "EAP Exception"

class EAPProcessor(object):
    def __init__(self, server):
        self.server = server

        self.auth_states = {}

        self.auth_methods = [
            self.eapMD5
        ]

    def eapMD5(self, message):
        if message.eap_type == EAPRequestIdentity:
            return EAPMD5ChallengeRequest(message.pkt, self.server.secret)
        elif message.eap_type == EAPMD5Challenge:
            # Challenge accepted

            print message.pkt.getUserPassword(self.server.secret)

    def processEAPMessage(self, message):
        print message, message.pkt.attributes
        now = time.time()
        # Get incomming State if there is one
        state = message.pkt.get('state')

        print state
        if not state:
            state = uuid.uuid1().bytes
            self.auth_states[state] = [0, now]
        else:
            state = state[0]

        # Find a processor for this state
        r = self.auth_methods[self.auth_states[state][0]](message)

        packet = r.createPacket()
        # Add State attribute 
        packet.addAttribute('State', state)

        return packet

    def processMessage(self, pkt, host):
        # Long EAP messages are sent as multiple attributes so just join them
        eap_data = ''.join(pkt.get('EAP-Message'))

        message = EAPMessage(pkt, self.server.secret, data=eap_data)
        
        return self.processEAPMessage(message)

class EAPMessage(object):
    def __init__(self, pkt, secret, code=0, id=0, type=0, data=None):
        self.pkt = pkt
        self.secret = secret

        self.eap_code = code
        self.eap_type = type
        self.eap_id = id
        self.eap_data = ""

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
        l = len(data)+5

        pkt_hdr = struct.pack('!BBHB', self.eap_code, 
                                self.eap_id, l, self.eap_type)
        return pkt_hdr + data

    def __str__(self):
        return "<EAPMessage code=%s type=%s id=%s data=%s>" % (
            self.eap_code, self.eap_type, self.eap_id, repr(self.eap_data)
        )


class EAPMD5ChallengeRequest(EAPMessage):

    def __init__(self, pkt, secret):
        self.eap_code = 1
        self.eap_type = EAPMD5Challenge
        self.eap_id = 1
        self.pkt = pkt
        self.secret = secret

    def createPacket(self):
        "Create an MD5 challenge EAP message"
        self.randstr = uuid.uuid1().bytes
        data_hdr = struct.pack('!BB', self.eap_type, 16)
        data = hashlib.md5(self.randstr).digest()

        return self.createReplyPacket(packet.AccessChallenge, data_hdr + data)

