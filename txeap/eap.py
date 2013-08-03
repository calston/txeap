from OpenSSL import SSL
from zope.interface import implements

from twisted.internet import ssl, protocol
from twisted.protocols.tls import TLSMemoryBIOProtocol, TLSMemoryBIOFactory
from twisted.internet.interfaces import ITransport

from txeap import packet, proto_utils

import os
import hmac
import struct
import uuid
import hashlib
import time
from StringIO import StringIO

# EAP codes
EAPRequest = 1
EAPResponse = 2 
EAPSuccess = 3 
EAPFail = 4 

# Types
EAPRequestIdentity = 1
EAPNak = 3 
EAPMD5Challenge = 4
EAPPEAP = 25

TLSLen = 0b10000000
TLSFrag = 0b01000000
TLSStart = 0b00100000

def joinbits(s):
    # Join bits together
    return reduce(lambda x,y: x|y, s)

def matchflag(f, i):
    return f & i == i 

class EAPException(Exception):
    "EAP Exception"


class EAPTLSProtocol(protocol.Protocol):
    def __init__(self, state, protos):
        # Link the protocol instance back to the state holder
        protos[state][1] = self

    def dataReceived(self, bytes):
        print "EAPTLSProto <R< ", repr(bytes)


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

    def createReplyPacket(self, type, data=''):
        "Build a reply packet for this message"
        reply = self.pkt.createReply(type)
        self.eap_data = data
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

        if self.eap_type:
            l += 1
            t = struct.pack('!B', self.eap_type)
        else:
            t = ''

        pkt_hdr = struct.pack('!BBH', self.eap_code, 
                                self.eap_id, l)

        return pkt_hdr + t + data

    def __str__(self):
        return "<EAPMessage code=%s type=%s id=%s data=%s>" % (
            self.eap_code, self.eap_type, self.eap_id, repr(self.eap_data)
        )


class EAPMD5ChallengeRequest(EAPMessage):
    def __init__(self, pkt, id, secret):
        self.eap_code = EAPRequest
        self.eap_type = EAPMD5Challenge
        self.eap_id = id
        self.pkt = pkt
        self.secret = secret

    def createPacket(self):
        "Create an MD5 challenge EAP message"
        self.randstr = uuid.uuid1().bytes
        data_hdr = struct.pack('!BB', self.eap_type, 16)
        data = hashlib.md5(self.randstr).digest()

        return self.createReplyPacket(packet.AccessChallenge, data_hdr + data)

class EAPIdentity(EAPMessage):
    def __init__(self, pkt, id, secret):
        self.eap_code = EAPRequest
        self.eap_type = EAPRequestIdentity

        self.eap_id = id
        self.pkt = pkt
        self.secret = secret

class EAPPEAPIdentity(EAPMessage):
    def __init__(self, proto, in_proto, pkt, id, secret):
        self.eap_code = EAPRequest
        self.eap_type = EAPPEAP
        self.eap_id = id
        self.pkt = pkt
        self.secret = secret

        # PEAP needs an SSL context
        self.tlsProtocol = proto
        self.tlsInput = in_proto

    def createPacket(self):
        # Nest EAPIdentity
        ei = EAPIdentity(self.pkt, self.eap_id, self.secret).encodeEAPMessage('Hello')

        self.tlsProtocol.transport.clear()
        self.tlsInput.transport.write(ei)
        data = self.tlsProtocol.transport.value()

        data = struct.pack('!B', 0) + data

        return self.createReplyPacket(packet.AccessChallenge, data)

class EAPPEAPChallengeRequest(EAPMessage):
    def __init__(self, proto, pkt, id, secret, flags=0, exlen=0, data=''):
        self.eap_code = EAPRequest
        self.eap_type = EAPPEAP
        self.eap_id = id
        self.pkt = pkt
        self.secret = secret
        # PEAP needs an SSL context
        self.tlsProtocol = proto

        self.data = data
        self.flags = flags
        self.exlen = exlen

    def createPacket(self):
        "Create a PEAP challnge EAP message"

        if matchflag(self.flags, TLSLen):
            data = struct.pack('!BL', self.flags, self.exlen) + self.data
        else:
            data = struct.pack('!B', self.flags) + self.data

        return self.createReplyPacket(packet.AccessChallenge, data)


class EAPSuccessReply(EAPMessage):
     def __init__(self, pkt, id, secret):
        self.eap_code=EAPSuccess
        self.eap_type=None
        self.eap_id = id
        self.pkt = pkt
        self.secret = secret

     def createPacket(self):
        "Create a PEAP challnge EAP message"
        return self.createReplyPacket(packet.AccessAccept, '')


class EAPFailReply(EAPMessage):
     def __init__(self, pkt, id, secret):
        self.eap_code=EAPFail
        self.eap_type=None
        self.eap_id = id
        self.pkt = pkt
        self.secret = secret

     def createPacket(self):
        "Create a PEAP challnge EAP message"
        return self.createReplyPacket(packet.AccessReject, '')

