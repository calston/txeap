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

class EAPException(Exception):
    "EAP Exception"

class EAPTLSProtocol(protocol.Protocol):
    def dataReceived(self, bytes):
        print "EAPTLSProto <R< ", repr(bytes)

class EAPProcessor(object):
    def __init__(self, server):
        self.server = server

        self.auth_states = {}

        self.auth_methods = [
            self.eapMD5,
            self.eapPEAP
        ]

        self.key = server.config.get('main', 'ssl_key')
        self.cert = server.config.get('main', 'ssl_cert')

        self.peap_protocols = {}

    def eapMD5(self, message, state):
        "Handle EAP-MD5 sessions"
        if message.eap_type == EAPMD5Challenge:
            # Challenge accepted

            passwd = message.pkt.getUserPassword(self.server.secret)
            username = message.pkt.get('User-Name')[0]

            authorization = self.server.authenticateUser(username, passwd)
            if authorization:
                return EAPSuccessReply(
                    message.pkt, message.eap_id, self.server.secret)
            else:
                return EAPFailReply(
                    message.pkt, message.eap_id, self.server.secret)

            del self.auth_states[message.pkt.get('State')[0]]

        else:
            return EAPMD5ChallengeRequest(
                message.pkt, message.eap_id, self.server.secret)

    def eapPEAP(self, message, state):
        "Handle EAP-PEAP sessions"

        if state in self.peap_protocols:
            tlsProtocol = self.peap_protocols[state]
        else:
            # XXX Invalidate this somehow

            serverFactory = protocol.ServerFactory()
            serverFactory.protocol = EAPTLSProtocol

            contextFactory = ssl.DefaultOpenSSLContextFactory(self.key, self.cert)

            wrapperFactory = TLSMemoryBIOFactory(contextFactory, False, serverFactory)

            tlsProtocol = wrapperFactory.buildProtocol(None)

            transport = proto_utils.StringTransport()

            tlsProtocol.makeConnection(transport)

            self.peap_protocols[state] = tlsProtocol

            print self.peap_protocols[state], "<<"

        #print "PEAP", repr(state), tlsProtocol

        if ((message.eap_code == EAPResponse) and (message.eap_type == EAPPEAP)):
            # Write into the TLS protocol

            in_flags = struct.unpack('!B', message.eap_data[0])[0]
            if in_flags>0:
                in_len = struct.unpack('!L', message.eap_data[1:5])[0]
                in_tls = message.eap_data[5:]

                print "TO TLS", repr(in_tls)
                print tlsProtocol.dataReceived(in_tls)

                data = tlsProtocol.transport.value()

                print "next", repr(data)

                return EAPPEAPChallengeRequest(
                    tlsProtocol, message.pkt, message.eap_id, 
                    self.server.secret, data=data)

        return EAPPEAPChallengeRequest(tlsProtocol,
            message.pkt, message.eap_id, self.server.secret)

    def processEAPMessage(self, message):
        #print message
        now = time.time()
        # Get incomming State if there is one
        state = message.pkt.get('State')

        if not state:
            state = uuid.uuid1().bytes
            self.auth_states[state] = [0, now, None]
        else:
            state = state[0]

        if ((message.eap_code == EAPResponse) and (message.eap_type == EAPNak)):
            # Is EAP Nak
            print "Got NAK"
            if self.auth_states[state][0] < len(self.auth_methods)-1:
                # Advance to next method
                # XXX - actually, the NAK will (might?) include the desired auth type
                self.auth_states[state][0]+=1
            else:
                # No agreement
                print "No agreement reached"
                del self.auth_states[state]
                return message.pkt.createReply(packet.AccessReject)

        # Find a processor for this state
        r = self.auth_methods[self.auth_states[state][0]](message, state)

        pkt = r.createPacket()

        # Add State attribute 
        pkt.addAttribute('State', state)

        return pkt

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

    def createReplyPacket(self, type, data=''):
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

class EAPPEAPChallengeRequest(EAPMessage):
    def __init__(self, proto, pkt, id, secret, data='\x20'):
        self.eap_code = EAPRequest
        self.eap_type = EAPPEAP
        self.eap_id = id
        self.pkt = pkt
        self.secret = secret
        # PEAP needs an SSL context
        self.tlsProtocol = proto

        self.data = data

    def createPacket(self):
        "Create a PEAP challnge EAP message"

        return self.createReplyPacket(packet.AccessChallenge, self.data)

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

