from OpenSSL import SSL
from zope.interface import implements

from twisted.internet import ssl, protocol
from twisted.protocols.tls import TLSMemoryBIOProtocol, TLSMemoryBIOFactory
from twisted.internet.interfaces import ITransport

from txeap import packet, proto_utils, eap

import os
import hmac
import struct
import uuid
import hashlib
import time
from StringIO import StringIO

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
        self.peap_buffers = {}

    def eapMD5(self, message, state):
        "Handle EAP-MD5 sessions"
        if message.eap_type == eap.EAPMD5Challenge:
            # Challenge accepted

            passwd = message.pkt.getUserPassword(self.server.secret)
            username = message.pkt.get('User-Name')[0]

            # Call out to our authenticator (isn't this a deferred?)
            authorization = self.server.authenticateUser(username, passwd)
            if authorization:
                return eap.EAPSuccessReply(
                    message.pkt, message.eap_id, self.server.secret)
            else:
                return eap.EAPFailReply(
                    message.pkt, message.eap_id, self.server.secret)

            del self.auth_states[message.pkt.get('State')[0]]

        else:
            return eap.EAPMD5ChallengeRequest(
                message.pkt, message.eap_id, self.server.secret)

    def getEAPTLSTransport(self, state):
        # Create a server factory
        serverFactory = protocol.ServerFactory()
        serverFactory.protocol = lambda : eap.EAPTLSProtocol(state, self.peap_protocols)

        # Wrap it onto a context
        contextFactory = ssl.DefaultOpenSSLContextFactory(
            self.key, self.cert, sslmethod=SSL.TLSv1_METHOD
        )
        wrapperFactory = TLSMemoryBIOFactory(contextFactory, False, serverFactory)

        # Rig up a SSL wrapper to fake transport 
        tlsProtocol = wrapperFactory.buildProtocol(None)
        transport = proto_utils.StringTransport()
        tlsProtocol.makeConnection(transport)

        return tlsProtocol

    def eapPEAP(self, message, state):
        "Handle EAP-PEAP sessions"

        if state in self.peap_protocols:
            tlsProtocol, tlsInput = self.peap_protocols[state]
        else:
            # XXX Invalidate this somehow

            # Set the auth process state
            self.auth_states[state][2] = 0
            self.peap_protocols[state] = [None, None]
            tlsProtocol = self.getEAPTLSTransport(state)
            # Link the tlsProtocol, and extract the input protocol
            self.peap_protocols[state][0] = tlsProtocol
            tlsInput = self.peap_protocols[state][1]

        print "Proto object selected:", tlsProtocol, tlsInput

        buffer = tlsProtocol.transport.io
        if ((message.eap_code == eap.EAPResponse) and (message.eap_type == eap.EAPPEAP)):

            in_flags = struct.unpack('!B', message.eap_data[0])[0]

            if eap.matchflag(in_flags, eap.TLSLen):
                # Access-Request/response contains data
                in_len = struct.unpack('!L', message.eap_data[1:5])[0]
                in_tls = message.eap_data[5:]

                # Write into the TLS protocol

                tlsProtocol.dataReceived(in_tls)
    
                # Read response from TLS protocol
                tlsProtocol.transport.io.seek(0)
                data = tlsProtocol.transport.io.read(1000)

                flags = eap.TLSLen

                buffer_remaining = len(buffer.buf) - buffer.pos

                if buffer_remaining:
                    # Fragment this data
                    flags |= eap.TLSFrag
                    exlen = len(buffer.buf)
                else:
                    # Clear the buffer 
                    tlsProtocol.transport.clear()
                    buffer = tlsProtocol.transport.io
                    exlen = len(data)

                #print "Responded > ", flags, exlen, repr(data)[:10]

                return eap.EAPPEAPChallengeRequest(
                    tlsProtocol, message.pkt, message.eap_id, 
                    self.server.secret, flags = flags, exlen=exlen, data=data)

            else:
                buffer_remaining = len(buffer.buf) - buffer.pos
                if buffer_remaining:
                    # send next fragment
                    data = tlsProtocol.transport.io.read(1000)
                    flags = 0
                    return eap.EAPPEAPChallengeRequest(
                        tlsProtocol, message.pkt, message.eap_id, 
                        self.server.secret, flags = flags, data=data)
                else:
                    self.auth_states[state][2] += 1 
                    tlsProtocol.transport.clear()
                    buffer = tlsProtocol.transport.io

        auth_state = self.auth_states[state][2] 

        print "Current state:", auth_state

        if auth_state == 0:
            return eap.EAPPEAPChallengeRequest(tlsProtocol,
                message.pkt, message.eap_id, self.server.secret, flags = eap.TLSStart)

        elif auth_state == 1:
            
            return eap.EAPPEAPIdentity(tlsProtocol, tlsInput,
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

        if ((message.eap_code == eap.EAPResponse) and (message.eap_type == eap.EAPNak)):
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

        message = eap.EAPMessage(pkt, self.server.secret, data=eap_data)
        
        return self.processEAPMessage(message)

