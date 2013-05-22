from pyrad import dictionary, packet, curved, server

import os
import hmac
import struct

class RadiusServer(curved.RADIUSAccess):
    def __init__(self, config):
        self.config = config
        self.secret = config['secret']
        
        hosts = {}
        for host in config.get('hosts', ['127.0.0.1']):
            hosts[host] = server.RemoteHost(
                host,
                self.secret,
                host
            )

        cwd = os.path.dirname(__file__)

        mydict = dictionary.Dictionary(
            os.path.join(cwd, 'dictionary')
        )


        curved.RADIUS.__init__(self, hosts=hosts, dict=mydict)

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

            if eapm:
                eap_code, eap_id, eap_len = struct.unpack('!BBH', eapm[:4])
                eap_data = eapm[4:]
                if eap_code == 1:
                    # Request

                if eap_code == 2:
                    # Response

                if eap_code == 3:
                    # Success

                if eap_code == 4:
                    # Fail

            
            self.transport.write(   
                self.createReplyPacket(
                    packet.AccessAccept, 
                    pkt
                ), 
                pkt.source
            )
