from twisted.trial import unittest
from twisted.python import log

from txeap import packet, eap

EAPDatagram='\x01\x00\x00w%\xfd\xe7\xb5,\xc2\xbe-\xd9\xde\xd0\xcco\x94\x04\x8a\x01\x06test\x04\x06\x7f\x00\x00\x01\x1f\x1370-6F-6C-69-73-68\x0c\x06\x00\x00\x05x=\x06\x00\x00\x00\x13M\x1brad_eap_test + eapol_testO\x0b\x02\x00\x00\t\x01testP\x12\x0f\x99\xd2\xc1\xc8E\x88\xc2l07\x1c\xfb\xae\xde\xb0'

class Tests(unittest.TestCase):
    def setUp(self):
        self.pkt = packet.RadiusPacket(datagram=EAPDatagram)
        eap_data = self.pkt.get('EAP-Message')[0]
        self.eap_message = eap.EAPMessage(self.pkt, 'testseekrit', data=eap_data)

    def test_decode_message(self):
        self.assertEquals(self.eap_message.eap_code, eap.EAPResponse)
        self.assertEquals(self.eap_message.eap_id, 0)
        self.assertEquals(self.eap_message.eap_type, eap.EAPRequestIdentity)
        self.assertEquals(self.eap_message.eap_data, 'test')

    def test_build_response(self):
        pkt = packet.RadiusPacket(packet.AccessRequest)

        eapm = eap.EAPMessage(
            pkt, 'testseekrit', eap.EAPResponse, 0, eap.EAPRequestIdentity)

        pkt = eapm.createReplyPacket('test')

        dg = pkt.encodeDatagram('testseekrit')

        newpkt = packet.RadiusPacket(datagram=dg)
        eap_data = newpkt.get('EAP-Message')[0]
        eapm = eap.EAPMessage(newpkt, 'testseekrit', data=eap_data)

    def test_eapmd5(self):
        # Build a challenge request
        eapmd5 = eap.EAPMD5ChallengeRequest(self.pkt, 'testseekrit')

        dg = eapmd5.createPacket().encodeDatagram('testseekrit')

        pkt = packet.RadiusPacket(datagram=dg)
        eap_data = pkt.get('EAP-Message')[0]
        
        # Verify it can be decoded
        eapm = eap.EAPMessage(self.pkt, 'testseekrit', data=eap_data)

        self.assertEquals(eapm.eap_id, 1)
        self.assertEquals(eapm.eap_type, 4)
        self.assertEquals(eapm.eap_code, 1)
