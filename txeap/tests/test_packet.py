from twisted.trial import unittest
from twisted.python import log

from txeap import packet

EAPDatagram='\x01\x00\x00w\xabh\xa4\x98.\x81,\x9f\xbcAu\xf4N\xfe\xc9%\x01\x06test\x04\x06\x7f\x00\x00\x01\x1f\x1370-6F-6C-69-73-68\x0c\x06\x00\x00\x05x=\x06\x00\x00\x00\x13M\x1brad_eap_test + eapol_testO\x0b\x02\x00\x00\t\x01testP\x12\xb0Nd\xc2\xa1\xa6\xba\xc9\xd7P\r\xbcf\x85\xf5%'

class Tests(unittest.TestCase):

    def test_decode_packet(self):
        p = packet.RadiusPacket(datagram=EAPDatagram)
        
        self.assertEqual(p.rad_code, 1)
        self.assertEqual(p.rad_id, 0)

        self.assertEqual(p.get('User-Name'), ['test'])
        self.assertEqual(p.get('NAS-IP-Address'), ['127.0.0.1'])

    def test_encode_packet(self):
        p = packet.RadiusPacket(1, 33)

        pwstring = 'u\x9dw8\x81\xe9\xcfXb\xdb\x152\x9bR\xef\xf5'
        p.addAttribute('User-Name', 'testuser')
        p.addAttribute('User-Password', pwstring)

        raw_packet = p.encodeDatagram('testpass')

        newp = packet.RadiusPacket(datagram=raw_packet)
        self.assertEqual(p.get('User-Name'), ['testuser'])
        self.assertEqual(p.get('User-Password'), [pwstring])

    def test_add_attributes(self):
        p = packet.RadiusPacket()

        p.addAttribute('User-Name', 'testuser')

        self.assertEqual(p.get('User-Name'), ['testuser'])
        self.assertEqual(p.raw_attributes[1], ['testuser'])

    def test_decoders(self):
        p = packet.RadiusPacket()

        raw = '\x01\x02\x03'
        p.addAttribute('CHAP-Password', raw)
        self.assertEqual(p.raw_attributes[3], [raw])

        num = 12345123
        p.addAttribute('Login-Service', num)
        self.assertEqual(p.raw_attributes[15], ['\x00\xbc_#'])

        p.addAttribute('Login-IP-Host', '10.0.0.1')
        self.assertEqual(p.raw_attributes[14], ['\n\x00\x00\x01'])
