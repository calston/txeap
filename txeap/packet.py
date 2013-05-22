import struct

AccessRequest = 1
AccessAccept = 2
AccessReject = 3
AccountingRequest = 4
AccountingResponse = 5
AccessChallenge = 11
StatusServer = 12
StatusClient = 13
DisconnectRequest = 40
DisconnectACK = 41
DisconnectNAK = 42
CoARequest = 43
CoAACK = 44
CoANAK = 45

class RadiusPacket(object):
    # Lets do this less insanely

    def __init__(self, datagram=None):

        self.datagram = datagram

        if self.datagram:
            self.decodeDatagram()

    def decodeDatagram(self):
        header = self.datagram[:20]
        (
            self.rad_code, self.rad_id, length, self.rad_auth
        ) = struct.unpack('!BBH16s', header)

        buffer = self.datagram[20:]

        


