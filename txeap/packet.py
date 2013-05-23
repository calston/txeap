import struct

from txeap import dictionary

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

    def __init__(self, code=1, id=1, datagram=None, dictionary=dictionary.SimpleDict):
        # Non decoded attributes
        self.raw_attributes = {}
        # decoded attributes
        self.attributes = {}

        self.rad_code = code
        self.rad_id = id
        self.rad_auth = None

        self.dictionary = dictionary

        self.datagram = datagram

        if self.datagram:
            self.decodeDatagram()

    def getDecoder(self, key):
        decoder = self.dictionary.get(key, None)
        if not decoder:
            return lambda x: x
        return decoder[1]

    def getAttributeName(self, key):
        return self.dictionary.get(key,[key])[0]

    def get(self, key, default=[None]):
        return self.attributes.get(key, default)

    def addAttribute(self, key, value):
        # Store the raw attribute
        if key in self.raw_attributes:
            self.raw_attributes[key].append(value)
        else:
            self.raw_attributes[key] = [value]

        # Get the attribute name and decoder for this key id
        name = self.getAttributeName(key)
        d_val = self.getDecoder(key)(value)

        # Store pretty attribute list
        if name in self.attributes:
            self.attributes[name].append(d_val)
        else:
            self.attributes[name] = [d_val]

    def decodeDatagram(self):
        header = self.datagram[:20]
        (
            self.rad_code, self.rad_id, length, self.rad_auth
        ) = struct.unpack('!BBH16s', header)

        buffer = self.datagram[20:]

        while buffer:
            (key, val_len) = struct.unpack('!BB', buffer[:2])
            val = buffer[2:val_len]

            self.addAttribute(key, val)

            buffer = buffer[val_len:]

