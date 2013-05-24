import struct
import hashlib
import uuid

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

class InvalidAttribute(Exception):
    "Invalid attribute exception"

class RadiusPacket(object):
    def __init__(self, code=1, id=1, auth=None,
                 datagram=None, dict=dictionary.SimpleDict):
        # Non decoded attributes
        self.raw_attributes = {}
        # decoded attributes
        self.attributes = {}

        self.rad_code = code
        self.rad_id = id

        if auth:
            self.rad_auth = auth
        else:
            # Worlds laziest PRG 
            self.rad_auth = hashlib.md5(uuid.uuid1().bytes).digest()

        self.dictionary = dict
        self.reverse_dictionary = dictionary.reverseDict(dict)

        self.datagram = datagram

        if self.datagram:
            self.decodeDatagram()

    def createReply(self, code=1):
        "Return a configured reply packet for this packet of type 'code'"
        return RadiusPacket(code, self.rad_id, self.rad_auth, 
                            dict=self.dictionary)

    def getDecoder(self, key):
        "Return a decoder function for this key from the dictionary"
        decoder = self.dictionary.get(key, None)
        if not decoder:
            return lambda x: x
        return decoder[1]

    def getAttributeName(self, key):
        "Return the attribute name for key id"
        return self.dictionary.get(key,[key])[0]

    def getAttributeId(self, keyname):
        return self.reverse_dictionary.get(keyname, None)

    def get(self, key, default=None):
        "Return the decoded value for a key by its attribute name"
        return self.attributes.get(key, default)

    def _addRawAttribute(self, key, value):
        if key in self.raw_attributes:
            self.raw_attributes[key].append(value)
        else:
            self.raw_attributes[key] = [value]

    def _addAttribute(self, key, value):
        if key in self.attributes:
            self.attributes[key].append(value)
        else:
            self.attributes[key] = [value]

    def setAttribute(self, key, value):
        if isinstance(key, int):
            name = self.getAttributeName(key)
            key = key
        else:
            name = key
            key = self.getAttributeId(key)
        
        # Clear any attributes
        if key in self.raw_attributes:
            del self.raw_attributes[key]
        if name in self.attributes:
            del self.attributes[name]

        self.addAttribute(key, value)
        
    def addAttribute(self, key, value):
        "Add a attribute to this packet"

        if isinstance(key, int):
            # Store the raw attribute
            self._addRawAttribute(key, value)

            # Get the attribute name and decoder for this key id
            name = self.getAttributeName(key)
            if not name:
                raise InvalidAttribute(
                    "Attribute '%s' not found in local dictionary" % key)

            d_val = self.getDecoder(key)(value)

            # Store pretty attribute list
            self._addAttribute(name, d_val)
        else:
            # Assume this needs encoding
            self._addAttribute(key, value)

            id = self.getAttributeId(key)
            if not id:
                raise InvalidAttribute(
                    "Attribute '%s' not found in local dictionary" % key)

            r_val = self.getDecoder(id)(value, en=True)
            self._addRawAttribute(id, r_val)

    def decodeDatagram(self):
        "Decodes a datagram and configures this packet object appropriately"
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

    def encodeHeader(self, length, authenticator):
        return struct.pack('!BBH16s', 
            self.rad_code, 
            self.rad_id, 
            length,
            authenticator
        )

    def encodeDatagram(self, secret):
        "Return a datagram for this packet"
        # Encode attributes
        attributes = ""
        attr_keys = self.raw_attributes.keys()
        # Ensure we always do this in the same order (important for hashing)
        attr_keys.sort()
        for k in attr_keys:
            v = self.raw_attributes[k]
            for attr in v:
                attr_hdr = struct.pack('!BB', k, len(attr)+2)
                attributes += attr_hdr + attr

        length = 20+len(attributes)
        
        # Create first authenticator header
        first_header = self.encodeHeader(length, self.rad_auth)
        # Create real hash
        s = hashlib.md5(first_header + secret).digest()

        return self.encodeHeader(length, s) + attributes
