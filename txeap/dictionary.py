import struct
import socket


class Transcoders(object):
    def string(self, val, en=False):
        return val

    def octets(self, val, en=False):
        return val

    def integer(self, val, en=False):
        if en:
            return struct.pack('!I', val)

        return struct.unpack('!I', val)[0]

    def ipaddr(self, val, en=False):
        if en:
            return socket.inet_aton(val)

        return socket.inet_ntoa(val)
        
    def date(self, val, en=False):
        if en:
            return struct.pack('!I', val)

        return struct.unpack('!I', val)[0]

def reverseDict(d):
    newd={}
    for k,v in d.items():
        attr_name, decoder = v
        newd[attr_name] = k
    return newd

decoders = Transcoders()

SimpleDict = {
    1: ('User-Name', decoders.string),
    2: ('User-Password', decoders.string),
    3: ('CHAP-Password', decoders.octets),
    4: ('NAS-IP-Address', decoders.ipaddr),
    5: ('NAS-Port', decoders.integer),
    6: ('Service-Type', decoders.integer),
    7: ('Framed-Protocol', decoders.integer),
    8: ('Framed-IP-Address', decoders.ipaddr),
    9: ('Framed-IP-Netmask', decoders.ipaddr),
    10: ('Framed-Routing', decoders.integer),
    11: ('Filter-Id', decoders.string),
    12: ('Framed-MTU', decoders.integer),
    13: ('Framed-Compression', decoders.integer),
    14: ('Login-IP-Host', decoders.ipaddr),
    15: ('Login-Service', decoders.integer),
    16: ('Login-TCP-Port', decoders.integer),
    18: ('Reply-Message', decoders.string),
    19: ('Callback-Number', decoders.string),
    20: ('Callback-Id', decoders.string),
    22: ('Framed-Route', decoders.string),
    23: ('Framed-IPX-Network', decoders.ipaddr),
    24: ('State', decoders.octets),
    25: ('Class', decoders.octets),
    26: ('Vendor-Specific', decoders.octets),
    27: ('Session-Timeout', decoders.integer),
    28: ('Idle-Timeout', decoders.integer),
    29: ('Termination-Action', decoders.integer),
    30: ('Called-Station-Id', decoders.string),
    31: ('Calling-Station-Id', decoders.string),
    32: ('NAS-Identifier', decoders.string),
    33: ('Proxy-State', decoders.octets),
    34: ('Login-LAT-Service', decoders.string),
    35: ('Login-LAT-Node', decoders.string),
    36: ('Login-LAT-Group', decoders.octets),
    37: ('Framed-AppleTalk-Link', decoders.integer),
    38: ('Framed-AppleTalk-Network', decoders.integer),
    39: ('Framed-AppleTalk-Zone', decoders.string),
    40: ('Acct-Status-Type', decoders.integer),
    41: ('Acct-Delay-Time', decoders.integer),
    42: ('Acct-Input-Octets', decoders.integer),
    43: ('Acct-Output-Octets', decoders.integer),
    44: ('Acct-Session-Id', decoders.string),
    45: ('Acct-Authentic', decoders.integer),
    46: ('Acct-Session-Time', decoders.integer),
    47: ('Acct-Input-Packets', decoders.integer),
    48: ('Acct-Output-Packets', decoders.integer),
    49: ('Acct-Terminate-Cause', decoders.integer),
    50: ('Acct-Multi-Session-Id', decoders.string),
    51: ('Acct-Link-Count', decoders.integer),
    52: ('Acct-Input-Gigawords', decoders.integer),
    53: ('Acct-Output-Gigawords', decoders.integer),
    55: ('Event-Timestamp', decoders.date),
    60: ('CHAP-Challenge', decoders.string),
    61: ('NAS-Port-Type', decoders.integer),
    62: ('Port-Limit', decoders.integer),
    63: ('Login-LAT-Port', decoders.integer),
    68: ('Acct-Tunnel-Connection', decoders.string),
    70: ('ARAP-Password', decoders.string),
    71: ('ARAP-Features', decoders.string),
    72: ('ARAP-Zone-Access', decoders.integer),
    73: ('ARAP-Security', decoders.integer),
    74: ('ARAP-Security-Data', decoders.string),
    75: ('Password-Retry', decoders.integer),
    76: ('Prompt', decoders.integer),
    77: ('Connect-Info', decoders.string),
    78: ('Configuration-Token', decoders.string),
    79: ('EAP-Message', decoders.octets),
    80: ('Message-Authenticator', decoders.octets),
    84: ('ARAP-Challenge-Response', decoders.string),
    85: ('Acct-Interim-Interval', decoders.integer),
    87: ('NAS-Port-Id', decoders.string),
    88: ('Framed-Pool', decoders.string),
    95: ('NAS-IPv6-Address', decoders.octets),
    96: ('Framed-Interface-Id', decoders.octets),
    97: ('Framed-IPv6-Prefix', decoders.octets),
    98: ('Login-IPv6-Host', decoders.octets),
    99: ('Framed-IPv6-Route', decoders.string),
    100: ('Framed-IPv6-Pool', decoders.string),
    206: ('Digest-Response', decoders.string),
    207: ('Digest-Attributes', decoders.octets),
    500: ('Fall-Through', decoders.integer),
    502: ('Exec-Program', decoders.string),
    503: ('Exec-Program-Wait', decoders.string),
    1029: ('User-Category', decoders.string),
    1030: ('Group-Name', decoders.string),
    1031: ('Huntgroup-Name', decoders.string),
    1034: ('Simultaneous-Use', decoders.integer),
    1035: ('Strip-User-Name', decoders.integer),
    1040: ('Hint', decoders.string),
    1041: ('Pam-Auth', decoders.string),
    1042: ('Login-Time', decoders.string),
    1043: ('Stripped-User-Name', decoders.string),
    1044: ('Current-Time', decoders.string),
    1045: ('Realm', decoders.string),
    1046: ('No-Such-Attribute', decoders.string),
    1047: ('Packet-Type', decoders.integer),
    1048: ('Proxy-To-Realm', decoders.string),
    1049: ('Replicate-To-Realm', decoders.string),
    1050: ('Acct-Session-Start-Time', decoders.date),
    1051: ('Acct-Unique-Session-Id', decoders.string),
    1052: ('Client-IP-Address', decoders.ipaddr),
    1053: ('Ldap-UserDn', decoders.string),
    1054: ('NS-MTA-MD5-Password', decoders.string),
    1055: ('SQL-User-Name', decoders.string),
    1057: ('LM-Password', decoders.octets),
    1058: ('NT-Password', decoders.octets),
    1059: ('SMB-Account-CTRL', decoders.integer),
    1061: ('SMB-Account-CTRL-TEXT', decoders.string),
    1062: ('User-Profile', decoders.string),
    1063: ('Digest-Realm', decoders.string),
    1064: ('Digest-Nonce', decoders.string),
    1065: ('Digest-Method', decoders.string),
    1066: ('Digest-URI', decoders.string),
    1067: ('Digest-QOP', decoders.string),
    1068: ('Digest-Algorithm', decoders.string),
    1069: ('Digest-Body-Digest', decoders.string),
    1070: ('Digest-CNonce', decoders.string),
    1071: ('Digest-Nonce-Count', decoders.string),
    1072: ('Digest-User-Name', decoders.string),
    1073: ('Pool-Name', decoders.string),
    1074: ('Ldap-Group', decoders.string),
    1075: ('Module-Success-Message', decoders.string),
    1076: ('Module-Failure-Message', decoders.string),
    1000: ('Auth-Type', decoders.integer),
    1001: ('Menu', decoders.string),
    1002: ('Termination-Menu', decoders.string),
    1003: ('Prefix', decoders.string),
    1004: ('Suffix', decoders.string),
    1005: ('Group', decoders.string),
    1006: ('Crypt-Password', decoders.string),
    1007: ('Connect-Rate', decoders.integer),
    1008: ('Add-Prefix', decoders.string),
    1009: ('Add-Suffix', decoders.string),
    1010: ('Expiration', decoders.date),
    1011: ('Autz-Type', decoders.integer)
}
