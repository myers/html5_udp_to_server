#!/usr/bin/env python


# http://tools.ietf.org/html/rfc5389

from twisted.internet.protocol import DatagramProtocol
from twisted.internet import defer
import time, socket, math, random, struct, md5, zlib, hmac, hashlib
import pprint, traceback
"""
s = STUN()
reactor.listenUDP(0,s)
def found( (addr, port) )
    print "%s:%s" % (addr, port)
s.request('stunserver.org').addCallback(found)
"""

BINDING_REQUEST  = 0x0001
BINDING_RESPONSE = 0x0101
BINDING_ERROR    = 0x0111
SS_REQUEST  = 0x0002
SS_RESPONSE = 0x0102
SS_ERROR    = 0x0112

FAMILY_IPV4 = 0x01
FAMILY_IPV6 = 0x02

STUN_ATTRIBUTES = {
    0x0001: 'mapped_address',
    0x0002: 'response_address',
    0x0003: 'change_request',
    0x0004: 'source_address',
    0x0005: 'changed_address',
    0x0006: 'username',
    0x0007: 'password',
    0x0008: 'message_integrity',
    0x0009: 'error_code',
    0x000a: 'unknown_attributes',
    0x000b: 'reflected_from',
    0x0020: 'xor_mapped_address',
    0x8028: 'fingerprint',
    0x8022: 'software',
    0x8023: 'alternate_server',
    # from https://tools.ietf.org/html/rfc5245
    0x0024: 'priority',
    0x0025: 'use_candidate',
    0x8029: 'ice_controlled',
    0x802a: 'ice_controlling',
}

STUN_ATTRIBUTE_CODES = dict((v,k) for k, v in STUN_ATTRIBUTES.iteritems())

STATE_UNREADY = 0
STATE_SENT_REQUEST = 1

FINGERPRINT_MASK = 0x5354554e
MAGIC_COOKIE = 0x2112A442
MAGIC_COOKIE_STR = struct.pack("!I", MAGIC_COOKIE)

class STUN(DatagramProtocol):
    """
    Basic (incomplete) STUN implementation. Works for simple cases though
    """
    password = None
    state = STATE_UNREADY
    requestAttributes = None
    transactionId = None

    def __init__(self, password=None):
       self.password = password

    def datagramReceived(self, data, (host, port)):
        self.requestAttributes = {}
        #print "%r %r %r" % (host, port, data,)
        #print "size", len(data)
        packetType, length = struct.unpack('!2H', data[:4])
        if packetType not in (BINDING_REQUEST, BINDING_RESPONSE, BINDING_ERROR,):
            raise NotSTUNPacket("unknown packet packetType %#x" % (packetType,))

        #print "header says this is ", length
        self.requestAttributes = {'transaction_id': data[4:20]}
        
        # TODO: verify this has the magic cookie, valid fingerprint and valid message integrity
        if struct.unpack('!L', self.requestAttributes['transaction_id'][:4])[0] != MAGIC_COOKIE:
            raise IsNotMagicalError()

        for attribute_id, value_length, value, startOffset in self.getAttributes(data[20:length+20]):
            #print "%r %r %r" % (packetType, value_length, value,)
            if attribute_id not in STUN_ATTRIBUTES.keys():
                print "unknown attribute %#x" % (attribute_id,)
                continue
            #print "%s: %r" % (STUN_ATTRIBUTES[attribute_id], value,)
            if STUN_ATTRIBUTES[attribute_id] == 'fingerprint':
                packet_fingerprint = zlib.crc32(data[:startOffset]) ^ FINGERPRINT_MASK
                recorded_fingerprint = struct.unpack("!i", value)[0]
                if packet_fingerprint != recorded_fingerprint:
                    raise FingerprintMismatch()
            elif STUN_ATTRIBUTES[attribute_id] == 'message_integrity' and self.password:
                key = self.password
                data_to_hash = data[:2] + struct.pack('!H', len(data[:startOffset]) - 20 + 24) + data[4:startOffset]
                packet_hmac = hmac.new(key, data_to_hash, hashlib.sha1).digest()
                recorded_hmac = value
                if packet_hmac != recorded_hmac:
                    raise MessageIntegrityMismatch()
            else:
                method_name = "decode_%s" % (STUN_ATTRIBUTES[attribute_id],)
                if not hasattr(self, method_name):
                    raise Exception('Cannot decode %r' % (STUN_ATTRIBUTES[attribute_id],))
                getattr(self, method_name)(value)
                
        if packetType == BINDING_REQUEST:
            self.requestRecieved(self.requestAttributes, (host, port,))
        elif packetType == BINDING_RESPONSE:
            self.responseRecieved(self.requestAttributes, (host, port,))
        elif packetType == BINDING_ERROR:
            raise RuntimeError(self.requestAttributes)
            #self.responseRecieved(self.requestAttributes, (host, port,))
        else:
            raise RuntimeError("Unknown packet")

    def request(self, server, port=3478):
        self.transport.connect( socket.gethostbyname(server), port )
        self.transport.write(self.getBindingRequest())
        self.state = STATE_SENT_REQUEST
        self.result = defer.Deferred()
        return self.result
    
    def decode_use_candidate(self, value):
        assert len(value) == 0, "this should have no value"

    def decode_error_code(self, value):
        self.requestAttributes['error_code'] = struct.unpack('!I', value[:4])[0]

    def decode_username(self, value):
        self.requestAttributes['username'] = value

    def decode_priority(self, value):
        self.requestAttributes['priority'] = struct.unpack('!I', value)[0]

    def decode_mapped_address(self, value):
        family, recv_port, ip_addr = struct.unpack('!xBH4s', data)
        ip_addr = socket.inet_ntoa(ip_addr)
        self.requestAttributes['mapped_address'] = (ip_addr, recv_port,)

    def decode_xor_mapped_address(self, value):
        if struct.unpack("!H", value[:2])[0] != FAMILY_IPV4:
            raise Exception("IPv6 not supported yet")
        binary_port = sxor(MAGIC_COOKIE_STR[:2], value[2:4])
        binary_ip_address = sxor(MAGIC_COOKIE_STR, value[4:])
        self.requestAttributes['mapped_address'] = (socket.inet_ntoa(binary_ip_address), struct.unpack("!H", binary_port)[0])

    def decode_ice_controlled(self, value):
        self.requestAttributes['ice_controlled'] = struct.unpack('!Q', value)[0]

    def requestRecieved(self, attrib, source):
        pass

    def responseRecieved(self, attrib, source):
        pass

    def addMessageIntegrityAndFingerprint(self, packet):
        # HMAC
        packet[1] = struct.pack("!H", len(''.join(packet[3:])) + 24)
        data_to_hash = ''.join(packet)
        packet_hmac = hmac.new(self.password, data_to_hash, hashlib.sha1).digest()
        packet.append(encodeAttribute('message_integrity', packet_hmac))

        # FINGERPRINT
        packet[1] = struct.pack("!H", len(''.join(packet[3:])) + 8)
        data_to_crc32 = ''.join(packet)
        fingerprint = zlib.crc32(data_to_crc32) ^ FINGERPRINT_MASK
        packet.append( encodeAttribute('fingerprint', struct.pack('!i', fingerprint)) )

        return ''.join(packet)

    def buildBindingRequest(self, attribs):
        if 'transaction_id' in attribs:
            self.transactionId = attribs['transaction_id']
        else:
            self.transactionId = MAGIC_COOKIE_STR + hashlib.md5(str(random.getrandbits(32))).digest()[:12]
        assert len(self.transactionId) == 16, len(self.transactionId)
        request = [
            struct.pack("!H", BINDING_REQUEST), # type
            struct.pack("!H", 0), # length
            self.transactionId,
        ]
        assert len(''.join(request)) == 20, len(''.join(request))
        if 'username' in attribs:
            request.append(encodeUsername(attribs['username']))
        if 'use_candidate' in attribs:
            request.append(encodeUseCanidate())
        if 'priority' in attribs:
            request.append(encodePriority(attribs['priority']))
        if 'ice_controlling' in attribs:
            request.append(encodeIceControlling(attribs['ice_controlling']))
        if 'ice_controlled' in attribs:
            request.append(encodeIceControlled(attribs['ice_controlled']))

        return self.addMessageIntegrityAndFingerprint(request)

    def buildBindSuccessReply(self, transactionId, address):
        response = [
            struct.pack("!H", BINDING_RESPONSE), # type
            None, # length
            transactionId,
            encodeXORMappedAddress(address[0], address[1])
        ]

        return self.addMessageIntegrityAndFingerprint(response)


    def receiveBindingResponse(self, (host,port), response):
        for type, length, data in self.getAttributes(response):
            if type == MAPPED_ADDRESS:
                family, recv_port, ip_addr = struct.unpack('>xBH4s', data)
                ip_addr = socket.inet_ntoa(ip_addr)
                self.result.callback( (ip_addr, recv_port) )
            elif type == SOURCE_ADDRESS:
                pass    
    
    def getAttributes(self, data):
        # After the STUN header are zero or more attributes.  Each attribute
        # MUST be TLV encoded, with a 16-bit type, 16-bit length, and value.
        # Each STUN attribute MUST end on a 32-bit boundary.  As mentioned
        # above, all fields in an attribute are transmitted most significant
        # bit first.
        ptr = 0
        while ptr<len(data):
            type, length = struct.unpack('!2H', data[ptr:ptr+4])
            yield type, length, data[ptr+4:ptr+4+length], ptr+20
            attribute_length = 4 + 4 * int(math.ceil(length / 4.0))
            ptr += attribute_length

    def connectionRefused(self):
        print "noone listening"

def sxor(s1,s2):    
    # convert strings to a list of character pair tuples
    # go through each tuple, converting them to ASCII code (ord)
    # perform exclusive or on the ASCII code
    # then convert the result back to ASCII (chr)
    # merge the resulting array of characters as a string
    return ''.join(chr(ord(a) ^ ord(b)) for a,b in zip(s1,s2))

def encodeAttribute(attributeType, value):
    attrib = [struct.pack("!HH", STUN_ATTRIBUTE_CODES[attributeType], len(value)), value,]
    padding_length = 4 - (len(value) % 4)
    if padding_length < 4:
        attrib.append("\x00" * padding_length)
    return ''.join(attrib)

def encodeUsername(username):
    return encodeAttribute('username', username)

def encodePriority(priority):
    return encodeAttribute('priority', struct.pack("!I", priority))

def encodeIceControlling(value):
    return encodeAttribute('ice_controlling', struct.pack("!Q", value))

def encodeIceControlled(value):
    return encodeAttribute('ice_controlled', struct.pack("!Q", value))

def encodeUseCanidate(value=None):
    return encodeAttribute('use_candidate', '')

def encodeMappedAddress(ip_addr, port, family=FAMILY_IPV4):
    ip_addr = socket.inet_aton(ip_addr)
    return struct.pack('!xBH4s', family, port, ip_addr)

def encodeXORMappedAddress(ip_addr, port, family=FAMILY_IPV4):
    family = struct.pack("!H", family)
    port = sxor(MAGIC_COOKIE_STR[:2], struct.pack("!H", port))
    ip_address = sxor(MAGIC_COOKIE_STR, socket.inet_aton(ip_addr))
    value = ''.join((family, port, ip_address,))
    return encodeAttribute('xor_mapped_address', value)

class NotSTUNPacket(RuntimeError):
    pass
class FingerprintMismatch(NotSTUNPacket):
    pass
class MessageIntegrityMismatch(NotSTUNPacket):
    pass
class IsNotMagicalError(NotSTUNPacket):
    pass
