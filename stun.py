#!/usr/bin/env python


# http://tools.ietf.org/html/rfc5389

from twisted.internet.protocol import DatagramProtocol
from twisted.internet import defer
import time, socket, math, random, struct, md5, zlib, hmac, hashlib

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

def dump(data):
    for p in xrange(0, len(data), 16):
        print ' '.join(['%02X' % ord(x) for x in list(data[p:p+16])])

class STUN(DatagramProtocol):
    """
    Basic (incomplete) STUN implementation. Works for simple cases though
    """
    def __init__(self, password=None):
        self.password = password

    password = None
    state = STATE_UNREADY
    requestAttributes = None
    def getBindingRequest(self):
        random.seed(time.time())
        self.transaction_id = md5.new(str(random.getrandbits(32))).digest()
        header = struct.pack('!2H', BINDING_REQUEST, 0) + self.transaction_id
        return header
    
    def startProtocol(self):
        pass

    def request(self, server, port=3478):
        self.transport.connect( socket.gethostbyname(server), port )
        self.transport.write(self.getBindingRequest())
        self.state = STATE_SENT_REQUEST
        self.result = defer.Deferred()
        return self.result
    
    def decode_username(self, value):
        self.requestAttributes['username'] = value

    def decode_priority(self, value):
        self.requestAttributes['priority'] = struct.unpack('!I', value)[0]

    def decode_ice_controlled(self, value):
        self.requestAttributes['ice_controlled'] = struct.unpack('!Q', value)[0]

    def datagramReceived(self, data, (host, port)):
        self.requestAttributes = {}
        print "%r %r %r" % (host, port, data,)
        print "size", len(data)
        type, length = struct.unpack('!2H', data[:4])
        print "header says this is ", length
        id = data[4:20]
        if struct.unpack('!L', id[:4])[0] == MAGIC_COOKIE:
            #print "magic!"
            pass
        attributes = {}
        for attribute_id, value_length, value, startOffset in self.getAttributes(data[20:length+20]):
            #print "%r %r %r" % (type, value_length, value,)
            if attribute_id in STUN_ATTRIBUTES.keys():
                print "%s: %r" % (STUN_ATTRIBUTES[attribute_id], value,)
                method_name = "decode_%s" % (STUN_ATTRIBUTES[attribute_id],)
                if STUN_ATTRIBUTES[attribute_id] == 'fingerprint':
                    print "size of fingerprint", len(data[startOffset:])
                    print "claims it's ", value_length
                    print "%r" % (zlib.crc32(data[:startOffset]) ^ FINGERPRINT_MASK,)
                    print "%r" % (struct.unpack("!i", value)[0],)
                elif STUN_ATTRIBUTES[attribute_id] == 'message_integrity' and self.password:
                    key = self.password
                    #key = hashlib.md5(key).digest()
                    print "size w/o fingerprint", len(data[:startOffset]) - 20 + 24
                    print "other", length - 8
                    data_to_hash = data[:2] + struct.pack('!H', len(data[:startOffset]) - 20 + 24) + data[4:startOffset]
                    print len(data_to_hash), len(data[:startOffset])
                    #data_to_hash[2:4]
                    print "%r" % key
                    print "%r" % hmac.new(key, data_to_hash, hashlib.sha1).digest()
                    print "%r" % value

                if hasattr(self, method_name):
                    getattr(self, method_name)(value)
            else:
                print "unknown attribute %#x" % (attribute_id,)
            # if type == MAPPED_ADDRESS:
            #     family, recv_port, ip_addr = struct.unpack('!xBH4s', data)
            #     ip_addr = socket.inet_ntoa(ip_addr)
            #     print family, recv_port, ip_addr
            # elif type == SOURCE_ADDRESS:
            #     pass
            # elif type == USERNAME:
            #     print "username"
            # elif type == 0x8028:
            #     print 'fingerprint'
            # elif type == ICE_CONTROLLED:
            #     print 'ice controlled'
            # elif type == PRIORITY:
            #     print 'priority'
            # elif type == MESSAGE_INTEGRITY:
            #     print 'MESSAGE_INTEGRITY'
            # else:
            #     print "unknown type %r" % (hex(type),)
        print self.requestAttributes
        if type == BINDING_REQUEST:
            print "binding request"
            #self.transport.write("asd;lfakl;sdljkasdlkf", (host, port))

    def buildBindSuccessReply(self, requestHash):

        # packet dump of response says we just need
        # XOR mapped address
        # message integry
        # finger print
        response = [
            BINDING_ERROR, # type
            None, # length
            MAGIC_COOKIE,
            requestHash['transaction_id'],
            self.encodeAttribute('username', requestHash['username']),
            self.encodeAttribute('priority', requestHash['priority']),
            self.encodeAttribute('ice_controlling', requestHash['ice_controlled']),
            self.encodeAttribute('ice_controlling', requestHash['ice_controlled']),
            ]


    def encodeAttribute(self, type, value, encoding="!H"):
        encodedValue = struct.pack(encoding, value)
        return [STUN_ATTRIBUTE_CODES[type], struct.pack("!H", len(encodedValue)), encodedValue]

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

FAMILY_IPV4 = 0x01
FAMILY_IPV6 = 0x02

def encodeMappedAddress(ip_addr, port, family=FAMILY_IPV4):
    ip_addr = socket.inet_aton(ip_addr)
    return struct.pack('!xBH4s', family, port, ip_addr)

if __name__ == "__main__":
    from twisted.internet import reactor
    from twisted.python import log
    import sys
    #log.startLogging(sys.stdout)
    s = STUN(password='9b4424d9e8c5e253c0290d63328b55b3')
    print "STUN server listening on UDP 4488..."
    reactor.listenUDP(4488, s)
    #def found( (addr,port) ):
    #    print "%s:%s" % (addr, port)
    #    reactor.stop()
    #s.request('stunserver.org').addCallback(found)
    reactor.run()
    
