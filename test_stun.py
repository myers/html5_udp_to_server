from twisted.trial import unittest
import stun

class STUNTestCase(unittest.TestCase):
    def testWebrtcRequest(self):
        webrtc_stun_request = "\x00\x01\x00L!\x12\xa4BCW\xe1\xabj\x9bV\xa38SQ\xb1\x00\x06\x00\x113081b21e:24b1caa0\x00\x00\x00\x00$\x00\x04n\xfb\x00\xff\x80)\x00\x08\x8bK\x8e\xab\n\xf1\x00\x07\x00\x08\x00\x14[\xa5i\x95OIM\xd9\xc0\x08e\xa9p\x8a\xf7v'\x16K9\x80(\x00\x04\x96Yv\xf0"
        #password = '30b4706261556ebb9bc8205f800275c5' # from firefox console
        password = '9b4424d9e8c5e253c0290d63328b55b3'
        protocol = stun.STUN(password=password)
        protocol.datagramReceived(webrtc_stun_request, ('127.0.0.1', 4242,))

    #def testEncodeMappedAddress(self):
    #    self.assertEqual('', stun.encodeMappedAddress('192.168.42.8', 4242))

    def testEncodeXORMappedAddress(self):
        # from the captured request
        requiredResults = '\x00 \x00\x08\x00\x01\xeb\xfa\xe1\xba\x8eJ'
        results = stun.encodeXORMappedAddress('192.168.42.8', 51944)
        self.assertEqual(requiredResults, results)

    def testParseCapturedRequest(self):
        stun_request_1 = ''.join([chr(x) for x in STUN_REQUEST_1])
        class STUNNode(stun.STUN):
            def requestRecieved(stunNode, request, source):
                self.assertEqual('d7de9017:b52d0601', request['username'])
                self.assertEqual(1853817087, request['priority'])
                self.assertEqual(1139902001367096328, request['ice_controlled'])
        protocol = STUNNode(password='755f33f22509329a49ab3d6420e947e9')
        protocol.datagramReceived(stun_request_1, ('127.0.0.1', 4242,))

    def testParseCapturedResponse(self):
        stun_response_1 = ''.join([chr(x) for x in STUN_RESPONSE_1])
        class STUNNode(stun.STUN):
            def responseRecieved(stunNode, request, source):
                self.assertEqual(('192.168.42.8', 51944,), request['mapped_address'])
        protocol = STUNNode(password='755f33f22509329a49ab3d6420e947e9')
        protocol.datagramReceived(stun_response_1, ('127.0.0.1', 4242,))
        
#Captured from Wireshark with two Firefox 28 browser talking to each other
STUN_REQUEST_1 = [
    0x00, 0x01, 0x00, 0x4c, 0x21, 0x12, 0xa4, 0x42,
    0x7c, 0x53, 0xf3, 0x12, 0x79, 0x53, 0x6d, 0x99,
    0xc0, 0x0d, 0x14, 0x4d, 0x00, 0x06, 0x00, 0x11,
    0x64, 0x37, 0x64, 0x65, 0x39, 0x30, 0x31, 0x37,
    0x3a, 0x62, 0x35, 0x32, 0x64, 0x30, 0x36, 0x30,
    0x31, 0x00, 0x00, 0x00, 0x00, 0x24, 0x00, 0x04,
    0x6e, 0x7f, 0x00, 0xff, 0x80, 0x29, 0x00, 0x08,
    0x0f, 0xd1, 0xbe, 0xd4, 0xae, 0x3e, 0x1c, 0x08,
    0x00, 0x08, 0x00, 0x14, 0xae, 0xc2, 0xb0, 0x40,
    0xea, 0x55, 0x75, 0x6b, 0xfd, 0x61, 0xab, 0x4a,
    0xf8, 0x4d, 0x1e, 0x7c, 0xca, 0x36, 0x70, 0xad,
    0x80, 0x28, 0x00, 0x04, 0x7a, 0xc7, 0x0f, 0xad
]

STUN_RESPONSE_1 = [
    0x01, 0x01, 0x00, 0x2c, 0x21, 0x12, 0xa4, 0x42,
    0x7c, 0x53, 0xf3, 0x12, 0x79, 0x53, 0x6d, 0x99,
    0xc0, 0x0d, 0x14, 0x4d, 0x00, 0x20, 0x00, 0x08,
    0x00, 0x01, 0xeb, 0xfa, 0xe1, 0xba, 0x8e, 0x4a,
    0x00, 0x08, 0x00, 0x14, 0x30, 0x35, 0xe6, 0x1e,
    0xb7, 0xab, 0x88, 0x47, 0x63, 0xd3, 0x83, 0x4f,
    0x76, 0xb1, 0x8a, 0x02, 0x08, 0x66, 0x93, 0x25,
    0x80, 0x28, 0x00, 0x04, 0x4f, 0xf2, 0xf9, 0xa1
]

