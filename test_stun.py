from twisted.trial import unittest
import stun

class STUNTestCase(unittest.TestCase):
    def testWebrtcRequest(self):
        webrtc_stun_request = "\x00\x01\x00L!\x12\xa4BCW\xe1\xabj\x9bV\xa38SQ\xb1\x00\x06\x00\x113081b21e:24b1caa0\x00\x00\x00\x00$\x00\x04n\xfb\x00\xff\x80)\x00\x08\x8bK\x8e\xab\n\xf1\x00\x07\x00\x08\x00\x14[\xa5i\x95OIM\xd9\xc0\x08e\xa9p\x8a\xf7v'\x16K9\x80(\x00\x04\x96Yv\xf0"
        #password = '30b4706261556ebb9bc8205f800275c5' # from firefox console
        password = '9b4424d9e8c5e253c0290d63328b55b3'
        protocol = stun.STUN(password=password)
        protocol.datagramReceived(webrtc_stun_request, ('127.0.0.1', 4242,))

    def testEncodeMappedAddress(self):
        print "%r" % (stun.encodeMappedAddress('127.0.0.1', 4242),)