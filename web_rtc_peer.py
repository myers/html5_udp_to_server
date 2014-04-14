#!/usr/bin/env python

from twisted.internet.protocol import Protocol, Factory
from twisted.web import resource
from twisted.web.static import File
from twisted.internet import task
import json

import stun

class WebRTCSTUNServer(STUN):
    def requestRecieved(self, attribs, source):
        try:
            print "Replying to request from %r" % (source,)
            self.transport.write(self.buildBindSuccessReply(attribs['transaction_id'], source), source)
            print "attribs"
            pprint.pprint(attribs)

            request = {
                'ice_controlling': attribs['ice_controlled'],
                'priority': attribs['priority'],
                'username': ':'.join( reversed(attribs['username'].split(':')) ),
                'use_candidate': None,
            }
            print "sending request"
            pprint.pprint(request)
            self.transport.write(self.buildBindingRequest(request), source)
        except Exception, ee:
            print traceback.format_exc()
            print ee


class MultiplexingDatagramProtocol(DatagramProtocol):
    def __init__(self, protocols):
        self.protocols = protocols

    def startProtocol(self):
        for proto in self.protocols:
            proto.transport = self.transport

    def datagramReceived(self, data, source):
        print "MultiplexingDatagramProtocol datagramReceived %r: %r" % (source, data,)
        for proto in self.protocols:
            try:
                proto.datagramReceived(data, source)
                break
            except Exception, ee:
                print ee

if __name__ == '__main__':
    from twisted.internet import reactor
    from twisted.python import log
    import sys

    log.startLogging(sys.stdout)
    root = File('.')
    reactor.listenTCP(8080, root)

    s = WebRTCSTUNServer(password='9b4424d9e8c5e253c0290d63328b55b3')
    m = MultiplexingDatagramProtocol([s])
    print "STUN server listening on UDP 4488..."
    reactor.listenUDP(4488, m)

    reactor.run()