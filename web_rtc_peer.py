#!/usr/bin/env python
from twisted.internet import defer, protocol
#from twisted.internet.protocol import Protocol, Factory
from twisted.web import resource, static, server
from twisted.internet import task
import json, traceback, pprint

import stun

def siteRoot(s):
    root = static.File('.')
    root.putChild('answer_sdp', AnswerSDP(s))
    return root

class AnswerSDP(resource.Resource):
    def __init__(self, service):
        resource.Resource.__init__(self)
        self.service = service

    def render_POST(self, request):
        values = json.loads(request.content.getvalue())
        pprint.pprint(values)

        def extractPassword(sdp):
            sdp = sdp.replace("\r", "")
            sdp = sdp.split("\n")
            for line in sdp:
                if line.startswith('a=ice-pwd:'):
                    password = line.split(':', 1)[1]
                elif line.startswith('a=ice-ufrag:'):
                    username = line.split(':', 1)[1]
            self.service.addCred(username, password)

        extractPassword(values['sdp'])

        request.setHeader("content-type", "application/json")
        return json.dumps({'result': 'ok'})

class WebRTCSTUNServer(stun.STUN):
    def findPasswordFor(self, username):
        for u, p in self.creds.items():
            if ":" in username:
                username, u2 = username.split(":", 1)
            if u == username:
                print "password is %r" % (p,)
                return p
        raise Exception("couldn't find password %r %r" % (username, self.creds,))

    def requestRecieved(self, attribs, source):
        try:
            print "Replying to request from %r" % (source,)
            pprint.pprint(attribs)

            reply = self.buildBindSuccessReply(attribs['transaction_id'], attribs['username'], source)
            self.transport.write(reply, source)

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


class MultiplexingDatagramProtocol(protocol.DatagramProtocol):
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

    s = WebRTCSTUNServer()
    # this username/password is hardcoded in script.js 
    s.addCred('3081b21e', '9b4424d9e8c5e253c0290d63328b55b3')
    log.startLogging(sys.stdout)
    reactor.listenTCP(8080, server.Site(siteRoot(s)))
    m = MultiplexingDatagramProtocol([s])
    print "STUN server listening on UDP 4488..."
    reactor.listenUDP(4488, m)

    reactor.run()