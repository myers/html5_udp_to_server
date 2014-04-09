#!/usr/bin/env python

from twisted.internet.protocol import Protocol, Factory
from twisted.web import resource
from twisted.web.static import File
from twisted.internet import task
import json

from websocket import WebSocketHandler, WebSocketSite

peers = []

class WebRTCOffersHandler(WebSocketHandler):
    '''
    Send WebRTC SDP offers to others on this same channel
    '''
    def __init__(self, transport):
        WebSocketHandler.__init__(self, transport)

    def frameReceived(self, frame):
        global peers
        print 'Message from peer: %r %r' % (self.transport.getPeer(), frame,)
        decodedFrame = json.loads(frame)
        for peer in peers:
            if peer != self:
                peer.sendMessage(decodedFrame)

    def connectionMade(self):
        global peers
        print 'Connected to client %r' % (self.transport.getPeer(),)
        # here would be a good place to register this specific handler
        # in a dictionary mapping some client identifier (like IPs) against
        # self (this handler object)
        if len(peers) >= 2:
            self.sendMessage(error='too many peers')
            self.transport.close()
        peers.append(self)
        if len(peers) == 2:
            peers[0].sendMessage(state='controlling')
            peers[1].sendMessage(state='controlled')
        else:
            self.sendMessage(state='waiting')
    
    def sendMessage(self, *msg, **kwargs):
        if kwargs:
            self.transport.write(json.dumps(kwargs))
        else:
            self.transport.write(json.dumps(msg[0]))
        
    def connectionLost(self, reason):
        print 'Lost connection.'
        # here is a good place to deregister this handler object
        global peers
        peers.remove(self)

if __name__ == '__main__':
    from twisted.internet import reactor

    # run our websocket server
    # serve index.html from the local directory
    root = File('.')
    site = WebSocketSite(root)
    site.addHandler('/offers', WebRTCOffersHandler)
    reactor.listenTCP(8080, site)
    reactor.run()