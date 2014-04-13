# HTML5 UDP to Server

I'm excited that browsers can now speak UDP to each other.  UDP is a better
fit when you want to do games programming.  I want to have a python game server
that HTML5 clients can communicate with via UDP.

WebRTC allows this, but it's a lot more complex that opening a socket.  To
connect to via WebRTC you need to

1. Do ICE connectivity test, which means a STUN server
2. Communicate via DTLS, where pyopenssl doesn't yet expose DTLS
3. Send SCTP packets as the payload in DTLS.

This is my attempt at implementing all this in python using Twisted.

# Snags along the way

* How the message integerity attribute should be calcutated.  The trick is you have to change the packet size field before making the hmac

# Useful links

https://groups.google.com/forum/#!topic/discuss-webrtc/VVb3to005Iw

http://tools.ietf.org/html/draft-nandakumar-rtcweb-sdp-04#ref-MSID

http://chimera.labs.oreilly.com/books/1230000000545/ch18.html

http://tools.ietf.org/html/draft-rosenberg-rtcweb-rtpmux-00

https://developer.mozilla.org/en-US/docs/Web/Guide/API/WebRTC/WebRTC_architecture

https://groups.google.com/forum/#!topic/mozilla.dev.media/FrQE1OV7y38

https://github.com/konomae/stunpy/blob/master/stun.py
