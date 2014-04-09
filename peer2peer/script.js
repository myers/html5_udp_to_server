if (typeof window.RTCPeerConnection === 'undefined') {
  console.log('unprefix RTCPeerConnection');
  window.RTCPeerConnection = window.mozRTCPeerConnection || window.webkitRTCPeerConnection;
}
if (typeof window.RTCSessionDescription === 'undefined') {
  console.log('unprefix RTCSessionDescription');
  window.RTCSessionDescription = window.mozRTCSessionDescription || window.webkitRTCSessionDescription;
}

var peerConnection;
var peerChannel;
var webSocketConnection;
var state;

var sendButton = document.getElementById('sendButton');
sendButton.disabled = true;
sendButton.onclick = sendData;

var closeButton = document.getElementById('closeButton');
closeButton.disabled = true;
closeButton.onclick = closeDataChannels;

$(function() {
  webSocketConnection = new WebSocket('ws://' + window.location.host + '/offers');
  webSocketConnection.onmessage = onWebSocketMessage;
  //webSocketConnection.onopen = makePeerConnection;
  webSocketConnection.onclose = deletePeerConnection;
});

function onWebSocketMessage(e) {
  console.log('Server: ', e.data);
  var parsedFrame = JSON.parse(e.data);
  if (parsedFrame.hasOwnProperty('state')) {
    state = parsedFrame.state;
    makePeerConnection();
  }
  if (!parsedFrame.hasOwnProperty('type') && state === 'controlling') {
    setupAndMakeAnOffer();
  } else if (state === 'controlled' && parsedFrame.type === 'offer') {
    acceptOffer(parsedFrame);
  } else if (state === 'controlling' && parsedFrame.type === 'answer') {
    acceptAnswer(parsedFrame);
  }
}
function webSocketSend(data) {
  console.log("sending", data);
  webSocketConnection.send(JSON.stringify(data));
}
function setupAndMakeAnOffer() {
  //setup
  dataChannel = peerConnection.createDataChannel('chat', {maxRetransmits: 0, ordered: false});
  setupDataChannel(dataChannel);

  // offer
  peerConnection.createOffer(function(offer) {
    peerConnection.setLocalDescription(offer, function() {
      webSocketSend(offer);
    }, function() {
      console.error('setting local desc', arguments);
    });
  }, function() {
    console.error('Error creating offer', arguments);
  });
}

function acceptOffer(offer) {
  console.log('1');
  var remoteSessionDescription = new RTCSessionDescription(offer);
  console.log('2');
  peerConnection.setRemoteDescription(remoteSessionDescription, function() {
    console.log('3');
    peerConnection.createAnswer(function(answer) {
      console.log('4');
      var localSessionDescription = new RTCSessionDescription(answer);

      peerConnection.setLocalDescription(localSessionDescription, function() {
        console.log('5');
        webSocketSend(answer);
      }, function() {
        console.error('Error setting local desc', arguments);
      });
    }, function() {
      console.error('Error creating answer', arguments);
    });
  }, function() {
    console.error('Error setting remote description', arguments);
  });
}

function acceptAnswer(answer) {
  var remoteSessionDescription = new RTCSessionDescription(answer);
  peerConnection.setRemoteDescription(remoteSessionDescription, function() {
    console.log('done!!!?!');
  }, function() {
    console.error('Error setting remote description', arguments);
  });
}

function gotServerCandidate(event) {
  console.log('local ice callback', event);
  if (event.candidate) {
    console.log('Local ICE candidate:', event.candidate.candidate);
  }
}

function sendData() {
  var data = document.getElementById('dataChannelSend').value;
  peerChannel.send(data);
  console.log('Sent data:', data, peerChannel);
}

function onDataChannel(event) {
  console.log("onDataChannel", event);
  setupDataChannel(event.channel);
}

function setupDataChannel(dataChannel) {
  dataChannel.onmessage = handleMessage;
  dataChannel.onopen = handleServerChannelStateChange;
  dataChannel.onclose = handleServerChannelStateChange;
  dataChannel.onerror = onDataChannelError;
  peerChannel = dataChannel;
}

function makePeerConnection(state) {
  console.log("peerConnection", peerConnection);
  peerConnection = new RTCPeerConnection(null, null);
  peerConnection.onicecandidate = gotServerCandidate;
  peerConnection.onsignalingstatechange = console.log;
  peerConnection.ondatachannel = onDataChannel;
}

function onDataChannelError() {
  console.error('onDataChannelError', arguments);
}

function closeDataChannels() {
  console.log('Closing data channels');
  peerChannel.close();
  console.log('Closed data channel with label: ', peerChannel.label);
  //trace('Closed data channel with label: ' + receiveChannel.label);
  peerConnection.close();
  peerConnection = null;
  console.log('Closed peer connections');
  sendButton.disabled = true;
  closeButton.disabled = true;
  dataChannelSend.value = "";
  dataChannelReceive.value = "";
  dataChannelSend.disabled = true;
  dataChannelSend.placeholder = "Wait for connection, enter some text, then press Send.";
}

function handleMessage(event) {
  console.log('Received message:', event);
  document.getElementById("dataChannelReceive").value = event.data;
}

function handleServerChannelStateChange() {
  var readyState = peerChannel.readyState;
  console.log('Send channel state is:', readyState, arguments);
  if (readyState == 'open') {
    dataChannelSend.disabled = false;
    dataChannelSend.focus();
    dataChannelSend.placeholder = "";
    sendButton.disabled = false;
    closeButton.disabled = false;
  } else {
    dataChannelSend.disabled = true;
    sendButton.disabled = true;
    closeButton.disabled = true;
  }
}

function deletePeerConnection() {
  closeDataChannels();
}

