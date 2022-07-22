var WebSocket = require('ws');

var ws = new WebSocket('wss://localhost/relay', { rejectUnauthorized: false });

ws.on('open', function() {
    ws.send('Sending a text over websocket.');
});

ws.on('message', function(msg) {
    console.log(msg);
    ws.close();
});