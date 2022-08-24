var WebSocket = require('ws');

var ws = new WebSocket('wss://localhost/kpmu', { rejectUnauthorized: false });

var registerMessage = {
    "command": "clientRegister",
    "parameters" : {
        "username": "kpmu",
        "password": "kpmu",
        "clientId": "00DEADBEEF01",
        "token":""
    }
}

ws.on('open', function() {
    ws.send(JSON.stringify(registerMessage));
});

ws.on('message', function(msg) {
    console.log(msg);
    try {
        jmsg = JSON.parse(msg)
        if (jmsg["command"]!=null) {
            reply = {
                tid: jmsg.tid,
                statusCode: 0                
            }
            ws.send(JSON.stringify(reply))
        }
    } catch (e) {
        console.log(e)
    }
});