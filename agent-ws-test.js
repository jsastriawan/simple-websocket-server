const WebSocket = require('ws');
const tls = require("tls");
const crypto = require("crypto");
const fs = require("fs");
const encutil = require("./encryptionutil");

var ws = new WebSocket('wss://localhost/kpmu', { rejectUnauthorized: false });
var verifiedCert = false;
var testVerify = true;//flag to always verify certificate
var testChallenge = true; //use challenge instead of cert exchange
var challenge_message = "no-nonsense";
var nonce = 0;
var knownCert = new crypto.X509Certificate(fs.readFileSync("private/web-cert-public.crt"))
    
var registerMessage = {
    "command": "clientRegister",
    "parameters" : {
        "username": "kpmu",
        "password": "kpmu",
        "clientId": "00DEADBEEF01",
        "token":""
    }
}

var serverCertRequest = {
    "command": "serverCertRequest",
    "parameters" : {
        "token":""
    }
}

var serverCertChallenge = {
    "command": "serverCertChallenge",
    "parameters" : {
        "token":""
    }
}


ws.on('open', function() {
    var _socket = ws._socket;
    if (_socket instanceof require('tls').TLSSocket) {
        var peerCert = _socket.getPeerCertificate(false);//just get peer cert without full chain        
        // perform PEM string comparison        
        if (peerCert.raw.toString("base64") == knownCert.raw.toString("base64")) {
            console.log("TLS peer certificate verified.")
            verifiedCert = true;            
        }
    }
    if (verifiedCert && !testVerify) {
        console.log("Send clientRegister message")
        ws.send(JSON.stringify(registerMessage));
    } else {
        //reset verifiedCert status
        verifiedCert = false;
        // perform secondary verification
        if (testChallenge) {            
            serverCertChallenge["parameters"]["token"] = encutil.encryptStringWithRsaPublicKeyString(challenge_message,knownCert.raw.toString("base64"));
            console.log("Send serverCertChallenge message")
            ws.send(JSON.stringify(serverCertChallenge))
        } else {
            var clientCert = new crypto.X509Certificate(fs.readFileSync("client_private/client-cert-public.crt"))
            nonce = Math.floor(Math.random() * 10000)
            var message = clientCert.raw.toString("base64")+":"+nonce
            serverCertRequest["parameters"]["token"] = encutil.encryptStringWithRsaPublicKeyString(message,knownCert.raw.toString("base64"));
            console.log("Send serverCertRequest message")
            ws.send(JSON.stringify(serverCertRequest))
        }
    }
});

ws.on('message', function(msg) {
    console.log("Server message:",msg);
    try {
        jmsg = JSON.parse(msg)
        if (jmsg["command"]!=null) {
            reply = {
                tid: jmsg.tid,
                statusCode: 0                
            }
            console.log("Send response message")
            ws.send(JSON.stringify(reply))
        } else if (jmsg["response"] != null) {
            if (jmsg["response"] == "serverCertResponse") {
                var token = jmsg["parameters"]["token"].split(" ");

                if (testChallenge) {
                    var challenge_message_hash = crypto.createHash('sha256').update(challenge_message).digest('base64');
                    //console.log(challenge_message_hash,"\n", token[0])
                    if (challenge_message_hash == token[0]) {
                        console.log("Server challenge correctly answered.")
                        verifiedCert = true
                    }
                } else {
                    var decrypted_message = ""
                    for (i = 0; i < token.length; i++) {
                        decrypted_message += encutil.decryptStringWithRsaPrivateKey(token[i], "client_private/client-cert-private.key");
                    }    
                    var message = decrypted_message.split(":");
                    if (message.length == 2) {
                        if (knownCert.raw.toString("base64") == message[0] && nonce == message[1]) {
                            console.log("Server cert verified and nonce match.")
                            verifiedCert = true
                        }
                    }
                }

                if (verifiedCert) {
                    ws.send(JSON.stringify(registerMessage));
                } else {
                    console.log("Terminating connection due to unverified peer.");
                    ws.close();
                }
            }
        }
    } catch (e) {
        console.log(e)
    }
});