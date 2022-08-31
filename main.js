/**
 * @description Main.js
 * @author Joko Sastriawan
 * @copyright Joko Sastriawan 2020
 * @license Apache-2.0
 * @version 0.0.1
 */

const { json } = require('express');

function CreateSimpleWebserver() {
    var obj = {}
    obj.fs = require('fs');
    obj.crypto = require('crypto');
    obj.encutil = require('./encryptionutil');
    obj.express = require('express');    
    obj.app = obj.express();    
    obj.https = require('https');
    obj.kpmuConnections = {};
    obj.defaultKpmuUsername = "kpmu";
    obj.defaultKpmuPassword = "kpmu";
    var constants = require('constants')

    obj.config = {};
    try {
        obj.config = JSON.parse(obj.fs.readFileSync('private/config.json'));
    } catch (e) {
        console.log(e);
    }

    obj.Start = function () {
        var certificates = {}
        certificates.root = {}
        certificates.web = {}

        var certoperation = require('./certoperations.js').CertificateOperations();

        var rootCertificate, rootPrivateKey, rootCertAndKey;

        if (obj.fs.existsSync('private/root-cert-public.crt') && obj.fs.existsSync('private/root-cert-private.key')) {
            //load certificate
            rootCertificate = obj.fs.readFileSync('private/root-cert-public.crt', 'utf8');
            rootPrivateKey = obj.fs.readFileSync('private/root-cert-private.key', 'utf8');
            rootCertAndKey = { cert: certoperation.pki.certificateFromPem(rootCertificate), key: certoperation.pki.privateKeyFromPem(rootPrivateKey) }
        } else {
            console.log('Generating Root certificate...');
            rootCertAndKey = certoperation.GenerateRootCertificate(true, 'WebsiteRoot', null, null, true);
            rootCertificate = certoperation.pki.certificateToPem(rootCertAndKey.cert);
            rootPrivateKey = certoperation.pki.privateKeyToPem(rootCertAndKey.key);
            obj.fs.writeFileSync('private/root-cert-public.crt', rootCertificate);
            obj.fs.writeFileSync('private/root-cert-private.key', rootPrivateKey);
        }
        certificates.root.cert = rootCertificate;
        certificates.root.key = rootPrivateKey;

        var webCertificate, webPrivateKey, webCertAndKey;

        if (obj.fs.existsSync('private/web-cert-public.crt') && obj.fs.existsSync('private/web-cert-private.key')) {
            //load certificate
            webCertificate = obj.fs.readFileSync('private/web-cert-public.crt', 'utf8');
            webPrivateKey = obj.fs.readFileSync('private/web-cert-private.key', 'utf8');
            webCertAndKey = { cert: certoperation.pki.certificateFromPem(webCertificate), key: certoperation.pki.privateKeyFromPem(webPrivateKey) }
        } else {
            console.log('Generating Web certificate...');
            webCertAndKey = certoperation.IssueWebServerCertificate(rootCertAndKey, false, obj.config.commonName, obj.config.country, obj.config.organization, null, false);
            webCertificate = certoperation.pki.certificateToPem(webCertAndKey.cert);
            webPrivateKey = certoperation.pki.privateKeyToPem(webCertAndKey.key);
            obj.fs.writeFileSync('private/web-cert-public.crt', webCertificate);
            obj.fs.writeFileSync('private/web-cert-private.key', webPrivateKey);
        }
        certificates.web.cert = webCertificate;
        certificates.web.key = webPrivateKey;
        
        if (!obj.fs.existsSync('public/root.crt')) {
            obj.fs.writeFileSync('public/root.crt', rootCertificate);            
        }
        var options = {
            key: obj.fs.readFileSync('private/web-cert-private.key'),
            cert: obj.fs.readFileSync('private/web-cert-public.crt'),
            ciphers: "HIGH:TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_AES_128_CCM_8_SHA256:TLS_AES_128_CCM_SHA256:TLS_CHACHA20_POLY1305_SHA256", 
            secureOptions: constants.SSL_OP_NO_SSLv2 | constants.SSL_OP_NO_SSLv3 | constants.SSL_OP_NO_COMPRESSION | constants.SSL_OP_C | constants.SSL_OP_NO_TLSv1 | constants.SSL_OP_NO_TLSv1_1 
        };
        var server = obj.https.createServer(options,obj.app);
        obj.expressWs = require('express-ws')(obj.app, server);
        obj.app.use(require('body-parser').json())

        // debugger
        //obj.app.use(function (req,resp,next) {
        ///    console.log("Header:"+JSON.stringify(req.headers,null,3));
        ///    next();
        //});
        
        // create agent route, offer ws first
        obj.app.ws('/kpmu', function(ws, req) {
            ws.on('close', function(msg) {
                if (ws.clientId!=null) {
                    console.log("WS connection closed from:"+ ws.clientId);
                    delete obj.kpmuConnections[ws.clientId]
                } else {
                    console.log("WS connection closed.")
                }
                // debug
                console.log("KPMU connections: " + JSON.stringify(Object.keys(obj.kpmuConnections)))
            });

            ws.on('message', function(msg) {
                jmsg = {}
                console.log("Receive message: "+ msg)
                try {
                    jmsg = JSON.parse(msg)
                } catch (e) {
                    console.log("Invalid JSON: "+ msg)
                    ws.close()
                }
                if (ws.authenticated == null) {
                    // standard response
                    resp = {
                        code: 0
                    }
                    // decode message
                    if (jmsg["command"] != null) {
                        if (jmsg["command"] == "clientRegister" && jmsg["parameters"] !=null ) {
                            param = jmsg["parameters"]
                            if (param["username"] != null && param["password"] != null && param["username"] == obj.defaultKpmuUsername && param["password"] == obj.defaultKpmuPassword) {
                                resp["token"] = Buffer.from(param["clientId"]).toString('base64')
                                // Track the connection
                                obj.kpmuConnections[param["clientId"]] = ws
                                ws.clientId = param["clientId"]
                                ws.authenticated = true
                                // debug
                                console.log("KPMU connections: " + JSON.stringify(Object.keys(obj.kpmuConnections)))
                            }
                        } else if (jmsg["command"]== "serverCertRequest" && jmsg["parameters"] !=null && jmsg["parameters"]["token"] !=null) {
                            //console.log("Token:",jmsg["parameters"]["token"]);
                            var token = jmsg["parameters"]["token"].split(" ");
                            //console.log("Chunk:", token.length);
                            var decrypted_message = "";
                            // decrypt each chunk and append
                            for (i=0;i<token.length;i++) {
                                decrypted_message += obj.encutil.decryptStringWithRsaPrivateKey(token[i],"private/web-cert-private.key")
                            }
                            //console.log("Decrypted message:", decrypted_message)
                            var token_nonce = decrypted_message.split(":")
                            resp["response"] = "serverCertResponse"
                            if (token_nonce.length == 2) {
                                clientCert = token_nonce[0]
                                resp["parameters"] = {}
                                if (clientCert!=null) {
                                    // could be simpler by stripping string but this is also to validate the cert
                                    serverCertStr = new obj.crypto.X509Certificate(obj.fs.readFileSync('private/web-cert-public.crt')).raw.toString('base64');
                                    resp["parameters"]["token"] = obj.encutil.encryptStringWithRsaPublicKeyString( serverCertStr+":"+token_nonce[1], clientCert)
                                }
                            }                        
                        } else if (jmsg["command"]== "serverCertChallenge" && jmsg["parameters"] !=null && jmsg["parameters"]["token"] !=null) {
                            //simpler challenge to return sha256 hash of the secret message from NIC
                            //console.log("Token:",jmsg["parameters"]["token"]);
                            var token = jmsg["parameters"]["token"].split(" ");
                            //console.log("Chunk:", token.length);
                            var decrypted_message = "";
                            // decrypt each chunk and append
                            for (i=0;i<token.length;i++) {
                                decrypted_message += obj.encutil.decryptStringWithRsaPrivateKey(token[i],"private/web-cert-private.key")
                            }
                            //console.log("Decrypted message:", decrypted_message)
                            resp["response"] = "serverCertResponse"
                            resp["parameters"] = {}
                            resp["parameters"]["token"] = obj.crypto.createHash("sha256").update(decrypted_message).digest('base64');
                        } else {
                            resp["code"] = -1
                        }                    
                    }  else {
                        resp["code"] = -1
                    }                    
                    ws.send(JSON.stringify(resp));
                } else {
                    // we only forward response to oldest responder registered in responder array then remove it from responder
                    // FIFO
                    if (ws.responder!=null) {
                        if (ws.responder.length>0) {
                            resp = ws.responder.shift()
                            resp.send(JSON.stringify(jmsg))
                        } 
                    }
                }
            })
        })
        obj.app.get('/kpmu', function (req, resp) {
            resp.send('Agent should connect here using websocket.');
        });
        
        obj.app.get('/api', function (req, resp) {
            resp.send('Only accept POST command');
        });

        obj.app.post('/api', function (req, resp) {
            // request should be 
            // { request: cmd, arguments: text_or_json_obj }
            body = req.body
            // debug
            console.log(JSON.stringify(body))
            if (body!=null && body["request"]!=null) {
                if (body["request"]=="listConnections") {
                    reply = {
                        response : "listConnections",
                        statusCode: 0
                    }
                    reply["data"] = Object.keys(obj.kpmuConnections)
                    resp.send(JSON.stringify(reply))
                } else if (body["request"]=="sendCommand") {
                    // check if it has node as its destination
                    if (body["node"]!=null && body["message"]!=null) {
                        node = body["node"]
                        ws = obj.kpmuConnections[node]
                        // add resp obj for callback once
                        if (ws.responder==null) {
                            ws.responder = []
                        }
                        ws.responder.push(resp);

                        if (ws!=null) {
                            ws.send(JSON.stringify(body["message"]))
                        }
                    }
                }
            } else {
                resp.send(JSON.stringify({ error: "request is not defined"}))
            }
        });
        
        // create static folder
        obj.app.use(obj.express.static(__dirname+'/public'));

        server.listen(443);
        console.log("HTTPS server is listening at port 443");
        console.log("Use Ctrl+C to terminate web server");
    }
    return obj;
}
// instantiate and start
CreateSimpleWebserver().Start();