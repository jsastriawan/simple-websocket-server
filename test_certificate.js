const crypto = require("crypto");
const fs = require("fs");

var cert = new crypto.X509Certificate(fs.readFileSync("client_private/client-cert-public.crt"))

console.log("Fingerprint:", cert.fingerprint)
console.log("Fingerprint256:", cert.fingerprint256)
console.log("Fingerprint512:", cert.fingerprint512)
console.log(cert.raw.toString("base64"))

