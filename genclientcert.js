var certoperation = require('./certoperations.js').CertificateOperations();
var fs = require("fs");

if (!fs.existsSync('client_private/client-cert-public.crt') || !fs.existsSync('client_private/client-cert-private.key')) {
    console.log('Generating client certificate...');
    clientCertAndKey = certoperation.GenerateRootCertificate(true, 'ClientCert', null, null, true);
    clientCertificate = certoperation.pki.certificateToPem(clientCertAndKey.cert);
    clientPrivateKey = certoperation.pki.privateKeyToPem(clientCertAndKey.key);
    fs.writeFileSync('client_private/client-cert-public.crt', clientCertificate);
    fs.writeFileSync('client_private/client-cert-private.key', clientPrivateKey);
}
