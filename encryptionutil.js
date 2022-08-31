var crypto = require("crypto");
var path = require("path");
var fs = require("fs");

var encryptStringWithRsaPublicKey = function(toEncrypt, relativeOrAbsolutePathToPublicKey) {
    var absolutePath = path.resolve(relativeOrAbsolutePathToPublicKey);
    var publicKey = fs.readFileSync(absolutePath, "utf8");
    var buffer = Buffer.from(toEncrypt);
    var encrypted = crypto.publicEncrypt(publicKey, buffer);
    return encrypted.toString("base64");
};

var encryptStringWithRsaPublicKeyString = function(toEncrypt, publicKeyPemString) {
    var publicKey = "-----BEGIN CERTIFICATE-----\n"+publicKeyPemString+"\n-----END CERTIFICATE-----\n";
    var slice_size=200;// split 200 bytes
    var orig_len = toEncrypt.length
    var encrypted = []
    var idx=0
    var buffer = ""
    while (idx<orig_len) {        
        buffer = Buffer.from(toEncrypt.substring(idx,idx+slice_size));
        encrypted.push(crypto.publicEncrypt(publicKey, buffer).toString("base64"));
        idx+=slice_size;
    }
    return encrypted.join(" ");
};


var decryptStringWithRsaPrivateKey = function(toDecrypt, relativeOrAbsolutePathtoPrivateKey) {
    var absolutePath = path.resolve(relativeOrAbsolutePathtoPrivateKey);
    var privateKey = fs.readFileSync(absolutePath, "utf8");
    var buffer = Buffer.from(toDecrypt, "base64");
    var decrypted = crypto.privateDecrypt(privateKey, buffer);
    return decrypted.toString("utf8");
};

var decryptStringWithRsaPrivateKeyString = function(toDecrypt, privateKeyPemString) {
    var privateKey = "-----BEGIN RSA PRIVATE KEY-----\n"+privateKeyPemString+"\n-----END RSA PRIVATE KEY-----\n";
    var buffer = Buffer.from(toDecrypt, "base64");
    var decrypted = crypto.privateDecrypt(privateKey, buffer);
    return decrypted.toString("utf8");
};


module.exports = {
    encryptStringWithRsaPublicKey: encryptStringWithRsaPublicKey,
    encryptStringWithRsaPublicKeyString: encryptStringWithRsaPublicKeyString,
    decryptStringWithRsaPrivateKey: decryptStringWithRsaPrivateKey,
    decryptStringWithRsaPrivateKeyString: decryptStringWithRsaPrivateKeyString
}