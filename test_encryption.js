const encutil = require("./encryptionutil")

var message = "This is clear text message.This is clear text message.This is clear text message.This is clear text message.This is clear text message.This is clear text message.This is clear text message.This is clear text message.This is clear text message.This is clear text message.This is clear text message.This is clear text message.This is clear text message";
console.log("message length: ", message.length);
console.log("Prior to encryption: ", message)
secure_message = encutil.encryptStringWithRsaPublicKey(message,"client_private/client-cert-public.crt");
console.log("Post encryption: ", secure_message)
decoded_message = encutil.decryptStringWithRsaPrivateKey(secure_message, "client_private/client-cert-private.key");
console.log("Post decoding: ", decoded_message);