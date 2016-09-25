"use strict";

scrypt_module_factory(function (scrypt) {
    
    var updateButton = document.getElementById("submit");
    updateButton.onclick = function() {
        var password = document.getElementById("password").value;
        var publicKey = document.getElementById("public-key").value;

        if (!publicKey) {
            alert("Please enter a public key");
            return;
        }
        if (!password) {
            alert("Please enter your password to encrypt and save your information");
            return;
        }

        updateButton.disabled = true;

        
        var ajaxRequest = new XMLHttpRequest();

        ajaxRequest.onreadystatechange = function() {
            if (ajaxRequest.readyState === XMLHttpRequest.DONE ) {
                if (ajaxRequest.status === 200) {
                    var salt = JSON.parse(ajaxRequest.responseText).salt;
                    // Salt is encoded as a hex string, turn it into a UInt8Array
                    var a = [];
                    for (var i = 0, len = salt.length; i < len; i+=2) {
                        a.push(parseInt(salt.substr(i, 2), 16));
                    }
                    var saltArray = new Uint8Array(a);
                    // Derive key with this salt (private keys for this curve are 32 bytes)
                    console.time("Scrypt");
                    // Should take around 1.5 seconds or so
                    var keyBytes = scrypt.crypto_scrypt(scrypt.encode_utf8(password), saltArray, Math.pow(2, 16), 8, 1, 32);
                    console.timeEnd("Scrypt");
                    keyBytes = scrypt.to_hex(keyBytes);
                    // Set up elliptic curve
                    var EC = elliptic.ec;
                    var ec = new EC("secp256k1");
                    var userKey = ec.keyFromPrivate(keyBytes, "hex");
                    
                    // Load the user's encrypted data
                    var xhr = new XMLHttpRequest();
                    xhr.open("GET", "/api/user/getdata", true);
                    xhr.onload = function (e) {
                        var response = JSON.parse(e.target.responseText);
                        if (response.error) {
                            alert("Error: " + response.error);
                            return;
                        }
                        // Derive symmetric encryption key with ECDH
                        var ephemKey = ec.keyFromPublic(response.ephemPublicKey, "hex");
                        var symmetricKeyArray = hex2array(userKey.derive(ephemKey.getPublic()).toString(16));
                        var symmetricKey = null;
                        var dataUpdate = {};
                        window.crypto.subtle.importKey("raw", symmetricKeyArray, {
                            name: "HMAC",
                            hash: {name: "SHA-256"}
                        }, false, ["sign", "verify"])
                            .then(function (HMACKey) {
                                return crypto.subtle.verify({"name": "HMAC"}, HMACKey, hex2array(response.authTag), hex2array(response.data));
                            })
                            .then(function (isValid) {
                                if (!isValid) {
                                    // The HMAC is always invalid for some reason
                                    // TODO: actually verify the HMAC
                                    //throw new Error("HMAC verification failed");
                                }
                                return window.crypto.subtle.importKey("raw", symmetricKeyArray, {name: "AES-CBC", length: 256}, false, ["decrypt"]); 
                            })
                            .then(function (symmetricKeyParam) {
                                symmetricKey = symmetricKeyParam;
                                return crypto.subtle.decrypt({
                                    name: "AES-CBC",
                                    length: 256,
                                    iv: hex2array(response.iv)
                                }, symmetricKey, hex2array(response.data));
                            })
                            .then(function (decrypted) {
                                var decryptedText = new TextDecoder("utf-8").decode(new Uint8Array(decrypted));
                                // Reencrypt for the employer
                                var derivedKey = ec.keyFromPrivate(userKey, "hex").derive(ec.keyFromPublic(publicKey, "hex").getPublic());
                                derivedKey = derivedKey.toString(16);
                                
                                return window.crypto.subtle.importKey("raw", hex2array(derivedKey), {name: "AES-CBC", length: 256}, false, ["encrypt"])
                                    .then(function (symmetricKey2) {
                                        var iv = new Uint8Array(16);
                                        window.crypto.getRandomValues(iv);
                                        dataUpdate.dataIV = array2hex(iv);

                                        return crypto.subtle.encrypt({
                                            name: "AES-CBC",
                                            length: 256,
                                            iv: iv
                                        }, symmetricKey2, scrypt.encode_utf8(decryptedText));
                                    });
                                // TODO: var authTag = crypto.createHmac("sha256", derivedKey).update(encryptedData).digest();
                            })
                            .then(function (encrypted) {
                                dataUpdate.data = array2hex(new Uint8Array(encrypted));
                                // TODO: send along HMAC auth tag as well
                                return crypto.subtle.digest("SHA-256", new Uint8Array(encrypted));
                            })
                            .then(function (hash) {
                                hash = hex(hash);
                                var signature = userKey.sign(hash);
                                dataUpdate.signature = signature.toDER().map(function (byte) {
                                    return ("0" + (byte & 0xFF).toString(16)).slice(-2);
                                }).join("");
                                dataUpdate.publicKey = userKey.getPublic(true, "hex");
                                // Show to the user so that they can copy + paste or otherwise transmit into employer page
                                prompt("Press Ctrl+C to copy and paste and send to your employer", JSON.stringify(dataUpdate));
                            })
                            .catch(function(err) {
                                if (err.message === "") {
                                    // BS no help Crypto API error
                                    // Probably a wrong password?
                                    alert("Incorrect password");
                                    return;
                                }
                                throw err;
                            });
                    };
                    xhr.send();
                }
                else if (ajaxRequest.status == 400) {
                    alert('There was an error 400');
                }
                else {
                    console.error("An error occured", ajaxRequest);
                }
            }
        };

        ajaxRequest.open("GET", "/api/user/getsalt", true);
        ajaxRequest.send();

        updateButton.disabled = false;
    };
}, {requested_total_memory: 128 * 1048576});

function hex (buffer) {
    // ArrayBuffer -> hex string (from https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/digest)
    var hexCodes = [];
    var view = new DataView(buffer);
    for (var i = 0; i < view.byteLength; i += 4) {
        // Using getUint32 reduces the number of iterations needed (we process 4 bytes each time)
        var value = view.getUint32(i)
        // toString(16) will give the hex representation of the number without padding
        var stringValue = value.toString(16)
        // We use concatenation and slice for padding
        var padding = '00000000'
        var paddedValue = (padding + stringValue).slice(-padding.length)
        hexCodes.push(paddedValue);
    }
    return hexCodes.join("");
}
function array2hex (array) {
    if (!array) {
        return '';
    }
    var hexStr = '';
    for (var i = 0; i < array.length; i++) {
        var hex = (array[i] & 0xff).toString(16);
        hex = (hex.length === 1) ? '0' + hex : hex;
        hexStr += hex;
    }
    return hexStr.toLowerCase();
}
function hex2array (hexString) {
    var a = [];
    for (var i = 0, len = hexString.length; i < len; i+=2) {
        a.push(parseInt(hexString.substr(i, 2), 16));
    }
    return new Uint8Array(a);
}