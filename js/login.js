"use strict";

scrypt_module_factory(function (scrypt) {
    // - Confirm login with server
    // - Download encrypted user information
    // - Derive key for decryption

    var loginButton = document.getElementById("login");
    loginButton.onclick = function() {
        var username = document.getElementById("username").value;
        var password = document.getElementById("password").value;

        if (!username || !password) {
            alert("Please enter your username and password");
            return;
        }

        loginButton.disabled = true;
        
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
                    // Fixed length message required for signing so use a SHA-256 hash
                    crypto.subtle.digest("SHA-256", new TextEncoder("utf-8").encode(username)).then(function (hash) {
                        hash = hex(hash);
                        var signature = userKey.sign(hash);
                        var hexSignature = signature.toDER().map(function (byte) {
                            return ("0" + (byte & 0xFF).toString(16)).slice(-2);
                        }).join("");
                        // POST this to the server to sign up
                        var xhr = new XMLHttpRequest();
                        xhr.open("POST", "/api/user/login", true);
                        xhr.setRequestHeader("Content-Type", "application/json");
                        xhr.onload = function (e) {
                            var response = JSON.parse(e.target.responseText);
                            if (response.error) {
                                alert("Error: " + response.error);
                            }
                            else {
                                window.location = "/dashboard";
                            }
                        };
                        xhr.send(JSON.stringify({
                            "username": username,
                            "publicKey": userKey.getPublic(true, "hex"),
                            "signature": hexSignature,
                            "salt": salt
                        }));
                    });
                }
                else if (ajaxRequest.status == 400) {
                    alert('There was an error 400');
                }
                else {
                    console.error("An error occured", ajaxRequest);
                }
            }
        };

        ajaxRequest.open("GET", `/api/user/getsalt/${username}`, true);
        ajaxRequest.send();

        loginButton.disabled = false;
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