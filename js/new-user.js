"use strict";

scrypt_module_factory(function (scrypt) {
    // - Ask server for the salt for this username
    // - Use scrypt to derive private key
    // - Sign username with private key

    var joinButton = document.getElementById("submit");
    joinButton.onclick = function() {
        var username = document.getElementById("username").value;
        var password = document.getElementById("password").value;
        var password2 = document.getElementById("confirmPassword").value;

        if (!username || !password || !password2) {
            alert("Please enter your username and password");
            return;
        }
        if (password !== password2) {
            alert("Your passwords don't match!");
            return;
        }

        joinButton.disabled = true;
        
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
                    salt = new Uint8Array(a);
                    // Derive key with this salt (private keys for this curve are 32 bytes)
                    var keyBytes = scrypt.crypto_scrypt(scrypt.encode_utf8(password), salt, 1048576, 8, 1, 32);
                    debugger;
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

        joinButton.disabled = false;
    };
});