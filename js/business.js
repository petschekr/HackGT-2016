document.getElementById("keypairgen").onclick = function() {
	var EC = elliptic.ec;
    var ec = new EC("secp256k1");
	var showPublic = document.getElementById("pubKey"); //make showPublic the value of the on screen Public Key textbox
	var showPrivate = document.getElementById("privKey");//same for showPrivate and Private Key textbox
	var companyKey = ec.genKeyPair(); //generate keypair
	window.publicKey = companyKey.getPublic(true, "hex"); //set the public key to publicKey
	window.privateKey = companyKey.getPrivate("hex"); //set the private key to privateKey
	showPublic.value = window.publicKey; //show public and private keys
	showPrivate.value = window.privateKey;


	document.getElementById("decrypt").onclick = function () {
		var rawData = document.getElementById("textDecrypt").value;
		var data;
		try {
			data = JSON.parse(rawData);
		}
		catch (e) {
			alert("Failed to parse data. Is it valid JSON?");
			return;
		}
		crypto.subtle.digest("SHA-256", hex2array(data.data))
			.then(function (hash) {
				hash = hex(hash);
				var publicKeyPair = ec.keyFromPublic(data.publicKey, "hex");
				if (!publicKeyPair.verify(hash, data.signature)) {
					alert("Invalid signature");
					return;
				}
				// Verified, now decrypt data
				var symmetricKeyArray = hex2array(ec.keyFromPrivate(window.privateKey).derive(publicKeyPair.getPublic()).toString(16));
				return window.crypto.subtle.importKey("raw", symmetricKeyArray, {name: "AES-CBC", length: 256}, false, ["decrypt"]);
			})
			.then(function (symmetricKey) {
				return crypto.subtle.decrypt({
					name: "AES-CBC",
					length: 256,
					iv: hex2array(data.dataIV)
				}, symmetricKey, hex2array(data.data));
			})
			.then(function (decrypted) {
				var decryptedText = new TextDecoder("utf-8").decode(new Uint8Array(decrypted));
				var pretty = JSON.stringify(JSON.parse(decryptedText));
				alert(`Received valid signature from ${data.publicKey}`);
				alert(`User data:\n${pretty}.`);
			})
			.catch(function (err) {
				alert("Failed due to unknown error");
				throw err;
			});
	}
}
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