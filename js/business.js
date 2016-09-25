document.getElementById("keypairgen").onclick=function(){
	var EC = elliptic.ec;
    var ec = new EC("secp256k1");
	var showPublic = document.getElementById("pubKey"); //make showPublic the value of the on screen Public Key textbox
	var showPrivate = document.getElementById("privKey");//same for showPrivate and Private Key textbox
	var companyKey = ec.genKeyPair(); //generate keypair
	var publicKey = companyKey.getPublic(true, "hex"); //set the public key to publicKey
	var privateKey = companyKey.getPrivate("hex"); //set the private key to privateKey
	showPublic.value = publicKey; //show public and private keys
	showPrivate.value = privateKey;
}