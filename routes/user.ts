import crypto = require("crypto");
import common = require("../common");
var database = common.db;
import express = require("express");
var router = express.Router();
import bodyParser = require("body-parser");
var postParser = bodyParser.json();
import r = require("rethinkdb");

// TODO: use secp256k1 on server for faster, native implementation
var EC = require("elliptic").ec;
var ec = new EC("secp256k1");

interface User extends common.User { };

router.route("/").get(common.authenticateMiddleware, function (request, response) {
    if (response.locals.authenticated) {
        let user: User = response.locals.user;
        response.json({
            "username": user.username
        });
    }
    else {
        response.status(403).json({
            "error": "Invalid identification cookie"
        });
    }
});
router.route("/join").post(postParser, function (request, response) {
    var username = request.body.username.toString().trim();
    var publicKey = Buffer.from(request.body.publicKey.toString(), "hex");
    var signature = Buffer.from(request.body.signature.toString(), "hex");
    if (!username || !publicKey || !signature) {
        response.status(400).send({
           "error": "Missing username, public key, or signature"
        });
        return;
    }
    // Verify signature
    var publicKeyPair = ec.keyFromPublic(publicKey, "hex");
    var signedData = crypto.createHash("sha256").update(username).digest();
    if (!publicKeyPair.verify(signedData, signature)) {
        response.status(400).send({
           "error": "Invalid signature"
        });
        return;
    }
    // Signature checked out, set up this user with some basic information
    var data = JSON.stringify({
        "username": username
    });
    var ephemKey = crypto.randomBytes(32);
    var derivedKey = ec.keyFromPrivate(ephemKey, "hex").derive(publicKeyPair.getPublic());
    var iv = crypto.randomBytes(16)
    const cipher = crypto.createCipheriv("id-aes256-GCM", derivedKey, iv);
    var encryptedData = cipher.update(data, "utf8", "hex");
    encryptedData += cipher.final("hex");

    var user: User = {
        username: username,
        publicKey: publicKey.toString("hex"),
        ephemPublicKey: publicKey.toString("hex"),
        data: encryptedData
    };
    r.table("users").insert([user]).run(common.db, function(err) {
        response.send({
            "success": true, "message": "Account successfully created"
        });
    });
});

export = router;