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
router.route("/getsalt/:username").get(function (request, response) {
    var username = request.params.username.toString();
    r.table("users").filter({username: username}).run(common.db, function(err, cursor) {
        if (err) throw err;
		cursor.toArray(function (err, results) {
			if (err) throw err;
			
			var user: any = {};
			var loggedIn: boolean;
            var salt: string;
			if (results.length < 1) {
				// Username not found in database, return random salt
				salt = crypto.randomBytes(16).toString("hex");
			}
			else {
				// Pull the user's salt from the database for them to log in
                salt = results[0].salt;
			}
            response.json({ "salt": salt });
		});
    });
});
router.route("/getsalt").get(common.authenticateMiddleware, function (request, response) {
    if (!response.locals.user) {
        response.locals.user = {};
    }
    var username = response.locals.user.username;
    r.table("users").filter({username: username}).run(common.db, function(err, cursor) {
        if (err) throw err;
		cursor.toArray(function (err, results) {
			if (err) throw err;
			
			var user: any = {};
			var loggedIn: boolean;
            var salt: string;
			if (results.length < 1) {
				// Username not found in database, return random salt
				salt = crypto.randomBytes(16).toString("hex");
			}
			else {
				// Pull the user's salt from the database for them to log in
                salt = results[0].salt;
			}
            response.json({ "salt": salt });
		});
    });
});
router.route("/login").post(postParser, function (request, response) {
    response.clearCookie("username");
    var username = request.body.username.toString().trim();
    var publicKey = Buffer.from(request.body.publicKey.toString(), "hex");
    var signature = Buffer.from(request.body.signature.toString(), "hex");
    
    if (!username || !publicKey || !signature) {
        response.status(400).send({
           "error": "Missing username, public key, or signature"
        });
        return;
    }
    r.table("users").filter({username: username}).run(common.db, function(err, cursor) {
        if (err) throw err;
		cursor.toArray(function (err, results) {
			if (err) throw err;
            if (results.length === 0) {
                response.status(400).send({
                    "error": "Username not found"
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
            response.cookie("username", username, common.cookieOptions);
            response.send({
                "success": true
            });
        });
    });
});
router.route("/getdata").get(common.authenticateMiddleware, function (request, response) {
    if (!response.locals.authenticated) {
        response.status(401).json({
            "error": "Not logged in"
        });
        return;
    }
    var username = response.locals.user.username;
    r.table("users").filter({username: username}).run(common.db, function(err, cursor) {
        if (err) throw err;
		cursor.toArray(function (err, results) {
			if (err) throw err;
			
			var user: User;
			var loggedIn: boolean;
            var salt: string;
			if (results.length < 1) {
				// Username not found in database
				response.status(400).json({
                    "error": "Username not found"
                });
			}
			else {
                user = results[0];
				response.json({
                    "data": user.data,
                    "iv": user.dataIV,
                    "authTag": user.dataAuthTag,
                    "ephemPublicKey": user.ephemPublicKey
                });
			}
		});
    });
});
router.route("/setdata").post(common.authenticateMiddleware, postParser, function (request, response) {
    if (!response.locals.authenticated) {
        response.status(401).json({
            "error": "Not logged in"
        });
        return;
    }
    var username = response.locals.user.username;
    var data = Buffer.from(request.body.data.toString(), "hex");
    var dataIV = Buffer.from(request.body.dataIV.toString(), "hex");
    var ephemPublicKey = Buffer.from(request.body.ephemPublicKey.toString(), "hex");
    var signature = Buffer.from(request.body.signature.toString(), "hex");
    // Verify signature
    var publicKeyPair = ec.keyFromPublic(response.locals.user.publicKey, "hex");
    var signedData = crypto.createHash("sha256").update(data).digest();
    if (!publicKeyPair.verify(signedData, signature)) {
        response.status(400).send({
            "error": "Invalid signature"
        });
        return;
    }
    // Signature checks out, update data fields in database
    // TODO: dataAuthTag should be in update
    r.table("users").filter({username: username}).update({
        "data": data.toString("hex"),
        "dataIV": dataIV.toString("hex"),
        "ephemPublicKey": ephemPublicKey.toString("hex")
    }).run(common.db, function(err, result) {
        if (err)
            throw err;
        response.send({
            "success": true, "message": "Account successfully created"
        });
    });
});
router.route("/join").post(postParser, function (request, response) {
    var username = request.body.username.toString().trim();
    var publicKey = Buffer.from(request.body.publicKey.toString(), "hex");
    var signature = Buffer.from(request.body.signature.toString(), "hex");
    // Save the salt that the user used to derive their private key
    var salt = request.body.salt.toString();
    if (!username || !publicKey || !signature) {
        response.status(400).send({
           "error": "Missing username, public key, or signature"
        });
        return;
    }
    r.table("users").filter({username: username}).run(common.db, function(err, cursor) {
        if (err) throw err;
		cursor.toArray(function (err, results) {
			if (err) throw err;
            if (results.length !== 0) {
                response.status(400).send({
                    "error": "That username is already taken"
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
            derivedKey = new Buffer(derivedKey.toString(16), "hex");
            var iv = crypto.randomBytes(16);
            const cipher = crypto.createCipheriv("AES-256-CBC", derivedKey, iv);
            var encryptedData = cipher.update(data, "utf8", "hex");
            encryptedData += cipher.final("hex");
            //cipher.getAuthTag();
            // TODO: Use HMAC here because only GCM supports automatic authtags
            var authTag = crypto.createHmac("sha256", derivedKey).update(encryptedData).digest();

            var user: User = {
                username: username,
                salt: salt,
                publicKey: publicKey.toString("hex"),
                ephemPublicKey: ec.keyFromPrivate(ephemKey, "hex").getPublic(true, "hex"),
                data: encryptedData,
                dataIV: iv.toString("hex"),
                dataAuthTag: authTag.toString("hex")
            };
            r.table("users").insert([user]).run(common.db, function(err) {
                // Set authentication cookie
                response.clearCookie("username");
                response.cookie("username", username, common.cookieOptions);
                response.send({
                    "success": true, "message": "Account successfully created"
                });
            });
        });
    });
});

export = router;