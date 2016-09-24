import fs = require("fs");
import express = require("express");

/*export enum UserType {
	Student,
	Teacher,
	Parent,
	Alum,
	Visitor,
	Other
};*/

export interface User {
	"username": String;
}
export var keys: {
	"rethinkdb": {
		"username": string;
		"password": string;
		"server": string;
	};
	"cookieSecret": string;
} = JSON.parse(fs.readFileSync("keys.json").toString("utf8"));
export var cookieOptions = {
	"path": "/",
	"maxAge": 1000 * 60 * 60 * 24 * 30 * 6, // 6 months
	"secure": false,
	"httpOnly": true,
	"signed": true
};

// RethinkDB database
import r = require("rethinkdb");
var connection: r.Connection | null = null;
r.connect( {host: "localhost", port: 28015}, function(err, conn) {
    if (err) throw err;
    connection = conn;
	console.info("Connected to RethinkDB instance");
});

//var dbRaw = new neo4j.GraphDatabase(`http://${keys.neo4j.username}:${keys.neo4j.password}@${keys.neo4j.server}:7474`);
//export var db = Promise.promisifyAll(dbRaw);
/*export var authenticateMiddleware = function (request: express.Request, response: express.Response, next: express.NextFunction): void {
	var username = request.signedCookies.username || "";
	db.cypherAsync({
		query: "MATCH (user:User {username: {username}}) RETURN user",
		params: {
			username: username
		}
	}).then(function (results) {
		var user = null;
		var loggedIn: boolean;
		if (results.length < 1) {
			// Username not found in database
			loggedIn = false;
		}
		else {
			user = results[0].user.properties;
			user.admin = !!user.admin; // Could be true or null
			loggedIn = true;
		}
		response.locals.authenticated = loggedIn;
		response.locals.user = user;
		next();
	}).catch(handleError.bind(response));
};*/

/*var pusher = require("pushbullet");
pusher = Promise.promisifyAll(new pusher(keys.pushbullet));
// Enumerate active devices to push to in case of an error
var pushbulletDevices: string[] = [];
pusher.devicesAsync()
	.then(function (response) {
		var devices: any[] = response.devices;
		for (let device of devices) {
			if (device.active) {
				pushbulletDevices.push(device.iden);
			}
		}
	})
	.catch(function (err: Error) {
		throw err;
	});
*/
export var handleError = function (err: any): void {
	console.error(err.stack);

	// Check if this error occurred while responding to a request
	if (this.status && this.send) {
		var response: express.Response = this;
		fs.readFile("pages/500.html", "utf8", function (err, html) {
			response.status(500);
			if (err) {
				console.error(err);
				response.send("An internal server error occurred and an additional error occurred while serving an error page.");
				return;
			}
			response.send(html);
		});
	}

	const debugging: boolean = true;
	if (debugging) {
		return;
	}
	// Notify via PushBullet
	/*var pushbulletPromises: any[] = [];
	for (let deviceIden of pushbulletDevices) {
		pushbulletPromises.push(pusher.noteAsync(deviceIden, "WPP Error", `${new Date().toString()}\n\n${err.stack}`));
	}
	Promise.all(pushbulletPromises).then(function () {
		console.log("Error report sent via Pushbullet");
	}).catch(function (err: Error) {
		console.error("Error encountered while sending error report via Pushbullet");
		console.error(err);
	});*/
};