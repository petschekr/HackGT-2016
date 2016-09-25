import fs = require("fs");
import crypto = require("crypto");
import http = require("http");
import https = require("https");
import cheerio = require("cheerio");

import common = require("./common");
var keys = common.keys;
//var db = common.db;

// Set up the Express server
import express = require("express");
import serveStatic = require("serve-static");
const responseTime = require("response-time");
const compress = require("compression");
const cookieParser = require("cookie-parser");
const bodyParser = require("body-parser");

var app = express();
var postParse = bodyParser.urlencoded({"extended": false});
app.use(compress());
app.use(responseTime());
app.use(cookieParser(
    keys.cookieSecret, // Secret for signing cookies,
    common.cookieOptions
));

//app.use("/css", serveStatic("public/css"));
//app.use("/img", serveStatic("public/img"));
app.use("/js", serveStatic("js"));

// Routes
import userRouter = require("./routes/user");
app.use("/api/user", userRouter);

app.route("/").get(function (request, response) {
	fs.readFile("pages/index.html", "utf8", function(err, html) {
        if (err) {
            common.handleError.bind(response);
            return;
        }
        response.send(html);
    });
});
app.route("/join").get(common.authenticateMiddleware, function (request, response) {
    if (response.locals.authenticated) {
        response.redirect("/setup");
        return;
    }
    fs.readFile("pages/create-user-account.html", "utf8", function(err, html) {
        if (err) {
            common.handleError.bind(response);
            return;
        }
        response.send(html);
    });
});
app.route("/setup").get(common.authenticateMiddleware, function (request, response) {
    if (!response.locals.authenticated) {
        response.redirect("/join");
        return;
    }
    fs.readFile("pages/new-user-form.html", "utf8", function(err, html) {
        if (err) {
            common.handleError.bind(response);
            return;
        }
        response.send(html);
    });
});
app.route("/employer").get(function (request, response) {
	fs.readFile("pages/employers.html", "utf8", function(err, html) {
        if (err) {
            common.handleError.bind(response);
            return;
        }
        response.send(html);
    });
});

// Hack because I'm too lazy to put this in css/
app.route("/styles.css").get(function (request, response) {
	fs.readFile("styles.css", "utf8", function(err, css) {
        if (err) {
            common.handleError.bind(response);
            return;
        }
        response.set("Content-Type', 'text/css");
        response.send(css);
    });
});

// 404 page
app.use(/*common.authenticateMiddleware,*/ function (request, response, next) {
	console.info(`Handled 404 for ${request.url} (${request.method}) (${request.ip}) at ${new Date().toString()}`);
	response.status(404).send("404 Not found!");
	/*fs.readFile("pages/404.html", "utf8", function (err, html) {
        if (err) {
            common.handleError.bind(response);
            return;
        }
        var $ = cheerio.load(html);
        $("#url").text(request.url);
        response.status(404).send($.html());
    });*/
});
// Generic error handling
app.use(function (err: Error, request, response, next) {
	common.handleError.bind(response)(err);
});

const PORT = 80;
const HTTPS_PORT = 443;
const httpsOptions = {
	key: fs.readFileSync("/etc/letsencrypt/live/panid.tech/privkey.pem"),
	cert: fs.readFileSync("/etc/letsencrypt/live/panid.tech/cert.pem"),
	ca: fs.readFileSync("/etc/letsencrypt/live/panid.tech/chain.pem"),
	//secureProtocol: "TLSv1_method"
	ciphers: "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK"
};

// Set up the server
https.createServer(httpsOptions, app).listen(HTTPS_PORT, "0.0.0.0", 511, function () {
	console.log("HTTPS server listening on port " + HTTPS_PORT);
});

export = app;