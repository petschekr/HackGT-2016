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

// RethinkDB database
import r = require("rethinkdb");

app.use("/css", serveStatic("public/css"));
app.use("/img", serveStatic("public/img"));

app.route("/").get(function (request, response) {
	fs.readFile("pages/index.html", "utf8", function(err, html) {
        if (err) {
            common.handleError.bind(response);
            return;
        }
        response.send(html);
    });
});

// 404 page
app.use(/*common.authenticateMiddleware,*/ function (request, response, next) {
	console.info(`Handled 404 for ${request.url} (${request.method}) (${request.ip}) at ${new Date().toString()}`);
	//response.status(404).send("404 Not found!");
	fs.readFile("pages/404.html", "utf8", function (err, html) {
        if (err) {
            common.handleError.bind(response);
            return;
        }
        var $ = cheerio.load(html);
        $("#url").text(request.url);
        response.status(404).send($.html());
    });
});
// Generic error handling
app.use(function (err: Error, request, response, next) {
	common.handleError.bind(response)(err);
});

const PORT = 8080;

// Set up the Socket.io server
var server = http.createServer(app).listen(PORT, "0.0.0.0", 511, function () {
	console.log("HTTP server listening on port " + PORT);
});

export = app;