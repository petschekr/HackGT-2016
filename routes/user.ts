import common = require("../common");
var database = common.db;
import express = require("express");
var router = express.Router();
import bodyParser = require("body-parser");
var postParser = bodyParser.json();

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

export = router;
