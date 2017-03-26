"use strict";
var page = require('webpage').create(),
    system = require('system');

page.onError = function(msg, trace) {
    return true;
};

if (system.args.length === 1) {
    console.log('Usage: check.js <URL>');
    phantom.exit(1);
} else {
    page.address = system.args[1];
    page.resources = [];

    page.onResourceRequested = function (req) {
        page.resources.push(req.url);
    };

    page.open(page.address, function (status) {
        if (status !== 'success') {
            console.log('FAIL to load the address');
            phantom.exit(1);
        } else {
            var links = page.evaluate(function () {
                var linkQuery = document.querySelectorAll('a');
                return Array.prototype.map.call(linkQuery, function (elem) {
                    return elem.href;
                });
            });
            var allLinks = page.resources.concat(links);
            var linksToValidate = [];
            var host = '://' + page.evaluate(function() {
                return window.location.hostname;
            });
            allLinks.forEach(function (link) {
                if (link.lastIndexOf("http", 0) === 0) {
                    if (link.indexOf(host) === -1) {
                        linksToValidate.push(link);
                    }
                }
            });
            linksToValidate.forEach(function (link) {
                console.log(link);
            });
            phantom.exit();
        }
    });
}
