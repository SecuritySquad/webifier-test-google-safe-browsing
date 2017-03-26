"use strict";
if (!Date.prototype.toISOString) {
    Date.prototype.toISOString = function () {
        function pad(n) { return n < 10 ? '0' + n : n; }
        function ms(n) { return n < 10 ? '00'+ n : n < 100 ? '0' + n : n }
        return this.getFullYear() + '-' +
            pad(this.getMonth() + 1) + '-' +
            pad(this.getDate()) + 'T' +
            pad(this.getHours()) + ':' +
            pad(this.getMinutes()) + ':' +
            pad(this.getSeconds()) + '.' +
            ms(this.getMilliseconds()) + 'Z';
    }
}

var page = require('webpage').create(),
    system = require('system');

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
