var turnOnDebugLogging = true;

var Fido2Component = require("../index.js");
var assert = require("chai").assert;
const sinon = require("sinon");
const helpers = require("fido2-helpers");


var dummyComponentManager = {
    registerType: function() {},
    getType: function() {},
    register: function() {},
    get: function(name) {
        if (name === "logger") return dummyLogger;
    },
    clear: function() {},
    config: function() {},
    init: function() {},
    shutdown: function() {},
    componentList: new Map(),
    typeList: new Map()
};

var dummyLogger = {
    create: function() {
        return new Proxy(function() {}, {
            get: function() {
                return function(...msg) {
                    if (turnOnDebugLogging) console.log(...msg);
                };
            },
        });
    }
};

describe("Fido2Component", function() {
    var f2c;
    beforeEach(function() {
        f2c = new Fido2Component(dummyComponentManager);
        f2c.setServerDomain("localhost");
    });

    afterEach(function() {
        f2c.shutdown();
    });

    it("can be initialized", function() {
        var ret = f2c.init();
        assert.isUndefined(ret);
    });

    describe("feature", function() {
        it("setServerName", function() {
            f2c.setServerDomain("example.com");
            assert.strictEqual(f2c.serverDomain, "example.com");
        });
        it("getServerName", function() {
            f2c.setServerDomain("example.com");
            var ret = f2c.getServerDomain();
            assert.strictEqual(ret, "example.com");
        });
        it("setServerName", function() {
            f2c.setServerName("Facebook");
            assert.strictEqual(f2c.serverName, "Facebook");
        });
        it("getServerName", function() {
            f2c.setServerName("Google");
            var ret = f2c.getServerName();
            assert.strictEqual(ret, "Google");
        });
    });

    describe("registerRequest", function() {
        it.skip("resolves to a challenge", function(done) {
            var args = [
                null, {
                    send: sendCb
                }
            ];

            function sendCb(msg) {
                assert.isString(msg);
                msg = JSON.parse(msg);
                console.log("msg", msg);
                assert.isString(msg.challenge);
                assert.strictEqual(msg.timeout, 60000);
                assert.isObject(msg.rp);
                assert.strictEqual(msg.rp.id, "example.com");
                assert.strictEqual(msg.rp.name, "example.com");
                done();
            }

            f2c.setServerDomain("example.com");
            f2c.init();
            f2c.registerRequest(...args);
        });
    });

    describe("registerResponse", function() {
        it("accepts a response", function(done) {
            var body = helpers.copyObject(helpers.registerResponseMsg);
            var args = [{
                body: body
            }, {
                send: sendCb
            }];

            function sendCb() {
                console.log ("sendCb");
                done();
            }

            f2c.init();
            f2c.registerResponse(...args);
        });
        it("errors when response is missing fields");
    });

    describe("loginRequest", function() {

    });

    describe("loginResponse", function() {

    });

    describe("setRegisterRequest", function() {

    });

    describe("setRegisterResponse", function() {

    });

    describe("setLoginRequest", function() {

    });

    describe("setLoginResponse", function() {

    });
});