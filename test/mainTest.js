"use strict";

var turnOnDebugLogging = true;

const Fido2Component = require("../index.js");
const assert = require("chai").assert;
const sinon = require("sinon");
const h = require("fido2-helpers");


var dummyComponentManager = {
    registerType: function() {},
    getType: function() {},
    register: function() {},
    get: function(name) {
        if (name === "logger") return dummyLogger;
        if (name === "uds") return dummyUds;
    },
    clear: function() {},
    config: function(module, cmd) {
        if (module === "https" && cmd === "get-protocol") return "https";
        if (module === "https" && cmd === "get-domain") return "localhost";
        if (module === "https" && cmd === "get-port") return "443";
    },
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
            }
        });
    }
};

var dummyUds = {
    createUser() {
        return new DummyTableClass();
    },
    findUsers() {},
    saveUser() {},
    destroyUser() {},
    findCredentials() {},
    createCredential() {},
    saveCredential() {},
    destroyCredential() {}
};

class DummyTableClass {
    set(prop) {
        this[prop] = prop;
    }

    get(prop) {
        return this[prop];
    }

    commit() {
        console.log("DOING COMMIT");
    }
}

describe("Fido2Component", function() {
    var f2c;
    beforeEach(function() {
        f2c = new Fido2Component(dummyComponentManager);
    });

    afterEach(function() {
        f2c.shutdown();
    });

    it("can be initialized", function() {
        var ret = f2c.init();
        assert.isUndefined(ret);
    });

    it("sets right origin", function() {
        f2c.init();
        assert.strictEqual(f2c.origin, "https://localhost");
    });

    describe("feature", function() {
        it("setRegisterRequest");
        it("setRegisterResponse");
        it("setLoginRequest");
        it("setLoginResponse");
    });

    describe("registerRequest", function() {
        it("errors on missing body");
        it("errors on missing username");
        it("user not found");
        it("user found");
        it("commits user");
        it("commits credential");

        it.skip("resolves to a challenge", function(done) {
            var args = [{
                body: h.functions.cloneObject(h.server.challengeRequestMsg)
            }, {
                send: sendCb
            }];
            var findUsersStub = sinon.stub(dummyUds, "findUsers");
            findUsersStub.onCall(0).returns(Promise.resolve([]));
            var createCredStub = sinon.stub(dummyUds, "createCredential");
            var newCred = new DummyTableClass();
            createCredStub.onCall(0).returns(newCred);
            var newCredCommitStub = sinon.stub(newCred, "commit");
            newCredCommitStub.onCall(0).returns(Promise.resolve());

            function sendCb(msg) {
                assert.isString(msg);
                msg = JSON.parse(msg);
                assert.isString(msg.challenge);
                assert.strictEqual(msg.timeout, 60000);
                assert.isObject(msg.rp);
                assert.strictEqual(msg.rp.id, "example.com");
                assert.strictEqual(msg.rp.name, "example.com");

                assert(newCredCommitStub.calledOnce, "should commit new credential");

                createCredStub.restore();
                findUsersStub.restore();
                done();
            }

            f2c.init();
            f2c.registerRequest(...args);
        });
    });

    describe("registerResponse", function() {
        it.skip("accepts a response", function(done) {
            var args = [
                h.functions.cloneObject(h.server.challengeResponseAttestationNoneMsg), {
                    send: sendCb
                }, {
                    status: () => args[0]
                }
            ];

            function sendCb(msg) {
                done();
            }

            f2c.init();
            f2c.registerResponse(...args);
        });
        it("errors when user not found");
        it("errors when multiple users found");
        it("errors when no pending credentials");
        it("errors when multiple pending crednetials");
        it("deletes credential after timeout");
        it("errors when response is missing fields");
    });

    describe("loginRequest", function() {
        it("errors when user not found");
        it("errors when credential not found");
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
