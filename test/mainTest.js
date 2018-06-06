"use strict";

// const mockery = require("mockery");
// // mock fido2-lib
// mockery.enable({
//     warnOnReplace: false,
//     warnOnUnregistered: false,
//     useCleanCache: true
// });
// class MockFido2Lib {
//     createCredentialChallenge() {
//         return Promise.resolve({
//             challenge: Uint8Array.from([0x1, 0x2, 0x3]).buffer
//         });
//     }
// }
// mockery.registerMock("fido2-lib", {
//     Fido2Lib: MockFido2Lib
// });

const Fido2Component = require("../index.js");
const assert = require("chai").assert;
const sinon = require("sinon");
const h = require("fido2-helpers");
var httpMocks = require("node-mocks-http");
var cloneObject = h.functions.cloneObject;

const {
    MockTableClass,
    MockUser,
    MockCred,
    MockUds,
    dummyComponentManager,
    dummyLogger,
    dummyUds,
    goodDummyUser,
    goodDummyCred,
    enableDebugLogging
} = require("./helpers/component-helpers");
enableDebugLogging(false);

describe("Fido2Component", function() {
    var f2c;
    beforeEach(function() {
        f2c = new Fido2Component(dummyComponentManager);
    });

    afterEach(function() {
        f2c.shutdown();
    });

    describe("init", function() {
        it("can be initialized", function() {
            var ret = f2c.init();
            assert.isUndefined(ret);
        });

        it("sets right origin", function() {
            f2c.init();
            assert.strictEqual(f2c.origin, "https://localhost");
        });
    });

    describe("features", function() {
        it("setRegisterRequest");
        it("setRegisterResponse");
        it("setLoginRequest");
        it("setLoginResponse");
        it("setServiceName", function() {
            f2c.config("set-service-name", "example.com");
            assert.strictEqual(f2c.serviceName, "example.com");
        });
        it("dangerousOpenRegistration", function() {
            assert.strictEqual(f2c.dangerousOpenRegistration, false);
        });
    });

    describe("registerRequest", function() {
        beforeEach(() => {
            // configure fido2-component so that we can stub Fido2Lib
            f2c.init();
        });

        it("returns options", function() {
            var req = httpMocks.createRequest({
                method: "POST",
                url: "/attestation/options",
                body: h.server.creationOptionsRequest,
                session: {}
            });
            var res = httpMocks.createResponse();

            return f2c.registerRequest(req, res)
                .then(() => {
                    assert.strictEqual(res.statusCode, 200);
                    var msg = res._getData();
                    assert.isString(msg);
                    msg = JSON.parse(msg);

                    // check message
                    assert.strictEqual(msg.status, "ok");
                    assert.strictEqual(msg.errorMessage, "");
                    assert.isString(msg.challenge);
                    assert.strictEqual(msg.challenge.length, 86);
                    assert.strictEqual(msg.timeout, 60000);
                    assert.isObject(msg.user);
                    assert.strictEqual(msg.user.name, "bubba");
                    assert.isString(msg.user.id);
                    assert.strictEqual(msg.user.id.length, 22);
                    assert.strictEqual(msg.user.displayName, "Bubba Smith");
                    assert.isObject(msg.rp);
                    assert.strictEqual(msg.rp.name, "ANONYMOUS SERVICE");
                    // assert.strictEqual(msg.rp.id, "example.com");
                    // assert.strictEqual(msg.rp.name, "example.com");
                    assert.isArray(msg.pubKeyCredParams);
                    assert.strictEqual(msg.pubKeyCredParams.length, 2);
                    assert.deepEqual(msg.pubKeyCredParams, [{
                        alg: -7,
                        type: "public-key"
                    }, {
                        type: "public-key",
                        alg: -257
                    }]);

                    // check session
                    assert.isObject(req.session);
                    assert.isString(req.session.registerChallenge);
                    assert.strictEqual(req.session.registerChallenge.length, 88);
                    assert.isNumber(req.session.registerChallengeTime);
                    assert.strictEqual(req.session.username, "bubba");
                });
        });

        it("errors on missing body");
        it("errors on missing username");
        it("user not found");
        it("user found");
        it("commits user");
        it("commits credential");
    });

    describe("registerResponse", function() {
        var testObj;
        beforeEach(() => {
            // configure fido2-component so that we can stub Fido2Lib
            f2c.serviceName = "example.com";
            f2c.dangerousOpenRegistration = true;
            f2c.init();
            // var credCreate = sinon.stub(f2c.fido2lib, "createCredentialChallenge");
            // credCreate.returns(Promise.resolve({
            //     challenge: Uint8Array.from([0x1, 0x2, 0x3]).buffer
            // }));
            // create attestation object
            testObj = cloneObject(h.server.challengeResponseAttestationNoneMsgB64Url);
        });

        // afterEach(() => {
        //     // restore stubbed methods
        //     f2c.fido2lib.createCredentialChallenge.restore();
        // });

        it("returns a Promise");

        it("sends a response", function() {
            var req = httpMocks.createRequest({
                method: "POST",
                url: "/attestation/options",
                body: testObj,
                session: {
                    registerChallenge: "33EHav-jZ1v9qwH783aU-j0ARx6r5o-YHh-wd7C6jPbd7Wh6ytbIZosIIACehwf9-s6hXhySHO-HHUjEwZS29w",
                    // registerChallenge: Uint8Array.from([0xdf, 0x71, 0x07, 0x6a, 0xff, 0xa3, 0x67, 0x5b, 0xfd, 0xab, 0x01, 0xfb, 0xf3, 0x76, 0x94, 0xfa, 0x3d, 0x00, 0x47, 0x1e, 0xab, 0xe6, 0x8f, 0x98, 0x1e, 0x1f, 0xb0, 0x77, 0xb0, 0xba, 0x8c, 0xf6, 0xdd, 0xed, 0x68, 0x7a, 0xca, 0xd6, 0xc8, 0x66, 0x8b, 0x08, 0x20, 0x00, 0x9e, 0x87, 0x07, 0xfd, 0xfa, 0xce, 0xa1, 0x5e, 0x1c, 0x92, 0x1c, 0xef, 0x87, 0x1d, 0x48, 0xc4, 0xc1, 0x94, 0xb6, 0xf7]).buffer,
                    registerChallengeTime: Date.now(),
                    username: "bubba",
                    userId: "ANhji75E904yjZSK78HUyw"
                }
            });
            var res = httpMocks.createResponse();

            f2c.origin = "https://localhost:8443";
            return f2c.registerResponse(req, res)
                .then(() => {
                    assert.strictEqual(res.statusCode, 200);
                    var msg = res._getData();
                    assert.isString(msg);
                    msg = JSON.parse(msg);
                    assert.strictEqual(msg.status, "ok");
                    assert.strictEqual(msg.errorMessage, "");
                });
        });

        it("includes debugInfo", function() {
            var req = httpMocks.createRequest({
                method: "POST",
                url: "/attestation/options",
                body: testObj,
                session: {
                    registerChallenge: "33EHav-jZ1v9qwH783aU-j0ARx6r5o-YHh-wd7C6jPbd7Wh6ytbIZosIIACehwf9-s6hXhySHO-HHUjEwZS29w",
                    // registerChallenge: Uint8Array.from([0xdf, 0x71, 0x07, 0x6a, 0xff, 0xa3, 0x67, 0x5b, 0xfd, 0xab, 0x01, 0xfb, 0xf3, 0x76, 0x94, 0xfa, 0x3d, 0x00, 0x47, 0x1e, 0xab, 0xe6, 0x8f, 0x98, 0x1e, 0x1f, 0xb0, 0x77, 0xb0, 0xba, 0x8c, 0xf6, 0xdd, 0xed, 0x68, 0x7a, 0xca, 0xd6, 0xc8, 0x66, 0x8b, 0x08, 0x20, 0x00, 0x9e, 0x87, 0x07, 0xfd, 0xfa, 0xce, 0xa1, 0x5e, 0x1c, 0x92, 0x1c, 0xef, 0x87, 0x1d, 0x48, 0xc4, 0xc1, 0x94, 0xb6, 0xf7]).buffer,
                    registerChallengeTime: Date.now(),
                    username: "bubba",
                    userId: "ANhji75E904yjZSK78HUyw"
                }
            });
            var res = httpMocks.createResponse();

            f2c.dangerousXmitDebugInfo = true;
            f2c.origin = "https://localhost:8443";
            return f2c.registerResponse(req, res)
                .then(() => {
                    // assert.strictEqual(res.statusCode, 200);
                    var msg = res._getData();
                    assert.isString(msg);
                    msg = JSON.parse(msg);
                    assert.strictEqual(msg.status, "ok");
                    assert.strictEqual(msg.errorMessage, "");

                    // clientData
                    assert.isObject(msg.debugInfo);
                    assert.isObject(msg.debugInfo.clientData);
                    assert.isString(msg.debugInfo.clientData.challenge);
                    assert.isString(msg.debugInfo.clientData.origin);
                    assert.isString(msg.debugInfo.clientData.type);
                    assert.isUndefined(msg.debugInfo.clientData.tokenBinding);
                    assert.isString(msg.debugInfo.clientData.rawClientDataJson);
                    assert.isString(msg.debugInfo.clientData.rawId);

                    // authnrData
                    assert.isObject(msg.debugInfo.authnrData);
                    assert.isString(msg.debugInfo.authnrData.fmt);
                    assert.isString(msg.debugInfo.authnrData.rawAuthnrData);
                    assert.isString(msg.debugInfo.authnrData.rpIdHash);
                    assert.isArray(msg.debugInfo.authnrData.flags);
                    assert.isNumber(msg.debugInfo.authnrData.counter);
                    assert.isString(msg.debugInfo.authnrData.aaguid);
                    assert.isNumber(msg.debugInfo.authnrData.credIdLen);
                    assert.isString(msg.debugInfo.authnrData.credId);
                    assert.isString(msg.debugInfo.authnrData.credentialPublicKeyCose);
                    assert.isObject(msg.debugInfo.authnrData.credentialPublicKeyJwk);
                    assert.isString(msg.debugInfo.authnrData.credentialPublicKeyPem);
                });
        });

        it("errors when user not found");
        it("errors when multiple users found");
        it("errors when no pending credentials");
        it("errors when multiple pending crednetials");
        it("deletes credential after timeout");
        it("errors when response is missing fields");
        it("errors when timeout");
    });

    describe("loginRequest", function() {
        beforeEach(() => {
            // mock UDS
            var findUsersStub = sinon.stub(dummyUds, "findUsers");
            findUsersStub.onCall(0).returns(Promise.resolve([goodDummyUser]));
            // mock credential
            var getCredStub = sinon.stub(goodDummyUser, "getCredentials");
            getCredStub.returns(Promise.resolve([goodDummyCred]));
            // configure fido2-component so that we can stub Fido2Lib
            f2c.serviceName = "example.com";
            f2c.init();
        });

        afterEach(() => {
            // restore stubbed methods
            dummyUds.findUsers.restore();
            goodDummyUser.getCredentials.restore();
        });

        it("returns options", function() {
            var req = httpMocks.createRequest({
                method: "POST",
                url: "/attestation/options",
                body: h.server.getOptionsRequest,
                session: {}
            });
            var res = httpMocks.createResponse();

            return f2c.loginRequest(req, res)
                .then(() => {
                    assert.strictEqual(res.statusCode, 200);
                    var msg = res._getData();
                    assert.isString(msg);
                    msg = JSON.parse(msg);

                    // check message
                    assert.strictEqual(msg.status, "ok");
                    assert.strictEqual(msg.errorMessage, "");
                    assert.isString(msg.challenge);
                    assert.strictEqual(msg.challenge.length, 86);
                    assert.isArray(msg.allowCredentials);
                    assert.strictEqual(msg.allowCredentials.length, 1);
                    assert.strictEqual(msg.timeout, 60000);

                    // check session
                    assert.isObject(req.session);
                    assert.isString(req.session.loginChallenge);
                    assert.strictEqual(req.session.loginChallenge.length, 88);
                    assert.isNumber(req.session.loginChallengeTime);
                    assert.strictEqual(req.session.username, "bubba");
                });
        });

        it("errors when user not found");
        it("errors when credential not found");
    });

    describe("loginResponse", function() {
        var testObj;
        beforeEach(() => {
            // mock UDS
            var findUsersStub = sinon.stub(dummyUds, "findUsers");
            findUsersStub.onCall(0).returns(Promise.resolve([goodDummyUser]));
            // mock credential
            var getCredStub = sinon.stub(goodDummyUser, "getCredentials");
            getCredStub.returns(Promise.resolve([goodDummyCred]));
            var credGetStub = sinon.stub(goodDummyCred, "get");
            credGetStub.withArgs("publicKey").returns(h.lib.assnPublicKey);
            credGetStub.withArgs("prevCounter").returns(1);
            // configure fido2-component so that we can stub Fido2Lib
            f2c.serviceName = "example.com";
            f2c.init();
            f2c.origin = "https://localhost:8443";
            // var credCreate = sinon.stub(f2c.fido2lib, "createCredentialChallenge");
            // credCreate.returns(Promise.resolve({
            //     challenge: Uint8Array.from([0x1, 0x2, 0x3]).buffer
            // }));
            // test object
            testObj = cloneObject(h.server.assertionResponseMsgB64Url);
        });

        afterEach(() => {
            // restore stubbed methods
            dummyUds.findUsers.restore();
            goodDummyUser.getCredentials.restore();
            goodDummyCred.get.restore();
            // f2c.fido2lib.createCredentialChallenge.restore();
        });

        it("sends a response", function() {
            var req = httpMocks.createRequest({
                method: "POST",
                url: "/attestation/result",
                body: testObj,
                session: {
                    loginChallenge: "eaTyUNnyPDDdK8SNEgTEUvz1Q8dylkjjTimYd5X7QAo-F8_Z1lsJi3BilUpFZHkICNDWY8r9ivnTgW7-XZC3qQ",
                    // loginChallenge: Uint8Array.from([0x79, 0xa4, 0xf2, 0x50, 0xd9, 0xf2, 0x3c, 0x30, 0xdd, 0x2b, 0xc4, 0x8d, 0x12, 0x04, 0xc4, 0x52, 0xfc, 0xf5, 0x43, 0xc7, 0x72, 0x96, 0x48, 0xe3, 0x4e, 0x29, 0x98, 0x77, 0x95, 0xfb, 0x40, 0x0a, 0x3e, 0x17, 0xcf, 0xd9, 0xd6, 0x5b, 0x09, 0x8b, 0x70, 0x62, 0x95, 0x4a, 0x45, 0x64, 0x79, 0x08, 0x08, 0xd0, 0xd6, 0x63, 0xca, 0xfd, 0x8a, 0xf9, 0xd3, 0x81, 0x6e, 0xfe, 0x5d, 0x90, 0xb7, 0xa9]).buffer,
                    loginChallengeTime: Date.now(),
                    username: "bubba",
                    userId: "ANhji75E904yjZSK78HUyw",
                    regenerate: function(cb) {
                        cb();
                    }
                }
            });
            var res = httpMocks.createResponse();

            return f2c.loginResponse(req, res)
                .then(() => {
                    assert.strictEqual(res.statusCode, 200);
                    var msg = res._getData();
                    assert.isString(msg);
                    msg = JSON.parse(msg);
                    assert.strictEqual(msg.status, "ok");
                    assert.strictEqual(msg.errorMessage, "");
                });
        });

        it("includes debugInfo", function() {
            var req = httpMocks.createRequest({
                method: "POST",
                url: "/attestation/result",
                body: testObj,
                session: {
                    loginChallenge: "eaTyUNnyPDDdK8SNEgTEUvz1Q8dylkjjTimYd5X7QAo-F8_Z1lsJi3BilUpFZHkICNDWY8r9ivnTgW7-XZC3qQ",
                    // loginChallenge: Uint8Array.from([0x79, 0xa4, 0xf2, 0x50, 0xd9, 0xf2, 0x3c, 0x30, 0xdd, 0x2b, 0xc4, 0x8d, 0x12, 0x04, 0xc4, 0x52, 0xfc, 0xf5, 0x43, 0xc7, 0x72, 0x96, 0x48, 0xe3, 0x4e, 0x29, 0x98, 0x77, 0x95, 0xfb, 0x40, 0x0a, 0x3e, 0x17, 0xcf, 0xd9, 0xd6, 0x5b, 0x09, 0x8b, 0x70, 0x62, 0x95, 0x4a, 0x45, 0x64, 0x79, 0x08, 0x08, 0xd0, 0xd6, 0x63, 0xca, 0xfd, 0x8a, 0xf9, 0xd3, 0x81, 0x6e, 0xfe, 0x5d, 0x90, 0xb7, 0xa9]).buffer,
                    loginChallengeTime: Date.now(),
                    username: "bubba",
                    userId: "ANhji75E904yjZSK78HUyw",
                    regenerate: function(cb) {
                        cb();
                    }
                }
            });
            var res = httpMocks.createResponse();

            f2c.dangerousXmitDebugInfo = true;
            return f2c.loginResponse(req, res)
                .then(() => {
                    // assert.strictEqual(res.statusCode, 200);
                    var msg = res._getData();
                    assert.isString(msg);
                    msg = JSON.parse(msg);
                    assert.isObject(msg.debugInfo);

                    // clientData
                    assert.isObject(msg.debugInfo);
                    assert.isObject(msg.debugInfo.clientData);
                    assert.isString(msg.debugInfo.clientData.challenge);
                    assert.isString(msg.debugInfo.clientData.origin);
                    assert.isString(msg.debugInfo.clientData.type);
                    assert.isUndefined(msg.debugInfo.clientData.tokenBinding);
                    assert.isString(msg.debugInfo.clientData.rawClientDataJson);
                    assert.isString(msg.debugInfo.clientData.rawId);

                    // authnrData
                    assert.isObject(msg.debugInfo.authnrData);
                    assert.isString(msg.debugInfo.authnrData.rawAuthnrData);
                    assert.isString(msg.debugInfo.authnrData.rpIdHash);
                    assert.isArray(msg.debugInfo.authnrData.flags);
                    assert.isNumber(msg.debugInfo.authnrData.counter);
                });
        });
    });

    describe("setRegisterRequest", function() {
        it("updates endpoint");
    });

    describe("setRegisterResponse", function() {
        it("updates endpoint");
    });

    describe("setLoginRequest", function() {
        it("updates endpoint");
    });

    describe("setLoginResponse", function() {
        it("updates endpoint");
    });
});
