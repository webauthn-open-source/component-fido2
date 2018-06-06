"use strict";

const Component = require("component-class");
const { Fido2Lib } = require("fido2-lib");
const { URL } = require("url");
const {
    WebAuthnHelpers, Msg, ServerResponse,
    CreateOptionsRequest, CreateOptions,
    CredentialAttestation,
    GetOptionsRequest, GetOptions,
    CredentialAssertion,
    WebAuthnOptions
} = require("webauthn-simple-app");
const crypto = require("crypto");
var log;

module.exports = class Fido2Component extends Component {
    constructor(cm) {
        super(cm);

        // features
        this.addFeature("set-register-request", this.setRegisterRequest);
        this.addFeature("set-register-response", this.setRegisterResponse);
        this.addFeature("set-login-request", this.setLoginRequest);
        this.addFeature("set-login-response", this.setLoginResponse);
        this.addSetterGetterFeature("serviceName", "string", "ANONYMOUS SERVICE");
        this.addSetterGetterFeature("timeout", "number", 60000);
        this.addEnableFeature("dangerousOpenRegistration", false);
        this.addEnableFeature("dangerousXmitDebugInfo", false);

        // default routes
        this.setRegisterRequest({
            path: WebAuthnHelpers.defaultRoutes.attestationOptions,
            method: "POST",
            cb: this.registerRequest
        });

        this.setRegisterResponse({
            path: WebAuthnHelpers.defaultRoutes.attestationResult,
            method: "POST",
            cb: this.registerResponse
        });

        this.setLoginRequest({
            path: WebAuthnHelpers.defaultRoutes.assertionOptions,
            method: "POST",
            cb: this.loginRequest
        });

        this.setLoginResponse({
            path: WebAuthnHelpers.defaultRoutes.assertionResult,
            method: "POST",
            cb: this.loginResponse
        });

        this.addDependency("logger");
        this.addDependency("https");
        this.addDependency("uds");
    }

    init() {
        var logger = this.cm.get("logger");
        if (logger === undefined) {
            throw new Error("logger component not found");
        }
        log = logger.create("Fido2Component");
        log.debug("Starting Fido2Component ...");

        // configure user data store
        this.uds = this.cm.get("uds");
        if (!this.uds) {
            throw new Error("could not load UDS, failing");
        }

        // configure Fido2Lib
        this.fido2lib = new Fido2Lib(this.getConfig());

        // register https routes
        this.cm.config("https", "add-dynamic", {
            path: this.registerRequestRoute,
            method: this.registerRequestMethod,
            fn: this.registerRequestCb
        });

        this.cm.config("https", "add-dynamic", {
            path: this.registerResponseRoute,
            method: this.registerResponseMethod,
            fn: this.registerResponseCb
        });

        this.cm.config("https", "add-dynamic", {
            path: this.loginRequestRoute,
            method: this.loginRequestMethod,
            fn: this.loginRequestCb
        });

        this.cm.config("https", "add-dynamic", {
            path: this.loginResponseRoute,
            method: this.loginResponseMethod,
            fn: this.loginResponseCb
        });

        var protocol = this.cm.config("https", "get-protocol");
        var domain = this.cm.config("https", "get-domain");
        var port = this.cm.config("https", "get-port");
        var originUrl = new URL(`${protocol}://${domain}:${port}`);
        this.origin = originUrl.origin;
    }

    getConfig() {
        // TODO: timeout
        // TODO: challenge size
        // TODO: exclude list
        // TODO: crypto prefs
        return {
            rpName: this.serviceName,
            timeout: this.timeout
        };
    }

    async registerRequest(req, res) {
        try {
            log.debug("registerRequest", req.body);
            var optReq = CreateOptionsRequest.from(req.body);
            optReq.validate();
            optReq.decodeBinaryProperties();

            // get options
            const opts = await this.fido2lib.attestationOptions();
            opts.user.name = optReq.username;
            opts.user.id = crypto.randomBytes(16); // TODO: variable ID size? id from UDS?
            opts.user.displayName = optReq.displayName;

            // convert options to Msg
            var respOpts = CreateOptions.from(opts);
            respOpts.status = "ok";

            // save data to session
            req.session.username = optReq.username;
            req.session.userId = coerceToBase64(opts.user.id);
            req.session.registerChallenge = coerceToBase64(opts.challenge);
            req.session.registerChallengeTime = Date.now();

            // send response
            respOpts.encodeBinaryProperties();
            respOpts.validate();
            res.send(respOpts.toString());
        } catch (err) {
            log.warn("registerRequest error", err);
            return sendErrorMessage(res, 400, "error getting registration options: " + err.message);
        }
    }

    async registerResponse(req, res) {
        try {
            log.debug("registerResponse", req.body);
            var attResult = CredentialAttestation.from(req.body);
            attResult.validate();
            attResult.decodeBinaryProperties();

            // check session and grab values
            if (!req.session ||
                typeof req.session.username !== "string" ||
                typeof req.session.userId !== "string" ||
                typeof req.session.registerChallengeTime !== "number" ||
                typeof req.session.registerChallenge !== "string") {
                throw new Error("Could not find session information. Are cookies disabled?");
            }
            req.session.registerChallenge = coerceToArrayBuffer(req.session.registerChallenge, "session.registerChallenge");
            var username = req.session.username;
            var userId = req.session.userId;

            // check timeout
            if (Date.now() >= req.session.registerChallengeTime + this.timeout) {
                throw new Error("register request timed out");
            }

            // set expectations
            var attestationExpectations = {
                challenge: req.session.registerChallenge,
                origin: this.origin,
                factor: "either"
            };

            // validate result
            var result = await this.fido2lib.attestationResult(attResult.toObject(), attestationExpectations);

            // create user
            var user = await this.getRegisterUser(username, userId);
            var cred = user.createCredential();

            // save registration results
            cred.set("publicKey", result.authnrData.get("credentialPublicKeyPem"));
            cred.set("aaguid", result.authnrData.get("aaguid"));
            cred.set("credId", coerceToBase64(result.authnrData.get("credId")));
            cred.set("prevCounter", result.authnrData.get("counter"));
            await cred.commit();

            // log registration
            log.info("register success", {
                origin: result.expectations.get("origin"),
                username: username,
                flags: result.authnrData.get("flags"),
                audit: result.audit.complete,
                credId: coerceToBase64(result.authnrData.get("credId")),
                aaguid: coerceToBase64(result.authnrData.get("aaguid")) // TODO: log in hex
            });

            // send response
            var response = ServerResponse.from({
                status: "ok"
            });
            addDebugInfo(this, response, result);
            response.encodeBinaryProperties();
            response.validate();
            var msg = response.toString();
            log.debug("sending registration options:", msg);
            res.send(msg);
        } catch (err) {
            log.warn("registerResponse error", err);
            return sendErrorMessage(res, 400, "registration failed: " + err.message);
        }
    }

    async getRegisterUser(username, userId) {
        try {
            var users = await this.uds.findUsers({
                username: username
            });
            if (users.length > 1) {
                throw new Error("multiple users found with the username: " + username);
            }

            var user = users[0];

            // if no users found
            if (users.length === 0) {
                if (this.dangerousOpenRegistration) {
                    user = this.uds.createUser();
                    user.set("username", username);
                    user.set("userId", userId);
                // TODO: set displayName, userId, etc.
                } else {
                    throw new Error("user not found");
                }
            }

            await user.commit();

            return user;
        } catch (err) {
            log.warn("getRegisteredUser error", err);
            throw err;
        }
    }

    async loginRequest(req, res, next) {
        try {
            log.debug("loginRequest", req.body);
            var optReq = GetOptionsRequest.from(req.body);
            optReq.validate();
            optReq.decodeBinaryProperties();

            var username = optReq.username;

            // find user
            var users = await this.uds.findUsers({
                username: username
            });

            if (users.length !== 1) {
                throw new Error("error finding user: " + username);
            }

            // get credentials
            var user = users[0];
            var creds = await user.getCredentials();

            if (creds.length < 1) {
                throw new Error("no credentials available");
            }

            // create challenge
            var {
                challenge
            } = await this.fido2lib.assertionOptions();

            // form response message
            var response = new GetOptions();
            response.challenge = challenge;
            response.timeout = this.timeout;
            // send credIds available for login
            response.allowCredentials = creds.map((cred) => ({
                id: cred.get("credId"),
                type: "public-key",
                // transports: ["usb", "nfc", "ble"]
            }));
            response.status = "ok";

            // save challenge to session; set loginPending flag;
            req.session.loginChallenge = coerceToBase64(challenge);
            req.session.loginChallengeTime = Date.now();
            req.session.username = username;
            req.session.userId = user.get("userId");

            // send response
            response.encodeBinaryProperties();
            response.validate();
            var msg = response.toString();
            log.debug("sending login options:", msg);
            res.send(msg);
        } catch (err) {
            log.warn("loginRequest error", err);
            return sendErrorMessage(res, 400, "login failed: " + err.message);
        }
    }

    async loginResponse(req, res, next) {
        try {
            log.debug("loginResponse", req.body);
            var assn = CredentialAssertion.from(req.body);
            assn.validate();
            assn.decodeBinaryProperties();

            // check session information
            if (!req.session ||
                typeof req.session.username !== "string" ||
                typeof req.session.userId !== "string" ||
                typeof req.session.loginChallengeTime !== "number" ||
                typeof req.session.loginChallenge !== "string") {
                throw new Error("Could not find session information. Are cookies disabled?");
            }
            req.session.loginChallenge = coerceToArrayBuffer(req.session.loginChallenge, "session.loginChallenge");
            var username = req.session.username;
            var userId = req.session.userId;

            // check timeout
            if (Date.now() >= req.session.loginChallengeTime + this.timeout) {
                throw new Error("login request timed out");
            }

            // find user
            var users = await this.uds.findUsers({
                username: username
            });

            if (users.length !== 1) {
                throw new Error("error finding user: " + username);
            }

            // find credential by credential ID
            var user = users[0];
            var creds = await user.getCredentials({
                credId: coerceToBase64(assn.rawId)
            });

            if (creds.length !== 1) {
                throw new Error("error finding credential ID: " + coerceToBase64(assn.rawId));
            }

            var cred = creds[0];

            // set assertion expectations
            var assertionExpectations = {
                challenge: req.session.loginChallenge,
                origin: this.origin,
                factor: "either",
                publicKey: cred.get("publicKey"),
                prevCounter: cred.get("prevCounter"),
                userHandle: userId
            };

            // do the real work
            var result = await this.fido2lib.assertionResult(assn, assertionExpectations);

            // save new counter
            cred.set("prevCounter", result.authnrData.get("counter"));
            await cred.commit();

            // regenerate cookie
            await new Promise((resolve, reject) => {
                req.session.regenerate((err) => {
                    if (err) return reject(err);
                    resolve();
                });
            });

            // log useful info
            log.info("login success", {
                origin: result.expectations.get("origin"),
                username: username,
                flags: result.authnrData.get("flags"),
                audit: result.audit.complete,
                credId: coerceToBase64(assn.rawId)
            });

            // send success response
            var response = ServerResponse.from({
                status: "ok"
            });

            addDebugInfo(this, response, result);

            response.validate();
            response.encodeBinaryProperties();
            var msg = response.toObject();
            res.send(JSON.stringify(msg));
        } catch (err) {
            log.warn("loginResponse error", err);
            return sendErrorMessage(res, 400, "login failed: " + err.message);
        }
    }

    setRegisterRequest(opts) {
        updateEndpoint(this, "registerRequest", opts);
    }

    setRegisterResponse(opts) {
        updateEndpoint(this, "registerResponse", opts);
    }

    setLoginRequest(opts) {
        updateEndpoint(this, "loginRequest", opts);
    }

    setLoginResponse(opts) {
        updateEndpoint(this, "loginResponse", opts);
    }

    shutdown() {
        // log.debug("Shutting down Fido2Component.");
    }
};

function addDebugInfo(ctx, response, result) {
    if (!ctx.dangerousXmitDebugInfo) return;

    response.debugInfo = {
        clientData: {},
        authnrData: {},
        audit: {}
    };

    result.clientData.forEach((v, k) => {
        response.debugInfo.clientData[k] = v;
    });

    result.authnrData.forEach((v, k) => {
        response.debugInfo.authnrData[k] = v;
    });

    response.debugInfo.audit.validExpectations = result.audit.validExpectations;
    response.debugInfo.audit.validRequest = result.audit.validRequest;
    response.debugInfo.audit.complete = result.audit.complete;
    response.debugInfo.audit.warning = result.audit.warning;
    response.debugInfo.audit.info = result.audit.info;
}

function validInput(res, obj, prop, type) {
    if (typeof obj[prop] !== type) {
        let errStr = `bad '${prop}': expected type '${type}', got type ${typeof obj[prop]}`;
        sendErrorMessage(res, 400, errStr);
        return false;
    }

    return true;
}

function sendErrorMessage(res, status, msg) {
    log.warn(`HTTP ${status}: ${msg}`);
    var errMsg = ServerResponse.from({
        status: "failed",
        errorMessage: msg
    });
    errMsg.validate();
    errMsg.encodeBinaryProperties();

    res.status(status).send(errMsg.toString());
}

function updateEndpoint(ctx, type, opts) {
    if (typeof opts !== "object") {
        throw new TypeError("expected 'opts' to be object");
    }

    if (typeof opts.path !== "undefined" &&
        typeof opts.path !== "string") {
        throw new TypeError("expect 'path' to be undefined or string, got " + typeof opts.path);
    }

    if (typeof opts.method !== "undefined" &&
        typeof opts.method !== "string") {
        throw new TypeError("expect 'method' to be undefined or string, got " + typeof opts.path);
    }
    // method types (GET, POST, HEAD, PUT, etc) are assumed to be checked by the component that implements them

    if (typeof opts.cb !== "undefined" &&
        typeof opts.cb !== "function") {
        throw new TypeError("expect 'cb' to be undefined or function, got " + typeof opts.path);
    }

    if (opts.path) ctx[type + "Route"] = opts.path;
    if (opts.method) ctx[type + "Method"] = opts.method;
    if (opts.cb) ctx[type + "Cb"] = opts.cb.bind(ctx);
}

function coerceToBase64(thing, name) {
    // Array to Uint8Array
    if (Array.isArray(thing)) {
        thing = Uint8Array.from(thing);
    }

    // Uint8Array, etc. to ArrayBuffer
    if (thing.buffer instanceof ArrayBuffer && !(thing instanceof Buffer)) {
        thing = thing.buffer;
    }

    // ArrayBuffer to Buffer
    if (thing instanceof ArrayBuffer && !(thing instanceof Buffer)) {
        thing = new Buffer(thing);
    }

    // Buffer to base64 string
    if (thing instanceof Buffer) {
        thing = thing.toString("base64");
    }

    if (typeof thing !== "string") {
        throw new Error(`couldn't coerce '${name}' to string`);
    }

    // base64 to base64url
    // NOTE: "=" at the end of challenge is optional, strip it off here so that it's compatible with client
    // thing = thing.replace(/\+/g, "-").replace(/\//g, "_").replace(/=*$/g, "");

    return thing;
}

function coerceToArrayBuffer(buf, name) {
    if (typeof buf === "string") {
        // base64url to base64
        buf = buf.replace(/-/g, "+").replace(/_/g, "/");
        // base64 to Buffer
        buf = Buffer.from(buf, "base64");
    }

    if (buf instanceof Buffer || Array.isArray(buf)) {
        buf = new Uint8Array(buf);
    }

    if (buf instanceof Uint8Array) {
        buf = buf.buffer;
    }

    if (!(buf instanceof ArrayBuffer)) {
        throw new TypeError(`could not coerce '${name}' to ArrayBuffer`);
    }

    return buf;
}

function printHex(msg, buf) {
    // if the buffer was a TypedArray (e.g. Uint8Array), grab its buffer and use that
    if (ArrayBuffer.isView(buf) && buf.buffer instanceof ArrayBuffer) {
        buf = buf.buffer;
    }

    // check the arguments
    if ((typeof msg != "string") ||
        (typeof buf != "object")) {
        console.log("Bad args to printHex");
        return;
    }
    if (!(buf instanceof ArrayBuffer)) {
        console.log("Attempted printHex with non-ArrayBuffer:", buf);
        return;
    }

    // print the buffer as a 16 byte long hex string
    var arr = new Uint8Array(buf);
    var len = buf.byteLength;
    var i, str = "";
    console.log(msg, `(${buf.byteLength} bytes)`);
    for (i = 0; i < len; i++) {
        var hexch = arr[i].toString(16);
        hexch = (hexch.length == 1) ? ("0" + hexch) : hexch;
        str += hexch.toUpperCase() + " ";
        if (i && !((i + 1) % 16)) {
            console.log(str);
            str = "";
        }
    }
    // print the remaining bytes
    if ((i) % 16) {
        console.log(str);
    }
}
