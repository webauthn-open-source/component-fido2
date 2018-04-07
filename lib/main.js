"use strict";

const Component = require("component-class");
const { Fido2Lib } = require("fido2-lib");
const { URL } = require("url");
var log;

module.exports = class Fido2Component extends Component {
    constructor(cm) {
        super(cm);

        // features
        this.addFeature("set-register-request", this.setRegisterRequest);
        this.addFeature("set-register-response", this.setRegisterResponse);
        this.addFeature("set-login-request", this.setLoginRequest);
        this.addFeature("set-login-response", this.setLoginResponse);

        // default routes
        this.setRegisterRequest({
            path: "/webauthn/register/challenge",
            method: "POST",
            cb: this.registerRequest
        });

        this.setRegisterResponse({
            path: "/webauthn/register/response",
            method: "POST",
            cb: this.registerResponse
        });

        this.setLoginRequest({
            path: "/webauthn/login/challenge",
            method: "POST",
            cb: this.loginRequest
        });

        this.setLoginResponse({
            path: "/webauthn/login/response",
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
        };
    }

    async registerRequest(req, res, next) {
        try {
            log.debug("registerRequest", req.body);
            var body = req.body || {};
            if (!validInput(res, body, "username", "string")) return;
            var username = body.username;

            // get user id
            // getAttestationChallenge
            // create credential record {pending, challenge, user id}

            // response fields:
            // serverDomain
            // serverName
            // serverIcon
            // userId
            // username
            // displayName
            // userIcon
            // algList
            // timeout

            var challenge = await this.fido2lib.createCredentialChallenge();
            // format challenge
            challenge.challenge = coerceToBase64(challenge.challenge);
            challenge.binaryEncoding = "base64";
            challenge.success = true;

            // save data to session
            req.session.username = username;
            req.session.registerChallenge = challenge.challenge;
            req.session.registerChallengeTime = Date.now();

            log.debug("sent register challenge");

            // send response
            res.send(JSON.stringify(challenge));
        } catch (err) {
            log.warn("registerRequest error", err);
            return sendErrorMessage(res, 400, "error getting attestation challenge: " + err.message);
        }
    }

    async registerResponse(req, res, next) {
        try {
            log.debug("registerResponse", req.body);
            var body = req.body || {};
            if (!validInput(res, body, "username", "string")) return;
            if (!validInput(res, body, "id", "string")) return;
            if (!validInput(res, body, "response", "object")) return;
            if (!validInput(res, body.response, "clientDataJSON", "string")) return;
            if (!validInput(res, body.response, "attestationObject", "string")) return;
            if (!validInput(res, req.session, "registerChallenge", "string")) return;
            if (!validInput(res, req.session, "registerChallengeTime", "number")) return;
            if (!validInput(res, req.session, "username", "string")) return;

            body.response.clientDataJSON = coerceToArrayBuffer(body.response.clientDataJSON, "clientDataJSON");
            body.response.attestationObject = coerceToArrayBuffer(body.response.attestationObject, "attestationObject");
            var username = body.username;

            // wouldn't this be weird...?
            if (username !== req.session.username) {
                throw new Error("username changed");
            }

            // make sure timeout hasn't expired
            this.timeout = 30000; // TODO
            if (Date.now() >= req.session.registerChallengeTime + this.timeout) {
                throw new Error("register request timed out");
            }

            var challenge = req.session.registerChallenge;
            var result = await this.fido2lib.createCredentialResponse(body, challenge, this.origin, "either");

            var user = await this.getRegisterUser(username);
            var cred = user.createCredential();

            cred.set("publicKey", result.authnrData.get("credentialPublicKeyPem"));
            cred.set("aaguid", result.authnrData.get("aaguid"));
            cred.set("credId", coerceToBase64(result.authnrData.get("credId")));
            cred.set("prevCounter", result.authnrData.get("counter"));
            await cred.commit();

            var msg = {
                success: true
            };

            log.info("register success", {
                origin: result.expectations.get("origin"),
                username: username,
                flags: result.authnrData.get("flags"),
                audit: result.audit.complete,
                credId: coerceToBase64(result.authnrData.get("credId")),
                aaguid: coerceToBase64(result.authnrData.get("aaguid")) // TODO: log in hex
            });

            res.send(JSON.stringify(msg));
        } catch (err) {
            log.warn("registerResponse error", err);
            return sendErrorMessage(res, 400, "registration failed: " + err.message);
        }
    }

    async getRegisterUser(username) {
        try {
            this.allowCreateUser = true; // XXX, TODO
            var users = await this.uds.findUsers({
                username: username
            });
            if (users.length > 1) {
                throw new Error("multiple users found with the username: " + username);
            }

            var user = users[0];

            // if no users found
            if (users.length === 0) {
                if (this.allowCreateUser) {
                    user = this.uds.createUser();
                    user.set("username", username);
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
            // parse input
            log.debug("loginRequest", req.body);
            var body = req.body || {};
            if (!validInput(res, body, "username", "string")) return;
            var username = body.username;

            // find user
            this.allowCreateUser = true; // XXX, TODO
            var users = await this.uds.findUsers({
                username: username
            });

            if (users.length !== 1) {
                throw new Error("error finding user: " + username);
            }

            var user = users[0];
            var creds = await user.getCredentials();

            if (creds.length < 1) {
                throw new Error("no credentials available");
            }

            // create challenge
            var challenge = await this.fido2lib.getAssertionChallenge();

            // format challenge
            challenge.challenge = coerceToBase64(challenge.challenge);
            challenge.binaryEncoding = "base64";
            challenge.success = true;

            // send credIds available for login
            var credIdlist = creds.map((cred) => cred.get("credId"));
            challenge.credIdList = credIdlist;

            // TODO: save challenge to session; set loginPending flag;
            req.session.loginChallenge = challenge.challenge;
            req.session.loginChallengeTime = Date.now();
            req.session.username = username;

            log.debug("sent login challenge");

            // send response
            res.send(JSON.stringify(challenge));
        } catch (err) {
            log.warn("loginRequest error", err);
            return sendErrorMessage(res, 400, "login failed: " + err.message);
        }
    }

    async loginResponse(req, res, next) {
        try {
            log.debug("loginResponse", req.body);
            var body = req.body || {};
            if (!validInput(res, body, "username", "string")) return;
            if (!validInput(res, body, "id", "string")) return;
            if (!validInput(res, body, "response", "object")) return;
            if (!validInput(res, body.response, "clientDataJSON", "string")) return;
            if (!validInput(res, body.response, "authenticatorData", "string")) return;
            if (!validInput(res, body.response, "signature", "string")) return;
            if (!validInput(res, req.session, "loginChallenge", "string")) return;
            if (!validInput(res, req.session, "loginChallengeTime", "number")) return;
            if (!validInput(res, req.session, "username", "string")) return;

            // if (!validInput(res, body.response, "userHandle", "string")) return;

            body.response.clientDataJSON = coerceToArrayBuffer(body.response.clientDataJSON, "clientDataJSON");
            body.response.authenticatorData = coerceToArrayBuffer(body.response.authenticatorData, "authenticatorData");
            body.response.signature = coerceToArrayBuffer(body.response.signature, "signature");
            body.response.userHandle = (body.response.userHandle) ? coerceToArrayBuffer(body.response.userHandle, "userHandle") : body.response.userHandle;
            var username = body.username;

            // wouldn't this be weird...?
            if (username !== req.session.username) {
                throw new Error("username changed");
            }

            // make sure timeout hasn't expired
            this.timeout = 30000; // TODO
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
                credId: coerceToBase64(body.id)
            });

            if (creds.length !== 1) {
                console.log("BAD CRED LIST:", creds);
                throw new Error("error finding credential ID: " + body.id);
            }

            var cred = creds[0];

            var challenge = req.session.loginChallenge;
            var publicKey = cred.get("publicKey");
            var prevCounter = cred.get("prevCounter");
            var result = await this.fido2lib.getAssertionResponse(
                body,
                challenge,
                this.origin,
                "either",
                publicKey,
                prevCounter
            );

            // save new counter
            cred.set("prevCounter", result.authnrData.get("counter"));
            await cred.commit();

            await new Promise((resolve, reject) => {
                req.session.regenerate((err) => {
                    if (err) return reject(err);
                    resolve();
                });
            });

            var msg = {
                success: true
            };

            log.info("login success", {
                origin: result.expectations.get("origin"),
                username: username,
                flags: result.authnrData.get("flags"),
                audit: result.audit.complete,
                credId: coerceToBase64(body.id)
            });

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
    var jsonMsg = {
        success: false,
        errorMsg: msg
    };

    res.status(status).send(jsonMsg);
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
