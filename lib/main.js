var Component = require("component-class");
const { Fido2Lib } = require("fido2-lib");
var log;

module.exports = class Fido2Component extends Component {
    constructor(cm) {
        super(cm);

        // features
        this.configTable["set-server-domain"] = this.setServerDomain;
        this.configTable["get-server-domain"] = this.getServerDomain;
        this.configTable["set-server-name"] = this.setServerName;
        this.configTable["get-server-name"] = this.getServerName;
        this.configTable["set-register-request"] = this.setRegisterRequest;
        this.configTable["set-register-response"] = this.setRegisterResponse;
        this.configTable["set-login-request"] = this.setLoginRequest;
        this.configTable["set-login-response"] = this.setLoginResponse;

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

        // check config
        if (!this.serverDomain) {
            throw new TypeError("server domain not set");
        }

        // configure user data store
        this.uds = this.cm.get("uds");

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
        this.origin = `${protocol}://${domain}:${port}`;
    }

    getConfig() {
        // TODO: timeout
        // TODO: challenge size
        // TODO: exclude list
        // TODO: crypto prefs
        return {
            serverDomain: this.serverDomain
        };
    }

    setServerDomain(serverDomain) {
        if (typeof serverDomain !== "string") {
            throw new TypeError("expected 'serverDomain' to be string, got " + typeof serverName);
        }

        this.serverDomain = serverDomain;
    }

    getServerDomain() {
        return this.serverDomain;
    }

    setServerName(serverName) {
        if (typeof serverName !== "string") {
            throw new TypeError("expected 'serverName' to be string, got " + typeof serverName);
        }

        this.serverName = serverName;
    }

    getServerName() {
        return this.serverName;
    }

    async registerRequest(req, res, next) {
        try {
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

            var uds = this.cm.get("uds");
            this.allowCreateUser = true; // XXX, TODO
            var users = await uds.findUsers({
                username: username
            });
            if (users.length > 1) {
                throw new Error("multiple users found with the username: " + username);
            }

            var user = users[0];

            // if no users found
            if (users.length === 0) {
                if (this.allowCreateUser) {
                    user = uds.createUser();
                    user.set("username", username);
                    // TODO: set displayName, userId, etc.
                } else {
                    throw new Error("user not found");
                }
            }

            var challenge = await this.fido2lib.createCredentialChallenge();
            // format challenge
            challenge.challenge = coerceToBase64(challenge.challenge);
            challenge.binaryEncoding = "base64";
            challenge.success = true;

            // create credential
            var cred = uds.createCredential(user);
            cred.set("challenge", challenge.challenge);
            cred.set("registerChallengePending", true);
            cred.set("registerTime", Date.now());
            cred.set("username", user.get("username"));

            req.session.username = username;
            req.session.registerChallenge = challenge.challenge;
            req.session.registerChallengeTime = Date.now();

            console.log("<<< REQUEST SESSION:", req.session);

            // save credential
            await cred.commit();
            // save user
            await user.commit();
            // send response
            res.send(JSON.stringify(challenge));
        } catch (err) {
            log.warn(err.toString());
            return sendErrorMessage(res, 500, "error getting attestation challenge: " + err);
        }
    }

    async registerResponse(req, res, next) {
        try {
            var body = req.body || {};
            if (!validInput(res, body, "username", "string")) return;
            if (!validInput(res, body, "id", "string")) return;
            if (!validInput(res, body, "response", "object")) return;
            if (!validInput(res, body.response, "clientDataJSON", "string")) return;
            if (!validInput(res, body.response, "attestationObject", "string")) return;

            body.response.clientDataJSON = coerceToArrayBuffer(body.response.clientDataJSON, "clientDataJSON");
            body.response.attestationObject = coerceToArrayBuffer(body.response.attestationObject, "attestationObject");
            var username = body.username;
            var user;

            console.log(">>> RESPONSE SESSION:", req.session);

            var uds = this.cm.get("uds");
            var users = await uds.findUsers({
                username: username
            });

            if (users.length != 1) {
                throw new Error("error finding user: " + username);
            }

            user = users[0];

            var creds = await user.getCredentials();

            // TODO: refactor into cleanPendingCredentials()
            // find pending credentials
            creds = creds.filter((cred) => {
                return cred.get("registerChallengePending") === true;
            });

            // destroy old pending credentials
            var destroyList = [];
            var now = Date.now();
            var timeout = 30000; // TODO: get from config
            // TODO: collapse with other filter statement
            creds = creds.filter((cred) => {
                let regTime = cred.get("registerTime");
                if ((regTime + timeout) < now) {
                    destroyList.push(cred.destroy());
                    return false;
                }
                return true;
            });
            await Promise.all(destroyList);

            if (creds.length < 1) {
                throw new Error("no pending registration credentials found for user: " + username);
            }

            // TODO: session management

            var cred = creds[0];
            var challenge = coerceToArrayBuffer(cred.get("challenge"), "challenge");
            var result = await this.fido2lib.createCredentialResponse(body, challenge, this.origin, "either");

            // TODO: store publicKey, credential id, aaguid
            cred.set("publicKey", result.authnrData.get("credentialPublicKeyPem"));
            cred.set("aaguid", result.authnrData.get("aaguid"));
            cred.set("credId", coerceToBase64(result.authnrData.get("credId")));
            cred.set("counter", result.authnrData.get("counter"));
            cred.delete("registerChallengePending");
            await cred.commit();
            // printHex("rawId", body.rawId);
            printHex("credId", result.authnrData.get("credId"));

            var msg = {
                success: true
            };
            res.send(JSON.stringify(msg));
        } catch (err) {
            log.debug("ERROR", err);
            return sendErrorMessage(res, 400, "registration failed: " + err);
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
            var uds = this.cm.get("uds");
            this.allowCreateUser = true; // XXX, TODO
            var users = await uds.findUsers({
                username: username
            });

            if (users.length !== 1) {
                throw new Error("error finding user: " + username);
            }

            var user = users[0];
            var creds = await user.getCredentials();
            console.log("creds", creds);
            // TODO: cleanup creds
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

            // send response
            res.send(JSON.stringify(challenge));
        } catch (err) {
            log.debug("ERROR", err);
            return sendErrorMessage(res, 400, "login failed: " + err);
        }
    }

    loginResponse(req, res, next) {
        try {
            log.debug("loginResponse", req.body);
            // TODO: req.session.regenerate
        } catch (err) {
            log.debug("ERROR", err);
            return sendErrorMessage(res, 400, "login failed: " + err);
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
    console.log("coercing:", buf);

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