var Component = require("component-class");
const {
    Fido2Lib
} = require("fido2-lib");
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

    registerRequest(req, res, next) {
        log.debug("registerRequestCb");
        var body = req.body;
        if (!validInput(res, body, "username", "string")) return;

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

        this.fido2lib.getAttestationChallenge()
            .then((challenge) => {
                //.toString("hex");
                console.log("challenge", challenge);
                challenge.challenge = challenge.challenge.toString('base64');
                challenge.binaryEncoding = "base64";
                challenge.success = true;
                res.send(JSON.stringify(challenge));
            })
            .catch((err) => {
                return sendErrorMessage(res, 500, "error getting attestation challenge: " + err);
            });
    }

    registerResponse(req, res, next) {
        log.debug("registerResponse:", req.body);
        var body = req.body;
        if (!validInput(res, body, "username", "string")) return;
        if (!validInput(res, body, "id", "string")) return;
        if (!validInput(res, body, "response", "object")) return;
        if (!validInput(res, body.response, "clientDataJSON", "object")) return;
        if (!validInput(res, body.response, "attestationObject", "object")) return;
    }

    loginRequest(req, res, next) {
        log.debug("loginRequest", req.body);
    }

    loginResponse(req, res, next) {
        log.debug("loginResponse", req.body);
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
    var jsonMsg = {
        success: false,
        errorMsg: msg
    };

    res.send(status).send(jsonMsg);
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