"use strict";

var turnOnDebugLogging = true;
var Component = require("component-class");

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

var internalLogger = dummyLogger.create();

function enableDebugLogging(bool) {
    turnOnDebugLogging = bool;
}

class MockTableClass {
    set(prop) {
        internalLogger.debug("MockTableClass.set");
        this[prop] = prop;
    }

    get(prop) {
        internalLogger.debug("MockTableClass.get");
        return this[prop];
    }

    commit() {
        internalLogger.debug("MockTableClass.commit");
    }

    createSchema() {
        internalLogger.debug("MockTableClass.createSchema");
    }

    initialize() {
        internalLogger.debug("MockTableClass.initialize");
    }

    delete() {
        internalLogger.debug("MockTableClass.delete");
    }

    getJournal() {
        internalLogger.debug("MockTableClass.getJournal");
        return {};
    }
}

class MockUser extends MockTableClass {
    createCredential() {
        internalLogger.debug("MockUser.createCredential");
        return new MockUser();
    }

    getCredentials() {
        internalLogger.debug("MockUser.getCredentials");
        return Promise.resolve([]);
    }

    commit() {
        internalLogger.debug("MockUser.commit");
        return Promise.resolve();
    }

    destroy() {
        internalLogger.debug("MockUser.destroy");
        return Promise.resolve();
    }
}

class MockCred extends MockTableClass {
    commit() {
        internalLogger.debug("MockCred.commit");
        return Promise.resolve();
    }

    destroy() {
        internalLogger.debug("MockCred.destroy");
        return Promise.resolve();
    }
}

class MockUds extends Component {
    createUser() {
        internalLogger.debug("MockUds.createUser");
        return new MockUser();
    }

    findUsers() {
        internalLogger.debug("MockUds.findUsers");
        return Promise.resolve([]);
    }

    saveUser() {
        internalLogger.debug("MockUds.saveUser");
        return Promise.resolve();
    }

    destroyUser() {
        internalLogger.debug("MockUds.destroyUser");
        return Promise.resolve();
    }

    findCredentials() {
        internalLogger.debug("MockUds.findCredentials");
        return Promise.resolve([]);
    }

    createCredential() {
        internalLogger.debug("MockUds.createCredential");
        return new MockCred();
    }

    saveCredential() {
        internalLogger.debug("MockUds.saveCredential");
        return Promise.resolve();
    }

    destroyCredential() {
        internalLogger.debug("MockUds.destroyCredential");
        return Promise.resolve();
    }
}

var dummyUds = new MockUds(dummyComponentManager);

var goodDummyUser = new MockUser();
goodDummyUser.username = "bubba";
goodDummyUser.displayName = "bubba";

var goodDummyCred = new MockCred();
goodDummyCred.publicKey = "PUBLIC KEY";
goodDummyCred.aaguid = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
goodDummyCred.credId = "AAAAAAAA";
goodDummyCred.prevCounter = 0;

module.exports = {
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
};
