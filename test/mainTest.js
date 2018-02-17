var turnOnDebugLogging = false;

var Fido2Component = require ("../index.js");
var assert = require ("chai").assert;

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
                    if(turnOnDebugLogging) console.log(...msg);
                };
            },
        });
    }
};

describe ("cert tests", function() {
    var c;
    beforeEach(function() {
        c = new Fido2Component(dummyComponentManager);
    });

    afterEach(function() {
        c.shutdown();
    });

    it("can be initialized", function() {
        var ret = c.init();
        assert.isUndefined(ret);
    });
});