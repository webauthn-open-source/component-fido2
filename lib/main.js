var Component = require("component-class");
var log;

module.exports = class Fido2Component extends Component {
    constructor(cm) {
        super(cm);

        this.configTable["config-option"] = this.configOption;
    }

    dependencies() {
        return [
            "logger",
            "external-module-name"
        ];
    }

    init() {
        var logger = this.cm.get("logger");
        if (logger === undefined) {
            throw new Error("logger component not found");
        }
        log = logger.create("Fido2Component");

        log.debug ("Starting Fido2Component ...");
    }

    shutdown() {
        log.debug ("Shutting down Fido2Component.");
    }

    configOption(opts) {
        log.debug ("Setting option to: ", opts);
    }
};