/*\
created: 20210723152326655
type: application/javascript
title: $:/plugins/security_tools/twsm/twsm_trees.js
tags: 
modified: 20220723070445305
module-type: filteroperator
\*/

(function(){

"use strict";

var shlex = require("$:/plugins/security_tools/twsm/shlex.js");

function indentToBullet(indent) {
    return (new Array(indent + 1).join("*")) + " ";
}

function lstrip(x, characters) {
    var start = 0;
    while (characters.indexOf(x[start]) >= 0) {
        start += 1;
    }
    var end = x.length - 1;
    return x.substr(start);
}

function eatWhiteSpace(x) {
    return lstrip(x, " \t");
}

class AttackTreeSyntaxError extends Error {
    constructor(message) {
        super(message);
    }
}

function parseMacro(line) {
    var result = [];
    if ((line.slice(0,2) !== "<<") || (line.slice(-2) !== ">>")) {
        return result;
    }
    try {
        return shlex.twsm_split(line.slice(2, -2));
    } catch (errorObj) {
        throw new AttackTreeSyntaxError(errorObj.message);
    }
}

var branchOperators = {
    "OR": function(children) {
        if (children.length == 0) {
            return 1.0;
        }
        var max = 0.0;
        for (let c of children) {
            max = Math.max(max, c.get_probability());
        }
        return max;
    },
    "AND": function(children) {
        var running = 1.0;
        for (let c of children) {
            running = running * c.get_probability();
        }
        return running;
    }
}

const likelihood_calibration = [
    {
        band: [0.0, 0.075],
        names: ["remote chance", "rc"],
        title: "Remote Chance",
    }, {
        band: [0.075, 0.225],
        names: ["highly unlikely", "hu"],
        title: "Highly Unlikely",
    }, {
        band: [0.225, 0.375],
        names: ["unlikely", "u"],
        title: "Unlikely",
    }, {
        band: [0.375, 0.525],
        names: ["realistic possibility", "rp"],
        title: "Realistic Possibility",
    }, {
        band: [0.525, 0.775],
        names: ["likely", "l"],
        title: "Likely",
    }, {
        band: [0.775, 0.925],
        names: ["highly likely", "hl"],
        title: "Highly Likely",
    }, {
        band: [0.925, 1],
        names: ["almost certain", "ac"],
        title: "Almost Certain",
    }
];

function phia2Probability(likelihood) {
    likelihood = likelihood.trim().toLowerCase();
    for (const b of likelihood_calibration) {
        if (b.names.includes(likelihood)) {
            // Return the upper
            return b.band[1];
        }
    }
    throw new AttackTreeSyntaxError("Unsupported PHIA likelihood (" + likelihood + ")");
}

function probability2Phia(probability) {
    var c = "Remote Chance";
    for (const b of likelihood_calibration) {
        if ((probability > b.band[0]) && (probability <= b.band[1])) {
            c = b.title;
            break;
        }
    }
    return c;
}

class Branch {
    constructor(parent, branchName, indent, operator="OR") {
        operator = operator.toUpperCase();
        var operatorFunction = branchOperators[operator];
        if (!operatorFunction) {
            throw new AttackTreeSyntaxError("Unsupported operator (" + operator + ")");
        }

        this.parent = parent;
        this.branchName = branchName;
        this.operator = operator;
        this.operatorFunction = operatorFunction;
        this.indent = indent;
        this.children = [];
        this._probability = null;
        this._phia = null;
    }

    get_phia() {
        if (this._phia === null) {
            this._phia = probability2Phia(this.get_probability());
        }
        return this._phia;
    }

    render() {
        var lines = [];
        lines.push(indentToBullet(this.indent + 1) + "<<rendered_branch \"" + this.branchName + "\" " + this.operator + " " + this.get_probability() + " \"" + this.get_phia() + "\">>");
        for (let c of this.children) {
            lines.push(...c.render());
        }
        return lines;
    }

    console_log() {
        console.log("Branch: (" + this.indent + "): " + this.branchName);
        for (let c of this.children) {
            // console.log("Child: " + JSON.stringify(c));
            c.console_log();
        }
    }

    get_probability() {
        if (this._probability === null) {
            this._probability = this.operatorFunction(this.children);
        }
        return this._probability;
    }
}

class Leaf {
    constructor(parent, leafName, indent, probability="almost certain") {
        this.parent = parent;
        this.leafName = leafName;
        this.indent = indent;
        this._probability = phia2Probability(probability);
        this._phia = null;
    }

    get_phia() {
        if (this._phia === null) {
            this._phia = probability2Phia(this.get_probability());
        }
        return this._phia;
    }

    render() {
        var lines = [];
        lines.push(indentToBullet(this.indent + 1) + "<<rendered_leaf \"" + this.leafName + "\" " + this.get_probability() + " \"" + this.get_phia() + "\">>");
        return lines;
    }
    
    console_log() {
        console.log("Leaf (" + this.indent + "): " + this.leafName);
    }
    get_probability() {
        return this._probability;
    }
}


class Control {
    constructor(parent, controlName, indent) {
        if (!is_control(controlName)) {
            throw new AttackTreeSyntaxError("Not a control!");
        }
        this.parent = parent;
        this.controlName = controlName;
        this.indent = indent;
        this.probability = phia2Probability(get_control_failure_likelihood(controlName));
        this.phia = probability2Phia(this.probability);
    }

    get_phia() {
        return this.phia;
    }

    render() {
        var lines = [];
        lines.push(indentToBullet(this.indent + 1) + "<<rendered_control \"" + this.controlName + "\" " + this.get_probability() + " \"" + this.get_phia() + "\">>");
        return lines;
    }

    console_log() {
        console.log("Control (" + this.indent + "): " + this.controlName);
    }
    get_probability() {
        return this.probability;
    }
}


class Ref {
    constructor(parent, refName, indent) {
        if (!is_ref(refName)) {
            throw new AttackTreeSyntaxError("Not a ref!");
        }
        this.parent = parent;
        this.refName = refName;
        this.indent = indent;
        this._probability = 0.25;
        this._phia = null
    }

    get_phia() {
        if (this._phia === null) {
            this._phia = probability2Phia(this.get_probability());
        }
        return this._phia;
    }

    render() {
        var lines = [];
        var l = indentToBullet(this.indent + 1) + "<<rendered_ref \"" + this.refName + "\" " + this.get_probability() + " \"" + this.get_phia() + "\">>";
        lines.push(l);
        return lines;
    }

    console_log() {
        console.log("Ref (" + this.indent + "): " + this.refName);
    }
    get_probability() {
        return this._probability;
    }
}


function tw_filter_to_bool(filter) {
    // console.log(filter);
    return $tw.wiki.filterTiddlers(filter)[0] === "True";
}

function is_control(controlTitle) {
    return tw_filter_to_bool(
        "[title[" + controlTitle + "]twsm_class[control]then[True]else[False]]"
    )
}

function get_control_failure_likelihood(controlTitle) {
    return $tw.wiki.filterTiddlers(
        "[title[" + controlTitle + "]get[failure_likelihood]else[Almost Certain]]"
    )[0];
}


function is_ref(refTitle) {
    return tw_filter_to_bool(
        "[title[" + refTitle + "]twsm_class[attack_tree]then[True]else[False]]"
    )
}

function parse_attack_tree(attack_tree) {

    var controls = [];
    var attack_sub_trees = [];
    var root = new Branch(null, "Root", 0);
    var currentBranch = root;

    var ops = {
        "branch": function(indent, args) {
            var branchName = args[0];
            var operator = args[1];
            var branch = new Branch(currentBranch, branchName, indent, operator);
            console.log("B: " + branch);
            currentBranch.children.push(branch);
            currentBranch = branch;
        },
        "leaf": function(indent, args) {
            var leafName = args[0];
            var probability = args[1];
            var leaf = new Leaf(currentBranch, leafName, indent, probability);
            currentBranch.children.push(leaf);
        },
        "control": function(indent, args) {
            var controlName = args[0];
            var control = new Control(currentBranch, controlName, indent);
            currentBranch.children.push(control);
            controls.push(controlName);
        },
        "ref": function(indent, args) {
            var refName = args[0];
            var ref = new Ref(currentBranch, refName, indent);
            currentBranch.children.push(ref);
            attack_sub_trees.push(refName);
        }
    }

    var lines = attack_tree.split('\n');
    var error = "";
    var lineNo = 1;
    for (let l of lines) {
        try {
            var t = lstrip(l, "*")
            var indent = l.length - t.length;
            if ((!indent) && (t.trim().length > 0)) {
                throw new AttackTreeSyntaxError("Line doesn't start with a '*'!");
            }
            if (indent) {
                if (indent > (currentBranch.indent + 1)) {
                    throw new AttackTreeSyntaxError("Branch children too indented!");
                }

                // Walk back up the tree finding the correct parent.
                while (indent > (currentBranch.indent + 1)) {
                    currentBranch = currentBranch.parent;
                }
                var macroArgs = parseMacro(t.trim());
                if (macroArgs.length === 0) {
                    throw new AttackTreeSyntaxError("Missing macro prefix!");
                }
                var opFunc = ops[macroArgs[0]];
                if (!opFunc) {
                    throw new AttackTreeSyntaxError("Unsupported macro!");
                }
                if (opFunc) {
                    opFunc(indent, macroArgs.slice(1,));
                }
    
                // var prefix = new Array(indent + 1).join("*");
                // newLines.push(prefix + " Indent " + indent + " " + t + " ADDED");
            }
        } catch (objError) {
            if (objError instanceof AttackTreeSyntaxError) {
                throw(new AttackTreeSyntaxError("Syntax error (line " + lineNo + "): " + objError.message));
            } else {
                // result.push(JSON.stringify({
                //     "error": objError.message
                // }));
                throw(objError);
            }        
        }
        lineNo += 1;
    }
    var newLines = root.render();
    console.log(newLines);
    var joined = newLines.join('\n');

    var obj = {
        renderer: 1,
        attack_tree: joined,
        error: error,
        likelihood: root.get_probability(),
        controls: controls,
        sub_trees: attack_sub_trees, 
    }
    return obj;
}

exports.twsm_render_attack = function(source, operator, options) {
    var result = [];

    source (function(tiddler, title) {
        try {
            var obj = parse_attack_tree(title);
            if (obj) {
                result.push(JSON.stringify(obj));
            }
        } catch (objError) {
            if (objError instanceof AttackTreeSyntaxError) {
                result.push(JSON.stringify({
                    "error": objError.message
                }));
            } else {
                // result.push(JSON.stringify({
                //     "error-monke": objError.message
                // }));
                throw(objError);
            }        
        }
    })
    console.log(result);
    return result;
}

exports.twsmextractcontrols = function(source, operator, options) {
    var result = [];

    source (function(tiddler, title) {
        try  {
            var s = JSON.parse(title);
            if (s) {
                result.push(s.controls || "");
            }
        } catch (objError) {
            if (objError instanceof SyntaxError) {
                // Do nothing...
            } else {
                throw(objError);
            }
        }
    })
    return result;
}

exports.twsm_attack_tree_result = function(source, operator, options) {
    
    var suffixes = operator.suffixes || [],
        field = (suffixes[0] || [])[0],
        result = [];

    if (!field) {
        return result;
    }

    source (function(tiddler, title) {
        try  {
            var s = JSON.parse(title);
            if (s) {
                result.push(String(s[field] || ""));
            }
        } catch (objError) {
            if (objError instanceof SyntaxError) {
                // Do nothing...
            } else {
                throw(objError);
            }
        }
    })
    return result;
}



exports.twsmextractcomputedattacktree = function(source, operator, options) {
    var result = [];

    source (function(tiddler, title) {
        try  {
            var s = JSON.parse(title);
            if (s) {
                result.push(s.computed_attack_tree || "");
            }
        } catch (objError) {
            if (objError instanceof SyntaxError) {
                // Do nothing...
            } else {
                throw(objError);
            }
        }
    })
    return result;
}

exports.twsmextracterror = function(source, operator, options) {
    var result = [];

    source (function(tiddler, title) {
        try  {
            var s = JSON.parse(title);
            if (s && s.error) {
                result.push(s.error);
            }
        } catch (objError) {
            if (objError instanceof SyntaxError) {
                // Do nothing...
            } else {
                throw(objError);
            }
        }
    })
    return result;
}


})();
