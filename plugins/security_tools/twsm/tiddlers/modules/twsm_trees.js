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

function probability2Hue(probability) {
    // In HSV, 0 = Green, 120 = Red.
    const hue_start = 120
    const hue_end = 0
    
    return hue_start + ((hue_end - hue_start) * probability);
}

class Likelihood {
    /**
     * 
     * @param {number} lower 
     * @param {number} upper 
     */
    constructor(lower, upper, phia) {
        this.lower = lower;
        this.lowerHue = probability2Hue(lower);
        this.upper = upper;
        this.upperHue = probability2Hue(upper);
        if (upper === lower) {
            this.tooltip = (upper * 100).toFixed() + "%";
        } else {
            this.tooltip = (lower * 100).toFixed() + "% - " + (upper * 100).toFixed() + "%";
        }

        if (phia === undefined) {
            this.phia = probability2Phia(upper);
        } else {
            this.phia = phia;
        }
    }
}

const likelihood_calibration = [
    {
        band: new Likelihood(0.0, 0.075, "Remote Chance"),
        names: ["remote chance", "rc"],
    }, {
        band: new Likelihood(0.075, 0.225, "Highly Unlikely"),
        names: ["highly unlikely", "hu"],
    }, {
        band: new Likelihood(0.225, 0.375, "Unlikely"),
        names: ["unlikely", "u"],
    }, {
        band: new Likelihood(0.375, 0.525, "Realistic Possibility"),
        names: ["realistic possibility", "rp"],
    }, {
        band: new Likelihood(0.525, 0.775, "Likely"),
        names: ["likely", "l"],
    }, {
        band: new Likelihood(0.775, 0.925, "Highly Likely"),
        names: ["highly likely", "hl"],
    }, {
        band: new Likelihood(0.925, 1, "Almost Certain"),
        names: ["almost certain", "ac"],
    }
];


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


class ComplexLikelihood {
    /**
     * 
     * @param {Likelihood} untreated 
     * @param {Likelihood} treated 
     */
    constructor(untreated, treated) {
        this.untreated = untreated;
        this.treated = treated;
    }
}

const NULL_LIKELIHOOD = new Likelihood(1.0, 1.0);
const NULL_COMPLEX_LIKELIHOOD = new ComplexLikelihood(NULL_LIKELIHOOD, NULL_LIKELIHOOD);


var branchOperators = {
    "OR": function(children) {
        if (children.length == 0) {
            return NULL_COMPLEX_LIKELIHOOD;
        }
        var treatedMaxLower = 0.0, treatedMaxUpper = 0.0, untreatedMaxLower = 0.0, untreatedMaxUpper = 0.0;
        for (let c of children) {
            treatedMaxLower = Math.max(treatedMaxLower, c.likelihood.treated.lower);
            treatedMaxUpper = Math.max(treatedMaxUpper, c.likelihood.treated.upper);
            untreatedMaxLower = Math.max(untreatedMaxLower, c.likelihood.untreated.lower);
            untreatedMaxUpper = Math.max(untreatedMaxUpper, c.likelihood.untreated.upper);
        }
        return new ComplexLikelihood(new Likelihood(untreatedMaxLower, untreatedMaxUpper), new Likelihood(treatedMaxLower, treatedMaxUpper));
    },
    "AND": function(children) {
        var runningUntreatedLower = 1.0, runningUntreatedUpper = 1.0, runningTreatedLower = 1.0, runningTreatedUpper = 1.0;
        for (let c of children) {
            runningUntreatedLower = runningUntreatedLower * c.likelihood.untreated.lower;
            runningUntreatedUpper = runningUntreatedUpper * c.likelihood.untreated.upper;
            runningTreatedLower = runningTreatedLower * c.likelihood.treated.lower;
            runningTreatedUpper = runningTreatedUpper * c.likelihood.treated.upper;
        }
        return new ComplexLikelihood(new Likelihood(runningUntreatedLower, runningUntreatedUpper), new Likelihood(runningTreatedLower, runningTreatedUpper));
    }
}

/**
 * 
 * @param {String} likelihood 
 * @returns {Likelihood}
 */
function phia2Likelihood(phia) {
    phia = phia.trim().toLowerCase();
    for (const b of likelihood_calibration) {
        if (b.names.includes(phia)) {
            // Return the upper
            return b.band;
        }
    }
    throw new AttackTreeSyntaxError("Unsupported PHIA likelihood (" + phia + ")");
}

/**
 * 
 * @param {Number} probability 
 * @returns {String}
 */
function probability2Phia(probability) {
    var c = "Remote Chance";
    for (const b of likelihood_calibration) {
        if ((probability > b.band.lower) && (probability <= b.band.upper)) {
            c = b.band.phia;
            break;
        }
    }
    return c;
}



class Node {
    /**
     * 
     * @param {Node} parent 
     * @param {String} nodeName 
     * @param {Number} indent 
     */
    constructor(parent, nodeName, indent, renderedMacroName) {
        this.parent = parent;
        this.nodeName = nodeName;
        this.indent = indent;
        this.likelihood = undefined;
        this.rendered_macro_name = renderedMacroName;
        this.extra_render_args = [];
    }

    /**
     * 
     * @returns {ComplexLikelihood}
     */
    resolve() {
        return NULL_COMPLEX_LIKELIHOOD;
    }

    addLikelihoodToRenderArgs(likelihood) {
        this.extra_render_args.push(likelihood.lower);
        this.extra_render_args.push(likelihood.lowerHue);
        this.extra_render_args.push(likelihood.upper);
        this.extra_render_args.push(likelihood.upperHue);
        this.extra_render_args.push("\"" + likelihood.tooltip + "\"");
        this.extra_render_args.push("\"" + likelihood.phia + "\"");
    }

    render() {
        var s = [];
        s.push(indentToBullet(this.indent + 1));
        s.push("<<" + this.rendered_macro_name);
        s.push("\"" + this.nodeName + "\"");
        s.push(...this.extra_render_args);
        s.push(">>");
        return [s.join(" ")];
    }
}


class Branch extends Node {
    constructor(parent, nodeName, indent, operator="OR") {
        super(parent, nodeName, indent, "rendered_branch");

        // Handle any case for operator name resolution.
        operator = operator.toUpperCase();
        var operatorFunction = branchOperators[operator];
        if (!operatorFunction) {
            throw new AttackTreeSyntaxError("Unsupported operator (" + operator + ")");
        }

        this.operator = operator;
        this.operatorFunction = operatorFunction;
        this.children = [];
    }

    // Override resolve
    resolve() {
        // Recurse resolution down tree
        for (let c of this.children) {
            c.resolve();
        }
        this.likelihood = this.operatorFunction(this.children);
        this.addLikelihoodToRenderArgs(this.likelihood.untreated);
        this.addLikelihoodToRenderArgs(this.likelihood.treated);
        this.extra_render_args.push(this.operator);
    }

    // Override render
    render() {
        var lines = super.render();
        for (let c of this.children) {
            lines.push(...c.render());
        }
        return lines;
    }
}

class Leaf extends Node {
    constructor(parent, nodeName, indent, probability="almost certain") {
        super(parent, nodeName, indent, "rendered_leaf");
        var l = phia2Likelihood(probability);
        this.likelihood = new ComplexLikelihood(l, l);
        this.addLikelihoodToRenderArgs(this.likelihood.treated);
    }
}


class Control extends Node {
    constructor(parent, nodeName, indent) {
        super(parent, nodeName, indent, "rendered_control");
        if (!is_control(nodeName)) {
            throw new AttackTreeSyntaxError("Not a control!");
        }
        this.likelihood = new ComplexLikelihood(NULL_LIKELIHOOD, phia2Likelihood(get_control_failure_likelihood(nodeName)));
        this.addLikelihoodToRenderArgs(this.likelihood.treated);
    }
}


class Ref extends Node {
    constructor(parent, refName, indent) {
        super(parent, nodeName, indent, "rendered_ref");
        if (!is_ref(nodeName)) {
            throw new AttackTreeSyntaxError("Not a ref!");
        }
        // TODO: Calculate likelihood
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
    // Now that the tree structure is in place, resolve the likelihood calculation.
    root.resolve();

    var newLines = root.render();
    var joined = newLines.join('\n');

    var obj = {
        renderer: 1,
        attack_tree: joined,
        error: error,
        untreated_probability: root.likelihood.untreated.probability,
        untreated_phia: root.likelihood.untreated.phia,
        treated_probability: root.likelihood.treated.probability,
        treated_phia: root.likelihood.treated.phia,
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
