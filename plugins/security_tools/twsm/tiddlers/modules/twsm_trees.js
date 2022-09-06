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
    return new Array(indent + 1).join("*");
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
    return shlex.twsm_split(line.slice(2, -2));
}

var branchOperators = {
    "OR": function() {

    },
    "AND": function() {

    }
}

class Branch {
    constructor(parent, branchName, indent, operator="OR") {
        var operatorFunction = branchOperators[operator];
        if (!operatorFunction) {
            throw new AttackTreeSyntaxError("Unsupported operator (" + operator + ")");
        }

        this.parent = parent;
        this.branchName = branchName;
        this.operator = operator;
        this.indent = indent;
        this.children = [];
    }

    console_log() {
        console.log("Branch: (" + this.indent + "): " + this.branchName);
        for (let c of this.children) {
            // console.log("Child: " + JSON.stringify(c));
            c.console_log();
        }
    }
}

class Leaf {
    constructor(parent, leafName, indent, probability="almost certain") {
        this.parent = parent;
        this.leafName = leafName;
        this.indent = indent;
        this.probability = probability;
    }

    console_log() {
        console.log("Leaf (" + this.indent + "): " + this.leafName);
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
    }
    console_log() {
        console.log("Control (" + this.indent + "): " + this.controlName);
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
    }
    console_log() {
        console.log("Ref (" + this.indent + "): " + this.refName);
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

function is_ref(refTitle) {
    return tw_filter_to_bool(
        "[title[" + refTitle + "]twsm_class[attack_tree]then[True]else[False]]"
    )
}

function parse_attack_tree(tiddler, title) {
    if (!tiddler) {
        return;
    }
    if (tiddler.fields.twsm_class !== "risk") {
        return;
    }

    if (!tiddler.fields.attack_tree) {
        return;
    }

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

            return indentToBullet(indent) + "BRANCH '" + branchName + "' - " + operator;
        },
        "leaf": function(indent, args) {
            var leafName = args[0];
            var probability = args[1];
            var leaf = new Leaf(currentBranch, leafName, indent, probability);
            currentBranch.children.push(leaf);
            return indentToBullet(indent) + "LEAF " + args;
        },
        "control": function(indent, args) {
            var controlName = args[0];
            var control = new Control(currentBranch, controlName, indent);
            currentBranch.children.push(control);
            controls.push(controlName);
            return indentToBullet(indent) + "CONTROL " + args;
        },
        "ref": function(indent, args) {
            var refName = args[0];
            var ref = new Ref(currentBranch, refName, indent);
            currentBranch.children.push(ref);
            attack_sub_trees.push(refName);
            return indentToBullet(indent) + "REF " + args;
        }
    }

    var lines = tiddler.fields.attack_tree.split('\n');
    var newLines = [];
    var error = "";
    var lineNo = 1;
    for (let l of lines) {
        try {
            var t = lstrip(l, "*")
            var indent = l.length - t.length;
            if (!indent) {
                throw new AttackTreeSyntaxError("Line doesn't start with a '*'!");
            }
            if (indent) {
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
                    var r = opFunc(indent, macroArgs.slice(1,));
                    if (r) {
                        newLines.push(r);
                    }
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
    root.console_log();
    var joined = newLines.join('\n');
    console.log("Joined: " + joined);
    // if (error) {
    //     joined = error;
    // }

    var obj = {
        computed_attack_tree: joined,
        error: error,
        likelihood: "0.245",
        controls: controls,
        attack_sub_trees: attack_sub_trees, 
    }
    return obj;
}

exports.twsmprocesstree = function(source, operator, options) {
    var result = [];

    source (function(tiddler, title) {
        try {
            var obj = parse_attack_tree(tiddler, title);
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


})();
