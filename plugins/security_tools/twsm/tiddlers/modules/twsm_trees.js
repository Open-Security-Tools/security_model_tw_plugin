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

function AttackTreeSyntaxError(message) {
    const error = new Error(message);
    return error;
}

AttackTreeSyntaxError.prototype = Object.create(Error.prototype);


function parseMacro(line) {
    var result = [];
    if ((line.slice(0,2) !== "<<") || (line.slice(-2) !== ">>")) {
        return result;
    }
    return shlex.twsm_split(line.slice(2, -2));
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

    var branchOperators = {
        "OR": function() {

        },
        "AND": function() {

        }
    }

    var ops = {
        "branch": function(indent, args) {
            var branchName = args[0];
            console.log("Args 1: " + args[1]);
            var operatorFunction = branchOperators[args[1] || "OR"];
            console.log("Operator function: " + operatorFunction);
            if (!operatorFunction) {
                throw new AttackTreeSyntaxError("Unsupported operator (" + args[1] + ")");
            }
            var operator = args[1] || "OR";
            return indentToBullet(indent) + "BRANCH '" + branchName + "' - " + operator;
        },
        "leaf": function(indent, args) {
            return indentToBullet(indent) + "LEAF" + args;
        },
        "control": function(indent, args) {
            return indentToBullet(indent) + "CONTROL" + args;
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
            if (indent) {
                var macroArgs = parseMacro(t.trim());
                console.log("macroArgs: " + macroArgs);
                var opFunc = ops[macroArgs[0]];
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
    var joined = newLines.join('\n');
    console.log("Joined: " + joined);
    // if (error) {
    //     joined = error;
    // }

    var obj = {
        computed_attack_tree: joined,
        error: error,
        likelihood: "0.245",
        controls: "[[Control1]] [[Control2]] [[Control3]]",
        attack_sub_trees: "[[Attack Sub Tree 1]] [[Attack Sub Tree 2]] [[Attack Sub Tree 3]]" 
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
                //     "error": objError.message
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
