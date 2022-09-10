/*\
created: 20220722215603976
title: $:/plugins/security_tools/twsm/attack_utils.js
type: application/javascript
tags: 
modified: 20220723070445305
module-type: library
\*/

(function(){

"use strict";

var likelihood_utils = require("$:/plugins/security_tools/twsm/likelihood_utils.js");
var impact_utils = require("$:/plugins/security_tools/twsm/impact_utils.js")
var risk_utils = require("$:/plugins/security_tools/twsm/risk_utils.js")
var shlex = require("$:/plugins/security_tools/twsm/shlex.js")

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



class Node {
    /**
     * 
     * @param {Node} parent 
     * @param {String} nodeName 
     * @param {Number} indent
     * @param {String} pillClass
     * @param {String} pillIconClass
     */
    constructor(parent, nodeName, indent, pillClass, pillIconClass) {
        this.parent = parent;
        this.nodeName = nodeName;
        this.indent = indent;
        this.likelihood = new likelihood_utils.ComplexLikelihood(new likelihood_utils.Likelihood(0.0, 0.0), new likelihood_utils.Likelihood(0.0, 0.0));
        this.pillClass = pillClass;
        this.pillIconClass = pillIconClass;
        this.comments = [];
        this.criticalPath = false;
    }

    resolve() {}

    markCriticalPath() {
        this.criticalPath = true;
    }

    pillTextPreamble() {
        return "<i class=\"" + this.pillIconClass + "\"/> ";
    }

    description() {
        return this.nodeName;
    }

    render() {
        if (this.indent < 1) {
            return [];
        }
        var nodePillStyle = this.likelihood.treated.buildLikelihoodBackgroundStyle();
        var nodePillText = this.pillTextPreamble() + " · " + this.likelihood.treated.phia;
        var nodePillTooltip = "";
        if (this.likelihood.isControlled()) {
            nodePillText += " · " + this.likelihood.calculateControlProportion().toFixed() + "% mitigation";
            nodePillTooltip = "Treated band: " + this.likelihood.treated.toBandPercentageDescription() + ", Untreated band: " + this.likelihood.untreated.toBandPercentageDescription();
        } else {
            nodePillTooltip = "Likelihood band: " + this.likelihood.treated.toBandPercentageDescription();
        }
        var criticalPathClass = "";
        if (this.criticalPath) {
            criticalPathClass = " critical_path "
        }
        var span = "<span class=\"attack_tree_node " + this.pillClass + criticalPathClass + "\" style=\"" + nodePillStyle + "\" title=\"" + nodePillTooltip + "\">" + nodePillText + "</span>";
        var comments = this.comments.join("\n").trim().replaceAll("\n", "<br>");

        var criticalPathPrefixText = "";
        if (this.criticalPath) {
            criticalPathPrefixText = "<i class=\"far fa-check-circle\"/>"
        } else {
            criticalPathPrefixText = "<i class=\"far fa-times-circle\"/>";
        }
        var criticalPathPrefixSpan = "<span class=\"attack_tree_path_prefix\">" + criticalPathPrefixText + "</span>";

        var s = [];
        s.push(indentToBullet(this.indent));
        s.push(criticalPathPrefixSpan);
        s.push(span + " " + this.description());
        if (comments.length > 0) {
            s.push("\"\"\"<br>" + comments + "\"\"\"");
        }
        return [s.join(" ")];
    }
}


class Branch extends Node {
    constructor(parent, nodeName, indent, operator) {
        super(parent, nodeName, indent, "branch_node", "fas fa-code-branch");

        // Handle any case for operator name resolution.
        this.operator = operator;
        this.children = [];
    }

    calculateBranchProbability() {
        throw new Error("Not implemented!");
    }

    pillTextPreamble() {
        return super.pillTextPreamble() + this.operator + " ";
    }

    // Override resolve
    resolve() {
        // Recurse resolution down tree
        for (let c of this.children) {
            c.resolve();
        }
        this.likelihood = this.calculateBranchProbability();
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

class OrBranch extends Branch {
    constructor(parent, nodeName, indent) {
        super(parent, nodeName, indent, "OR");
    }

    calculateBranchProbability() {
        if (this.children.length == 0) {
            // If no children, then task is impossible!
            return new ComplexLikelihood(new Likelihood(0.0, 0.0), new Likelihood(0.0, 0.0));
        }
        var treatedMaxLower = 0.0, treatedMaxUpper = 0.0, untreatedMaxLower = 0.0, untreatedMaxUpper = 0.0;
        for (let c of this.children) {
            console.log("Child: " + c.nodeName);
            treatedMaxLower = Math.max(treatedMaxLower, c.likelihood.treated.lower);
            treatedMaxUpper = Math.max(treatedMaxUpper, c.likelihood.treated.upper);
            untreatedMaxLower = Math.max(untreatedMaxLower, c.likelihood.untreated.lower);
            untreatedMaxUpper = Math.max(untreatedMaxUpper, c.likelihood.untreated.upper);
        }
        return new likelihood_utils.ComplexLikelihood(new likelihood_utils.Likelihood(untreatedMaxLower, untreatedMaxUpper), new likelihood_utils.Likelihood(treatedMaxLower, treatedMaxUpper));
    }

    markCriticalPath() {
        super.markCriticalPath();
        for (let c of this.children) {
            if (c.likelihood.treated.upper === this.likelihood.treated.upper) {
                c.markCriticalPath();
            }
        }
    }

    renderRiskAssessment(impact) {
        var impactName = impact_utils.impact2Name[impact];
        var impactClass = impact_utils.impact2Class[impact];
    
        var inherent = (impact * this.likelihood.untreated.upper * 2);
        var residual = (impact * this.likelihood.treated.upper * 2);

        var treatedBand = this.likelihood.treated.toBandSimplePercentageDescription();
        var treatedBackgroundStyle = this.likelihood.treated.buildLikelihoodBackgroundStyle();

        var untreatedBand = this.likelihood.untreated.toBandSimplePercentageDescription();
        var untreatedBackgroundStyle = this.likelihood.untreated.buildLikelihoodBackgroundStyle();

        var l = [];
        l.push(risk_utils.generateRiskMetric(risk_utils.score2Class(residual), "Treated Risk", residual.toFixed(1), risk_utils.score2Name(residual), ""));
        l.push(risk_utils.generateRiskMetric(risk_utils.score2Class(inherent), "Untreated Risk", inherent.toFixed(1), risk_utils.score2Name(inherent), ""));
        l.push(risk_utils.generateRiskMetric(impactClass, "Impact", impact, impactName, ""));

        l.push(risk_utils.generateRiskMetric("", "Likelihood", treatedBand, this.likelihood.treated.phia, treatedBackgroundStyle));
        // l.push(generateRiskMetric("", "Untreated Likelihood", untreatedBand, this.likelihood.untreated.phia, untreatedBackgroundStyle));
        return {
            rendered_summary: l.join(""),
            untreated_risk: inherent,
            treated_risk: residual,
        }
    }
}

class AndBranch extends Branch {
    constructor(parent, nodeName, indent) {
        super(parent, nodeName, indent, "AND");

    }
    calculateBranchProbability() {
        var runningUntreatedLower = 1.0, runningUntreatedUpper = 1.0, runningTreatedLower = 1.0, runningTreatedUpper = 1.0;
        for (let c of this.children) {
            runningUntreatedLower = runningUntreatedLower * c.likelihood.untreated.lower;
            runningUntreatedUpper = runningUntreatedUpper * c.likelihood.untreated.upper;
            runningTreatedLower = runningTreatedLower * c.likelihood.treated.lower;
            runningTreatedUpper = runningTreatedUpper * c.likelihood.treated.upper;
        }
        return new likelihood_utils.ComplexLikelihood(new likelihood_utils.Likelihood(runningUntreatedLower, runningUntreatedUpper), new likelihood_utils.Likelihood(runningTreatedLower, runningTreatedUpper));
    }

    markCriticalPath() {
        super.markCriticalPath();
        for (let c of this.children) {
            c.markCriticalPath();
        }
    }

}


class Leaf extends Node {
    constructor(parent, nodeName, indent, probability="almost certain") {
        super(parent, nodeName, indent, "leaf_node", "fab fa-envira");
        var l = likelihood_utils.phia2Likelihood(probability);
        this.likelihood = new likelihood_utils.ComplexLikelihood(l, l);
    }
}


class Control extends Node {
    constructor(parent, nodeName, indent) {
        super(parent, nodeName, indent, "control_node", "fas fa-shield-alt");
        if (!is_control(nodeName)) {
            throw new AttackTreeSyntaxError("Not a control!");
        }
        this.likelihood = new likelihood_utils.ComplexLikelihood(likelihood_utils.NULL_LIKELIHOOD, likelihood_utils.phia2Likelihood(get_control_failure_likelihood(nodeName)));
    }

    description() {
        return "<<attack_tree_control_reference \"" + this.nodeName + "\">>";
    }
}


class Ref extends Node {
    constructor(parent, refName, indent) {
        super(parent, nodeName, indent, "reference_node", "fas fa-link");
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

const branchFactoryLookup = {
    "OR": function(currentBranch, branchName, indent) {
        return new OrBranch(currentBranch, branchName, indent, "OR");
    },
    "AND": function(currentBranch, branchName, indent) {
        return new AndBranch(currentBranch, branchName, indent, "OR");
    },
}

function parse_attack_tree(attack_tree) {

    var controls = [];
    var attack_sub_trees = [];
    var root = new OrBranch(null, "<$view field=title/>", 0);
    var currentBranch = root;

    var ops = {
        "branch": function(indent, args) {
            var branchName = args[0];
            var operator = (args[1] || "OR").toUpperCase();
            var branchFactory = branchFactoryLookup[operator];
            if (!branchFactory) {
                throw new AttackTreeSyntaxError("Unsupported operator (" + operator + ")");
            }
            var branch = branchFactory(currentBranch, branchName, indent, operator);
            currentBranch.children.push(branch);
            currentBranch = branch;
        },
        "leaf": function(indent, args) {
            var leafName = args[0];
            var probability = args[1];
            var leaf = new Leaf(currentBranch, leafName, indent, probability);
            if (leaf.indent !== (currentBranch.indent + 1)) {
                throw new Error("Mismatch! Leaf is " + leaf.indent + " and parent branch is " + currentBranch.indent);
            }
            currentBranch.children.push(leaf);
            console.log("Pushing leaf to branch: " + leaf.nodeName);
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

    try {

        for (let l of lines) {
            try {
                var t = lstrip(l, "*")
                var indent = l.length - t.length;
                if (!indent) {
                    currentBranch.comments.push(t);
                }
                if (indent) {
                    if (indent > (currentBranch.indent + 1)) {
                        throw new AttackTreeSyntaxError("Branch children too indented!");
                    }

                    // Walk back up the tree finding the correct parent.
                    while ((indent - 1) < currentBranch.indent) {
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
                    throw(objError);
                }        
            }
            lineNo += 1;
        }
        // Now that the tree structure is in place, resolve the likelihood calculation.
        root.resolve();
        root.markCriticalPath();

    } catch (objError) {
        if (objError instanceof AttackTreeSyntaxError) {
            error = objError.message;
        } else {
            throw(objError);
        }        
    }

    // Make sure we are not returning any duplicate entries for x-references
    return {
        renderer: 2,
        error: error,
        root: root,
        controls: controls.filter((v, i, a) => a.indexOf(v) === i),
        sub_trees: attack_sub_trees.filter((v, i, a) => a.indexOf(v) === i),
    }
}

exports.parse_attack_tree = parse_attack_tree;

})();