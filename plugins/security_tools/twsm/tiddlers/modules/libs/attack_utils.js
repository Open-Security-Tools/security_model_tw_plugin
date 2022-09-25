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
var utils = require("$:/plugins/security_tools/twsm/utils.js")
var shlex = require("$:/plugins/security_tools/twsm/shlex.js")

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

    get nodeCount() {
        return 1;
    }

    resolve() {}

    markCriticalPath() {
        this.criticalPath = true;
    }

    pillTextPreamble() {
        return "<i class=\"" + this.pillIconClass + "\"/> ";
    }

    customCircle() {
        return "<svg viewBox=\"0 0 6.3 4\" width=\"19\">" +
            "<path transform=\"translate(0 0)\" fill=\"" + this.parent.nodeCircleColour() + "\" d=\"M 3 0 A 3 2 0 0 0 3 4 Z\"/>" +
            "<path transform=\"translate(3.2 0)\" fill=\"" + this.nodeCircleColour() + "\"  d=\"M  0 0 A 3 2 0 0 1  0 4 Z\"/>" + 
            "</svg>";
    }

    description() {
        return this.nodeName + " " + this.likelihoodSpan();
    }

    likelihoodSpan() {
        return "<span class=\"attack_tree_node_likelihood\"><i class=\"fas fa-calculator\"/> " + this.likelihood.treated.phia + "</span>";
    }

    oldLikelihoodSpan() {
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
        return "<span class=\"attack_tree_node " + this.pillClass + criticalPathClass + "\" style=\"" + nodePillStyle + "\" title=\"" + nodePillTooltip + "\">" + nodePillText + "</span>";
    }

    nodeCircleColour() {
        return "grey";
    }

    renderStart() {
        if (this.indent < 1) {
            return [];
        }

        var s = [];
        s.push("<li>");
        s.push(this.customCircle());
        
        // AND/OR node
        var criticalPathStyle = this.criticalPath ? " critical_path" : "";
        s.push("<span class=\"attack_tree_branch_type" + criticalPathStyle + "\">" + this.parent.operator + "</span>");

        s.push(this.description());

        // Comments added as additional lines
        var comments = this.comments.join("\n").trim().replaceAll("\n", "<br>");
        if (comments.length > 0) {
            s.push("<div class=\"attack_tree_node_comments\">" + comments + "</div>");
        }
        return [s.join(" ")];
    }

    renderEnd() {
        if (this.indent < 1) {
            return [];
        }
        return ["</li>"];
    }
}


class Branch extends Node {
    constructor(parent, nodeName, indent, operator, hue) {
        super(parent, nodeName, indent, "branch_node", "fas fa-code-branch");

        // Handle any case for operator name resolution.
        this.operator = operator;
        this.hue = hue;
        this.children = [];
    }

    get nodeCount() {
        var count = 1;
        for (let c of this.children) {
            count += c.nodeCount;
        }
        return count;
    }

    nodeCircleColour() {
        if (this.parent === null) {
            return "grey";
        } else {
            return "hsl(" + this.hue + ", 50%, 50%)";
        }
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
    renderStart() {
        var lines = super.renderStart();
        if (this.children.length > 0){
            lines.push("<ul>")
            for (let c of this.children) {
                lines.push(...c.renderStart());
                lines.push(...c.renderEnd());
            }
            lines.push("</ul>")
        }
        return lines;
    }
}

class OrBranch extends Branch {
    constructor(parent, nodeName, indent, hue) {
        super(parent, nodeName, indent, "OR", hue);
    }

    // Root render
    render() {
        var lines = [];
        lines.push("<div class=\"attack_tree\">");

        var comments = this.comments.join("\n").trim().replaceAll("\n", "<br>");
        if (comments.length > 0) {
            lines.push("<div class=\"attack_tree_root_comments\">" + comments + "</div>");
        }
        lines.push(...this.renderStart());
        lines.push(...this.renderEnd());
        lines.push("</div>");
        return lines.join("\n");
    }

    calculateBranchProbability() {
        if (this.children.length == 0) {
            // If no children, then task is impossible!
            return new likelihood_utils.ComplexLikelihood(new likelihood_utils.Likelihood(0.0, 0.0), new likelihood_utils.Likelihood(0.0, 0.0));
        }
        var treatedMaxLower = 0.0, treatedMaxUpper = 0.0, untreatedMaxLower = 0.0, untreatedMaxUpper = 0.0;
        for (let c of this.children) {
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

        var l = [];
        l.push(utils.generateMetric(risk_utils.score2Class(residual), "Treated Risk", residual.toFixed(1), risk_utils.score2Name(residual), ""));
        l.push(utils.generateMetric(risk_utils.score2Class(inherent), "Untreated Risk", inherent.toFixed(1), risk_utils.score2Name(inherent), ""));
        l.push(utils.generateMetric(impactClass, "Impact", impact, impactName, ""));

        l.push(utils.generateMetric("", "Likelihood", treatedBand, this.likelihood.treated.phia, treatedBackgroundStyle));
        return {
            rendered_summary: l.join(""),
            untreated_risk: inherent,
            treated_risk: residual,
        }
    }

    renderAttackAssessment() {

        var treatedBand = this.likelihood.treated.toBandSimplePercentageDescription();
        var treatedBackgroundStyle = this.likelihood.treated.buildLikelihoodBackgroundStyle();

        var untreatedBand = this.likelihood.untreated.toBandSimplePercentageDescription();
        var untreatedBackgroundStyle = this.likelihood.untreated.buildLikelihoodBackgroundStyle();

        var l = [];
        l.push(utils.generateMetric("", "Treated Likelihood", treatedBand, this.likelihood.treated.phia, treatedBackgroundStyle));
        l.push(utils.generateMetric("", "Untreated Likelihood", untreatedBand, this.likelihood.untreated.phia, untreatedBackgroundStyle));
        return {
            rendered_summary: l.join(""),
        }
    }


}

class AndBranch extends Branch {
    constructor(parent, nodeName, indent, hue) {
        super(parent, nodeName, indent, "AND", hue);

    }
    calculateBranchProbability() {
        if (this.children.length == 0) {
            // If no children, then task is impossible!
            return new likelihood_utils.ComplexLikelihood(new likelihood_utils.Likelihood(0.0, 0.0), new likelihood_utils.Likelihood(0.0, 0.0));
        }

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

    likelihoodSpan() {
        return "<span class=\"attack_tree_node_likelihood\"><i class=\"fas fa-leaf\"/> " + this.likelihood.treated.phia + "</span>";
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
    constructor(parent, nodeName, indent) {
        super(parent, nodeName, indent, "reference_node", "fas fa-link");
        if (!is_ref(nodeName)) {
            throw new AttackTreeSyntaxError("Not a ref!");
        }
        this.likelihood = get_attack_treated_likelihood(nodeName);
    }
    likelihoodSpan() {
        return "<span class=\"attack_tree_node_likelihood\"><i class=\"fas fa-biohazard\"/> " + this.likelihood.treated.phia + "</span>";
    }
    description() {
        return "<<attack_tree_attack_reference \"" + this.nodeName + "\">>" + " " + this.likelihoodSpan();
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
    var tiddler = $tw.wiki.getTiddler(controlTitle);
    return likelihood_utils.calculateControlFailureLikelihood(tiddler.fields.failure_likelihood, tiddler.fields.is_idea);
}

function get_attack_treated_likelihood(attackTitle) {
    var tiddler = $tw.wiki.getTiddler(attackTitle);
    return new likelihood_utils.ComplexLikelihood(
        new likelihood_utils.Likelihood(tiddler.fields.untreated_likelihood_lower, tiddler.fields.untreated_likelihood_upper),
        new likelihood_utils.Likelihood(tiddler.fields.treated_likelihood_lower, tiddler.fields.treated_likelihood_upper)
    );
}

function is_ref(refTitle) {
    return tw_filter_to_bool(
        "[title[" + refTitle + "]twsm_class[attack]then[True]else[False]]"
    )
}

const branchFactoryLookup = {
    "OR": function(currentBranch, branchName, indent, hue) {
        return new OrBranch(currentBranch, branchName, indent, hue);
    },
    "AND": function(currentBranch, branchName, indent, hue) {
        return new AndBranch(currentBranch, branchName, indent, hue);
    },
}

function parse_attack_tree(attack_tree) {

    var controls = new Set();
    var accumulatedControls = new Set();
    var attackSubTrees = new Set();
    var accumulatedAttackSubTrees = new Set();
    var hue = 200;
    var root = new OrBranch(null, "<$view field=title/>", 0, hue);
    var hueDelta = 75;
    hue += hueDelta;
    var currentBranch = root;
    var currentNode = currentBranch;

    var branchFunction = function(indent, args) {
        var branchName = args[0];
        var operator = (args[1] || "OR").toUpperCase();
        var branchFactory = branchFactoryLookup[operator];
        if (!branchFactory) {
            throw new AttackTreeSyntaxError("Unsupported operator (" + operator + ")");
        }
        var branch = branchFactory(currentBranch, branchName, indent, hue);
        hue += hueDelta;
        currentBranch.children.push(branch);
        currentBranch = branch;
        currentNode = currentBranch;
    }

    var andFunction = function(indent, args) {
        var branchName = args[0];
        var branchFactory = branchFactoryLookup["AND"];
        var branch = branchFactory(currentBranch, branchName, indent, hue);
        hue += hueDelta;
        currentBranch.children.push(branch);
        currentBranch = branch;
        currentNode = branch;
    }

    var orFunction = function(indent, args) {
        var branchName = args[0];
        var branchFactory = branchFactoryLookup["OR"];
        var branch = branchFactory(currentBranch, branchName, indent, hue);
        hue += hueDelta;
        currentBranch.children.push(branch);
        currentBranch = branch;
        currentNode = branch;
    }

    var taskFunction = function(indent, args) {
        var leafName = args[0];
        var probability = args[1];
        var leaf = new Leaf(currentBranch, leafName, indent, probability);
        if (leaf.indent !== (currentBranch.indent + 1)) {
            throw new Error("Mismatch! Leaf is " + leaf.indent + " and parent branch is " + currentBranch.indent);
        }
        currentBranch.children.push(leaf);
        currentNode = leaf;
    }

    var controlFunction = function(indent, args) {
        var controlName = args[0];
        var control = new Control(currentBranch, controlName, indent);
        currentBranch.children.push(control);
        controls.add(controlName);
        accumulatedControls.add(controlName);
        currentNode = control;
    }

    var attackFunction = function(indent, args) {
        var refName = args[0];
        var ref = new Ref(currentBranch, refName, indent);
        currentBranch.children.push(ref);
        attackSubTrees.add(refName);
        accumulatedAttackSubTrees.add(refName);
        currentNode = ref;
        
        // Also pull in the controls and attack trees referenced in this sub tree
        var accumControls = $tw.wiki.filterTiddlers("[title[" + refName + "]get[accumulated_controls]enlist-input[]]");
        for (let c of accumControls) {
            accumulatedControls.add(c);
        }
        var accumSubTrees = $tw.wiki.filterTiddlers("[title[" + refName + "]get[accumulated_sub_trees]enlist-input[]]");
        for (let s of accumSubTrees) {
            accumulatedAttackSubTrees.add(s);
        }
    }

    var ops = {
        "branch": branchFunction,
        "and": andFunction,
        "or": orFunction,
        "leaf": taskFunction,
        "task": taskFunction,
        "control": controlFunction,
        "ref": attackFunction,
        "attack": attackFunction,
    }

    var lines = "";
    if (attack_tree !== undefined) {
        lines = attack_tree.split('\n');
    }
    var error = "";
    var lineNo = 1;

    try {

        for (let l of lines) {
            try {
                var t = lstrip(l, "*")
                var indent = l.length - t.length;
                if (!indent) {
                    currentNode.comments.push(t);
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
                }
            } catch (objError) {
                if (objError instanceof AttackTreeSyntaxError) {
                    throw(new AttackTreeSyntaxError("Syntax error (line " + lineNo + "): " + objError.message));
                } else if (objError instanceof likelihood_utils.LikelihoodError) {
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
        node_count: root.nodeCount,
        controls: Array.from(controls),
        accumulated_controls: Array.from(accumulatedControls),
        sub_trees: Array.from(attackSubTrees),
        accumulated_sub_trees: Array.from(accumulatedAttackSubTrees),
    }
}

exports.parse_attack_tree = parse_attack_tree;

})();