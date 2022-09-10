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
var likelihood_utils = require("$:/plugins/security_tools/twsm/likelihood_utils.js");
var impact_utils = require("$:/plugins/security_tools/twsm/impact_utils.js")
var risk_utils = require("$:/plugins/security_tools/twsm/risk_utils.js")



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

function twListify(l) {
    var p = l.map(function(x){ return "[[" + x + "]]";});
    return p.join(" ");
}


exports.twsm_render_attack = function(source, operator, options) {
    var result = [],
        impactOperand = (operator.operand || "").toLowerCase();

    source (function(tiddler, title) {
        var rendered = parse_attack_tree(title);
        var ret = {};
        ret.renderer = rendered.renderer;
        ret.attack_tree = rendered.root.render().join("\n");
        ret.error = rendered.error;

        // The attack properties are sent back so they can be incorporated into subsequent actions.
        ret.untreated_likelihood_lower = rendered.root.likelihood.untreated.lower;
        ret.untreated_likelihood_upper = rendered.root.likelihood.untreated.upper;
        ret.treated_likelihood_lower = rendered.root.likelihood.treated.lower;
        ret.treated_likelihood_upper = rendered.root.likelihood.treated.upper;

        // Controls and sub trees are used to maintain x-references
        ret.controls = twListify(rendered.controls);
        ret.sub_trees = twListify(rendered.sub_trees);

        if (impactOperand.length > 0) {
            var risk_assessment = rendered.root.renderRiskAssessment(impact_utils.impactDict[impactOperand]);
            ret.risk_assessment = risk_assessment.rendered_summary;
            ret.untreated_risk = risk_assessment.untreated_risk;
            ret.treated_risk = risk_assessment.treated_risk;
        }

        result.push(JSON.stringify(ret));
    });
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

class RiskAssessment {
    constructor(tiddlerFields) {
        this.impact = impact_utils.impactDict[(tiddlerFields.twsm_impact || "").toLowerCase()];
        this.impactName = impact_utils.impact2Name[this.impact];
        this.impactClass = impact_utils.impact2Class[this.impact];
    
        this.treatedLikelihood = new likelihood_utils.Likelihood(tiddlerFields.treated_likelihood_lower || 0.0, tiddlerFields.treated_likelihood_upper || 0.0);
        this.untreatedLikelihood = new likelihood_utils.Likelihood(tiddlerFields.untreated_likelihood_lower || 0.0, tiddlerFields.untreated_likelihood_upper || 0.0);
    
        this.untreatedRisk = (this.impact * this.untreatedLikelihood.upper * 2);
        this.treatedRisk = (this.impact * this.treatedLikelihood.upper * 2);
        this.treatedRiskForCalculations = this.treatedRisk;
        if (this.treatedRiskForCalculations == 0.0) {
            this.treatedRiskForCalculations = 10.0;
        }

        this.treatedClass = risk_utils.score2Class(this.treatedRisk);
        this.treatedName = risk_utils.score2Name(this.treatedRisk);
        this.untreatedClass = risk_utils.score2Class(this.untreatedRisk);
        this.untreatedName = risk_utils.score2Name(this.untreatedRisk);

        // We round the risk scores at the end...
        this.treatedRisk = this.treatedRisk.toFixed(1);
        this.untreatedRisk = this.untreatedRisk.toFixed(1);
    }

    get rendered_summary() {

        var treatedBand = this.treatedLikelihood.toBandSimplePercentageDescription();
        var treatedBackgroundStyle = this.treatedLikelihood.buildLikelihoodBackgroundStyle();
    
        var untreatedBand = this.untreatedLikelihood.toBandSimplePercentageDescription();
        var untreatedBackgroundStyle = this.untreatedLikelihood.buildLikelihoodBackgroundStyle();
    
        var l = [];
        l.push(risk_utils.generateRiskMetric(this.treatedClass, "Treated Risk", this.treatedRisk, this.treatedName, ""));
        l.push(risk_utils.generateRiskMetric(this.untreatedClass, "Untreated Risk", this.untreatedRisk, this.untreatedName, ""));
        l.push(risk_utils.generateRiskMetric(this.impactClass, "Impact", this.impact, this.impactName, ""));
    
        l.push(risk_utils.generateRiskMetric("", "Likelihood", treatedBand, this.treatedLikelihood.phia, treatedBackgroundStyle));
        // l.push(generateRiskMetric("", "Untreated Likelihood", untreatedBand, this.untreatedLikelihood.phia, untreatedBackgroundStyle));

        return l.join("");
    }

}

exports.twsm_risk_assessment = function(source, operator, options) {
    var suffixes = operator.suffixes || [],
        field = (suffixes[0] || [])[0],
        result = [];
    source (function(tiddler, title) {
        var assessment = new RiskAssessment(tiddler.fields);
        var value = assessment[field];
        if (value !== undefined) {
            result.push(String(value));
        }
    });
    return result; 
}

exports.twsm_is_unassessed = function(source, operator, options) {
    var result = [];
    source (function(tiddler, title) {
        var assessment = new RiskAssessment(tiddler.fields);
        if (assessment.treatedRisk == 0.0) {
            result.push(title);
        }
    });
    return result; 
}

exports.twsm_is_high = function(source, operator, options) {
    var result = [];
    source (function(tiddler, title) {
        var assessment = new RiskAssessment(tiddler.fields);
        if (assessment.treatedName === "High") {
            result.push(title);
        }
    });
    return result; 
}

exports.twsm_is_medium = function(source, operator, options) {
    var result = [];
    source (function(tiddler, title) {
        var assessment = new RiskAssessment(tiddler.fields);
        if (assessment.treatedName === "Medium") {
            result.push(title);
        }
    });
    return result; 
}

exports.twsm_is_low = function(source, operator, options) {
    var result = [];
    source (function(tiddler, title) {
        var assessment = new RiskAssessment(tiddler.fields);
        if (assessment.treatedName === "Low") {
            result.push(title);
        }
    });
    return result; 
}

exports.twsm_is_non_trivial = function(source, operator, options) {
    var result = [];
    source (function(tiddler, title) {
        var assessment = new RiskAssessment(tiddler.fields);
        if (assessment.treatedRisk > LOW_THRESHOLD) {
            result.push(title);
        }
    });
    return result; 
}

exports.twsm_control_failure_likelihood = function(source, operator, options) {
    var result = [];
    source (function(tiddler, title) {
        if (tiddler.fields) {
            var l = tiddler.fields.failure_likelihood || "";
            result.push(likelihood_utils.phia2Likelihood(l).phia);
        }
    });
    return result; 
}



})();
