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
    // const hue_start = 180;
    // const hue_end = 220;
    const hue_start = 235;
    const hue_end = 360;
    
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

    toBandPercentageDescription() {
        return (this.lower * 100).toFixed() + "% - " + (this.upper * 100).toFixed() + "%";
    }

    toBandSimplePercentageDescription() {
        return (this.lower * 100).toFixed() + "-" + (this.upper * 100).toFixed();
    }

    buildLikelihoodBackgroundStyle() {
        return "background: linear-gradient(90deg, hsl(" + this.lowerHue + ", 100%, 80%) 0%, hsl(" + this.upperHue + ",100%,80%) 100%);";
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




const impactDict = {
	"unknown": 0,
	"insignificant": 1,
	"minimal": 1,
	"minor": 2,
	"moderate": 3,
	"significant": 4,
	"major": 4,
	"extreme/catastrophic": 5,
	"severe": 5
};

const impact2Name = {
    0: "Unknown",
    1: "Minimal",
    2: "Minor",
    3: "Moderate",
    4: "Major",
    5: "Severe",
}

const impact2Class = {
    0: "twsm_impact_unknown",
    1: "twsm_impact_minimal",
    2: "twsm_impact_minor",
    3: "twsm_impact_moderate",
    4: "twsm_impact_major",
    5: "twsm_impact_severe",
}


var LOW_THRESHOLD = 3.6;
var MEDIUM_THRESHOLD = 6.4;

function score2Name(score) {
	if (score <= 0) {
		return "Unknown";
	}
	else if (score <= LOW_THRESHOLD) {
		return "Low";
	}
	else if (score <= MEDIUM_THRESHOLD) {
	  return "Medium";
	}
	else {
		return "High";
	}
}

function score2Class(score) {
	if (score <= 0) {
		return "twsm_risk_unknown";
	}
	else if (score <= LOW_THRESHOLD) {
		return "twsm_risk_low";
	}
	else if (score <= MEDIUM_THRESHOLD) {
	  return "twsm_risk_medium";
	}
	else {
		return "twsm_risk_high";
	}
}

function generateRiskMetric(metricClass, header, metric, footer, style) {
    return "<div class=\"twsm_risk_metric " + metricClass + "\" style=\"" + style + "\">" + header + "<span>" + metric + "</span>" + footer + "</div>";
}


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

    /**
     * 
     * @returns {bool}
     */
    isControlled() {
        return (this.treated.upper < this.untreated.upper) && (this.untreated.upper !== 1.0) && (this.untreated.lower !== 1.0);
    }

    calculateControlProportion() {
        // Amount of control is 1 - likelihood of attack.
        // Note that untreated will always be larger than treated.
        // Therefore, proportion of control is (Untreated - Treated) / (1 - Treated)
        return ((this.untreated.upper - this.treated.upper) * 100) / (1 - this.treated.upper);
    }
}

const NULL_LIKELIHOOD = new Likelihood(1.0, 1.0);
const NULL_COMPLEX_LIKELIHOOD = new ComplexLikelihood(NULL_LIKELIHOOD, NULL_LIKELIHOOD);




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
     * @param {String} pillClass
     * @param {String} pillIconClass
     */
    constructor(parent, nodeName, indent, pillClass, pillIconClass) {
        this.parent = parent;
        this.nodeName = nodeName;
        this.indent = indent;
        this.likelihood = new ComplexLikelihood(new Likelihood(0.0, 0.0), new Likelihood(0.0, 0.0));
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
        s.push(indentToBullet(this.indent + 1));
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
        return new ComplexLikelihood(new Likelihood(untreatedMaxLower, untreatedMaxUpper), new Likelihood(treatedMaxLower, treatedMaxUpper));
    }

    markCriticalPath() {
        super.markCriticalPath();
        for (let c of this.children) {
            if (c.likelihood.treated.upper === this.likelihood.treated.upper) {
                c.markCriticalPath();
            }
        }
    }

    renderRiskActions(impact) {
        var impactName = impact2Name[impact];
        var impactClass = impact2Class[impact];
    
        var inherent = (impact * this.likelihood.untreated.upper * 2);
        var residual = (impact * this.likelihood.treated.upper * 2);

        var actionFields = {
            untreated_risk: inherent,
        }

        var actions = [];
        actions.push("<$action-setfield");
        for (const [k, v] of Object.entries(actionFields)) {
            actions.push(k + "=\"" + v + "\"");
        }
        actions.push("/>");
        return actions.join(" ");

        /**
         * Action fields...
         * 
         * untreated_risk
         * treated_risk
         * 
         */        
    }

    renderRiskAssessment(impact) {
        var impactName = impact2Name[impact];
        var impactClass = impact2Class[impact];
    
        var inherent = (impact * this.likelihood.untreated.upper * 2);
        var residual = (impact * this.likelihood.treated.upper * 2);

        var treatedBand = this.likelihood.treated.toBandSimplePercentageDescription();
        var treatedBackgroundStyle = this.likelihood.treated.buildLikelihoodBackgroundStyle();

        var untreatedBand = this.likelihood.untreated.toBandSimplePercentageDescription();
        var untreatedBackgroundStyle = this.likelihood.untreated.buildLikelihoodBackgroundStyle();

        var l = [];
        l.push(generateRiskMetric(score2Class(residual), "Treated Risk", residual.toFixed(1), score2Name(residual), ""));
        l.push(generateRiskMetric(score2Class(inherent), "Untreated Risk", inherent.toFixed(1), score2Name(inherent), ""));
        l.push(generateRiskMetric(impactClass, "Impact", impact, impactName, ""));

        l.push(generateRiskMetric("", "Treated Likelihood", treatedBand, this.likelihood.treated.phia, treatedBackgroundStyle));
        l.push(generateRiskMetric("", "Untreated Likelihood", untreatedBand, this.likelihood.untreated.phia, untreatedBackgroundStyle));
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
        return new ComplexLikelihood(new Likelihood(runningUntreatedLower, runningUntreatedUpper), new Likelihood(runningTreatedLower, runningTreatedUpper));
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
        var l = phia2Likelihood(probability);
        this.likelihood = new ComplexLikelihood(l, l);
    }
}


class Control extends Node {
    constructor(parent, nodeName, indent) {
        super(parent, nodeName, indent, "control_node", "fas fa-shield-alt");
        if (!is_control(nodeName)) {
            throw new AttackTreeSyntaxError("Not a control!");
        }
        this.likelihood = new ComplexLikelihood(NULL_LIKELIHOOD, phia2Likelihood(get_control_failure_likelihood(nodeName)));
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
    return {
        renderer: 2,
        error: error,
        root: root,
        controls: controls,
        sub_trees: attack_sub_trees,
    }
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

        // TODO - we need controls and sub_trees added!

        if (impactOperand.length > 0) {
            var risk_assessment = rendered.root.renderRiskAssessment(impactDict[impactOperand]);
            ret.risk_assessment = risk_assessment.rendered_summary;
            ret.untreated_risk = risk_assessment.untreated_risk;
            ret.treated_risk = risk_assessment.treated_risk;
        }

        result.push(JSON.stringify(ret));
    });
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

function renderRiskAssessment(t) {
    var impact = impactDict[t.twsm_impact.toLowerCase()];
    var impactName = impact2Name[impact];
    var impactClass = impact2Class[impact];

    var treated = new Likelihood(t.treated_likelihood_lower || 0.0, t.treated_likelihood_upper || 0.0);
    var untreated = new Likelihood(t.untreated_likelihood_lower || 0.0, t.untreated_likelihood_upper || 0.0);

    var inherent = (impact * untreated.upper * 2);
    var residual = (impact * treated.upper * 2);

    var treatedBand = treated.toBandSimplePercentageDescription();
    var treatedBackgroundStyle = treated.buildLikelihoodBackgroundStyle();

    var untreatedBand = untreated.toBandSimplePercentageDescription();
    var untreatedBackgroundStyle = untreated.buildLikelihoodBackgroundStyle();

    var l = [];
    l.push(generateRiskMetric(score2Class(residual), "Treated Risk", residual.toFixed(1), score2Name(residual), ""));
    l.push(generateRiskMetric(score2Class(inherent), "Untreated Risk", inherent.toFixed(1), score2Name(inherent), ""));
    l.push(generateRiskMetric(impactClass, "Impact", impact, impactName, ""));

    l.push(generateRiskMetric("", "Treated Likelihood", treatedBand, treated.phia, treatedBackgroundStyle));
    l.push(generateRiskMetric("", "Untreated Likelihood", untreatedBand, untreated.phia, untreatedBackgroundStyle));
    return {
        rendered_summary: l.join(""),
        untreated_risk: inherent,
        treated_risk: residual,
    }
}

exports.twsm_get_assessment = function(source, operator, options) {
    var result = [];
    source (function(tiddler, title) {
        var obj = renderRiskAssessment(tiddler.fields);
        result.push(obj.rendered_summary);
    });
    return result;
}

exports.twsm_get_residual_class = function(source, operator, options) {
    var result = [];
    source (function(tiddler, title) {
        var impactName = tiddler.fields.twsm_impact || "";
        var impact = impactDict[impactName.toLowerCase()] || 0;
        var treatedLikelihood = tiddler.fields.treated_likelihood_upper || 0;
        var residual = (impact * treatedLikelihood * 2);
        result.push(score2Class(residual));
    });
    return result;
}

exports.twsm_get_residual_name = function(source, operator, options) {
    var result = [];
    source (function(tiddler, title) {
        var impactName = tiddler.fields.twsm_impact || "";
        var impact = impactDict[impactName.toLowerCase()] || 0;
        var treatedLikelihood = tiddler.fields.treated_likelihood_upper || 0;
        var residual = (impact * treatedLikelihood * 2);
        result.push(score2Name(residual));
    });
    return result;
}


})();
