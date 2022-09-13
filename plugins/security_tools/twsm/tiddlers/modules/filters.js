/*\
created: 20210723152326655
type: application/javascript
title: $:/plugins/security_tools/twsm/filters.js
tags: 
modified: 20220723070445305
module-type: filteroperator
\*/

(function(){

"use strict";

var likelihood_utils = require("$:/plugins/security_tools/twsm/likelihood_utils.js");
var impact_utils = require("$:/plugins/security_tools/twsm/impact_utils.js")
var risk_utils = require("$:/plugins/security_tools/twsm/risk_utils.js")
var attack_utils = require("$:/plugins/security_tools/twsm/attack_utils.js")
var utils = require("$:/plugins/security_tools/twsm/utils.js");


exports.twsm_render_attack = function(source, operator, options) {
    var result = [],
        impactOperand = (operator.operand || "").toLowerCase();

    source (function(tiddler, title) {
        var rendered = attack_utils.parse_attack_tree(title);
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
        ret.controls = utils.twListify(rendered.controls);
        ret.sub_trees = utils.twListify(rendered.sub_trees);

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


exports.twsm_risk_assessment = function(source, operator, options) {
    var suffixes = operator.suffixes || [],
        field = (suffixes[0] || [])[0],
        result = [];
    source (function(tiddler, title) {
        var assessment = new risk_utils.RiskAssessment(tiddler.fields);
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
        var assessment = new risk_utils.RiskAssessment(tiddler.fields);
        if (assessment.treatedRisk == 0.0) {
            result.push(title);
        }
    });
    return result; 
}

exports.twsm_get_at_for_deprecated_state = function(source, operator, options) {
    var result = [];
    source (function(tiddler, title) {
        var l = [];
        l.push("* <<branch \"Basic attack\" AND>>");
        l.push("** <<leaf \"Migrated probability from previous risk model version\" \"" + tiddler.fields.twsm_likelihood + "\">>");
        var controls = $tw.wiki.filterTiddlers("[title[" + title + "]tags[]twsm_class[control]] [title[" + title + "]tags[]twsm_class[vulnerability]tags[]twsm_class[control]]");
        for (let c of controls) {
            l.push("** <<control \"" + c + "\">>");
        }

        result.push(l.join("\n"));
    });
    return result;
}

exports.twsm_is_high = function(source, operator, options) {
    var result = [];
    source (function(tiddler, title) {
        var assessment = new risk_utils.RiskAssessment(tiddler.fields);
        if (assessment.treatedName === "High") {
            result.push(title);
        }
    });
    return result; 
}

exports.twsm_is_medium = function(source, operator, options) {
    var result = [];
    source (function(tiddler, title) {
        var assessment = new risk_utils.RiskAssessment(tiddler.fields);
        if (assessment.treatedName === "Medium") {
            result.push(title);
        }
    });
    return result; 
}

exports.twsm_is_low = function(source, operator, options) {
    var result = [];
    source (function(tiddler, title) {
        var assessment = new risk_utils.RiskAssessment(tiddler.fields);
        if (assessment.treatedName === "Low") {
            result.push(title);
        }
    });
    return result; 
}

exports.twsm_is_non_trivial = function(source, operator, options) {
    var result = [];
    source (function(tiddler, title) {
        var assessment = new risk_utils.RiskAssessment(tiddler.fields);
        if (assessment && assessment.treatedRisk > risk_utils.LOW_THRESHOLD) {
            result.push(title);
        }
    });
    return result; 
}

exports.twsm_control_failure_likelihood = function(source, operator, options) {
    var result = [];
    source (function(tiddler, title) {
        if (tiddler && tiddler.fields !== undefined) {
            var l = likelihood_utils.calculateControlFailureLikelihood(tiddler.fields.failure_likelihood, tiddler.fields.is_idea);
            if (l !== undefined) {
                result.push(l);
            }
        }
    });
    return result; 
}

function get_generic_actions(tiddler, title, options) {
    if ((tiddler === undefined) || (tiddler.fields.twsm_class === undefined)) {
        return [];
    }

    var result = [];
    result.push("edit_external_references");
    return result;
}

function get_control_actions(tiddler, title, options) {
    if ((tiddler === undefined) || (tiddler.fields === undefined) || (tiddler.fields.twsm_class === undefined) || (tiddler.fields.twsm_class !== "control")) {
        return [];
    }

    var result = [];
    if (tiddler.fields.is_idea === "yes") {
        result.push("clear_control_idea_status");
    } else {
        result.push("set_control_idea_status");
    }
    return result;
}

function get_risk_actions(tiddler, title, options) {
    if ((tiddler === undefined) || (tiddler.fields.twsm_class === undefined) || (tiddler.fields.twsm_class !== "risk")) {
        return [];
    }

    var result = [];
    if (tiddler.fields.edit_attack_tree === "yes") {
        result.push("commit_risk");
        result.push("cancel_edit_risk");
    } else {
        result.push("edit_risk");
    }
    return result;
}

function get_theme_actions(tiddler, title, options) {
    if ((tiddler === undefined) || (tiddler.fields.twsm_class === undefined) || (tiddler.fields.twsm_class !== "theme")) {
        return [];
    }

    var result = [];
    result.push("edit_theme_risk_coverage");
    result.push("edit_theme_control_coverage");
    result.push("edit_theme_poc");
    return result;
}

function actions_filter_all(source, options) {
    var result = [];
    source(function(tiddler, title) {
        result.push(...get_control_actions(tiddler, title, options));
        result.push(...get_risk_actions(tiddler, title, options));
        result.push(...get_generic_actions(tiddler, title, options));
        result.push(...get_theme_actions(tiddler, title, options));
    });
    return result;
}

function actions_filter_control(source, options) {
    var result = [];
    source(function(tiddler, title) {
        result.push(...get_control_actions(tiddler, title, options));
    });
    return result;
}


function actions_filter_risk(source, options) {
    var result = [];
    source(function(tiddler, title) {
        result.push(...get_risk_actions(tiddler, title, options));
    });
    return result;
}

function actions_filter_generic(source, options) {
    var result = [];
    source(function(tiddler, title) {
        result.push(...get_generic_actions(tiddler, title, options));
    });
    return result;
}

function actions_filter_theme(source, options) {
    var result = [];
    source(function(tiddler, title) {
        result.push(...get_theme_actions(tiddler, title, options));
    });
    return result;
}


var contexts = {
    "all": actions_filter_all,
    "control": actions_filter_control,
    "risk": actions_filter_risk,
    "generic": actions_filter_generic,
    "theme": actions_filter_theme,
}


exports.twsm_actions = function (source, operator, options) {
    var suffixes = operator.suffixes || [],
		context = (suffixes[0] || [])[0],
        contextFn = contexts[context] || contexts.all
    return contextFn(source, options);
}

function calculate_security_score(tiddler, title) {
    if (!tiddler.fields || (tiddler.fields.twsm_class !== "theme")) {
        return;
    }

    // Maximum risk score
    // Maximum risk class
    // Maximum risk name
    // Risk coverage score
    // Risk coverage assessment date
    // Control coverage score
    // Control coverage assessment date

    var riskCount = $tw.wiki.filterTiddlers("[title[" + title + "]tagging[]twsm_class[risk]count[]]")[0];
    var maxRiskScore = $tw.wiki.filterTiddlers("[title[" + title + "]tagging[]twsm_class[risk]twsm_risk_assessment:treatedRiskForCalculations[]maxall[]]")[0];
    if (maxRiskScore == -Infinity) {
        maxRiskScore = 0;
    }
    var risk = 1 - (maxRiskScore / 10.0);

    var controlCount = $tw.wiki.filterTiddlers("[title[" + title + "]tagging[]twsm_class[risk]get[controls]enlist-input[]unique[]count[]]")[0];

    // Balancing data...
    const assessmentLimit = 90;
    const maxRiskWeighting = 1
    const riskCoverageWeighting = 1
    const controlCoverageWeighting = 1
    const powerRollOff = 5

    // Risk coverage assessment gets aged
    var originalRiskCoverage = (tiddler.fields.risk_coverage_assessment || 0) / 100;
    var daysSinceRiskCoverage = utils.daysSince(tiddler.fields.risk_coverage_checked);
    var riskCoverageDecay = 0;
    if (daysSinceRiskCoverage !== undefined) {
        riskCoverageDecay = 1 - Math.pow(Math.min((daysSinceRiskCoverage / assessmentLimit), 1), powerRollOff);
    }
    var riskCoverage = originalRiskCoverage * riskCoverageDecay;

    // Control coverage assessment gets aged
    var originalControlCoverage = (tiddler.fields.control_coverage_assessment || 0) / 100;
    var daysSinceControlCoverage = utils.daysSince(tiddler.fields.control_coverage_checked);
    var controlCoverageDecay = 0;
    if (daysSinceControlCoverage !== undefined) {
        controlCoverageDecay = 1 - Math.pow(Math.min((daysSinceControlCoverage / assessmentLimit), 1), powerRollOff);
    }
    var controlCoverage = originalControlCoverage * controlCoverageDecay;

    var score = ((risk * maxRiskWeighting) + (riskCoverage * riskCoverageWeighting) + (controlCoverage * controlCoverageWeighting)) / (maxRiskWeighting + riskCoverageWeighting + controlCoverageWeighting);

    var l = [];
    l.push(utils.generateRiskMetric("", "Security Score", (score * 100).toFixed(), "out of 100", ""));
    l.push(utils.generateRiskMetric(risk_utils.score2Class(maxRiskScore, false), "Max Risk", Number(maxRiskScore).toFixed(1), risk_utils.score2Name(maxRiskScore, false), ""));
    if (daysSinceRiskCoverage === undefined) {
        l.push(utils.generateRiskMetric("", "Risk Coverage", "?", "", ""));
    } else {
        l.push(utils.generateRiskMetric("", "Risk Coverage", (riskCoverage * 100).toFixed() + "%", daysSinceRiskCoverage + " day(s) old", ""));
    }
    if (daysSinceControlCoverage === undefined) {
        l.push(utils.generateRiskMetric("", "Control Coverage", "?", "", ""));
    } else {
        l.push(utils.generateRiskMetric("", "Control Coverage", (controlCoverage * 100).toFixed() + "%", daysSinceControlCoverage + " day(s) old", ""));
    }

    var renderedHeader = l.join("");


    return {
        risk_count: riskCount,
        max_risk_score: Number(maxRiskScore).toFixed(1),
        max_risk_class: risk_utils.score2Class(maxRiskScore, false),
        max_risk_name: risk_utils.score2Name(maxRiskScore, false),
        control_count: controlCount,
        risk_coverage_original: (originalRiskCoverage * 100).toFixed(),
        risk_coverage_age: daysSinceRiskCoverage,
        risk_coverage_age_penalty: ((1 - riskCoverageDecay) * 100).toFixed(),
        risk_coverage: (riskCoverage * 100).toFixed(),
        control_coverage_original: (originalControlCoverage * 100).toFixed(),
        control_coverage_age: daysSinceControlCoverage,
        control_coverage_penalty: ((1 - controlCoverageDecay) * 100).toFixed(),
        control_coverage: (controlCoverage * 100).toFixed(),
        score: (score * 100).toFixed(),
        rendered_header: renderedHeader,
    }
}



exports.twsm_security_score = function (source, operator, options) {
    var result = [];
    source(function(tiddler, title) {
        var score = calculate_security_score(tiddler, title);
        if (score !== undefined) {
            result.push(JSON.stringify(score));
        }
    });
    return result;
}


})();
