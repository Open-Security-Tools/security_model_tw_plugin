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
        impactOperand = (operator.operand || "").toLowerCase(),
        suffixes = operator.suffixes || [],
        isRedacted = ((suffixes[0] || [])[0] === "redacted");

    source (function(tiddler, title) {
        var rendered = attack_utils.parse_attack_tree(title, isRedacted ? "yes" : "");
        var ret = {};
        ret.renderer = rendered.renderer;
        ret.attack_tree = rendered.root.render();
        ret.error = rendered.error;

        // The attack properties are sent back so they can be incorporated into subsequent actions.
        ret.untreated_likelihood_lower = rendered.root.likelihood.untreated.lower;
        ret.untreated_likelihood_upper = rendered.root.likelihood.untreated.upper;
        ret.treated_likelihood_lower = rendered.root.likelihood.treated.lower;
        ret.treated_likelihood_upper = rendered.root.likelihood.treated.upper;

        // Controls and sub trees are used to maintain x-references
        ret.controls = utils.twListify(rendered.controls);
        ret.accumulated_controls = utils.twListify(rendered.accumulated_controls);
        ret.sub_trees = utils.twListify(rendered.sub_trees);
        ret.accumulated_sub_trees = utils.twListify(rendered.accumulated_sub_trees);

        if (impactOperand.length > 0) {
            var risk_assessment = rendered.root.renderRiskAssessment(impact_utils.impactDict[impactOperand]);
            ret.risk_assessment = risk_assessment.rendered_summary;
            ret.untreated_risk = risk_assessment.untreated_risk;
            ret.treated_risk = risk_assessment.treated_risk;
        } else {
            var attackAssessment = rendered.root.renderAttackAssessment();
            ret.attack_assessment = attackAssessment.rendered_summary;
        }

        result.push(JSON.stringify(ret));
    });
    return result;
}

exports.twsm_json_field = function(source, operator, options) {
    
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

exports.twsm_attack_assessment = function(source, operator, options) {
    var suffixes = operator.suffixes || [],
        field = (suffixes[0] || [])[0],
        result = [];
    source (function(tiddler, title) {
        var assessment = new risk_utils.AttackAssessment(tiddler.fields);
        var value = assessment[field];
        if (value !== undefined) {
            result.push(String(value));
        }
    });
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
    var characteristics = ["Physical", "Policy", "Procedural", "Technical"];
    for (let c of characteristics) {
        if (c !== tiddler.fields.twsm_characteristic_class) {
            result.push("set_control_characteristic_" + c.toLowerCase());
        }
    }
    var temporal = ["Preventative", "Detective", "Corrective"]
    for (let t of temporal) {
        if (t !== tiddler.fields.twsm_temporal_class) {
            result.push("set_control_temporal_" + t.toLowerCase());
        }
    }
    
    // Controls should not be linked to themes
    var themeCount = $tw.wiki.filterTiddlers("[title[" + title + "]tags[]twsm_class[theme]count[]]")[0];
    if (themeCount > 0) {
        result.push("remove_themes_from_control");
    }

    // Controls should be linked to risks
    var riskCount = $tw.wiki.filterTiddlers("[title[" + title + "]listed[controls]count[]]")[0];
    if (riskCount == 0) {
        result.push("fix_orphaned_control");
    }

    return result;
}

function get_assurance_actions(tiddler, title, options) {
    if ((tiddler === undefined) || (tiddler.fields === undefined) || (tiddler.fields.twsm_class === undefined)) {
        return [];
    }

    var isAssuranceActivity = ($tw.wiki.filterTiddlers("[title[" + title + "]get[twsm_class]addprefix[$:/plugins/security_tools/twsm/defs/twsm_class/]provides_assurance[yes]then[yes]else[no]]")[0]) == "yes";
    if (!isAssuranceActivity) {
        return [];
    }

    var result = [];
    if (tiddler.fields.assurance_completed === "yes") {
        result.push("mark_assurance_activity_incomplete");
    } else {
        result.push("mark_assurance_activity_complete");
    }

    // Every assurance activity needs a control or risk
    var riskOrControlCount = $tw.wiki.filterTiddlers("[title[" + title + "]tags[]twsm_class[risk]] [title[" + title + "]tags[]twsm_class[control]]" + " +[count[]]")[0];
    if (riskOrControlCount == 0) {
        result.push("add_assurance_activity_to_risk_or_control");
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

    // Calculate the residual risk
    if (tiddler.fields.edit_attack_tree !== "yes") {
        var assessment = new risk_utils.RiskAssessment(tiddler.fields);
        if (assessment.treatedName === "Unknown") {
            result.push("assess_unknown_risk");
        }
    }

    // Every risk needs a theme...
    var themeCount = $tw.wiki.filterTiddlers("[title[" + title + "]tags[]twsm_class[theme]count[]]")[0];
    if (themeCount == 0) {
        result.push("add_theme_to_risk");
    }


    return result;
}

function get_attack_actions(tiddler, title, options) {
    if ((tiddler === undefined) || (tiddler.fields.twsm_class === undefined) || (tiddler.fields.twsm_class !== "attack")) {
        return [];
    }

    var result = [];
    if (tiddler.fields.edit_attack_tree === "yes") {
        result.push("commit_attack");
        result.push("cancel_edit_attack");
    } else {
        result.push("edit_attack");
    }

    if (tiddler.fields.redacted === "yes") {
        result.push("remove_mark_attack_redacted");

        // Only show errors about the redaction status if in edit
        if (tiddler.fields.edit_attack_tree !== "yes") {
            if (tiddler.fields.node_count > 1) {
                result.push("attack_needs_redacting");
            }
        }

    } else {
        result.push("mark_attack_redacted");
    }

    // Attacks should not be linked to themes
    var themeCount = $tw.wiki.filterTiddlers("[title[" + title + "]tags[]twsm_class[theme]count[]]")[0];
    if (themeCount > 0) {
        result.push("remove_themes_from_attack");
    }

    // Attacks should be used!
    var riskCount = $tw.wiki.filterTiddlers("[title[" + title + "]listed[sub_trees]count[]]")[0];
    if (riskCount == 0) {
        result.push("fix_orphaned_attack");
    }
    

    return result;
}

function get_theme_actions(tiddler, title, options) {
    if ((tiddler === undefined) || (tiddler.fields.twsm_class === undefined) || (tiddler.fields.twsm_class !== "theme")) {
        return [];
    }

    var result = [];
    result.push("edit_theme_risk_coverage");
    result.push("edit_theme_attack_coverage");
    result.push("edit_theme_poc");
    return result;
}

function actions_filter_all(source, options) {
    var result = [];
    source(function(tiddler, title) {
        result.push(...get_control_actions(tiddler, title, options));
        result.push(...get_risk_actions(tiddler, title, options));
        result.push(...get_attack_actions(tiddler, title, options));
        result.push(...get_generic_actions(tiddler, title, options));
        result.push(...get_theme_actions(tiddler, title, options));
        result.push(...get_assurance_actions(tiddler, title, options));
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

function actions_filter_attack(source, options) {
    var result = [];
    source(function(tiddler, title) {
        result.push(...get_attack_actions(tiddler, title, options));
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

function actions_filter_assurance_activity(source, options) {
    var result = [];
    source(function(tiddler, title) {
        result.push(...get_assurance_actions(tiddler, title, options));
    });
    return result;
}

var contexts = {
    "all": actions_filter_all,
    "control": actions_filter_control,
    "risk": actions_filter_risk,
    "generic": actions_filter_generic,
    "theme": actions_filter_theme,
    "assurance_activity": actions_filter_assurance_activity,
    "attack": actions_filter_attack,
}

exports.twsm_actions = function (source, operator, options) {
    var suffixes = operator.suffixes || [],
		context = (suffixes[0] || [])[0],
        contextFn = contexts[context] || contexts.all
    return contextFn(source, options);
}

function daysPlural(days) {
    if (days == 1) {
        return "1 day";
    } else {
        return days + " days";
    }
}

function addScoreCoverageMetric(name, original, decayed, days) {
    if (original === undefined) {
        return utils.generateMetric("", name, "?", "", "");
    }

    // Convert to fixed point percentages
    original = (original * 100).toFixed();
    decayed = (decayed * 100).toFixed();

    if (original === decayed) {
        return utils.generateMetric("", name, original + "%", "Current", "")
    }
    
    return utils.generateMetric("", name, decayed + "%", original + "% (" + daysPlural(days) + " ago)", "")
}

function calculate_security_score(tiddler, title) {
    if (!tiddler.fields || (tiddler.fields.twsm_class !== "theme")) {
        return;
    }

    // Balancing data...
    const ASSESSMENT_LIMIT_DAYS = 90;
    const RESIDUAL_RISK_WEIGHTING = 3;
    const ATTACK_COVERAGE_WEIGHTING = 2;
    const RISK_COVERAGE_WEIGHTING = 2;
    const WEIGHT_DIVISOR = RESIDUAL_RISK_WEIGHTING + ATTACK_COVERAGE_WEIGHTING + RISK_COVERAGE_WEIGHTING;
    const ASSESSMENT_POWER_ROLLOFF = 2

    // Keep track
    var scoreCalculations = [];
    var points = 0;
    function updatePoints(newPoints, description) {
        if (newPoints > points) {
            scoreCalculations.push(description + ": <span style=\"color: green;\">+" + (newPoints - points) + " points</span>");
        } else if (points > newPoints) {
            scoreCalculations.push(description + ": <span style=\"color: red;\">-" + (points - newPoints) + " points</span>");
        }
        points = newPoints;
    }

    // -------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    // Risk coverage scale
    var riskCoverageMultiplier = (tiddler.fields.risk_coverage_assessment || 0) / 100;
    updatePoints(
        Number(((riskCoverageMultiplier * ATTACK_COVERAGE_WEIGHTING * 100) / WEIGHT_DIVISOR).toFixed()),
        "Risk coverage of " + (riskCoverageMultiplier * 100).toFixed() + "%",
    )

    var daysSinceRiskCoverageAssessment = utils.daysSince(tiddler.fields.risk_coverage_checked);
    var riskCoveragePenaltyMultiplier = 0;
    if (daysSinceRiskCoverageAssessment !== undefined) {
        riskCoveragePenaltyMultiplier = 1 - Math.pow(Math.min((daysSinceRiskCoverageAssessment / ASSESSMENT_LIMIT_DAYS), 1), ASSESSMENT_POWER_ROLLOFF);
    }
    var riskCoverageMultiplier = (tiddler.fields.risk_coverage_assessment || 0) / 100;
    updatePoints(
        Number(((riskCoverageMultiplier * riskCoveragePenaltyMultiplier * ATTACK_COVERAGE_WEIGHTING * 100) / WEIGHT_DIVISOR).toFixed()),
        "Reduced risk coverage confidence (" + daysSinceRiskCoverageAssessment + " days elapsed)",
    )


    // -------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    // Attack coverage adds to this
    var cachedPoints = points;
    var attackCoverageMultiplier = (tiddler.fields.attack_coverage_assessment || 0) / 100;
    updatePoints(
        cachedPoints + (Number(((attackCoverageMultiplier * ATTACK_COVERAGE_WEIGHTING * 100) / WEIGHT_DIVISOR).toFixed())),
        "Attack coverage of " + (attackCoverageMultiplier * 100).toFixed() + "%",
    )

    var daysSinceAttackCoverageAssessment = utils.daysSince(tiddler.fields.attack_coverage_checked);
    var attackCoveragePenaltyMultiplier = 0;
    if (daysSinceAttackCoverageAssessment !== undefined) {
        attackCoveragePenaltyMultiplier = 1 - Math.pow(Math.min((daysSinceAttackCoverageAssessment / ASSESSMENT_LIMIT_DAYS), 1), ASSESSMENT_POWER_ROLLOFF);
    }
    updatePoints(
        cachedPoints + (Number(((attackCoverageMultiplier * attackCoveragePenaltyMultiplier * ATTACK_COVERAGE_WEIGHTING * 100) / WEIGHT_DIVISOR).toFixed())),
        "Reduced risk coverage confidence (" + daysSinceAttackCoverageAssessment + " days elapsed)",
    )

    // -------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    // We want a scale where 0 represents a high residual risk, and 1 represents a low residual risk.
    var cachedPoints = points;
    var maxRiskScore = $tw.wiki.filterTiddlers("[title[" + title + "]tagging[]twsm_class[risk]twsm_risk_assessment:treatedRiskForCalculations[]maxall[]]")[0];
    if (maxRiskScore == -Infinity) {
        maxRiskScore = 0;
    }
    var risk = 1 - (maxRiskScore / 10.0);
    updatePoints(
        cachedPoints + (Number(((risk * RESIDUAL_RISK_WEIGHTING * attackCoverageMultiplier * attackCoveragePenaltyMultiplier * riskCoverageMultiplier * riskCoveragePenaltyMultiplier *  100) / WEIGHT_DIVISOR).toFixed())),
        "Max residual risk of " + Number(maxRiskScore).toFixed(1),
    )

    var score = points;
    
    var l = [];
    l.push("<$button class=\"tc-btn-invisible\">");
    l.push("<$action-setfield $tiddler=<<tabState>> text=\"$:/plugins/security_tools/twsm/components/entity/theme/score\"/>");
    l.push(utils.generateMetric("", "Security Score <i class=\"fas fa-crosshairs\"/>", score, "Out of 100", ""));
    l.push("</$button>");
    l.push("<$button class=\"tc-btn-invisible\">");
    l.push("<$action-setfield $tiddler=<<tabState>> text=\"$:/plugins/security_tools/twsm/components/entity/theme/risks\"/>");
    l.push(utils.generateMetric(risk_utils.score2Class(maxRiskScore, false), "Max Risk <i class=\"fas fa-balance-scale\"/>", Number(maxRiskScore).toFixed(1), risk_utils.score2Name(maxRiskScore, false), ""));
    l.push("</$button>");
    l.push("<$button class=\"tc-btn-invisible\">");
    l.push("{{||$:/plugins/security_tools/twsm/components/entity/generic/actions/edit_theme_risk_coverage}}");
    l.push(addScoreCoverageMetric("Risk Coverage <i class=\"fas fa-balance-scale\"/>", riskCoverageMultiplier, riskCoverageMultiplier * riskCoveragePenaltyMultiplier, daysSinceRiskCoverageAssessment));
    l.push("</$button>");
    l.push("<$button class=\"tc-btn-invisible\">");
    l.push("{{||$:/plugins/security_tools/twsm/components/entity/generic/actions/edit_theme_attack_coverage}}");
    l.push(addScoreCoverageMetric("Attack Coverage <i class=\"fas fa-shield-alt\"/>", attackCoverageMultiplier, attackCoverageMultiplier * attackCoveragePenaltyMultiplier, daysSinceAttackCoverageAssessment));
    l.push("</$button>");

    var renderedHeader = l.join("");
    
    var riskCount = $tw.wiki.filterTiddlers("[title[" + title + "]tagging[]twsm_class[risk]count[]]")[0];
    var maxImpact = $tw.wiki.filterTiddlers("[title[" + title + "]tagging[]twsm_class[risk]twsm_risk_assessment:impact[]maxall[]]")[0];
    if (maxImpact == -Infinity) {
        maxImpact = 0;
    }
    var controlCount = $tw.wiki.filterTiddlers("[title[" + title + "]tagging[]twsm_class[risk]get[controls]enlist-input[]unique[]count[]]")[0];

    return {
        risk_count: riskCount,
        max_impact: maxImpact,
        max_risk_score: Number(maxRiskScore).toFixed(1),
        max_risk_class: risk_utils.score2Class(maxRiskScore, false),
        max_risk_name: risk_utils.score2Name(maxRiskScore, false),
        control_count: controlCount,
        risk_coverage: (riskCoverageMultiplier * riskCoveragePenaltyMultiplier * 100).toFixed(),
        attack_coverage: (attackCoverageMultiplier * attackCoveragePenaltyMultiplier * 100).toFixed(),
        score: score,
        rendered_header: renderedHeader,
        score_calculations: utils.twListify(scoreCalculations),
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
