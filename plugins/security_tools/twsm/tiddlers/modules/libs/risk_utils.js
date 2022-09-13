/*\
created: 20220722215603976
title: $:/plugins/security_tools/twsm/risk_utils.js
type: application/javascript
tags: 
modified: 20220723070445305
module-type: library
\*/

(function(){

"use strict";

var impact_utils = require("$:/plugins/security_tools/twsm/impact_utils.js")
var likelihood_utils = require("$:/plugins/security_tools/twsm/likelihood_utils.js");
var utils = require("$:/plugins/security_tools/twsm/utils.js");

var LOW_THRESHOLD = 3.6;
var MEDIUM_THRESHOLD = 6.4;

function score2Name(score, includeUnknown=true) {
	if (includeUnknown && (score <= 0)) {
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

function score2Class(score, includeUnknown=true) {
	if (includeUnknown && (score <= 0)) {
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

        // If a risk is undefined, then leave it alone.
        // if (this.treatedRiskForCalculations == 0.0) {
        //     this.treatedRiskForCalculations = 10.0;
        // }

        this.treatedClass = score2Class(this.treatedRisk);
        this.treatedName = score2Name(this.treatedRisk);
        this.untreatedClass = score2Class(this.untreatedRisk);
        this.untreatedName = score2Name(this.untreatedRisk);

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
        l.push(utils.generateRiskMetric(this.treatedClass, "Treated Risk", this.treatedRisk, this.treatedName, ""));
        l.push(utils.generateRiskMetric(this.untreatedClass, "Untreated Risk", this.untreatedRisk, this.untreatedName, ""));
        l.push(utils.generateRiskMetric(this.impactClass, "Impact", this.impact, this.impactName, ""));
    
        l.push(utils.generateRiskMetric("", "Likelihood", treatedBand, this.treatedLikelihood.phia, treatedBackgroundStyle));
        // l.push(generateRiskMetric("", "Untreated Likelihood", untreatedBand, this.untreatedLikelihood.phia, untreatedBackgroundStyle));

        return l.join("");
    }

}

exports.score2Class = score2Class;
exports.score2Name = score2Name;
exports.RiskAssessment = RiskAssessment;

})();