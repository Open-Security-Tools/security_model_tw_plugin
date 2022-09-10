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

exports.score2Class = score2Class;
exports.score2Name = score2Name;
exports.generateRiskMetric = generateRiskMetric;


})();