/*\
created: 20210719190017982
type: application/javascript
title: $:/plugins/security_tools/twsm/macros/calculate_risk_name.js
tags: 
modified: 20210725201204815
module-type: macro

Macro to convert an impact name to integer

\*/
(function(){

/*jslint node: true, browser: true */
/*global $tw: false */
"use strict";

/*
Information about this macro
*/

exports.name = "calculate_risk_name";

exports.params = [
	{name: "impact"},
	{name: "likelihood"},
	{name: "mitigation"}
];

var impactDict = {
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

var likelihoodDict = {
  "unknown": 0,
	"remote": 1,
	"rare": 1,
	"unlikely": 2,
	"possible": 3,
	"credible": 3,
	"likely": 4,
	"almost certain": 5
};

/*
Run the macro
*/
exports.run = function(impact, likelihood, mitigation) {

	var i = impactDict[impact.toLowerCase()];
	if (typeof i === "undefined") {
	  return "Error (Bad Impact)";
	}

	var l = likelihoodDict[likelihood.toLowerCase()];
	if (typeof l === "undefined") {
	  return "Error (Bad Likelihood)";
	}

  var m = (100 - Math.max(Math.min(+mitigation, 100.0), 0)) / 100.0;

	// SimpleRisk calculation (https://www.simplerisk.com/blog/normalizing-risk-scoring-across-different-methodologies)
	var r = ((i * l * 10) / 25) * m;
	if (r <= 0) {
	  return "Unknown";
	}	
	if (r <= 3.6) {
		return "Low";
	}
	if (r <= 6.4) {
	  return "Medium";
	}
	return "High";
};

})();
