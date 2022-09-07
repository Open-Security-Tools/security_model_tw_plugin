/*\
created: 20210723152326655
type: application/javascript
title: $:/plugins/security_tools/twsm/twsm.js
tags: 
modified: 20210723155538045
module-type: startup

A startup module add security model field processing during tiddler save

\*/
(function(){

/*jslint node: true, browser: true */
/*global $tw: false */
"use strict";

// Export name and synchronous status
exports.name = "twsm";
exports.platforms = ["browser"];
exports.after = ["startup"];
exports.synchronous = true;

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

var LOW_THRESHOLD = 3.6;
var MEDIUM_THRESHOLD = 6.4;

function getRandomInt(max) {
	return Math.floor(Math.random() * max);
}

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

function score2class(score) {
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

const twsmClasses = ["risk", "control", "assurance_activity", "theme", "attack_tree", "vulnerability"];


function checkId(cf, nf, draftF) {
	var currentId = cf["twsm_id"];

	// Detecting duplicates on the twsm_id field is made more complicated when renaming because both the old tiddler object and 
	// draft of objects need to be discarded.
	var duplicateFilter = "[has[twsm_class]twsm_id[" + currentId + "]!title[" + draftF["draft.of"] + "]!title[" + draftF["title"] + "]]";
	var results = $tw.wiki.filterTiddlers(duplicateFilter);
	var duplicateId = results[0];

	// Autogenerate a reference id
	if ((currentId == undefined) || (currentId === "") || (duplicateId)) {

		if (duplicateId) {
			console.log("Duplicate id detected (duplicate=" + duplicateId + "), resetting id for '" + cf.title + ";");
		}

		var maxRefId = $tw.wiki.filterTiddlers("[has[twsm_class]get[twsm_id]maxall[]]");
		var candidate = maxRefId[0];

		// Minus infinity passed back as a string
		if (candidate === "-Infinity") {
			candidate = 1000;
		}
		else {
			// Force pass as number
			candidate = +candidate + 1;
		}
		nf["twsm_id"] = candidate;
	}

	return nf;
}

function processRisk(cf, nf) {
	// Test edit another tiddler...
	// var tmpTiddler = "TempTiddler";
	// var t = $tw.wiki.getTiddler(tmpTiddler);
	// var newFields = {}
	// newFields["newField"] = "A new field Value!"
	// $tw.wiki.addTiddler(new $tw.Tiddler(t,newFields));


	// We want to hide the body (we incorporate it into a view)
	if (cf["hide-body"] === undefined) {
		nf["hide-body"] = "yes";
	}

	// Default impact
	var impact = cf["twsm_impact"];
	if (impact === undefined) {
		impact = "Unknown"
		nf["twsm_impact"] = impact;
	}

	// Default likelihood
	var likelihood = cf["twsm_likelihood"]; 
	if (likelihood === undefined) {
		likelihood = "Unknown";
		nf["twsm_likelihood"] = likelihood;
	}

	// Default mitigation
	var mitigation = cf["twsm_mitigation_percent"];
	if (mitigation === undefined) {
		mitigation = "0"
		nf["twsm_mitigation_percent"] = mitigation;
	}

	// Calculate score
	var impactScore = impactDict[impact.toLowerCase()];
	var likelihoodScore = likelihoodDict[likelihood.toLowerCase()];

	if (impactScore === undefined) {
		nf["twsm_error"] = "Bad impact"
	}
	else if (likelihoodScore === undefined) {
		nf["twsm_error"] = "Bad likelihood"
	}
	else {
		var inherentScore = ((impactScore * likelihoodScore * 10) / 25);
		var inherentName = score2Name(inherentScore);
		var inherentClass = score2class(inherentScore);

		nf["twsm_inherent_score"] = (Math.round((inherentScore + Number.EPSILON) * 100) / 100).toString();
		nf["twsm_inherent_name"] = inherentName;
		nf["twsm_inherent_class"] = inherentClass;

		var m = (100 - Math.max(Math.min(+mitigation, 100.0), 0)) / 100.0;

		var residualScore = ((impactScore * likelihoodScore * 10) / 25) * m;
		var residualName = score2Name(residualScore);
		var residualClass = score2class(residualScore);

		nf["twsm_residual_score"] = (Math.round((residualScore + Number.EPSILON) * 100) / 100).toString();
		nf["twsm_residual_name"] = residualName;
		nf["twsm_residual_class"] = residualClass;

		nf["twsm_risk_calculation_version"] = 1;
		nf["twsm_error"] = ""
	}
	return nf;
}

function processControl(cf, nf) {
	return nf;
}

function processAssuranceActivity(cf, nf) {
	return nf;
}

function processTheme(cf, nf) {

	var hue_colour = cf["twsm_hue"];
	if (hue_colour == undefined) {
		hue_colour = getRandomInt(360);
		nf["twsm_hue"] = hue_colour;
	}

	return nf;
}

function processAttackTree(cf, nf) {
	return nf;
}

exports.startup = function() {
	// Add hooks for trapping user actions
	$tw.hooks.addHook("th-saving-tiddler",function(tiddler, oldTiddler) {

		// Is this one of our classes?
		if (tiddler.fields.twsm_class !== undefined) {
		// if (twsmClasses.includes(tiddler.fields.twsm_class)) {

			// We'll manage current and new fields as dictionaries.
			var cf = tiddler.fields;
			var nf = {}

			// Make sure the id is set and unique.
			nf = checkId(cf, nf, oldTiddler.fields);

			if (cf.twsm_class === "risk") {
				nf = processRisk(cf, nf);
			} else if (cf.twsm_class === "control") {
				nf = processControl(cf, nf);
			} else if (cf.twsm_class === "assurance_activity") {
				nf = processAssuranceActivity(cf, nf);
			} else if (cf.twsm_class === "theme") {
				nf = processTheme(cf, nf);
			} else if (cf.twsm_class === "attack_tree") {
				nf = processAttackTree(cf, nf);
			}
			return new $tw.Tiddler(tiddler, nf);
		} else {
			return tiddler;
		}
	});
};

})();
