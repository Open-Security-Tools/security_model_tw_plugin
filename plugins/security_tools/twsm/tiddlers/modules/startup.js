/*\
created: 20210723152326655
type: application/javascript
title: $:/plugins/security_tools/twsm/startup.js
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


function getRandomInt(max) {
	return Math.floor(Math.random() * max);
}


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

	// Default impact
	var impact = cf["twsm_impact"];
	if (impact === undefined) {
		impact = "Unknown"
		nf["twsm_impact"] = impact;
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

function processAttack(cf, nf) {
	return nf;
}

exports.startup = function() {
	// Add hooks for trapping user actions
	$tw.hooks.addHook("th-saving-tiddler",function(tiddler, oldTiddler) {

		// Is this one of our classes?
		if (tiddler.fields.twsm_class !== undefined) {

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
			} else if (cf.twsm_class === "attack") {
				nf = processAttack(cf, nf);
			}
			return new $tw.Tiddler(tiddler, nf);
		} else {
			return tiddler;
		}
	});
};

})();
