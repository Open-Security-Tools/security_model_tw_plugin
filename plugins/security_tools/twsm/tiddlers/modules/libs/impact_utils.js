/*\
created: 20220722215603976
title: $:/plugins/security_tools/twsm/impact_utils.js
type: application/javascript
tags: 
modified: 20220723070445305
module-type: library
\*/

(function(){

"use strict";


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

exports.impactDict = impactDict;
exports.impact2Name = impact2Name;
exports.impact2Class = impact2Class;

})();