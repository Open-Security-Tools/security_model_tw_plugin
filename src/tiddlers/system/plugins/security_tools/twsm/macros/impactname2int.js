/*\
created: 20210719153526828
type: application/javascript
title: $:/plugins/security_tools/twsm/macros/impactname2int.js
tags: 
modified: 20210719160227200
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

exports.name = "impactname2int";

exports.params = [
	{name: "impactname"}
];

/*
Run the macro
*/
exports.run = function(impactname) {
	var dict = {
		"none": "0",
		"insignificant": "1",
		"minor": "2",
		"moderate": "3",
		"major": "4",
		"extreme/catastrophic": "5"
	};
	var c = dict[impactname.toLowerCase()];
	if (typeof c === "undefined") {
	  console.log(`WARNING: impactname2int, unknown key '${impactname}', defaulting to 'extreme/catastrophic=5'`);
	  return 5
	}
	return c
};

})();
