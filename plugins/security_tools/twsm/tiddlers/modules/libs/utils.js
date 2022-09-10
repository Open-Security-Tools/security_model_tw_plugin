/*\
created: 20220722215603976
title: $:/plugins/security_tools/twsm/utils.js
type: application/javascript
tags: 
modified: 20220723070445305
module-type: library
\*/

(function(){

"use strict";

function twListify(l) {
    var p = l.map(function(x){ return "[[" + x + "]]";});
    return p.join(" ");
}

exports.twListify = twListify;

})();
