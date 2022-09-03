/*\
created: 20210723152326655
type: application/javascript
title: $:/plugins/security_tools/twsm/twsm_trees.js
tags: 
modified: 20220723070445305
module-type: filteroperator
\*/

(function(){

"use strict";

function parse_attack_tree(tiddler, title) {
    if (!tiddler) {
        return;
    }
    if (tiddler.fields.twsm_class !== "risk") {
        return;
    }

    var obj = {
        computed_attack_tree: tiddler.fields.attack_tree,
        likelihood: "0.245",
        controls: "[[Control1]] [[Control2]] [[Control3]]",
        attack_sub_trees: "[[Attack Sub Tree 1]] [[Attack Sub Tree 2]] [[Attack Sub Tree 3]]" 
    }
    return obj;
}

exports.twsmprocesstree = function(source, operator, options) {
    var result = [];

    source (function(tiddler, title) {
        var obj = parse_attack_tree(tiddler, title);
        if (obj) {
            result.push(JSON.stringify(obj));
        }
    })
    return result;
}

exports.twsmextractcontrols = function(source, operator, options) {
    var result = [];

    source (function(tiddler, title) {
        var s = JSON.parse(title);
        result.push(s.controls);
    })
    return result;
}


exports.twsmextractcomputedattacktree = function(source, operator, options) {
    var result = [];

    source (function(tiddler, title) {
        var s = JSON.parse(title);
        result.push(s.computed_attack_tree);
    })
    return result;
}

exports.twsm_encode = function(source, operator, options) {
    var result = [];

    source (function(tiddler, title) {
        result.push(title.replaceAll('\n', '\\n'));
    })
    return result;
}

exports.twsm_decode = function(source, operator, options) {
    var result = [];

    source (function(tiddler, title) {
        result.push(title.replaceAll('\\n', '\n'));
    })
    return result;    
}

})();