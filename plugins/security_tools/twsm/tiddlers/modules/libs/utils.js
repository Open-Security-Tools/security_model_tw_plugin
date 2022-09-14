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

function daysSince(value) {
    if (value === undefined) {
        return undefined;
    }
    var today = (new Date()).setHours(0, 0, 0, 0);
    var reviewed = (new Date(($tw.utils.parseDate(value)))).setHours(0, 0, 0, 0);
    return Math.round((today - reviewed) / (1000*60*60*24));
}

function generateRiskMetric(metricClass, header, metric, footer, style) {
    return "<div class=\"twsm_risk_metric " + metricClass + "\" style=\"" + style + "\"><span class=\"metric_header\">" + header + "</span><span class=\"metric_value\">" + metric + "</span><span class=\"metric_footer\">" + footer + "</span></div>";
}


exports.twListify = twListify;
exports.daysSince = daysSince;
exports.generateRiskMetric = generateRiskMetric;

})();
