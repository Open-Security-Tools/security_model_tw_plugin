/*\
title: $:/core/modules/widgets/actions.js
type: application/javascript
module-type: widget

Action widget to update dependent risks of a control.

\*/
(function(){

/*jslint node: true, browser: true */
/*global $tw: false */
"use strict";

var risk_utils = require("$:/plugins/security_tools/twsm/risk_utils.js");
var attack_utils = require("$:/plugins/security_tools/twsm/attack_utils.js");
var Widget = require("$:/core/modules/widgets/widget.js").widget;

var UpdateRiskWidget = function(parseTreeNode,options) {
    this.initialise(parseTreeNode,options);
};

/*
Inherit from the base widget class
*/
UpdateRiskWidget.prototype = new Widget();

/*
Render this widget into the DOM
*/
UpdateRiskWidget.prototype.render = function(parent,nextSibling) {
    this.computeAttributes();
    this.execute();
};

/*
Compute the internal state of the widget
*/
UpdateRiskWidget.prototype.execute = function() {
    this.actionTiddler = this.getAttribute("$tiddler") || (!this.hasParseTreeNodeAttribute("$tiddler") && this.getVariable("currentTiddler"));
    this.actionTimestamp = this.getAttribute("$timestamp","yes") === "yes";
};

/*
Refresh the widget by ensuring our attributes are up to date
*/
UpdateRiskWidget.prototype.refresh = function(changedTiddlers) {
    // Nothing to refresh
    return this.refreshChildren(changedTiddlers);
};

/*
Invoke the action associated with this widget
*/
UpdateRiskWidget.prototype.invokeAction = function(triggeringWidget,event) {
    var self = this,
        options = {};
    if(this.actionTiddler) {
        var tiddler = $tw.wiki.getTiddler(this.actionTiddler);
        if (tiddler && tiddler.fields.twsm_class === "risk") {
            console.log("Processing risk: " + this.actionTiddler + " " + JSON.stringify(tiddler));
            var attackTree = attack_utils.parse_attack_tree(tiddler.fields.attack_tree);
            var riskAssessment = risk_utils.RiskAssessment()
            console.log("Attack tree: " + attackTree.root.likelihood.treated.phia);
        }


        // options.suppressTimestamp = !this.actionTimestamp;
        // if((typeof this.actionField == "string") || (typeof this.actionIndex == "string")  || (typeof this.actionValue == "string")) {
        //     this.wiki.setText(this.actionTiddler,this.actionField,this.actionIndex,this.actionValue,options);
        // }
        // $tw.utils.each(this.attributes,function(attribute,name) {
        //     if(name.charAt(0) !== "$") {
        //         self.wiki.setText(self.actionTiddler,name,undefined,attribute,options);
        //     }
        // });
    }
    return true; // Action was invoked
};

exports["action-updaterisk"] = UpdateRiskWidget;

})();
