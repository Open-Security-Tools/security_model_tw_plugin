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

var attack_utils = require("$:/plugins/security_tools/twsm/attack_utils.js");
var impact_utils = require("$:/plugins/security_tools/twsm/impact_utils.js")
var Widget = require("$:/core/modules/widgets/widget.js").widget;
var utils = require("$:/plugins/security_tools/twsm/utils.js");

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
            var risk = attackTree.root.renderRiskAssessment(impact_utils.impactDict[tiddler.fields.twsm_impact]);

            var setFields = {
                controls: utils.twListify(attackTree.controls),
                sub_trees: utils.twListify(attackTree.sub_trees),
                renderer: attackTree.renderer,
                rendered_attack_tree: rendered.root.render().join("\n"),
                untreated_likelihood_lower: rendered.root.likelihood.untreated.lower,
                untreated_likelihood_upper: rendered.root.likelihood.untreated.upper,
                treated_likelihood_lower: rendered.root.likelihood.treated.lower,
                treated_likelihood_upper: rendered.root.likelihood.treated.upper,
                untreated_risk: risk.untreated_risk,
                treated_risk: risk.treated_risk,
            }

            for (const [key, value] of Object.entries(setFields)) {
                self.wiki.setText(self.actionTiddler, key, undefined, value, options);
            }

            // console.log("Attack tree: " + attackTree.root.likelihood.treated.phia);
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
