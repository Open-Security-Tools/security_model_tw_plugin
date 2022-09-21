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
var Widget = require("$:/core/modules/widgets/widget.js").widget;
var utils = require("$:/plugins/security_tools/twsm/utils.js");

class ModelIntegrity {
    constructor() {
        this.updatedNodes = [];
    }

    updateControl(tiddler) {

    }

    updateRisk(tiddler) {

    }

    updateAttack(tiddler) {

    }

    updateEntity(tiddler) {
        if (!tiddler.fields) {
            return;
        }
        if (tiddler.fields.twsm_class === "control") {
            this.updateControl(tiddler);
        } else if (tiddler.fields.twsm_class === "risk") {
            this.updateRisk(tiddler);
        } else if (tiddler.fields.twsm_class === "attack") {
            this.updateAttack(tiddler);
        }
    }
}


var UpdateRiskWidget = function(parseTreeNode,options) {
    this.initialise(parseTreeNode,options);
};

var UpdateAttackWidget = function(parseTreeNode,options) {
    this.initialise(parseTreeNode,options);
};

var UpdateControlWidget = function(parseTreeNode,options) {
    this.initialise(parseTreeNode,options);
};

/*
Inherit from the base widget class
*/
UpdateRiskWidget.prototype = new Widget();
UpdateAttackWidget.prototype = new Widget();
UpdateControlWidget.prototype = new Widget();

/*
Render this widget into the DOM
*/
UpdateRiskWidget.prototype.render = function(parent,nextSibling) {
    this.computeAttributes();
    this.execute();
};
UpdateAttackWidget.prototype.render = function(parent,nextSibling) {
    this.computeAttributes();
    this.execute();
};
UpdateControlWidget.prototype.render = function(parent,nextSibling) {
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
UpdateAttackWidget.prototype.execute = function() {
    this.actionTiddler = this.getAttribute("$tiddler") || (!this.hasParseTreeNodeAttribute("$tiddler") && this.getVariable("currentTiddler"));
    this.actionTimestamp = this.getAttribute("$timestamp","yes") === "yes";
};
UpdateControlWidget.prototype.execute = function() {
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
UpdateAttackWidget.prototype.refresh = function(changedTiddlers) {
    // Nothing to refresh
    return this.refreshChildren(changedTiddlers);
};
UpdateControlWidget.prototype.refresh = function(changedTiddlers) {
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
            var attackTree = attack_utils.parse_attack_tree(tiddler.fields.attack_tree);

            var setFields = {
                controls: utils.twListify(attackTree.controls),
                sub_trees: utils.twListify(attackTree.sub_trees),
                renderer: attackTree.renderer,
                rendered_attack_tree: attackTree.root.render(),
                untreated_likelihood_lower: attackTree.root.likelihood.untreated.lower,
                untreated_likelihood_upper: attackTree.root.likelihood.untreated.upper,
                treated_likelihood_lower: attackTree.root.likelihood.treated.lower,
                treated_likelihood_upper: attackTree.root.likelihood.treated.upper,
            }

            for (const [key, value] of Object.entries(setFields)) {
                self.wiki.setText(self.actionTiddler, key, undefined, value, options);
            }
        }
    }
    return true; // Action was invoked
};

UpdateAttackWidget.prototype.invokeAction = function(triggeringWidget,event) {
    var self = this,
        options = {};

    if(this.actionTiddler) {
        var tiddler = $tw.wiki.getTiddler(this.actionTiddler);
        if (tiddler && tiddler.fields.twsm_class === "attack") {
            var attackTree = attack_utils.parse_attack_tree(tiddler.fields.attack_tree);

            var setFields = {
                controls: utils.twListify(attackTree.controls),
                sub_trees: utils.twListify(attackTree.sub_trees),
                renderer: attackTree.renderer,
                rendered_attack_tree: attackTree.root.render(),
                untreated_likelihood_lower: attackTree.root.likelihood.untreated.lower,
                untreated_likelihood_upper: attackTree.root.likelihood.untreated.upper,
                treated_likelihood_lower: attackTree.root.likelihood.treated.lower,
                treated_likelihood_upper: attackTree.root.likelihood.treated.upper,
            }

            for (const [key, value] of Object.entries(setFields)) {
                self.wiki.setText(self.actionTiddler, key, undefined, value, options);
            }
        }
    }
    return true; // Action was invoked
};

UpdateControlWidget.prototype.invokeAction = function(triggeringWidget,event) {
    var self = this,
        options = {};

    if(this.actionTiddler) {
        var tiddler = $tw.wiki.getTiddler(this.actionTiddler);
        if (tiddler && tiddler.fields.twsm_class === "control") {

            // Find the objects which reference this control and update them recursively
            // Risks and attacks reference this control in 'controls' field.


        }
    }
    return true; // Action was invoked
};


exports["action-updaterisk"] = UpdateRiskWidget;

exports["action-updateattack"] = UpdateAttackWidget;

exports["action-updatecontrol"] = UpdateControlWidget;


})();
