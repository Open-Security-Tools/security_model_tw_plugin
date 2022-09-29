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
var risk_utils = require("$:/plugins/security_tools/twsm/risk_utils.js");
var Widget = require("$:/core/modules/widgets/widget.js").widget;
var utils = require("$:/plugins/security_tools/twsm/utils.js");

class ModelIntegrity {
    constructor() {
        this.processedNodes = new Set();
    }

    updateControl(tiddler, title) {
        console.log("Updating control '" + title + "'");
        // Find attacks or risks which reference this control
        var entities = $tw.wiki.filterTiddlers("[title[" + title + "]listed[controls]]");
        for (let entityTitle of entities) {
            var entityTiddler = $tw.wiki.getTiddler(entityTitle);
            this.updateEntity(entityTiddler, entityTitle);
        }
    }

    _processAttackTree(tiddler, title) {
        var attackTree = attack_utils.parse_attack_tree(tiddler.fields.attack_tree);

        var setFields = {
            controls: utils.twListify(attackTree.controls),
            node_count: attackTree.node_count,
            accumulated_controls: utils.twListify(attackTree.accumulated_controls),
            sub_trees: utils.twListify(attackTree.sub_trees),
            accumulated_sub_trees: utils.twListify(attackTree.accumulated_sub_trees),
            renderer: attackTree.renderer,
            rendered_attack_tree: attackTree.root.render(),
            untreated_likelihood_lower: attackTree.root.likelihood.untreated.lower,
            untreated_likelihood_upper: attackTree.root.likelihood.untreated.upper,
            treated_likelihood_lower: attackTree.root.likelihood.treated.lower,
            treated_likelihood_upper: attackTree.root.likelihood.treated.upper,
        }

        for (const [key, value] of Object.entries(setFields)) {
            $tw.wiki.setText(title, key, undefined, value, {});
        }
    }

    updateRisk(tiddler, title) {
        console.log("Updating risk '" + title + "'");
        this._processAttackTree(tiddler, title);
        // Nothing else to do. Rest of risk is dynamically calculated.

        var tiddler = $tw.wiki.getTiddler(title);
        var assessment = new risk_utils.RiskAssessment(tiddler.fields);

        var setFields = {
            treated_risk: String(assessment.treatedRisk)
        }

        for (const [key, value] of Object.entries(setFields)) {
            $tw.wiki.setText(title, key, undefined, value, {});
        }
    }

    updateAttack(tiddler, title) {
        console.log("Updating attack '" + title + "'");
        // Detect circular references...
        if (this.processedNodes.has(title)) {
            console.log("Circular reference for '" + title + "'");
            return;
        }

        this._processAttackTree(tiddler, title);

        this.processedNodes.add(title);

        // Find attacks or risks which reference this attack tree
        var entities = $tw.wiki.filterTiddlers("[title[" + title + "]listed[sub_trees]]");
        for (let entityTitle of entities) {
            var entityTiddler = $tw.wiki.getTiddler(entityTitle);
            this.updateEntity(entityTiddler, entityTitle);
        }
    }

    updateEntity(tiddler, title) {
        if (!tiddler.fields) {
            return;
        }
        if (tiddler.fields.twsm_class === "control") {
            this.updateControl(tiddler, title);
        } else if (tiddler.fields.twsm_class === "risk") {
            this.updateRisk(tiddler, title);
        } else if (tiddler.fields.twsm_class === "attack") {
            this.updateAttack(tiddler, title);
        }
    }
}


var UpdateWidget = function(parseTreeNode,options) {
    this.initialise(parseTreeNode,options);
};

/*
Inherit from the base widget class
*/
UpdateWidget.prototype = new Widget();

/*
Render this widget into the DOM
*/
UpdateWidget.prototype.render = function(parent,nextSibling) {
    this.computeAttributes();
    this.execute();
};

/*
Compute the internal state of the widget
*/
UpdateWidget.prototype.execute = function() {
    this.actionTiddler = this.getAttribute("$tiddler") || (!this.hasParseTreeNodeAttribute("$tiddler") && this.getVariable("currentTiddler"));
    this.actionTimestamp = this.getAttribute("$timestamp","yes") === "yes";
};

/*
Refresh the widget by ensuring our attributes are up to date
*/
UpdateWidget.prototype.refresh = function(changedTiddlers) {
    // Nothing to refresh
    return this.refreshChildren(changedTiddlers);
};

/*
Invoke the action associated with this widget
*/
UpdateWidget.prototype.invokeAction = function(triggeringWidget,event) {
    if(this.actionTiddler) {
        var tiddler = $tw.wiki.getTiddler(this.actionTiddler);
        if (tiddler && tiddler.fields.twsm_class !== undefined) {
            var m = new ModelIntegrity();
            m.updateEntity(tiddler, this.actionTiddler);
        }
    }
    return true; // Action was invoked
};


exports["action-updatemodel"] = UpdateWidget;

})();
