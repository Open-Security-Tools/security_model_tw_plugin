/*\
created: 20220722215603976
title: $:/plugins/security_tools/twsm/likelihood_utils.js
type: application/javascript
tags: 
modified: 20220723070445305
module-type: library
\*/

(function(){

"use strict";


function probability2Hue(probability) {
    // In HSV, 0 = Green, 120 = Red.
    // const hue_start = 180;
    // const hue_end = 220;
    const hue_start = 235;
    const hue_end = 360;
    
    return hue_start + ((hue_end - hue_start) * probability);
}

class Likelihood {
    /**
     * 
     * @param {number} lower 
     * @param {number} upper 
     */
    constructor(lower, upper, phia) {
        this.lower = lower;
        this.lowerHue = probability2Hue(lower);
        this.upper = upper;
        this.upperHue = probability2Hue(upper);
        if (upper === lower) {
            this.tooltip = (upper * 100).toFixed() + "%";
        } else {
            this.tooltip = (lower * 100).toFixed() + "% - " + (upper * 100).toFixed() + "%";
        }

        if (phia === undefined) {
            this.phia = probability2Phia(upper);
        } else {
            this.phia = phia;
        }
    }

    toBandPercentageDescription() {
        return (this.lower * 100).toFixed() + "% - " + (this.upper * 100).toFixed() + "%";
    }

    toBandSimplePercentageDescription() {
        return (this.lower * 100).toFixed() + "-" + (this.upper * 100).toFixed() + "%";
        // return (this.lower * 100).toFixed() + "<i class=\"fas fa-arrows-alt-h\"/>" + (this.upper * 100).toFixed();
    }

    buildLikelihoodBackgroundStyle() {
        return "background: linear-gradient(90deg, hsl(" + this.lowerHue + ", 100%, 80%) 0%, hsl(" + this.upperHue + ",100%,80%) 100%);";
    }
    
}

const likelihood_calibration = [
    {
        band: new Likelihood(0.0, 0.0, "Impossible"),
        names: ["impossible"],
    }, {
        band: new Likelihood(0.0, 0.075, "Remote Chance"),
        names: ["remote chance", "rc", "remote"],
    }, {
        band: new Likelihood(0.075, 0.225, "Highly Unlikely"),
        names: ["highly unlikely", "hu", "rare"],
    }, {
        band: new Likelihood(0.225, 0.375, "Unlikely"),
        names: ["unlikely", "u"],
    }, {
        band: new Likelihood(0.375, 0.525, "Realistic Possibility"),
        names: ["realistic possibility", "rp", "credible", "possible"],
    }, {
        band: new Likelihood(0.525, 0.775, "Likely"),
        names: ["likely", "l"],
    }, {
        band: new Likelihood(0.775, 0.925, "Highly Likely"),
        names: ["highly likely", "hl"],
    }, {
        band: new Likelihood(0.925, 1, "Almost Certain"),
        names: ["almost certain", "ac"],
    }
];


class ComplexLikelihood {
    /**
     * 
     * @param {Likelihood} untreated 
     * @param {Likelihood} treated 
     */
    constructor(untreated, treated) {
        this.untreated = untreated;
        this.treated = treated;
    }

    /**
     * 
     * @returns {bool}
     */
    isControlled() {
        return (this.treated.upper < this.untreated.upper) && (this.untreated.upper !== 1.0) && (this.untreated.lower !== 1.0);
    }

    calculateControlProportion() {
        // Amount of control is 1 - likelihood of attack.
        // Note that untreated will always be larger than treated.
        // Therefore, proportion of control is (Untreated - Treated) / (1 - Treated)
        return ((this.untreated.upper - this.treated.upper) * 100) / (1 - this.treated.upper);
    }
}

const NULL_LIKELIHOOD = new Likelihood(1.0, 1.0);
const NULL_COMPLEX_LIKELIHOOD = new ComplexLikelihood(NULL_LIKELIHOOD, NULL_LIKELIHOOD);


class LikelihoodError extends Error {
    constructor(message) {
        super(message);
    }
}


/**
 * 
 * @param {String} likelihood 
 * @returns {Likelihood}
 */
function phia2Likelihood(phia) {
    phia = phia.trim().toLowerCase();
    for (const b of likelihood_calibration) {
        if (b.names.includes(phia)) {
            // Return the upper
            return b.band;
        }
    }
    throw new LikelihoodError("Unsupported PHIA likelihood (" + phia + ")");
}

/**
 * 
 * @param {Number} probability 
 * @returns {String}
 */
function probability2Phia(probability) {
    var c = "Impossible";
    for (const b of likelihood_calibration) {
        if ((probability > b.band.lower) && (probability <= b.band.upper)) {
            c = b.band.phia;
            break;
        }
    }
    return c;
}

function calculateControlFailureLikelihood(failureLikelihood, isIdea) {
    failureLikelihood = failureLikelihood || "";
    // If it is an idea, then default is null (1.0).
    var probability = NULL_LIKELIHOOD;

    try {
        if (isIdea !== "yes") {
            probability = phia2Likelihood(failureLikelihood);
        }

    } catch (objError) {
        if (objError instanceof LikelihoodError) {
            // Do nothing - leave clamped at 1.0.
        } else {
            throw(objError);
        }
    }
    return probability.phia;
}

exports.calculateControlFailureLikelihood = calculateControlFailureLikelihood;
exports.phia2Likelihood = phia2Likelihood;
exports.probability2Phia = probability2Phia;
exports.Likelihood = Likelihood;
exports.ComplexLikelihood = ComplexLikelihood;
exports.NULL_COMPLEX_LIKELIHOOD = NULL_COMPLEX_LIKELIHOOD;
exports.NULL_LIKELIHOOD = NULL_LIKELIHOOD;
exports.LikelihoodError = LikelihoodError;


})();