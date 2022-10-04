/*\
created: 20210805211811349
modified: 20211113160847552
tags: 
title: $:/plugins/security_tools/twsm/charts/radar_themes
type: application/javascript
module-type: echarts-component
echarts-refresh-trigger: [twsm_class[theme]twsm_security_score[]]
\*/

JSON.safeStringify = (obj, indent = 2) => {
  let cache = [];
  const retVal = JSON.stringify(
    obj,
    (key, value) =>
      typeof value === "object" && value !== null
        ? cache.includes(value)
          ? undefined // Duplicate reference found, discard key
          : cache.push(value) && value // Store value in our collection
        : value,
    indent
  );
  cache = null;
  return retVal;
};

exports.onMount = function (echart) {
  var state = {};
  echart.on("click", function (event) {
    if (event.componentType === "radar") {
      var themeName = event.name;
      new $tw.Story().navigateTiddler(themeName);
      // console.log("On click: " + JSON.safeStringify(event));
    }
  });
  return state;
};

exports.shouldUpdate = function (_, changedTiddlers) {
  return $tw.utils.count(changedTiddlers) > 0;
};

// See https://github.com/ecomfe/echarts-wordcloud
exports.onUpdate = function (echart) {
  var indicatorDefinitions = [];
  $tw.utils.each(
    $tw.wiki.filterTiddlers("[twsm_class[theme]sort[]]"),
    function (theme) {
      indicatorDefinitions.push({
        text: theme,
        max: 100,
      });
    }
  );

  var themeScores = [];
  $tw.utils.each(
    $tw.wiki.filterTiddlers(
      "[twsm_class[theme]sort[]twsm_security_score[]twsm_json_field:score[]]"
    ),
    function (score) {
      themeScores.push(score);
    }
  );

  var themeRiskCoverage = [];
  $tw.utils.each(
    $tw.wiki.filterTiddlers(
      "[twsm_class[theme]sort[]twsm_security_score[]twsm_json_field:risk_coverage[]]"
    ),
    function (riskCoverage) {
      themeRiskCoverage.push(riskCoverage);
    }
  );

  var themeAttackCoverage = [];
  $tw.utils.each(
    $tw.wiki.filterTiddlers(
      "[twsm_class[theme]sort[]twsm_security_score[]twsm_json_field:attack_coverage[]]"
    ),
    function (attackCoverage) {
      themeAttackCoverage.push(attackCoverage);
    }
  );

  var themeRisks = [];
  $tw.utils.each(
    $tw.wiki.filterTiddlers(
      "[twsm_class[theme]sort[]twsm_security_score[]twsm_json_field:max_risk_score[]]"
    ),
    function (score) {
      // We normalise
      themeRisks.push(score * 10.0);
    }
  );

  var themeImpacts = [];
  $tw.utils.each(
    $tw.wiki.filterTiddlers(
      "[twsm_class[theme]sort[]twsm_security_score[]twsm_json_field:max_impact[]]"
    ),
    function (score) {
      // We normalise
      themeImpacts.push(score * 20.0);
    }
  );

  var scoreSeries = {
    type: "radar",
    data: [
      {
        value: themeScores,
        name: "Score",
        symbol: "circle",
        symbolSize: 12,
        lineStyle: {
          type: "solid",
        },
        areaStyle: {
          color: "#A0A0CAA0",
        },
        label: {
          show: false,
          formatter: function (p) {
            // console.log(JSON.safeStringify(p));
              return p.value;
          }
        },
      },
    ],
  }

  var riskCoverageSeries = {
    type: "radar",
    data: [
      {
        value: themeRiskCoverage,
        name: "Risk Coverage",
        symbol: "square",
        symbolSize: 12,
        lineStyle: {
          type: "dashed",
        },
        label: {
          show: false,
        },
      },
    ],
  }

  var attackCoverageSeries = {
    type: "radar",
    data: [
      {
        value: themeAttackCoverage,
        name: "Attack Coverage",
        symbol: "square",
        symbolSize: 12,
        lineStyle: {
          type: "dashed",
        },
        label: {
          show: false,
        },
      },
    ],
  }


  var riskSeries = {
    type: "radar",
    data: [
      {
        value: themeRisks,
        name: "Maximum Risk",
        symbol: "circle",
        symbolSize: 12,
        lineStyle: {
          type: "solid",
        },
        areaStyle: {
          color: "#d3540080",
        },
        label: {
          show: false,
          formatter: function (p) {
            // console.log(JSON.safeStringify(p));
              return p.value / 10;
          }
        },
      },
    ],
  }
  var impactSeries = {
    type: "radar",
    data: [
      {
        value: themeImpacts,
        name: "Maximum Impact",
        symbol: "circle",
        symbolSize: 12,
        lineStyle: {
          type: "solid",
        },
        areaStyle: {
          color: "#FDDA0D80",
        },
        label: {
          show: false,
          formatter: function (p) {
            // console.log(JSON.safeStringify(p));
              return p.value / 20;
          }
        },
      },
    ],
  }



  var isDarkMode = echart.getOption();
  isDarkMode = isDarkMode ? isDarkMode.darkMode !== false : false;
  echart.setOption({
    legend: {
      right: "10%",
      top: "3%",
    },
    color: ["#FDDA0D", "#FF0000", "#0000FF", "#80F0F0D0", "#F07080D0"],
    radar: [
      {
        triggerEvent: true,
        shape: "circle",
        indicator: indicatorDefinitions,
        center: ["50%", "50%"],
        radius: 190,
        axisName: {
          color: "#fff",
          backgroundColor: "#666",
          borderRadius: 3,
          padding: [3, 5],
        },
      },
    ],
    series: [
      impactSeries, riskSeries, scoreSeries, riskCoverageSeries, attackCoverageSeries, 
    ],
  });
};
