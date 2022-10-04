/*\
created: 20210805211811349
modified: 20211113160847552
tags: 
title: $:/plugins/security_tools/twsm/charts/theme_controls
type: application/javascript
module-type: echarts-component
echarts-refresh-trigger: [twsm_class[theme]twsm_security_score[]twsm_json_field:control_count[]]
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

  var maxControlCount = 0;
  var controlCounts = [];
  $tw.utils.each(
    $tw.wiki.filterTiddlers(
      "[twsm_class[theme]sort[]twsm_security_score[]twsm_json_field:control_count[]]"
    ),
    function (controlCount) {
      maxControlCount = Math.max(maxControlCount, controlCount);
      controlCounts.push(controlCount);
    }
  );

  var indicatorDefinitions = [];
  $tw.utils.each(
    $tw.wiki.filterTiddlers("[twsm_class[theme]]"),
    function (theme) {
      indicatorDefinitions.push({
        text: theme,
        max: maxControlCount,
      });
    }
  );

  var controlCountSeries = {
    type: "radar",
    data: [
      {
        value: controlCounts,
        name: "Controls",
        symbol: "circle",
        symbolSize: 12,
        lineStyle: {
          type: "solid",
        },
        areaStyle: {
          color: "#A0A0A0A0",
        },
        label: {
          show: true,
          formatter: function (p) {
            // console.log(JSON.safeStringify(p));
              return p.value;
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
    color: ["#000000"],
    radar: [
      {
        triggerEvent: true,
        shape: "diamond",
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
      controlCountSeries, 
    ],
  });
};
