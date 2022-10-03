/*\
created: 20210805211811349
modified: 20211113160847552
tags: 
title: $:/plugins/security_tools/twsm/test_data2
type: application/javascript
module-type: echarts-component
echarts-refresh-trigger: [twsm_class[theme]twsm_security_score[]twsm_json_field:score[]]
\*/

exports.onMount = function (echart) {
  var state = {};
  echart.on("click", function (event) {
    console.log("On click: " + event.data.name);
    new $tw.Story().navigateTiddler(event.data.name);
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
    $tw.wiki.filterTiddlers("[twsm_class[theme]]"),
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
      "[twsm_class[theme]twsm_security_score[]twsm_json_field:score[]]"
    ),
    function (score) {
      themeScores.push(score);
    }
  );

  var isDarkMode = echart.getOption();
  isDarkMode = isDarkMode ? isDarkMode.darkMode !== false : false;
  echart.setOption({
    legend: {
      right: "10%",
      top: "3%",
    },
    color: ["#0000FF"],
    radar: [
      {
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
      {
        type: "radar",
        data: [
          {
            value: themeScores,
            name: "Score (0 = bad, 100 = good)",
            symbol: "circle",
            symbolSize: 12,
            lineStyle: {
              type: "dashed",
            },
            areaStyle: {
              color: "#A0A0CAA0",
            },
            label: {
              show: true,
            },
          },
        ],
      },
    ],
  });
};
