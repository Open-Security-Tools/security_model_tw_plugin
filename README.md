# Security Modelling TW Plugin

This repository is a security model plugin for TiddlyWiki (tw5, https://tiddlywiki.com).
It provides the ability to cross reference risks, vulnerabilities, controls, assurance activities, meetings, tasks and sprints.

The plugin (twsm) provides security modelling functionality.

This repository contains both the plugin code and an example wiki (with some limited documentation).
The demonstration wiki is published via GitHub pages. 
See https://open-security-tools.github.io/security_model_tw_plugin/.

## Configuration Management

The plugin uses semantic versioning (MAJOR.MINOR.PATCH).
Under the hood the MAJOR and MINOR versions relate to interfaces advisories:

* MAJOR denotes a breaking change. When upgrading you will need to something.
* MINOR denotes new functionality which is backwards compatible.
* PATCH is calculated by the number of commits in the main 
branch at the point of release.

The current MAJOR.MINOR version is tracked by [VERSION](./VERSION).
See [CHANGELOG.md](./CHANGELOG.md) for a description of version differences.

The CI/CD process which builds and publishes the plugin uses the  [inject_version.py](./inject_version.py) script to calculate the current version and inject into the plugin.


## Development

* Run `npm install`.
* Run `npm run develop`.
* Navigate to http://localhost:8081 in your web browser.

## Release

* Run `npm install`.
* Run `npm run release`.
* Run `ls -l editions/release/output/`.
       * Output contains both the packaged plugin and the demonstration wiki.

## Removing Thirdflow

Needed because ThirdFlow uses a fancy hierarchy filing system which fails to detect multi-line fields. 

TODO:

1. Plot current build process
2. Plot target build process
3. Make sure extra tiddlers are incorporated

### Current Build Process

```bash
npm run release
ls -l editions/release/output/
```
Release command:

```json
"release": "tiddlywiki editions/release --verbose --build release"
```

Release target (from `editions/release/tiddlywiki.info` build targets):

```json
"--releaseplugins",
"--releasedemowiki"
```

These are commands which are implemented by the thirdflow plugin.

The thirdflow plugin generates the `twsm.tid` and `demowiki.html` files.
It takes the contents of the `src/tiddlers/system/plugins/security_tools/twsm/` directory, but also:

```
[prefix[$:/config/EditTemplateFields/Visibility/twsm_]] $:/core/ui/ViewTemplate/tags [prefix[$:/config/flibbles/relink/fields/twsm_]] [prefix[$:/config/flibbles/relink/macros/twsm]]
```

Which maps to 24 additionsl plugins:

* $:/config/EditTemplateFields/Visibility/twsm_assurance_activity_status
* $:/config/EditTemplateFields/Visibility/twsm_assessment_description
* $:/config/EditTemplateFields/Visibility/twsm_characteristic_class
* $:/config/EditTemplateFields/Visibility/twsm_control_status
* $:/config/EditTemplateFields/Visibility/twsm_error
* $:/config/EditTemplateFields/Visibility/twsm_impact
* $:/config/EditTemplateFields/Visibility/twsm_inherent_class
* $:/config/EditTemplateFields/Visibility/twsm_inherent_name
* $:/config/EditTemplateFields/Visibility/twsm_inherent_score
* $:/config/EditTemplateFields/Visibility/twsm_likelihood
* $:/config/EditTemplateFields/Visibility/twsm_mitigation_description
* $:/config/EditTemplateFields/Visibility/twsm_mitigation_percent
* $:/config/EditTemplateFields/Visibility/twsm_residual_class
* $:/config/EditTemplateFields/Visibility/twsm_residual_name
* $:/config/EditTemplateFields/Visibility/twsm_residual_score
* $:/config/EditTemplateFields/Visibility/twsm_risk_calculation_version
* $:/config/EditTemplateFields/Visibility/twsm_simpleriskid
* $:/config/EditTemplateFields/Visibility/twsm_temporal_class
* $:/core/ui/ViewTemplate/tags
* $:/config/flibbles/relink/fields/twsm_assessment_description
* $:/config/flibbles/relink/fields/twsm_mitigation_description
* $:/config/flibbles/relink/macros/twsmid/title
* $:/config/flibbles/relink/macros/twsmname/title
* $:/config/flibbles/relink/macros/twsmtheme/title

Summary:

* The edit template field visibility is not important because there are better ways of implementing this (using the more modern template override technique). **Not important**
* The tags override is used to hide twsm entity tag references. A better mechanism would be to use a bespoke field to store cross-references which need to be presented differently. **Not important**
* The relink fields are important to maintain model integrity through renames.



