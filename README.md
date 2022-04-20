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

