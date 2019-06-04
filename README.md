# anchore_script

**TL;DR**

bash script to get vulnerability reports from repo. Supports private AWS ECR.

Script asks for ECR address, retrieves repos, sorts images by latest, feeds them to anchore, and retrieve the result which is shown in a nicely formatted HTML. Can retrieve report for all ECR images and a single repo:tag.

![Example screenshot](https://github.com/akerge/anchore_script/raw/master/img/anch_script.png "Example screenshot")

## Scenario

I was tired to see the vulnerability report on the CLI and made this is a handy script to query report(s) from anchore. Supports ECR and dockerhub.

## Prerequisites

* [anchore-cli](https://github.com/anchore/anchore-cli) - saves the trouble of `docker exec anchore-engine anchore cli` every time.

* [anchore engine docker container](https://hub.docker.com/r/anchore/anchore-engine/)
