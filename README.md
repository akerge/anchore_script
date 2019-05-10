# anchore_script

bash script to get repositories with tag names from private AWS ECR, feed them to anchore, and retrieve the result which is shown in a nicely formatted HTML:

![Example screenshot](https://github.com/akerge/anchore_script/raw/master/img/anch_script.png "Example screenshot")

## Scenario

I was tired to see the vulnerability report on the CLI and made this is a handy script to query report(s) from anchore. Currently supports AWS ECR only. TODO is to add support for all other images too.

## Prerequisites

* [anchore-cli](https://github.com/anchore/anchore-cli) - saves the trouble of `docker exec anchore-engine anchore cli` every time.

* [anchore engine docker container](https://hub.docker.com/r/anchore/anchore-engine/)
