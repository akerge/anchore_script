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

Don't forget to add PATH and environment variables (either to .profile or .bashrc, whichever you use):

```bash
PATH=$PATH:/usr/local/bin/anchore-cli
ANCHORE_CLI_URL=http://localhost:8228/v1
ANCHORE_CLI_USER=admin
ANCHORE_CLI_PASS=foobar
```

At the time of writing, anchore-cli runs on python 2.7!

### Commands

```
apt update
apt install aws docker.io python3 python3-pip docker-compose
aws configure
git clone https://github.com/anchore/anchore-cli
cd anchore-cli
pip install --user --upgrade .
git clone https://github.com/anchore/anchore-cli
cd anchore-cli
pip install --user --upgrade .
#add anchore-cli to PATH and others to env variable
# PATH="/usr/local/bin/anchore-cli:$PATH"
ANCHORE_CLI_URL=http://localhost:8228/v1
ANCHORE_CLI_USER=admin
ANCHORE_CLI_PASS=foobar" >> ~/.profile
mkdir aevolume
cd aevolume
docker pull anchore/anchore-engine:v0.4.0
docker create --name ae anchore/anchore-engine:v0.4.0
docker cp ae:/docker-compose.yaml . 
docker rm ae
docker-compose pull
docker-compose up -d
aws ecr get-login
# copy-pasta the output to log in docker and add the registry to anchore-cli
# if need to add user and password and environment variables in .profile or .bashrc don't work, create alias instead.
anchore-cli --url http://localhost:8228/v1 --u admin --p foobar registry add REGISTRY_sans_https REGISTRY_USERNAME REGISTRY_PASSWORD --registry-type docker_v2
```
