#!/bin/bash

# Script Name	anch.sh                                                                                              
# Author       	Artur Kerge                                                
# Email        	artur@kerge.eu 

# ABSTRACT
# name of all repos come from the output of
# `aws ecr describe-repositories`
# json output then has been grepped twice
# once to get the repositoryName and then to grep out the name itself without repositoryName

# query all images in repo
# save the output to a file with a repo name $repo.txt

# grep the imageTags from the $repo.txt to an array
# save the latest (last) array element to a file

# ideally it would append the element to a repo name
# $repo:$element > repo_tags.txt

# TODO
# * add simple stats to img:tag -- count vulnerabilites
# * clean up code
# * write proper header/description

tabs 4	# set tab len to 4 for prettier element alignment

# setting global variable to return from repoTag()
writImgs=""
skipImgs=""
repoTagName=""
repoArr=""
dest=""
getRepoNames(){
	echo Getting repos...
	aws ecr describe-repositories > desc_repos.txt
	grep -oP '(?<=repositoryName": ")([^\.{1}][a-zA-Z0-9-]*)' desc_repos.txt > repos.txt
	rm desc_repos.txt
	echo Done!
}

repoTag(){
	# greps all the tags
	arr=($(grep -oP --color '(?<=            ")([a-zA-Z0-9.\/\-_]+)' tmp/$1.txt))
	last=${#arr[*]}
#	echo $last array len
	arrEnd=$(($last-1))
#	echo array has $arrEnd indexes
	# sanity check if no images in repo (empty array)
	if [ "$last" -eq 1 ]
	then
		echo ! $repoName - nil images, skipping...
		let skipImgs++
		return 1
	else
		lastEl=${arr[$arrEnd]}
		#echo $lastEl this is the last element
		repoTagName=$lastEl
#		echo "$lastEl <- last element of array"
		echo $repoName:$repoTagName >> images_with_tags.txt
		let writImgs++
		#echo reoName:repoTagName
		#echo $repoName:$repoTagName added
	fi
	repoTagName=""
	return
}


sortImgsInRepo(){
	mkdir tmp/
	echo "Starting sort..."
	while read repo
	do
		echo "Querying $repo"
		aws ecr describe-images --repository $repo --query 'sort_by(imageDetails,& imagePushedAt)[*]' > tmp/$repo.txt
	done < repos.txt
	echo ""
	echo "Done querying."
}

outputImgTagname(){
	# saves froam bloating
	rm images_with_tags.txt
	while read repoName
	do
		echo "Writing $repoName:$repoTagName" 
		repoTag $repoName
	done < repos.txt
	echo ""
	echo "Done writing."
	echo ""
	echo "$writImgs images written."
	echo "$skipImgs images skipped."
}

ecr=""
isECRknown(){
	if [ ! -f ecr.txt ]; then
		getECR	
	else
		ecr=$(cat ecr.txt)
	fi
}

addToAnch(){
	#### TODO: 
	# ADD ERROR LOG
	# Timeout feature---if takes too long to respond >5s, then timeout, throw error
	isECRknown
#	echo This requires that user has logged in to AWS via CLI
#	echo "Please give the AWS ECR repo URL (sans protocol prefix and trailing slash, please)"
#	read URL
	while read latestAndGreatest
	do
		echo "Feeding $ecr/$latestAndGreatest to anchore to scan"
		echo "$line $line"
		anchore-cli image add $ecr/$latestAndGreatest #--force
	done < images_with_tags.txt
	echo Done feeding.

}

anchVulnResults(){
	echo Specify relative path to a new report directory
	read reportDir
	# CHECK FOR ecr.txt
	isECRknown
	mkdir $reportDir
#	touch $reportDir/$date-anchore-vuln-report.html
	pwd=$(pwd)
	date=$(date +%F)
	dest=$pwd/$reportDir/All-$date-anchore-vuln-report.html
	ecr=$(cat ecr.txt)
#	echo "$date"
#	echo "$ecr <- ecr"
	# If a single repo vuln report is wanted
	if [ ! -z $1 ]; then
		short=$(echo "$1" | grep -oP '(?<=\/)([a-zA-Z0-9\_-]+:[a-zA-Z0-9\_-]+)')
#		echo "$short <- short"
		dest=$pwd/$reportDir/$short-$date-anchore-vuln-report.html
	fi
	echo "<!DOCTYPE html><html><head>" > $dest
	echo "<style>
  body {
  background-color: black;
  background-image: radial-gradient(
    rgba(0, 150, 0, 0.75), black 120%
  );
  background-repeat: no-repeat;
  background-attachment: fixed;
  height: 100vh;
  margin: 0;
  padding: 2rem;
  color: white;
  font: 0.96rem Inconsolata, monospace;

  ::after {
    content: ;
    position: absolute;
    top: 0;
    left: 0;
    width: 100vw;
    height: 100vh;
    pointer-events: none;
  }
}

.crit {
  background-color: red;
  color: #000000;
  }
.crit a{
  background-color: red ;
  color: #000000;
}
.hi {
  background-color: orange;
  color: #000000;
  }
.hi a {
  background-color: orange;
  color: #000000;
}
.med {
  background-color: yellow;
  color: #000000;
  }
.med a {
  background-color: yellow;
  color: #000000;
}
a {
  color: white;
}
::selection {
  background: #502277;
  text-shadow: none;
}
pre {
  margin: 0;
}
	</style>
<title>$(date) anchore query</title></head><body><pre><code><h1>Anchore vulnerability scan results</h1>" >> $dest
echo "$(date)" >> $dest
	# if no $1, then output all
	if [ -z $1 ]; then
		while read scan
		do
			echo ""
			echo Querying $ecr/$scan
#			echo anchore-cli image vuln $ecr/$scan all INTO $reportDir/$scan
#			echo "
#			" >> $dest
			echo "<h2>$scan</h2>" >> $dest
#			echo "" >> $dest
			anchore-cli image vuln $ecr/$scan all >> $dest
		done < images_with_tags.txt
	else
	# if $1 exists, then
		echo "Querying $1"
		echo "<h2>$1</h2>" >> $dest
		anchore-cli image vuln $1 all >> $dest
	fi
	echo "</code></pre></html>" >> $dest
	echo "Location of report: $dest"
}

rw(){
#	echo "$dest should start hiliting"
	echo Highlighting...
	awk -v pat=Critical 'index($0, pat) {$0="<span class=crit>" $0} 1' $dest > tmp.html
	awk '/Critical/ {$0=$0"</span>"} 1' tmp.html > $dest
	awk -v pat=High 'index($0, pat) {$0="<span class=hi>" $0} 1' $dest > tmp.html
	awk '/High/ {$0=$0"</span>"} 1' tmp.html > $dest
	awk -v pat=Medium 'index($0, pat) {$0="<span class=med>" $0} 1' $dest > tmp.html
	awk '/Medium/ {$0=$0"</span>"} 1' tmp.html > $dest
	echo Making URL-s clickable...
	sed -r 's|(https?://[a-zA-Z./~0-9?-]+)(CVE[0-9A-Za-z-]+)|<a target="_blank" href="\1\2">Vuln Feed Link</a> <a target="_blank" href="https://google.com/search?q=\2">Search for \2</a>|g' $dest > tmp.html
	mv tmp.html $dest 
	echo "Done highlighting & URL-ing"
}

getVuln(){
	getRepoNames $1
	sortImgsInRepo
	outputImgTagname
	addToAnch
}

getResults(){
	anchVulnResults
	rw
	x-www-browser $dest &
}

getECR(){
	if [ ! -f ecr.txt ]; then
		aws ecr get-login | grep -oP '(?<=https:\/\/)([a-zA-Z0-9.-]*)' > ecr.txt
		echo "<Drum roll>"
		cat ecr.txt
		echo Saved to ecr.txt
	else
		cat ecr.txt
	fi
}

printImagesWithTags(){
	cat images_with_tags.txt
}

printPreferred(){
		# read repos and respective images to an array
		# print out index and index value
	if [ -f $allOrECR ]; then
		while read img
		do
			repoArr=($(cat $allOrECR))
		done < $allOrECR
		for i in "${!repoArr[@]}";
		do
			echo "$i	${repoArr[$i]}";
		done
		echo ""
		echo "Enter the number of image you want to retrieve the vuln list for"
		read getImgNum
#		anchore-cli image vuln ${repoArr[$i]} all
		repoArrLen=${#repoArr[@]}
#		echo "Length of repoArr: $repoArrLen"
		chosenRepo=${repoArr[$getImgNum]}
		echo "Chosen Repo: $chosenRepo"
		if [ $getImgNum -lt ${#repoArr[@]} ]; then
			anchVulnResults $chosenRepo
		fi
	else
		clear
		echo "No such listing."
		echo "Please re-run with option 3."
	fi
}

printSpecificImgVuln(){
	# Choose if print out of all or ECR
	echo "Get specific vuln report out of"
	echo "1 - ECR or"
	echo "2 - all"
	echo "Q - Quit"
	read choiceForAllOrECR
	allOrECR=""
	case $choiceForAllOrECR in
		1)	allOrECR=images_with_tags.txt
			clear
			printPreferred;;
		2)	getAllimgsRepos
			allOrECR=allRepos.txt
			clear
			printPreferred;;
		q|Q)	exit
	esac
		rw
		x-www-browser $dest &
}

getAllimgsRepos(){
	anchore-cli image list | grep -oP '([^ sha256\s][a-zA-Z\d\/\.-]+:[a-z\d\_\.-]+)' > allRepos.txt
}

line="= = = = = = = = = = = = = = = = ="

# HERE LIES THE START OF THE SCRIPT
clear
echo "Simple script to get all ECR repos with latest tags"
echo "$line $line"
echo "1  - Output all ECR images in repo to repos.txt"
echo "2  - Output all tags in all ECR images to tmp/<image>.txt"
echo "3  - Output images with tags to images_with_tags.txt "
echo "4  - Add images to anchore to scan"
echo "	   (needs anchore-cli installed and container running)"
echo "5  - Do all of the above"
echo "6  - Print vuln scan result(s) for ECR to HTML and show"
echo "7  - Print vuln scan result(s) for specific image:tag to HTML and show"
echo "8  - Show known ECR images:tags"
echo "9  - Show known ECR repo"
echo "99 - Show ALL known images:tags in anchore"
echo "Q  - Quit"

read INPUT

case $INPUT in
	1)	clear
		echo $line
		# noteworthy https://gist.github.com/rpherrera/d7a4d905775653b88e5f
		# jq is a prerequisite
		getRepoNames
		;;
	2)	clear
		echo Sorting images repo by repo, please stand by...
		echo $line
		sortImgsInRepo
		;;
	3)	clear
		echo Writing image:tag to a file...
		echo $line
		outputImgTagname
		;;
	4)	clear
		echo Submitting images to anchore...
		echo $line
		addToAnch
		;;
	5)	clear
		echo Here we go!
		echo $line
		getVuln
		echo ""
		echo Give some time for the images to be analyzed and then run the next option.
		echo You can check the status of engine by entering
		echo anchore-cli image list
		echo $line
		;;
	6)	clear
		echo Querying vuln results from anchore
		echo $line
		getResults
		;;
	7)	clear
		echo "Enter number to retrieve the report of an image:"
		echo $line
		printSpecificImgVuln
		;;
	8)	clear
		echo Known images with respective tags:
		echo $line
		printImagesWithTags
		;;
	9)	clear
		echo Known ECR repo is...
		echo $line
		getECR
		;;
	99)	clear
		echo "Retrieving all known repos and images from anchore..."
		echo "$line $line"
		getAllimgsRepos
		;;
	q|Q|0)	echo ""
		clear
		echo Bye!
		exit
		;;
	*)	echo ""
		clear
		echo Not an option. Please re-run.
		;;
esac
