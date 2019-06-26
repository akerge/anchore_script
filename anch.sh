#!/bin/bash

# Script Name   anch.sh
# Author       	Artur Kerge
# Email        	artur@kerge.eu

# ABSTRACT
# This script was made for easier and quicker adding new docker image tags from
# Bezos' (AWS) Elastic Container Repo (ECR) and to get a report for them.
#
# The general flow is as follows:
# Option 1.
# Query all images from ECR by running `aws ecr describe-repositories` in
# getRepoNames(), output of `aws` is then `grep`ed to get names of images in
# repositories.
# Option 2.
# Sorts the image names alphabetically in repos.txt. If no repos.txt file found,
# then executes option 1, followed by the alphabetical sort.
# Option 3.
# Fetches the latest tags of images and writes them to images_with_tags.txt by
# running outputImgTagname. repoTag does the grep'ing of latest tag.
# Option 4.
# Feeds the new/latest tags to anchore.
# Option 5.
# All previous steps in one option.
# Option 6.
# Output vulnerability scan results of the ECR images to a HTML which then will
# be shown in the default browser. There is a choice between all, os, all non-os
# vulnerabilities to show.
# Option 7.
# Output vuln report for specific image:tag, which has been added to anchore,
# Option 8.
# Echo all ECR images and tags (`cat images_with_tags.txt`).
# Option 9.
# Echo the ECR repo name, by `cat ecr.txt`. If no file, tries to retrieve it by
# executing `aws ecr get-login`

# TODO
# * Move vulnerability output either to one function for better portability or
#   for better containment (functions not being all over the script).
# * Add note regarding enabling extra vulnerability feeds.
# * Clean up code & rm dangling TODO's.
# * Change vulnerability count `echo` to `printf` instead.
# * Count new (not analyzed) images and print result in addToAnch().
# * Clarify how `awk` and `sed` commands work for future reference in rw()
# * Document `sed` and `awk` command details in functions.

tabs 4	# set tab len to 4 for prettier element alignment

# Global variables
critCount="0"
hiCount="0"
medCount="0"
writImgs="0"
skipImgs="0"
repoTagName=""
repoArr=""
dest=""
destTemp=""
repoName=""
imgName=""
repo=""
getRepoNames(){
	echo Getting repos...
	if aws ecr describe-repositories > desc_repos.txt ; then
		grep -oP '(?<=repositoryName": ")([^\.{1}][a-zA-Z0-9-]*)' desc_repos.txt > repos.txt
	else
		echo "Executing `aws` failed. Either not installed or configured."
		echo "Try adding the ECR registry to anchore by running:"
		echo "anchore-cli registry add REGISTRY USERNAME PASSWORD"
	fi
	rm desc_repos.txt
	echo Done!
}

repoTag(){
	# grep the imageTags from the $repo.txt to an array
	# save the latest (last) array element to a file
	arr=($(grep -oP --color '(?<=            ")([a-zA-Z0-9.\/\-_]+)' tmp/$1.txt))
	# ^ greps all the tags of an image
	first=${arr[0]} # first element of array
	# Sanity below check if no images in repo (empty array)
	if [ -z $first ];
	then
		echo "! $repoName - nil images, skipping..."
		let skipImgs++
		return 1
	else
		repoTagName=${arr[$arrEnd]} # reassigning last element or array for clarity
		echo $repoName:$repoTagName >> images_with_tags.txt
		let writImgs++
	fi
#	repoTagName=""
	sort images_with_tags.txt > tmp.txt
	cat tmp.txt > images_with_tags.txt
	rm tmp.txt
	return
}


sortImgsInRepo(){
	if [ ! -d tmp ]; then
		mkdir tmp/
	fi
	echo "Starting sort..."
	if [[ -f repos.txt ]]; then
		while read repo
		do
			echo "Querying $repo"
			aws ecr describe-images --repository $repo --query 'sort_by(imageDetails,& imagePushedAt)[*]' > tmp/$repo.txt
		done < repos.txt
		echo "Done querying."
	else
		echo "No repo names found, running option 1 -- getting repo names"
		getRepoNames
		sortImgsInRepo
	fi
	echo ""
}

outputImgTagname(){
	# saves froam bloating
	if [[ -f images_with_tags.txt ]]; then
		rm images_with_tags.txt
	fi
	while read repoName
	do
		# repoTag does the all the heavy lifting of grep'ing latest tag.
		repoTag $repoName
		echo "Writing $repoName:$repoTagName"
	done < repos.txt
	echo ""
	echo "Done writing."
	echo ""
	echo "$writImgs images written."
	echo "$skipImgs images skipped."
}

isECRknown(){
	if [ ! -f ecr.txt ]; then
		getECR
	else
		repo=$(cat ecr.txt)
	fi
}

addToAnch(){
	isECRknown
  #	^ This requires that user has logged in to AWS via CLI
	while read latestAndGreatest
	do
		echo "Feeding $repo/$latestAndGreatest to anchore to scan"
		echo "$line $line"
		anchore-cli image add $repo/$latestAndGreatest #--force
	done < images_with_tags.txt
	echo Done feeding.

}

anchVulnResults(){
	echo "Provide vuln spec:"
	echo "1 - all vulnerabilities"
	echo "2 - os vulns"
	echo "3 - non-os vulns"
	echo "* - enter any other value to exit"
	read vulnChoice
	case $vulnChoice in
		1) vulnSelection="all" ;;
		2) vulnSelection="os" ;;
		3) vulnSelection="non-os" ;;
		*) echo "Bye!"
			exit ;;
	esac
	echo "Specify relative path to a new report directory"
	read reportDir
	# CHECK FOR REPO (ecr.txt)
	isECRknown
	if [ ! -d $reportDir ];then
		mkdir $reportDir
	fi
	pwd=$(pwd)
	date=$(date +%F)
	dest=$pwd/$reportDir/All_imgs-$vulnSelection-vulns-$date-anchore_report.html
	# If a single image is wanted (no $1 argument), then the imageName:tag will be grepped:
	if [ ! -z $1 ]; then
		short=$(echo "$1" | grep -oP '(?<=\/)([a-zA-Z0-9\_-]+:[a-zA-Z0-9\_-]+)')
		dest=$pwd/$reportDir/$short-$vulnSelection-vulns-$date-anchore_report.html
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
<title>$(date) anchore query</title></head><body><pre><code><h1>Anchore $vulnSelection vulnerability scan results</h1>" >> $dest
echo "$(date)" >> $dest
echo ""
# Total Vuln Count goes here
echo "ZZZ" >> $dest
echo "ZZ" >> $dest
echo "Z" >> $dest

	# TODO
	# remove code duplication below, make into a function, say, queryAllOrSingle
	# filter repo name and img:tag in isECRknown()
	# so that it could be fed thru the queryAllOrSingle

	# if no $1, then output all
	if [ -z $1 ]; then
		while read scan
		do
			echo ""
			echo Querying $repo/$scan
			touch tmp.html
			# ^ creating temp file to get the vuln count
			destTemp=($dest)
			destTMP=$pwd/tmp.html
			dest=($destTMP)
			echo "<h2>$scan</h2>" >> $dest
			anchore-cli image vuln $repo/$scan $vulnSelection >> $dest
			placeholderPasta
			# ^ counting vulnerabilities and adding to placeholder
		done < images_with_tags.txt
	else
	# if $1 exists, then
		echo "Querying $1"
		destTemp=($dest)
		dest=($pwd/tmp.html)
		echo "<h2>$1</h2>" >> $dest
#		anchore-cli image vuln $repo/$1 $vulnSelection >> $dest
		anchore-cli image vuln $1 $vulnSelection >> $dest
		placeholderPasta
	fi
	echo "</code></pre></html>" >> $dest
	echo ""
	sed -ie "/ZZZ/c $(printf "%-22s%8u" "Total Critical Vulns:" $critCount)" $dest
	sed -ie "/ZZ/c $(printf "%-22s%8u" "Total High Vulns:" $hiCount)" $dest
	sed -ie "/Z/c $(printf "%-22s%8u" "Total Medium Vulns:" $medCount)" $dest
	echo "Location of report: $dest"
	e="e"
	echo "removing $dest$e"
	rm $dest$e
}

placeholderPasta(){
	crit=`awk '/Critical/ {count++} END{print count}' $dest`
	hi=`awk '/High/ {count++} END{print count}' $dest`
	med=`awk '/Medium/ {count++} END{print count}' $dest`
	if [[ "$med" -gt 0 && ! -z "$med" ]]; then
		sed -ie "/<\/h2>/a $(printf "%-16s%8u" "Medium Vulns:" $med)" $dest
	fi
	if [[ "$hi" -gt 0 && ! -z "$med" ]]; then
		sed -ie "/<\/h2>/a $(printf "%-16s%8u" "High Vulns:" $hi)" $dest
	fi
	if [[ "$crit" -gt 0 && ! -z "$med" ]];then
		sed -ie "/<\/h2>/a $(printf "%-16s%8u" "Critical Vulns:" $crit)" $dest
	fi
		# Note to self: for adding variables '$(( ))' is used
		critCount=$((critCount+crit))
		hiCount=$((hiCount+hi))
		medCount=$((medCount+med))
	# TODO
	# printf output below
	echo "$critCount <- total crit count"
	echo "$hiCount <- total hi count after"
  echo "$medCount <- total med count after"
	dest=$destTemp
	cat tmp.html >> $dest
	rm tmp.html
}

rw(){
	echo Highlighting...
	echo "$dest <- dest"
	#	"$dest <- destination before sed URL-ing"
	# TODO explain how the awk arguments work
	awk -v pat=Critical 'index($0, pat) {$0="<span class=crit>" $0} 1' $dest > tmp.html
	awk '/Critical/ {$0=$0"</span>"} 1' tmp.html > $dest
	awk -v pat=High 'index($0, pat) {$0="<span class=hi>" $0} 1' $dest > tmp.html
	awk '/High/ {$0=$0"</span>"} 1' tmp.html > $dest
	awk -v pat=Medium 'index($0, pat) {$0="<span class=med>" $0} 1' $dest > tmp.html
	awk '/Medium/ {$0=$0"</span>"} 1' tmp.html > $dest
	echo Making URL-s clickable...
	# TODO explain how following command works
	sed -r 's|(https?:\/\/[a-zA-Z.\~0-9\=\?\/-]*[\/|=])([A-Z]{3,4}[0-9A-Za-z\:-]+)|<a target="_blank" href="\1\2">Vuln Feed Link</a> <a target="_blank" href="https://google.com/search?q=\2">Search for \2</a>|g' $dest > tmp.html
	mv tmp.html $dest
	rm tmp.html
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
		echo "Figuring out ECR..."
		aws ecr get-login | grep -oP '(?<=https:\/\/)([a-zA-Z0-9.-]*)' > ecr.txt
		cat ecr.txt
		echo Saved to ecr.txt
	else
		cat ecr.txt
	fi
}

printImagesWithTags(){
	if [ -f images_with_tags.txt ]; then
		cat images_with_tags.txt
	else
		echo "images_with_tags.txt not found!"
		echo "Please run option 4 - print images images with tags to images_with_tags.txt"
	fi
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
		repoArrLen=${#repoArr[@]}
		chosenRepo=${repoArr[$getImgNum]}
		# -lt and -gt work better than '>' and '<'
		# also not much input validation here
		if [ $getImgNum -lt ${#repoArr[@]} ] && [ $getImgNum -gt 0 ]; then # && ! -z $getImg ]]; then
			echo "Chosen Repo: $chosenRepo"
		# TODO
		# check if $chosenRepo has (amazonaws) in it
		# if not:
		# separate $chosenRepo to repo and img
		# ([a-z\.\/]+\/+) captures repo
		# (?<=\/)([a-zA-Z-9\?-]+:[a-zA-Z0-9\_-]+) captures img:tag
		# feed the $repoName$imgName to anchVulnResults
			anchVulnResults $chosenRepo
		else
			echo "Input out of bounds."
			echo "Bye!"
			exit 0
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
		*)	echo "Bye!"
			exit 0
			;;
	esac
	rw
	x-www-browser $dest &
}

getAllimgsRepos(){
	anchore-cli image list | grep -oP '([^ sha256\s][a-zA-Z\d\/\.-]+:[a-z\d\_\.-]+)' > allRepos.txt
#	cat allRepos.txt
}

line="= = = = = = = = = = = = = = = = ="

# HERE LIES THE START OF THE SCRIPT
clear
echo "Simple script to get all ECR repos with latest tags"
echo "$line $line"
echo "1 - Automated steps 2-5 (all need anchore-cli installed and container running)"
echo "2 - Output all ECR images in repo to repos.txt"
echo "3 - Output all tags in all ECR images to tmp/<image>.txt"
echo "4 - Output images with tags to images_with_tags.txt "
echo "5 - Add images to anchore to scan"
echo "6 - Print ALL vuln scan result(s) for ECR to HTML and show"
echo "7 - Print vuln scan result(s) for specific image:tag to HTML and show"
echo "8 - Show known ECR images:tags"
echo "9 - Show known ECR repo"
echo "0 - Show ALL known images:tags in anchore"
echo "Q - Quit"

read INPUT

case $INPUT in
	1)	clear
		echo Here we go!
		echo $line
		getVuln
		echo ""
		echo Give some time for the images to be analyzed and then run the next option.
		echo You can check the status of engine by entering
		echo anchore-cli image list
		echo $line
		;;
	2)	clear
		echo $line
		# noteworthy https://gist.github.com/rpherrera/d7a4d905775653b88e5f
		# jq is a prerequisite
		getRepoNames
		;;
	3)	clear
		echo Sorting images repo by repo, please stand by...
		echo $line
		sortImgsInRepo
		;;
	4)	clear
		echo Writing image:tag to a file...
		echo $line
		outputImgTagname
		;;
	5)	clear
		echo Submitting images to anchore...
		echo $line
		addToAnch
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
		cat allRepos.txt
		;;
	q|Q|*)	echo ""
		clear
		echo Bye!
		exit
		;;
esac
