#!/bin/bash

# V0.02

# ABSTRACT
# name of all repos come from the output of
# `aws ecr describe-repositories`
# json output then has been grepped twice
# once to get the repositoryName and then to grep out the name itself without repositoryName

# query all images in repo
# save the output to a file with a repo name $repo.txt

# grep the imageTags from the $repo.txt to an array
# save the latest (last) array element to a file?

# ideally it would append the element to a repo name
# $repo:$element > repo_tags.txt

# setting global variable to return from repoTag()
writImgs=""
skipImgs=""
repoTagName=""
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
		echo $lastEl this is the last element
		repoTagName=$lastEl
#		echo "$lastEl <- last element of array"
		echo $repoName:$repoTagName >> images_with_tags.txt
		let writImgs++
		echo reoName:repoTagName
		echo $repoName:$repoTagName added
	fi
	repoTagName=""
	return
}


sortImgsInRepo(){
	mkdir tmp/
	while read repo
	do
		echo Querying $repo
		aws ecr describe-images --repository $repo --query 'sort_by(imageDetails,& imagePushedAt)[*]' > tmp/$repo.txt
	done < repos.txt
	echo Done querying.
}

outputImgTagname(){
	# saves froam bloating
	rm images_with_tags.txt
	while read repoName
	do
		echo Writing \'$repoName:$repoTagName\' to file
		repoTag $repoName
	done < repos.txt
	echo Done writing.
	echo $writImgs images written.
	echo $skipImgs images skipped.
}

addToAnch(){
	#### TODO: 
	# ADD ERROR LOG
	# Timeout feature---if takes too long to respond >5s, then timeout, throw error
	echo This requires that user has logged in to AWS via CLI
	echo "Please give the AWS ECR repo URL (sans protocol prefix and trailing slash, please)"
	read URL
	while read latestAndGreatest
	do
		echo Feeding $URL/$latestAndGreatest to anchore to scan
		anchore-cli image add $URL/$latestAndGreatest #--force
	done < images_with_tags.txt
	echo Done feeding.

} 

#dest=""
anchVulnResults(){
	echo Specify relative path to a new report directory
	read reportDir
	echo Specify container repository where the images were added from:
	echo "(No protocol and no trailing slash, please)"
	read ecr
	mkdir $reportDir
	touch $reportDir/index.html
	dest="$reportDir/index.html"
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
	while read scan
	do
		echo Querying $ecr/$scan
#		echo anchore-cli image vuln $ecr/$scan all INTO $reportDir/$scan
#		echo "
#		" >> $dest
		echo "<h2>$scan</h2>" >> $dest
#		echo "" >> $dest
		anchore-cli image vuln $ecr/$scan all >> $dest
	done < images_with_tags.txt
	echo "</code></pre></html>" >> $dest
}

rw(){
	echo 
	echo Highlighting...
	awk -v pat=Critical 'index($0, pat) {$0="<span class=crit>" $0} 1' $dest > tmp.html
	awk '/Critical/ {$0=$0"</span>"} 1' tmp.html > $dest
	awk -v pat=High 'index($0, pat) {$0="<span class=hi>" $0} 1' $dest > tmp.html
	awk '/High/ {$0=$0"</span>"} 1' tmp.html > $dest
	awk -v pat=Medium 'index($0, pat) {$0="<span class=med>" $0} 1' $dest > tmp.html
	awk '/Medium/ {$0=$0"</span>"} 1' tmp.html > $dest
	echo Making URL-s clickable...
	sed -r 's|(https?://[a-zA-Z./~0-9?-]+)|<a href="&1">&1</a>|g' $dest > tmp.html
	mv tmp.html $dest 
	echo "Done highlighting & URL-ing"
}

# HERE LIES THE START OF THE SCRIPT

echo Simple script to get all repos with latest tags
echo 1 TODO output all images in repo to repos.txt
echo "2 - Output all tags in all the images to tmp/<image>.txt"
echo 3 - Output images with tags to images_with_tags.txt 
echo "4 - Add images to anchore to scan (needs anchore-cli installed and container running, will force)"
echo "5 - Output Scan results (if any) to HTML and show"
echo 6 TODO do all of the above
echo Q - Quit

read INPUT

case $INPUT in
	1)
		# noteworthy https://gist.github.com/rpherrera/d7a4d905775653b88e5f
		# jq is a prerequisite
		echo WIP
		;;
	2)
		echo Sorting images repo by repo, please stand by...
		sortImgsInRepo
		;;
	3)
		echo Writing image:tag to a file...
		outputImgTagname
		;;
	4)
		echo Submitting images to anchore...
		addToAnch
		;;
	5)
		echo Querying vuln results from anchore
		anchVulnResults
		rw
		x-www-browser $dest
		;;
	6)
		echo WIP
		;;
	q)
		echo Bye!
		exit
		;;
	*)
		echo Not an option. Please re-run.
		;;
esac
