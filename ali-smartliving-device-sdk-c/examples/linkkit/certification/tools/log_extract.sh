#!/bin/bash
#This script can extract some lines from some log files according some key words
#Date:2020-03-03
#Version:1.0
#Author:Liuese
#Contacts:TingTalk number:13826595824
#Changes:Create

read -p "Please input a folder which include some log files:" logfiles
test -e $logfiles || echo "Folder $logfiles is not exist" || exit 1
test -r $logfiles || echo "Folder $logfiles can not read" || exit 1

read -p "Please input a keyword that want be searched:" keyword
test -z $keyword && echo "You input is none" && exit 1

declare -i lines
read -p "Please input a number which is the lines around the keyword $keyword:" lines
if test $lines -lt 1
then
   	echo "Please input a number that must larger than 0"
	exit 1
fi

if test $? -ne 0
then
	echo "Please input a number"
	exit 1
fi

time=$(date +%Y%m%d_%H%M%S)
savedfile=$logfiles-$time.log

files=$(ls $logfiles)
for file in $files
do
	printf "+++++++++++++++File:$file +++++++++++++++\r\n" >> ./$savedfile
	keylog=$(cat ./$logfiles/$file | grep -C $lines "$keyword")
	echo $keylog >> ./$savedfile
	printf "===============File:$file ===============\r\n" >> ./$savedfile
done

dir=$(pwd)
echo "Your input params log folder is:$logfiles keyword is:$keyword lines is:$lines"
echo "The parsed log saved to file:$dir/$savedfile"

exit 0
