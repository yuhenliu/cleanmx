#!/bin/sh

rootdir="/home/zagorakis/work/malware/clean-mx-md5"
urlhdr="https://www.virustotal.com/file/"
urltr="/analysis/"
daydir=$1

for hourdir in $(ls $rootdir/$daydir)
do
	cd $rootdir/$daydir/$hourdir
	for mwfile in $(ls *.exe)
	do
		newfilename=`md5sum $mwfile | awk '{print $1}'`
		sha256=`sha256sum $mwfile | awk '{print $1}'`
		mv $mwfile $newfilename.exe
		wget -c -nc -t 5 -T 30 -O $newfilename.html $urlhdr$sha256$urltr

	#	rm $filename
	done
done
