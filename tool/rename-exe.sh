#!/bin/sh

rtdir="/home/zagorakis/work/malware/clean-mx-md5"
urlhdr="https://www.virustotal.com/file/"
urltr="/analysis/"

for datedir in $(ls $rtdir | grep '[0-9]')
do
	for hourdir in $(ls $rtdir/$datedir)
	do
		for filename in $(ls $rtdir/$datedir/$hourdir | grep '.exe')
		do
			newfilename=`md5sum $rtdir/$datedir/$hourdir/$filename | awk '{print $1}'`
			sha256=`sha256sum $rtdir/$datedir/$hourdir/$filename | awk '{print $1}'`
			mv $rtdir/$datedir/$hourdir/$filename $rtdir/$datedir/$hourdir/$newfilename.exe
			wget -O $rtdir/$datedir/$hourdir/$newfilename.html $urlhdr$sha256$urltr
		done
	done
done
