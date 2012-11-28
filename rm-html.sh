#!/bin/sh

rtdir="/home/zagorakis/work/malware/clean-mx-md5"
urlhdr="https://www.virustotal.com/file/"
urltr="/analysis/"

for datedir in $(ls $rtdir | grep '[0-9]')
do
	for hourdir in $(ls $rtdir/$datedir)
	do
		for filename in $(ls $rtdir/$datedir/$hourdir | grep '.html')
		do
			fn=${filename%%.html}
			if [ $fn == $hourdir ]
			then
				echo $rtdir/$datedir/$hourdir/$filename
			fi
		done
	done
done
