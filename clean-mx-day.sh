#!/bin/sh

rootdir="/home/zagorakis/work/malware/clean-mx"
#day=`date +%Y%m%d`
day=$1

url=`echo "wget -qO - http://lists.clean-mx.com/pipermail/viruswatch/$day/thread.html |\
awk '/\[Virus/'|tail -n 1|sed 's:\": :g' |\
awk '{print \"http://lists.clean-mx.com/pipermail/viruswatch/$day/\"$3}'"|sh`

if test ! -d $rootdir/$day;then
	mkdir $rootdir/$day
fi
cd $rootdir/$day

wget -qO - http://lists.clean-mx.com/pipermail/viruswatch/$day/thread.html | awk '/\[Virus/' |\
while read LINE
do
	filename=`echo $LINE | sed 's/"/ /g' | awk '{print $3}'`
	dirname=`echo $filename |sed 's:.html::g'`

	if test ! -d $rootdir/$day/$dirname;then
		mkdir $rootdir/$day/$dirname
	fi
	cd $rootdir/$day/$dirname

	echo "Crawling $url$filename...................................................................................."
	links -dump $url$filename | awk '/Up/'|grep "TR\|exe" | awk '{print $2,$8,$10,$11,$12"\n"}' > $filename

	grep "exe$" $filename |awk '{print $5}'|sed 's/^\[.*\]//g' | xargs wget -c -nc -t 5
	ls *.exe | xargs md5sum >> checksums
done
