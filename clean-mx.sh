#!/bin/sh

rootdir="/home/zagorakis/work/malware/clean-mx"
#day=`date +%Y%m%d`
day=20121110

url=`echo "wget -qO - http://lists.clean-mx.com/pipermail/viruswatch/$day/thread.html |\
awk '/\[Virus/'|tail -n 1|sed 's:\": :g' |\
awk '{print \"http://lists.clean-mx.com/pipermail/viruswatch/$day/\"$3}'"|sh`

filename=`wget -qO - http://lists.clean-mx.com/pipermail/viruswatch/$day/thread.html |\
awk '/\[Virus/'|tail -n 1|sed 's:": :g' |awk '{print $3}'`

links -dump $url$filename | awk '/Up/'|grep "TR\|exe" | awk '{print $2,$8,$10,$11,$12"\n"}' > $rootdir/$filename

dirname=`wget -qO - http://lists.clean-mx.com/pipermail/viruswatch/$day/thread.html |\
awk '/\[Virus/'|tail -n 1|sed 's:": :g' |awk '{print $3}'|sed 's:.html::g'`

rm -rf $rootdir/$dirname
mkdir $rootdir/$dirname

cd $rootdir

grep "exe$" $filename |awk '{print $5}'|sed 's/^\[.*\]//g' | xargs wget -t 10

ls *.exe | xargs md5sum >> checksums
mv *.exe $dirname

rm -r $rootdir/*exe*
mv checksums $rootdir/$dirname
mv $filename $rootdir/$dirname
