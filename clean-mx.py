#!/usr/bin/env python

from elementtree.ElementTree import ElementTree

import urllib
import urllib2
import os
import errno
import shutil
import re
import time
import calendar
import base64
import hashlib
#from cuckoo.core.db import CuckooDatabase
#from cuckoo.logging.crash import crash
#from cuckoo.logging.colors import *
#from cuckoo.config.config import CuckooConfig

#db = CuckooDatabase()

MINUTE = 60
HOUR = MINUTE * 60
DAY = HOUR * 24

DESTINATION = "/tmp/cuckoo/"

delay = int(30 * MINUTE)
basePath = "/home/mboman/Src/cuckoo/"

analyzeIE = False
analyzeFF = False
analyzeEXE = True

def filename_from_url(url):
 return url.split('/')[-1].split('#')[0].split('?')[0]

def download(url):
	print(bold(cyan("INFO")) + ": Downloading URL %s" % url)

	try:
		url_handle = urllib2.urlopen(url)
		binary_data = url_handle.read()
	except Exception, why:
		print(bold(red("ERROR")) + ": Unable to download file: %s" % why)
	return False

	filename = filename_from_url(url)

	try:
		dest = os.path.join(DESTINATION, filename)
		f = open(dest, "wb")
		f.write(binary_data)
		f.close()
	except Exception, why:
		print(bold(red("ERROR")) + ": Unable to store file: %s" % why)
  return False

 return dest

def url(url):
 file_path = os.path.join(DESTINATION, "%s.url" % hashlib.md5(url).hexdigest())
 file_handle = open(file_path, "w")
 file_handle.write("[InternetShortcut]\n")
 file_handle.write("URL=%s\n" % url)
 file_handle.close()
 return file_path

def main():
 try:
  lastMod = int(os.path.getmtime(basePath + "xmlviruses.xml"))
 except Exception as e:
  print("Error: %s" % e)
  lastMod = 0

 curTime = int(calendar.timegm(time.gmtime()))

 if (lastMod + delay) < curTime:
  age = int((curTime - lastMod))

  age_d = age / DAY
  age   = age - (age_d * DAY)

  age_h = age / HOUR
  age   = age - (age_h * HOUR)

  age_m = age / MINUTE
  age   = age - (age_m * MINUTE)

  print("It has been " + str(age_d) + " days, " + str(age_h) + " hours, " + str(age_m) + " minutes and " + str(age) + " seconds since last update")

  urllib.urlretrieve("http://support.clean-mx.de/clean-mx/xmlviruses.php?response=alive&url=%.exe", basePath + "xmlviruses.xml")
 else:
  print("Not updating virus list as it is less then 30 minutes old")

 tree = ElementTree(file=basePath + "xmlviruses.xml")
 entryList = tree.findall("entries/entry")

 for entry in entryList:
  #print url.text
  urlString = entry[9].text
  if urlString:
   
   #md5String = entry[4].text

   #print "urlString: " + urlString
   #print "md5String: " + md5String

   #re.IGNORECASE
   #result = re.match("^.*\.[Ee][Xx][Ee]$", urlString)
   #result = re.match(".*", urlString)

   if analyzeIE:

    try: 
     #db = CuckooDatabase()
     # Surf to the URL and analyze it
     #task_id = db.add_task(url(urlString))
	 taks_id = url(urlString)
     print("Added task " + str(task_id) + " (" + urlString + ") for Internet Explorer Analysis")

     if not task_id:
      print(bold(red("ERROR")) + ": Unable to add task to database.")
      return False
     else:
      print(bold(cyan("DONE")) + ": Task successfully added with ID %d." % task_id)
    except Exception, why:
     print(bold(red("ERROR")) + ": Unable to add new URL task: %s" % why)


   if analyzeEXE:
    try:
     #db = CuckooDatabase()
     # Download the binary and analyze it
     #task_id = db.add_task(download(urlString))
     task_id = download(urlString)
 	 print("Added task " + str(task_id) + " (" + urlString + ") for Windows Analysis")
 
     if not task_id:
      print(bold(red("ERROR")) + ": Unable to add task to database.")
      return False
     else:
      print(bold(cyan("DONE")) + ": Task successfully added with ID %d." % task_id)
    except Exception, why:
     print(bold(red("ERROR")) + ": Unable to add new Download/Analysis task: %s" % why)



 print ("Queued all available samples for analysis")

if __name__ == "__main__":
    main()


