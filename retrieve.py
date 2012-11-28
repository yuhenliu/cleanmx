from __future__ import division
from urllib import urlopen
from BeautifulSoup import BeautifulSoup
import glob, os, sys
from datetime import *
import time
import MySQLdb, _mysql
import traceback
import hashlib
import getopt
import fnmatch

class Malware:
	def __init__(self):
		# basic information
		self.MD5=0
		self.SHA1=0
		self.SHA256=0
		self.FileName=0
		self.FileSize=0
		self.FileType=0
		self.DetectionRatio=0
		self.DetectedAV=0
		self.AllAV=0
		self.AnalysisDate=0
		# additional information
		self.Alias=[]
		# behaviour information
		self.HTTPrequest=[]
		self.DNSrequest=[]
		self.TCPconnection=[]
		self.UDPcommunication=[]

	def printAll(self):
		print self.MD5
		print self.SHA1
		print self.SHA256
		print self.FileName
		print self.FileSize
		print self.FileType
		print self.DetectionRatio
		print self.DetectedAV
		print self.AllAV
		print self.AnalysisDate
		print self.Alias
		print self.HTTPrequest
		print self.DNSrequest
		print self.TCPconnection
		print self.UDPcommunication

def retrieve(source):
	if os.path.isfile(source)==False:
		print "No such file: ", source
		return False
		
	print "Retrieving malware information from: ", source
	text = urlopen(source).read()
	soup = BeautifulSoup(text)
	
	tables = soup.findAll('table')
	mwInfo = Malware()
	if len(tables) == 0:
		mwFileName = os.path.splitext(source)[0]
		mwFileName = mwFileName+'.exe'
		if os.path.isfile(mwFileName):
			retrieveFromFile(mwFileName,mwInfo)
		else:
			print "No such file: ", mwFileName
			return False
	else:
		# retrieve basic information
		retrieveBasic(tables[0],mwInfo)
		# retrieve anti-virus result
		#retrieveAVR(tables[1],mwInfo)
		# retrieve additional information
		retrieveAddition(tables[2],mwInfo)
		# retrieve behaviour information
		if len(tables) >= 4:
			retrieveBehave(tables[3],mwInfo)
	
#	mwInfo.printAll()
	
	return writeDB(mwInfo)

def retrieveFromFile(mwfile,mw):
	fileContent = open(mwfile,"rb").read()
	mw.SHA256 = hashlib.sha256(fileContent).hexdigest()
	mw.SHA1 = hashlib.sha1(fileContent).hexdigest()
	mw.MD5 = hashlib.md5(fileContent).hexdigest()
	mw.FileSize = os.path.getsize(mwfile)
	mt = time.localtime(os.stat(mwfile).st_ctime)
	mw.AnalysisDate = time.strftime("%Y-%m-%d %H:%M:%S",mt)

def retrieveBasic(tab,mw):
	trItem = tab.find('tr')
	while trItem:
		tdItem = trItem.find('td')
		tdItemVal = tdItem.nextSibling.nextSibling
		
		if cmp(tdItem.text,"SHA256:")==0:
			mw.SHA256 = tdItemVal.text
		elif cmp(tdItem.text,"SHA1:")==0:
			mw.SHA1 = tdItemVal.text
		elif cmp(tdItem.text,"MD5:")==0:
			mw.MD5 = tdItemVal.text
		elif cmp(tdItem.text,"File name:")==0:
			mw.FileName = tdItemVal.text
		elif cmp(tdItem.text,"File size:")==0:
			filesize = tdItemVal.text.split(' ')
			mw.FileSize = filesize[3]
		elif cmp(tdItem.text,"File type:")==0:
			mw.FileType = tdItemVal.text
		elif cmp(tdItem.text,"Detection ratio:")==0:
			detectedratio = tdItemVal.text.split(' ')
			mw.DetectedAV = detectedratio[0]
			mw.AllAV = detectedratio[2]
			mw.DetectionRatio = int(mw.DetectedAV)/int(mw.AllAV)
		elif cmp(tdItem.text,"Analysis date:")==0:
			analysisdate = tdItemVal.text.split(' ')
			strDate = analysisdate[0]+' '+analysisdate[1] 
			mw.AnalysisDate = strDate #time.strptime(strDate,"%Y-%m-%d %H:%M:%S")
	
		trItem = trItem.nextSibling.nextSibling

def retrieveAddition(tab,mw):
	trList = tab.findAll('tr')
	if len(trList) >=1:
		aliaslist=[]
		trAlias = trList[len(trList)-1]
		liList = trAlias('li')
		for li in liList:
			aliaslist.append(li.text)
		mw.Alias = '\n'.join(aliaslist)

def retrieveBehave(tab,mw):
	bFind = False
	trList = tab.findAll('tr')
	for tr in trList:
		h4 = tr.find('h4')
		if h4 is None:
			continue
		if cmp(h4.text,'Network activity')==0:
			bFind = True
			break;
	
	if bFind:	
		trNetActivity = tr
		while trNetActivity:
			h5 = trNetActivity.find('h5')
			if h5 is None:
				trNetActivity = trNetActivity.nextSibling
				continue
			elif h5 == -1:
				trNetActivity = trNetActivity.nextSibling
				continue
			elif cmp(h5.text,'HTTP requests...')==0:
				pre = trNetActivity.find('pre')
				httprequests = pre.getText('\n')
				#httplist=httprequests.split('\n')
				mw.HTTPrequest=httprequests
			elif cmp(h5.text,'DNS requests...')==0:
				pre = trNetActivity.find('pre')
				dnsrequests = pre.getText('\n')
				#dnslist=dnsrequests.split('\n')
				mw.DNSrequest=dnsrequests
			elif cmp(h5.text,'TCP connections...')==0:
				pre = trNetActivity.find('pre')
				tcpconnections = pre.getText('\n')
				#tcplist=tcpconnections.split('\n')
				mw.TCPconnection=tcpconnections
			elif cmp(h5.text,'UDP communications...')==0:
				pre = trNetActivity.find('pre')
				udpcommunications = pre.getText('\n')
				#udplist=udpcommunications.split('\n')
				mw.UDPcommunication=udpcommunications

			trNetActivity = trNetActivity.nextSibling

def writeDB(mw):
	try:
		print "Writing to database"
		db = MySQLdb.connect(host="localhost",user="zagorakis",passwd="Temp@Win2012",db="malware_db",charset="utf8")
		cur = db.cursor()
		sql = "insert into malware values ('%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s')"%(mw.SHA256,mw.SHA1,mw.MD5,mw.FileName,mw.FileSize,mw.FileType,mw.DetectionRatio,mw.DetectedAV,mw.AllAV,mw.AnalysisDate,mw.Alias,mw.HTTPrequest,mw.DNSrequest,mw.TCPconnection,mw.UDPcommunication)
		cur.execute(sql)
		cur.close()
		db.commit()
		db.close()
	except Exception as e:
		print e
		return False

	return True

def allFiles(root, patterns='*'):
	patterns = patterns.split(';')
	for path, subdirs, files in os.walk(root):
#		files.extend(subdirs)
		files.sort()
		for name in files:
			for pattern in patterns:
				if fnmatch.fnmatch(name, pattern):
					yield os.path.join(path,name)
					break

def main():
	try:
		opts, args = getopt.getopt(sys.argv[1:], 'd:', 'directory=')
	except getopt.GetoptError, err:
		print str(err)
		sys.exit(2)
	
	rootdir = "/home/zagorakis/work/malware/clean-mx-md5/"
	for o, a in opts:
		if o == '-d':
			rootdir = a
		else:
			assert False, "unhanlded option"
	
	fileCount = 0
	mwCount = 0
	
	for htmlfile in allFiles(rootdir,'*.html'):
		fileCount = fileCount + 1
		if retrieve(htmlfile):
			mwCount = mwCount + 1
		print htmlfile
	print fileCount, " files were analyzed.", mwCount, " malware items  were written to database"

#	retrieve('/home/zagorakis/work/malware/clean-mx-md5/20121111/036802/b593f8723765f3f139b9f9e8649aa970.html')
#	retrieve('/home/zagorakis/work/malware/clean-mx-md5/20121110/036767/8c06eb7b26d8acdd0548277f9598a08c.html')
	
if __name__ == '__main__':
	main()	
