import sys,os,time,datetime
import threading
import urllib,urllib2
from urllib import urlopen
from BeautifulSoup import BeautifulSoup
import getopt
import math
import Queue
import hashlib
from urlparse import urlsplit
from termcolor import colored
import re

queue = Queue.Queue()

rootdir = '/home/zagorakis/work/malware/clean-mx-md5/'

mx_url1 = 'http://lists.clean-mx.com/pipermail/viruswatch/'
mx_url2 = '/thread.html'

vs_url1 = 'https://www.virustotal.com/file/'
vs_url2 = '/analysis/'

class ThreadMW(threading.Thread):
	def __init__(self, num, queue):
		threading.Thread.__init__(self)
		self.num = num
		self.queue = queue
		self.day = ''
		self.url = ''
		self.last_prec='0'
		self.this_prec='0'

	def run(self):
		while True:
		#	if self.queue.qsize()>0:
				self.day = self.queue.get()

				threadUrl = mx_url1 + self.day + mx_url2
			
				self.grabThread(threadUrl)

				self.queue.task_done()
		#	else:
		#		break;

	def grabThread(self, url):
		print time.strftime("%Y-%m-%d %H:%M:%S",time.localtime()), colored("Thread %d"%self.num, 'white'), ("is crawling thread at %s" %(url))

		threadDir = rootdir + self.day
		if not os.path.exists(threadDir):
			os.mkdir(threadDir)

		text = urlopen(url).read()
		soup = BeautifulSoup(text)
		
		for li in soup.findAll('li'):
			if li.text.find('[Viruswatch]')>=0:
				for attr in li.find('a').attrs:	
					name, value = attr
					if name == 'href':
						self.grabPage(value)
						break

	def grabPage(self, htmlfile):
		url = mx_url1 + self.day + '/' + htmlfile
		print time.strftime("%Y-%m-%d %H:%M:%S",time.localtime()), colored("Thread %d"%self.num, 'white'), ("is crawling page at %s" %(url))
		
		i = htmlfile.find('.html')
		pageName = htmlfile[0:i]
		pageDir = rootdir + self.day + '/' + pageName
		if not os.path.exists(pageDir):
			os.mkdir(pageDir)

		text = urlopen(url).read()
		soup = BeautifulSoup(text)
		
		pre = soup.find('pre')
		for mw in pre.findAll('a'):
		#	if mw.text.find('.exe')>=0:
			if re.search('.exe$', mw.text):
				self.url = mw.text
				mwbasename = 'malware.exe'#os.path.basename(urlsplit(mw.text)[2])
				mwpath = pageDir
				mwfilename = os.path.join(mwpath, mwbasename)
				
				# downloading malware file
				print time.strftime("%Y-%m-%d %H:%M:%S",time.localtime()), colored("Thread %d"%self.num, 'white'), ("starts downloading %s" %(mw.text))
				try:
					self.last_prec = '0'
					self.last_prec = '0'
					urllib.urlretrieve(mw.text, mwfilename, self.urlcallback)
				except Exception as e:
					print e

				#os.popen("wget -c -nc -t 5 -T 30 -O %s %s" %(mwfilename, mw.text))
				print time.strftime("%Y-%m-%d %H:%M:%S",time.localtime()), colored("Thread %d"%self.num, 'white'), ("ends downloading %s" %(mw.text))
				
				# rename malware file with md5 hash value
				if os.path.exists(mwfilename)==False:
					print "No such file %s" %mwfilename
				else:
					fileContent = open(mwfilename,"rb").read()
					mwhashmd5 = hashlib.md5(fileContent).hexdigest()
					new_mwbasename = mwhashmd5 + '.exe'
					os.rename(mwfilename, os.path.join(mwpath, new_mwbasename))
				
					# downloading malware information from virustotal.com
					mwhash256 = hashlib.sha256(fileContent).hexdigest()
					vsbasename = mwhashmd5 + '.html'
					vspath = mwpath
					vsfilename = os.path.join(vspath, vsbasename)
					vs_url = vs_url1 + mwhash256 + vs_url2

					print time.strftime("%Y-%m-%d %H:%M:%S",time.localtime()), colored("Thread %d"%self.num, 'white'), ("starts downloading %s" %(vs_url))
					try:
						urllib.urlretrieve(vs_url, vsfilename)			
					except Exception as e:
						print e

					#os.popen("wget -c -nc -t 5 -T 30 -O %s %s" %(vsfilename, vs_url))
					print time.strftime("%Y-%m-%d %H:%M:%S",time.localtime()), colored("Thread %d"%self.num, 'white'), ("ends downloading %s" %(vs_url))

	def urlcallback(self,block_num,block_size,file_size):
		prec = 100*block_num*block_size/file_size
		if 100 < prec:
			prec=100
		this_prec = str(prec)[0:5]
		if self.last_prec!=this_prec:
			print time.strftime("%Y-%m-%d %H:%M:%S",time.localtime()), colored("Thread %d"%self.num, 'white'), colored(this_prec+"%", 'white'), ("%s"%self.url)
		self.last_prec = this_prec
		#print "%.2f%%"%(prec)

def getDays(str_from, str_to):
	try:
		date_from = datetime.datetime.strptime(str_from,'%Y%m%d')
		date_to = datetime.datetime.strptime(str_to,'%Y%m%d')
	except Exception as e:
		print e
		sys.exit(2)

	date_range = date_to - date_from
	
	days = []
	
	if date_range.days >= 0:
		days_item = date_from
	else:
		days_item = date_to

	for i in range(abs(date_range.days)+1):
		days.append(days_item.strftime('%Y%m%d'))
		days_item += datetime.timedelta(days=1)

	return days

def main():
	try:
		opts, args = getopt.getopt(sys.argv[1:], 'f:t:')
	except getopt.GetoptError, err:
		print str(err)
		sys.exit(2)
	
	date_from = date_to = ''
	for o, a in opts:
		if o == '-f':
			date_from = a
		elif o == '-t':
			date_to = a
		else:
			assert False, "unhanlded option"
	
	days = getDays(date_from, date_to)
	
	for i in range(len(days)):
		t_mw = ThreadMW(i, queue)
		t_mw.setDaemon(True)
		t_mw.start()

	for oneday in days:
		queue.put(oneday)

	queue.join()

if __name__=='__main__':
	main()
