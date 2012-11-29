import MySQLdb
from retrieve import Malware
import sys

def connectDB():
	try:
		db = MySQLdb.connect(host="localhost",user="zagorakis",passwd="Temp@Win2012",db="malware_db",charset="utf8")
	except Exception as e:
		print e
		sys.exit(2)

	print "Database connected"
	return db

def disconnectDB(db):
	try:
		db.close()
	except Exception as e:
		print e
		sys.exit(2)
	print "Database disconnected"

def writeDB(db, mw):
	print "Writing to database"
	try:
		cur = db.cursor()
		sql = "insert into malware values ('%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s')"%(mw.SHA256,mw.SHA1,mw.MD5,mw.FileName,mw.FileSize,mw.FileType,mw.DetectionRatio,mw.DetectedAV,mw.AllAV,mw.AnalysisDate,mw.Alias,mw.HTTPrequest,mw.DNSrequest,mw.TCPconnection,mw.UDPcommunication)
		cur.execute(sql)
		cur.close()
		db.commit()
	except Exception as e:
		print e
		return False
	
	return True
