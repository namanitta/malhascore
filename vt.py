
'''This is the the virustotal script that creates the table for vt scans done of the files'''
import urllib, urllib2, re, os, sys, sqlite3, simplejson, pprint, argparse, hashlib,collections, time

def createDB(dbpath):
	con = sqlite3.connect(dbpath)
	dbconnect = con.cursor()
	dbconnect.execute('''CREATE TABLE IF NOT EXISTS MALWARE_TYPE(MD5 STRING , TYPE STRING, POSITIVES INT, DETECTION INT);''')	
	con.commit()
	con.close()

def query_vt(md5, api):
	base = 'https://www.virustotal.com/vtapi/v2/'
	param = {'resource':md5, 'apikey':api}
	maltype_list =[]
	det_percent = 0
	positive = 0
	maltype = ""
	url = base + 'file/report'
	data = urllib.urlencode(param)
	req = urllib2.Request(url,data)
	result = urllib2.urlopen(req)
	json =result.read()
	response_dict = simplejson.loads(json)
	try:
		ret = response_dict.get("scans", {})
		positive = int(response_dict["positives"])
		Total = int(response_dict["total"])
		det_percent = int((float(positive)/float(Total))*100)
		
		for x in ret:
			mal = str(ret[x]["result"])
			mal = mal.replace(".", " ")
			maltype_list .append(mal)
	
		mal_count = collections.Counter(maltype_list)
		if 'None' in maltype_list:
			maltype_list = [x for x in maltype_list if x !="None"]
	
		if maltype_list:
			maltype = max(set(maltype_list), key = maltype_list.count)
		else:
			maltype = str(ret["Kaspersky"]["result"]) 
			
	except:
		print "Error in VT response"
		
	return maltype, det_percent, positive
	
def main():
	dbname = 'PEmalScore.db' # The hashing database
	api = 'ea8928e2b3a259081ff3d90ef6818d2abaee2cbfe43907f800f161a8e4b1f6f3'
	dbpath = os.path.join(os.path.dirname(os.path.abspath(__file__)),'Signatures',dbname)
	createDB(dbpath)
		
	con = sqlite3.connect(dbpath)
	dbconnect = con.cursor()
	dbconnect.execute('''SELECT MD5 FROM FILE_HASHES WHERE MD5 NOT NULL;''')
	allmd5 = dbconnect.fetchall()
	#allmd5 = allmd5s[3:7]
	for md5 in allmd5:
		dbconnect.execute('''SELECT MD5 FROM MALWARE_TYPE WHERE MD5 = ?;''', (md5[0],))
		rows = dbconnect.fetchone()
		if rows is None:
			filetype, percent, positives = query_vt(md5[0], api)
			print (md5[0], '\t', filetype, percent)
			dbconnect.execute('''INSERT INTO MALWARE_TYPE(MD5, TYPE, POSITIVES, DETECTION) VALUES (?,?,?,?);''', (md5[0], filetype, positives, percent))
			con.commit()
			time.sleep(15)
		else:
			print "%s  Record already exists..."%md5[0]
	
	con.close()
	

if __name__ =='__main__':
	main()
