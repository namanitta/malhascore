
import hashlib
import time
import binascii
import string
import os, sys
import commands
import re
import collections
import pydeep
import ssdeep
import sqlite3
import subprocess
import string
import pefilev2
import peutils
#import fingerprint
import peHash
import json
import presentation
try:
    import magic
except ImportError:
    print 'python-magic is not installed, file types will not be available'
    
	
'''The is the section of functions that are supporting functions to the program'''


#checks if the dbname provided is available	
def isSQLiteDB(dbname): 
	if not os.path.isfile(dbname):
		return False
	else:
		fd = open(dbname, 'rb')
		header = fd.read(100)
		return header[:16] == 'SQLite format 3\x00'
		
		
# finds the interesection of any 2 sets.
def intersection(Hx, Hy): 
	HxHy = []
	for x in Hx:
		for y in Hy:
			if y == x:
				HxHy.append(y)
	return HxHy

def ensure_dir(d):
	#d = os.path.dirname(filename)
	if not os.path.exists(d):
		os.makedirs(d)

	
'''End of the supporting functions.'''

def load_file(filename):
	'''Function to load the file into the Pefile.py module and get the structure of the PE file loaded'''
	
	FILE = open(filename, "rb")
	data = FILE.read()
	FILE.close()
	pe = pefilev2.PE(data=data, fast_load=True)
	pe.parse_data_directories()#( directories)#=[pefilev2.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],pefilev2.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT'], pefilev2.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_TLS'], pefilev2.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])
	
	return pe
	
	
#Returns the dictionary of Hashes for the specific file uploaded
	
def get_PE_Hashes(pe, filename):
	imph = pe.get_imphash()
	resfuzzy = ""
	for section in pe.sections:
		scn  = section.Name
		if scn == ".rsrc":
			resfuzzy = section.get_hash_ssdeep()
			
	my_fuzzy = pydeep.hash_file(filename)
	pehash = peHash.get_peHash(filename)
	fh = open(filename, 'rb')
	m = hashlib.md5()
	s = hashlib.sha1()
	s256 = hashlib.sha256()
	while True:
		data = fh.read(8192)
		if not data:
			break
		m.update(data)
		s.update(data)
		s256.update(data)
	md5 = m.hexdigest()
	sha1 = s.hexdigest()
	sha256 = s256.hexdigest()
	
	slashed = filename.split('/')
	filename = slashed[len(slashed)-1]
	
	hashes ={"Filename":filename, "MD5":md5,"SHA1":sha1,"SHA256":sha256,"Imphash":imph,"peHash":pehash,"Fuzzy Hash": my_fuzzy, "ResFuzzy": resfuzzy}
	return hashes
def fuzzycompare(Rows, thehash):
	fuzzyRet = []
	if Rows:
		for rows in Rows:
			cfuz = rows[1]
			percent = pydeep.compare(thehash, cfuz)
			if percent > 0:
				fuzzyRet.append([rows [0], percent])
	return fuzzyRet	
	
def compare_hashes(con, hashesdict):
	
	fuzzy = hashesdict["Fuzzy Hash"]
	md5 = hashesdict["MD5"]
	imph = hashesdict["Imphash"]
	peHash = hashesdict["peHash"]
	resfuzzy =["ResFuzzy"]
	fuzzyRet = []
	dbcon = con.cursor()
	#md5 similarity check
	dbcon.execute('''SELECT MD5 FROM FILE_HASHES WHERE MD5 = ?;''', (md5,))
	crptoHash_ret = dbcon.fetchall()
		
	#imphash similarity check	
	dbcon.execute('''SELECT MD5, IMPHASH, FUZZY_HASH  FROM FILE_HASHES WHERE IMPHASH = ?;''', (imph,))
	impHash_ret = dbcon.fetchall()
		
	#Pehash similariy check	
	dbcon.execute('''SELECT MD5, PEHASH, FUZZY_HASH FROM FILE_HASHES WHERE PEHASH = ?;''', (peHash,))
	peHash_ret = dbcon.fetchall()
			
	#fuzzy hash comparison
	dbcon.execute('''SELECT MD5, FUZZY_HASH FROM FILE_HASHES WHERE FUZZY_HASH NOT NULL;''')
	fuzzyRows = dbcon.fetchall()
	fuzzyRet = fuzzycompare(fuzzyRows,fuzzy)
	
	con.close()	
					
	return crptoHash_ret,impHash_ret, peHash_ret, fuzzyRet


def Intersect_hashes(fname, con, hashesdict):
	Smd5, SimpH, SpeH, SfuzH = compare_hashes(con, hashesdict)
	Xfuz = []
	Ximp = []
	Xpe = []
	Xallpn = []
	
	for v in SfuzH:
		Xfuz.append(v[0])
	#print Xfuz	
	for v in SimpH:
		Ximp.append(v[0])
	
	for v in SpeH:
		Xpe.append(v[0])
	#print Ximp
	Xif = intersection(Ximp, Xfuz)
	Xpf = intersection(Xpe, Xfuz)
	Xpi = intersection(Ximp, Xpe)
	Xall = intersection(Xif,Xpe)
	if Xall:
		Xallp = fuzPercentage (SfuzH, Xall)
		Xallpn = maxFuzzyPercent(Xallp, 3)
		match = "FIP"
	elif Xpf:
		Xallp = fuzPercentage (SfuzH, Xpf)
		Xallpn = maxFuzzyPercent(Xallp, 2)
		match = "FP"
		
	elif Xif:
		Xallp = fuzPercentage (SfuzH, Xif)
		Xallpn = maxFuzzyPercent(Xallp, 2)
		match = "FI"
		
	elif Xpi:
		Xallpn.append([Xpi[0],0])
		Xallpn.append(2)
		match = "IP"
		
	elif SfuzH:
		Xallpn = maxFuzzyPercent(SfuzH, 1)
		match = "F"
		
	elif SimpH:
		Xallpn.append([SimpH[0][0],0])
		Xallpn.append(1)
		match = "I"
		
	elif SpeH:
		Xallpn = []
		Xallpn.append([SpeH[0][0],0])
		Xallpn.append(1)
		match = "P"

	if Xallpn:
		Xallpn.append(match)	
	return Xallpn

	
	
def print_intersect_hashes(fname, Xallpn,caf):
	if Xallpn:
		print "%s \t%s \t%s \t%s\t%s\t%s\t%s" %(fname,Xallpn[0][0],Xallpn[0][1],Xallpn[1], Xallpn[2],caf[0], caf[1])
	else:
		print "%s \tUnknown\n" %(fname)
						
						
								
def fuzPercentage (Y, X):
	Xallp = []
	if X and Y:
		for x in X:
			for v in Y:
				if v[0] == x:
					Xallp.append([x, v[1]])
	return Xallp
	
def maxFuzzyPercent(X, n):
	res = []
	for i,x in enumerate(X):
		if i ==0:
			res.append(x)
		else:
			if res[0][1]< x[1]:
				res =[]
				res.append(x)
	res.append (n)
	return res
	
	
def print_compare_Hashes(con, hashesdict):
	Smd5, SimpH, SpeH, SfuzH = compare_hashes(con, hashesdict)
	
	if Smd5:
		print "Similar MD5"
		for rows in Smd5:# and rs in SimpH:
			print rows[0]
			#print " %s \t %s" % (rows[0],rs[0])
	if SimpH:
		print "\tSimilar Imphash"
		for rows in SimpH:
			print "\t %s" % rows[0]
	if SpeH:
		print "\t\tSimilar Pehash"
		for rows in SpeH:
			print "\t\t %s" % rows[0]
	if SfuzH:
		print "\t\t\tSimilarity in Fuzzy Hashing"
		for rows in SfuzH:
			print "\t\t%s \t %s" % (rows[0],rows[1])
			
			#print " %s \t %s" % (rows[0],rows[1])
			
	
def list_HashTables(dbcon):
	dbcon.execute('''SELECT IMPHASH  FROM FILE_HASHES WHERE IMPHASH NOT NULL;''')
	imp_ret = dbcon.fetchall()
	imphashes =[]
	duplicate_imp = []
	for row in imp_ret:
		imp = row[0]
		duplicate_imp.append(imp)
		if imp not in imphashes:
			imphashes.append(imp)
	imp_count = collections.Counter(duplicate_imp)
			
	dbcon.execute('''SELECT PEHASH FROM FILE_HASHES WHERE PEHASH NOT NULL;''')
	peHash_ret = dbcon.fetchall()
	pehashes = []
	duplicate_peh = []
	for row in peHash_ret:
		peh = row[0]
		duplicate_peh.append(peh)
		if peh not in pehashes:
			pehashes.append(peh)
	peh_count = collections.Counter(duplicate_peh)
	
	return imphashes, pehashes, imp_count, peh_count


def update_hashesTable(hashes,con):
	if hashes:
		dbconnect = con.cursor()
		dbconnect.execute('''SELECT MD5 FROM FILE_HASHES WHERE MD5 = ?;''', (hashes["MD5"],))
		rows = dbconnect.fetchone()
		if rows is None:
			dbconnect.execute('''INSERT INTO FILE_HASHES(MD5, FILENAME, SHA_1, SHA_256,IMPHASH, PEHASH, FUZZY_HASH) VALUES (?,?,?,?,?,?,?);'''\
			,(hashes["MD5"],hashes["Filename"],hashes["SHA1"],hashes["SHA256"],hashes["Imphash"],hashes["peHash"],hashes["Fuzzy Hash"]))
			con.commit()
			con.close()
			return 'Details Successfully Saved....'
		else:
			con.close()
			return 'Details already exist in the table'
	else:
		return 'Unable to update the hashes'

def createDB(dbpath):
	con = sqlite3.connect(dbpath)
	dbconnect = con.cursor()
	dbconnect.execute('''CREATE TABLE IF NOT EXISTS FILE_HASHES(MD5 STRING , FILENAME STRING, SHA_1 STRING, \
						SHA_256 STRING,IMPHASH STRING, PEHASH STRING, FUZZY_HASH STRING, RES_FUZZY_HASH STRING);''')	
	con.commit()
	return con

def openDB(dbpath):
	con = sqlite3.connect(dbpath)
	dbconnect = con.cursor()
	con.commit()
	return con
	
def Combination_approaches(correct_bel,xallpn):
	if correct_bel:
		peBel = correct_bel[0]
		impBel = correct_bel[1]
		fuzzyBel = correct_bel[2]
	if xallpn:
		match = xallpn[2]
		if "F" in match:
			x = fuzzyBel*float(xallpn[0][1])/100.0
		else:
			x = fuzzyBel *0.0
	
		if "I" in match:
			y = impBel*1.00
		else:
			y = impBel*0.0	
	
		if "P" in match:
			z = peBel*1.00
		else:
			z = peBel*0.0
		#print y
		#print x	
		#print z	
		CF = MYCINFactor(x,y)
		CF = MYCINFactor(CF,Z)
		TotalCF = MYCINFactor(CF,z)
		FL = FuzzyLogic(x,y)
		TotalFL =  MYCINFactor(FL,z)
	
		return TotalCF*100.0, TotalFL*100
	else:
		return "No match"
		

def MYCINFactor (a,b):
	z = (a+b)/(1+(a*b))
	
	return z

def FuzzyLogic(a,b):
	z =a+b-(a*b)
	
	return z
	
	
def mcore(fname, filename, dbpath, option):
	pe = load_file(filename)
	hashing = get_PE_Hashes(pe, filename)
	if option == "u": # updating the database of Hashes
		con  = createDB(dbpath)
		update_hashesTable( hashing,con)
	if option == "p": #Getting the Database of Hashes
		presentation.print_dict(hashing)
	if option == "c": # Comparing the Hashes
		if not os.path.isfile(dbpath):
			print "No Database of Hashes."
		else:
			con  = openDB(dbpath)
			print_compare_Hashes(con, hashing)
	if option == "o": # Overall Score calculation
		if not os.path.isfile(dbpath):
			print "No Database of Hashes."
		else:
			con  = openDB(dbpath)
			xpn = Intersect_hashes(fname, con, hashing)
			correct_bel = [0.45,0.48,0.06]
			caf= Combination_approaches(correct_bel,xpn)
			print_intersect_hashes(fname, xpn, caf)
			
			
	
		

	
def main():
	
	if len(sys.argv) ==3:
		dbname = 'MALHASHES.db' # The hashing database
		sigpath = os.path.join(os.path.dirname(os.path.abspath(__file__)),'Signatures')
		resultpath = os.path.join(os.path.dirname(os.path.abspath(__file__)),'Results')
		dbpath = os.path.join(sigpath,dbname)	
		ensure_dir(sigpath)
		ensure_dir(resultpath)
		#print dbpath
		
		filename =sys.argv[2]
		option = sys.argv[1]
		
		#dirpath = '/home/cuckoo/Desktop/HashTest2'
		
		if os.path.isfile(filename):
			fname = (os.path.split(filename)[-1]).split(".")[0]
			testpath = '/'.join([resultpath,(fname+'.txt')])
			mcore(fname, filename,dbpath,option)
			
		elif os.path.isdir(filename):
			dirname = os.path.split(filename)[-1]
			#print dirname
			#print dirpath
			newdir = os.path.join(dirpath, dirname)
			#print newdir
			if not os.path.exists(newdir):
				os.mkdir(newdir)
			if option == "o":
				hfname = os.path.join(newdir, (dirname+'.txt'))
				sys.stdout = open(hfname,'w')
			for r, d, f in os.walk(filename):
				for files in f:
					#print files
					
					if option != "o":
						hfname = os.path.join(newdir, (files+'.txt'))
						sys.stdout = open(hfname,'w')
						
					fname = os.path.join(filename, files)
					try:
						mcore(files, fname,dbpath, option)
					except:
						pass
					
				
		#print " Analysis finished"'''
	else:
		print "Please use the format: python Hashes.py <option> <filename>"
		print "options: c - to get the list of all the md5s with file comparison.\
		\n \t u -to update the database.\
		\n \t p - to get the hash values.\
		\n \t get - to get the hash values."
if __name__ =='__main__':
	main()
