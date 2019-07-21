import os
import pydeep
import sqlite3
import Hashes
import sys

def main():
	#var = raw_input('Please enter something: ')
	#print "you entered ", var
	# Check if database exists and if the table exists.
	dbname = 'PEmalScore.db' # The hashing database
	#dbname = var
	dbpath = os.path.join(os.path.dirname(os.path.abspath(__file__)),'Signatures',dbname)
	
	if not Hashes.isSQLiteDB(dbpath):
		print 'The database provided does not exist'
		exit()
		
	con = sqlite3.connect(dbpath)
	dbconnect = con.cursor()
	
	if len(sys.argv) ==2:
		filename =sys.argv[1]
		pe = Hashes.load_file(filename)
		hashing = Hashes.get_PE_Hashes(pe, filename)
		hashes = \
		(hashing["Filename"],hashing["MD5"],hashing["SHA1"],hashing["SHA256"],\
		hashing["Imphash"],hashing["peHash"],hashing["Fuzzy Hash"])
		md5Match, impHashMatch, peHashMatch, FuzzyMatch = Hashes.compare_hashes(dbconnect, hashing)
		print "===================================== HASH MATCHING================================="
		print "MD5 file Match:"
		for md5 in md5Match:
			print md5[0]
		print "\nImphash file Match:"
		print Hashes.print_list(impHashMatch)
		print 
		print "\nPeHash file Match:"
		print Hashes.print_list(peHashMatch)
		print "\nFuzzyHash file Match:"
		print Hashes.print_list(FuzzyMatch)
				
	con.close()
	
if __name__ =='__main__':
	main()
	
