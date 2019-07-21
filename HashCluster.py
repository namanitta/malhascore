import os
import pydeep
import sqlite3
import Hashes
import sys



def main():
	# Check if database exists and if the table exists.
	dbname = 'PEmalScore.db' # The hashing database
	#dbname = var
	dbpath = os.path.join(os.path.dirname(os.path.abspath(__file__)),'Signatures',dbname)
	
	if not Hashes.isSQLiteDB(dbpath):
		print 'The database provided does not exist'
		exit()
		
	con = sqlite3.connect(dbpath)
	dbconnect = con.cursor()
	imp_list, peH_list, imp_count, peH_count = Hashes.list_HashTables(dbconnect)
	print " ===Imphash Cluster count===="
	#print Hashes.print_dict_list(imp_count)

	print " \n ===PEhash Cluster count===="
	#print Hashes.print_dict_list(peH_count)
	'''for i in peH_list:
		print i'''
		
	print imp_list
	print set(imp_list).intersection(peH_list)
	con.close()
	
if __name__ =='__main__':
	main()
	
