def print_list(array):
	result = ''
	if array:
		for lst in array:
			newline = '\t'.join([str(lst[0]), str(lst[1])])
			result ='\n'.join([result, newline])
		return result
	else:
		return "No Matches Found"
		
	
def print_dict_list(array):
	result = ""
	for y in array:
		newline = '\t'.join([str(y), str(array[y])])
		result ='\n'.join([result, newline])
	return result
			
'''Printing Items in a dictionary'''
def print_dict(array):
	if 'Section' in array:
		print "Section\t:%s" %array["Section"]
		print "Entropy\t:%s" %array["Entropy"]
		print "MD5\t:%s" %array["MD5"]
		print "SHA1\t:%s" %array["SHA1"]
		print "SHA256\t:%s\n" %array["SHA256"]
		
	elif 'Filename' in array:
		print "Filename\t:%s" %array["Filename"]
		print "MD5\t:%s" %array["MD5"]
		#print "SHA1\t:%s" %array["SHA1"]
		print "Resource Section Fuzzy\t:%s" %array["ResFuzzy"]
		print "Fuzzy Hash\t:%s" %array["Fuzzy Hash"]
		print "PeHash\t:%s" %array["peHash"]
		print "Imphash\t:%s" %array["Imphash"]
	else:
		for k, v in array.items():
			print "%s\t:%s" %(k,v)


