import hashlib
import string
import os
import commands
import pydeep
import ssdeep
import pefilev2
import peutils
import peHash
import fuzzyhashlib
import sdhash
try:
    import magic
except ImportError:
    print 'python-magic is not installed, file types will not be available'
 
#Opens the executable file for static analysis
def load_file(filename):
    '''Function to load the file into the Pefile.py module and get the structure of the PE file loaded'''
     
    FILE = open(filename, "rb")
    data = FILE.read()
    FILE.close()
    pe = pefilev2.PE(data=data, fast_load=True)
    pe.parse_data_directories( directories =[pefilev2.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],pefilev2.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT'], pefilev2.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_TLS'], pefilev2.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])
     
    return pe
     
#Returns the dictionary of Hashes for the specific file uploaded
def get_PE_Hashes(pe, filename):
    sdhash = None
    imph = pe.get_imphash()     
    my_fuzzy = pydeep.hash_file(filename)
    pehash = peHash.get_peHash(filename)
     
    fh = open(filename, 'rb')
    m = hashlib.md5()
     
    d = fh.read()
    sdhash  = fuzzyhashlib.sdhash(d).hexdigest()
    md5 = hashlib.md5(d).hexdigest()
    slashed = filename.split('/')
    filename = slashed[len(slashed)-1]
    hashes ={"Filename":filename, "MD5":md5,"Imphash":imph,\
    "peHash":pehash,"Fuzzy Hash": my_fuzzy, "sdhash": sdhash}
    return hashes
 
def main():
    res_dir = '/home/cuckoo/Desktop/Mac-Programs/Data2_C_res/'
    md5log = '/home/cuckoo/Desktop/Mac-Programs/Data2_C_res/md5log.txt'
    pehlog = '/home/cuckoo/Desktop/Mac-Programs/Data2_C_res/pehlog.txt'
    imphlog = '/home/cuckoo/Desktop/Mac-Programs/Data2_C_res/imphlog.txt'
    ssdlog = '/home/cuckoo/Desktop/Mac-Programs/Data2_C_res/ssdeeplog.txt'
    maldir = '/home/cuckoo/Desktop/Malware2/Data2_C/' # Malware directory
    fm = open(md5log,'w')
    fp = open(pehlog, 'w')
    fi = open(imphlog, 'w')
    fs = open(ssdlog, 'w')
     
    for r, d, f in os.walk(maldir):
        for files in f:
            print maldir
            mal = maldir+files
            filename =mal
            print filename
            try:
                pe = load_file(filename)
                hashing = get_PE_Hashes(pe, filename)
                fnam =hashing["Filename"].split('.')
                fname = fnam[0]
                del hashing["Filename"]
                for k, v in hashing.items():
                    if k == "MD5":
                        fm.write("%s\t  %s" %(fname, v))
                 
                    if k == "peHash":
                        fp.write("%s\t  %s" %(fname, v))
                 
                    if k == "Imphash":
                        fi.write("%s\t  %s" %(fname, v))
                 
                    if k == "Fuzzy Hash":
                        fs.write("%s\t  %s" %(fname, v))
                 
                    if k == "sdhash":
                        log = res_dir + "%s_%s.txt" %(k, fname)
                        fs = open( log, 'w')
                        fs.write(v)
                        fs.close()
            except:
                pass
             
    fm.close()
    fp.close()
    fi.close()
    fs.close()
     
if __name__ =='__main__':
    main()
