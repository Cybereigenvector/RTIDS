# --------------------------------------------------------------------------------------------------
# Property of UAH
# IDS module for ladder logic monitoring
# This codes is Written by Rishabh Das
# Date:- 18th June 2018
# --------------------------------------------------------------------------------------------------
import hashlib
import os

# ---------------------------------------------------------------------------------------------------
# This section declares the Global variables of the project
# ---------------------------------------------------------------------------------------------------
Monitoredlist=[]
list_create=[]
list_compare=[]


# ---------------------------------------------------------------------------------------------------
# This section notes the number of files in the directory and creates the list of the files that needs
# to be monitored
# ---------------------------------------------------------------------------------------------------
def Create_list():
    i=0
    for file in os.listdir(os.getcwd()):
        if file.endswith("openplc"):
            Monitoredlist.append(file)
            i += 1
    if i==0:
        print("No Files are being monitored!")
    else:
        print("The files being monitored are as follows")
        print(Monitoredlist)
# ---------------------------------------------------------------------------------------------------
# This is the Hasher module that creates the hash for the files and maintains a table of the file
# hashes
# ---------------------------------------------------------------------------------------------------
def Hasher():
    BLOCKSIZE = 65536
    hasher = hashlib.sha1()
    del list_create[:]
    for i in range(len(Monitoredlist)):
        list_create.append(Monitoredlist[i])
        with open(Monitoredlist[i], 'rb') as afile:
            buf = afile.read(BLOCKSIZE)
            while len(buf) > 0:
                hasher.update(buf)
                buf = afile.read(BLOCKSIZE)
            list_create.append(hasher.hexdigest())
    #print(list_create)
# --------------------------------------------------------------------------------------------------
# This Function records the hash of the files being monitored to a text file. This should only be
# called when the program is being executed for the first time
# --------------------------------------------------------------------------------------------------
def Create_record():
    progpath = os.getcwd()
    dirpath = progpath + '/Details'
    if not os.path.exists(dirpath):
        os.makedirs(dirpath)
    os.chdir(dirpath)
    file = open('Record.txt',"w")
    for item in list_create:
        file.write("%s\n" % item)
    file.close()
    os.chdir(progpath)
# --------------------------------------------------------------------------------------------------
# This module parses the stored hashes and stores them into a fresh python list
# --------------------------------------------------------------------------------------------------
def Read_hash():
    progpath = os.getcwd()
    dirpath = progpath + '/Details'
    os.chdir(dirpath)  
    file = open('Record.txt', 'r')
    list_compare=[]
    list_compare = file.readlines()
    list_compare = [x[:-1] for x in list_compare]
    os.chdir(progpath)
    #print(list_compare)
    #print(list_create)
    if list_compare == list_create:
        Response(0)
    else:
        Response(1)
# --------------------------------------------------------------------------------------------------
# Once the change is detected this module is used to respond to the threat
# flag ->>>> 1 Change is detected
# flag ->>>> 0 No change
# --------------------------------------------------------------------------------------------------
def Response(flag):
    if flag==1:
        print("Ladder Logic Tampered")
        #Launch recovery routine
    else:
        print("Ladder Logic is Secure")
# --------------------------------------------------------------------------------------------------
# The main Function
# --------------------------------------------------------------------------------------------------
def main():
    Create_list()
    Hasher()
    print(list_create)
    Create_record()
    Read_hash() # First call with 0 argument
    while(1):
      Hasher()
      Read_hash() # Next calls are all performed by argument
    

# 1. Create the folder for storing the new file->Done
# 2. Module to compare the files with a new file->Done
# 3. Module to backup the ladder logics
# 4. Module to restore the ladder logic
# 5. Reporting unit->Done
# 6. Push code to GitHub->Done

if __name__ == "__main__": main()
