##############################################################################
## Copyright 2015 Christian Roggia. All rights reserved.                    ##
## Use of this source code is governed by a Apache 2.0 license that can be  ##
## found in the LICENSE file.                                               ##
##############################################################################

import sys
import os
import struct
import ntpath

def LoadFileIndex(idx):
    l = index.splitlines()
    r = []
    
    print ("\n[APX FILE INDEX]")
    for i in range(len(l)):
        if i == 0:
            print ("\tFILE-CRC  : %08X" % int(l[i], 16))
        elif i == 1:
            print ("\tFILE-COUNT: %u" % int(l[i], 10))
        else:
            f = l[i].decode('gb2312', 'ignore').split('|')
            #print ("\tFILE      : [%s, %08X, %08X]" % (f[0], int(f[1], 16), int(f[2], 16)))
            r.append([f[0], int(f[1], 16), int(f[2], 16)])
    
    return r

if __name__ == "__main__":
    os.system('cls')
    
    if len(sys.argv) <= 1:
        exit()
    
    print ("[APX METADATA DECRYPTER]")
    print ("Look at how fucking awesome I am...")
    
    for i in sys.argv[1:]:
        f = open(i, "rb")
        
        data = f.read()
        h = struct.unpack("4sIIIIIIIII", data[:40])
        
        print ("\n[APX FILE HEADER]")
        print ("\tMARK    : %s" % h[0].decode())
        print ("\tUNKNOWN : [%08X, %08X]" % (h[1], h[2]))
        print ("\tPOINTER1: %08X" % h[3])
        print ("\tPOINTER2: %08X" % h[4])
        print ("\tRECORDS : %u" % h[5])
        print ("\tSEC-SIZE: %08X" % h[6])
        print ("\tPOINTER3: %08X" % h[7])
        print ("\tSEC-SIZE: %08X" % h[8])
        print ("\tUNKNOWN : [%08X]" % (h[9]))
        
        sec_1 = data[h[4]:h[4]+h[5]*12]
        
        lr = []
        ln = []
        
        print ("\n[APX RECORDS]")
        for k in range(h[5]):
            record = struct.unpack("III", sec_1[k*12:k*12+12])
            
            if k != h[5] - 1:  
                #print ("%s. [%08X, %08X, %08X]" % (('%d' % k).rjust(6), record[0], record[1], record[2]))
                lr.append(record)
            else:
                #print ("%s. [%08X, %08X, %08X]" % ('IDX'.rjust(6), record[0], record[1], record[2]))
                index = data[record[0]:record[0]+record[1]]
                ln = LoadFileIndex(index.decode('gb2312', 'ignore'))
        
        if len(lr) != len(ln):
            print ("[ERROR] Array size differs. Can't continue.")
            exit(0)
        
        for j in range(len(lr)):
            apx_name = os.path.splitext(os.path.basename(i).upper())[0]
            apx_path = '%s\\FILES-APX-%s\\%s' % (os.path.dirname(os.path.realpath(__file__)), apx_name, ln[j][0])
            if os.path.dirname(apx_path) != '':
                if not os.path.exists(os.path.dirname(apx_path)):
                    os.makedirs(os.path.dirname(apx_path))
            
            with open(apx_path, "wb") as of:
                of.write(data[lr[j][0]:lr[j][0]+lr[j][1]])
            
        f.close()
    
    os.system("pause")