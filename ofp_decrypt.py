import os
import sys
import binascii
import hashlib
from Crypto.Cipher import AES
from Crypto.Util import Counter

def swap(ch):
    return ((ch&0xF)<<4)+((ch&0xF0)>>4)

def keyshuffle(key,hkey):
    for i in range(0,0x10,4):
        key[i]=swap((hkey[i]^key[i]))
        key[i+1]=swap(hkey[i+1]^key[i+1])
        key[i+2]=swap(hkey[i+2]^key[i+2])
        key[i+3]=swap(hkey[i+3]^key[i+3])
    return key
    
def main(filename,start,length):
    key1="42F2D5399137E2B2813CD8ECDF2F4D72"
    key2="F6C50203515A2CE7D8C3E1F938B7E94C"
    key3="67657963787565E837D226B69A495D21"

    key1=bytearray.fromhex(key1)
    key2 = bytearray.fromhex(key2)
    key3 = bytearray.fromhex(key3)

    key2=keyshuffle(key2,key3)
    aeskey=bytes(hashlib.md5(key2).hexdigest()[0:16],'utf-8')
    key1=keyshuffle(key1,key3)
    iv=bytes(hashlib.md5(key1).hexdigest()[0:16],'utf-8')

    #print("Aes Key: "+str(binascii.hexlify(aeskey))+", "+str(binascii.hexlify(iv)))
    crypto = AES.new(aeskey, AES.MODE_CFB, iv, segment_size = 128)
    with open(filename,'rb') as rf:
        rf.seek(start)
        data=rf.read(length)
        with open(filename+".dec",'wb') as wf:
            wdata=crypto.decrypt(data)
            wf.write(wdata)

    print("File successfully decrypted to "+filename+".dec")
    
if __name__ == '__main__':
    if len(sys.argv) != 4:
        print ("Oppo OFP decrypt tool (c) B.Kerler 2017\n") 
        print ("Usage: %s <filename> <startoffset> <length>" % __file__)
        sys.exit(1)
    
    filename=sys.argv[1]
    start=int(sys.argv[2],16)
    length=int(sys.argv[3],16) 
    main(filename,start,length)