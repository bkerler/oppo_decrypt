#!/usr/bin/env python3
# Oppo OFP MTK Decrypter (c) B. Kerler 2022
# Licensed under MIT License

import os
import sys
import hashlib
from Cryptodome.Cipher import AES
from struct import unpack
from binascii import unhexlify, hexlify

def swap(ch):
    return ((ch&0xF)<<4)+((ch&0xF0)>>4)

def keyshuffle(key,hkey):
    for i in range(0,0x10,4):
        key[i]=swap((hkey[i]^key[i]))
        key[i+1]=swap(hkey[i+1]^key[i+1])
        key[i+2]=swap(hkey[i+2]^key[i+2])
        key[i+3]=swap(hkey[i+3]^key[i+3])
    return key

def mtk_shuffle(key,keylength,input,inputlength):
    for i in range(0,inputlength):
        k=key[(i%keylength)]
        h=((((input[i]) & 0xF0) >> 4) | (16 * ((input[i]) & 0xF)))
        input[i]=k ^ h
    return input

def mtk_shuffle2(key,keylength,input,inputlength):
    for i in range(0,inputlength):
      tmp = key[i % keylength] ^ input[i]
      input[i]=((tmp & 0xF0) >> 4) | (16 * (tmp & 0xF))
    return input


def aes_cfb(key, iv, data, decrypt=True, segment_size=128):
    cipher = AES.new(key, AES.MODE_CFB,  IV=iv, segment_size=segment_size)
    if decrypt:
        plaintext = cipher.decrypt(data)
        return plaintext
    else:
        ciphertext = cipher.encrypt(data)
        return ciphertext

keytables=[
        ["67657963787565E837D226B69A495D21", #A77 CPH1715EX_11_A.04_170426, F1S A1601_MT6750_EX_11_A.15_160913 FW
         "F6C50203515A2CE7D8C3E1F938B7E94C",
         "42F2D5399137E2B2813CD8ECDF2F4D72"],

        ["9E4F32639D21357D37D226B69A495D21", #A77 CPH1715EX_11_A.04_170426, F1S A1601_MT6750_EX_11_A.15_160913 CDT
         "A3D8D358E42F5A9E931DD3917D9A3218",
         "386935399137416B67416BECF22F519A"],

        ["892D57E92A4D8A975E3C216B7C9DE189",
         "D26DF2D9913785B145D18C7219B89F26",
         "516989E4A1BFC78B365C6BC57D944391"],

        ["27827963787265EF89D126B69A495A21",
         "82C50203285A2CE7D8C3E198383CE94C",
         "422DD5399181E223813CD8ECDF2E4D72"],

        ["3C4A618D9BF2E4279DC758CD535147C3",
         "87B13D29709AC1BF2382276C4E8DF232",
         "59B7A8E967265E9BCABE2469FE4A915E"],

        ["1C3288822BF824259DC852C1733127D3", #A83_CPH1827_11_A.21_2G_180923 FW, Realme 3 RMX1827EX_11_C.13_200624_1264686e
         "E7918D22799181CF2312176C9E2DF298",
         "3247F889A7B6DECBCA3E28693E4AAAFE"],

        ["1E4F32239D65A57D37D2266D9A775D43",
         "A332D3C3E42F5A3E931DD991729A321D",
         "3F2A35399A373377674155ECF28FD19A"],

        ["122D57E92A518AFF5E3C786B7C34E189",
         "DD6DF2D9543785674522717219989FB0",
         "12698965A132C76136CC88C5DD94EE91"],

        [
            "ab3f76d7989207f2",  #AES KEY
            "2bf515b3a9737835"   #AES IV
        ]

        
]

def getkey(index):
    kt=keytables[index]
    if len(kt) == 3 :
        obskey=bytearray(unhexlify(kt[0]))
        encaeskey=bytearray(unhexlify(kt[1]))
        encaesiv=bytearray(unhexlify(kt[2]))
        aeskey=hexlify(hashlib.md5(mtk_shuffle2(obskey,16,encaeskey,16)).digest())[:16]
        aesiv=hexlify(hashlib.md5(mtk_shuffle2(obskey, 16, encaesiv, 16)).digest())[:16]
    else:
        aeskey = bytes(kt[0],'utf-8')
        aesiv =  bytes(kt[1],'utf-8')
        print(aeskey,aesiv)
    return aeskey, aesiv

def brutekey(rf):
    rf.seek(0)
    encdata=rf.read(16)
    for keyid in range(0,len(keytables)):
        aeskey, aesiv = getkey(keyid)
        data = aes_cfb(aeskey, aesiv, encdata, True)
        if data[:3]==b"MMM":
            return aeskey, aesiv
    print("Unknown key. Please ask the author for support :)")
    exit(0)

def cleancstring(input):
    return input.replace(b"\x00",b"").decode('utf-8')

def main(filename,outdir):
    if not os.path.exists(outdir):
        os.mkdir(outdir)
    hdrkey = bytearray(b"geyixue")
    filesize=os.stat(filename).st_size
    hdrlength=0x6C
    with open(filename,'rb') as rf:
        aeskey, aesiv = brutekey(rf)
        rf.seek(filesize-hdrlength)
        hdr = mtk_shuffle(hdrkey, len(hdrkey), bytearray(rf.read(hdrlength)), hdrlength)
        prjname,unknownval, reserved, cpu, flashtype, hdr2entries,prjinfo,crc=unpack("46s Q 4s 7s 5s H 32s H",hdr)
        hdr2length=hdr2entries*0x60
        prjname=cleancstring(prjname)
        prjinfo=cleancstring(prjinfo)
        cpu = cleancstring(cpu)
        flashtype = cleancstring(flashtype)
        if prjname!="": print(f"Detected prjname:{prjname}")
        if prjinfo!="": print(f"Detected prjinfo:{prjinfo}")
        if cpu!="": print(f"Detected cpu:{cpu}")
        if flashtype != "": print(f"Detected flash:{flashtype}")

        rf.seek(filesize-hdr2length-hdrlength)
        hdr2 = mtk_shuffle(hdrkey, len(hdrkey), bytearray(rf.read(hdr2length)), hdr2length)
        for i in range(0,len(hdr2)//0x60):
            name,start,length,enclength,filename,crc=unpack("<32s Q Q Q 32s Q",hdr2[i*0x60:(i*0x60)+0x60])
            name=name.replace(b"\x00",b"").decode('utf-8')
            filename = filename.replace(b"\x00", b"").decode('utf-8')
            print(f"Writing \"{name}\" as \"{outdir}/{filename}\"...")
            with open(os.path.join(outdir,filename),'wb') as wb:
                if enclength>0:
                    rf.seek(start)
                    encdata=rf.read(enclength)
                    if enclength%16!=0:
                        encdata+=b"\x00"*(16-(enclength%16))
                    data=aes_cfb(aeskey,aesiv,encdata,True)
                    wb.write(data[:enclength])
                    length-=enclength
                while length>0:
                    size=0x200000
                    if length<size:
                        size=length
                    data=rf.read(size)
                    length-=size
                    wb.write(data)

    print(f"Files successfully decrypted to subdirectory {outdir}")
    
if __name__ == '__main__':
    if len(sys.argv) != 3:
        print ("Oppo MTK OFP decrypt tool 1.1 (c) B.Kerler 2020-2022\n")
        print ("Usage: %s <filename> <directory to extract>" % __file__)
        sys.exit(1)
    
    filename=sys.argv[1]
    outdir=sys.argv[2]
    main(filename,outdir)