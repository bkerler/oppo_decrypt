#!/usr/bin/env python3
# (c) B.Kerler 2018-2021, MIT license
import os
import sys
import xml.etree.ElementTree as ET
import zipfile
from struct import unpack
from binascii import unhexlify, hexlify
from Cryptodome.Cipher import AES
import hashlib
import shutil

def swap(ch):
    return ((ch & 0xF) << 4) + ((ch & 0xF0) >> 4)


def keyshuffle(key, hkey):
    for i in range(0, 0x10, 4):
        key[i] = swap((hkey[i] ^ key[i]))
        key[i + 1] = swap(hkey[i + 1] ^ key[i + 1])
        key[i + 2] = swap(hkey[i + 2] ^ key[i + 2])
        key[i + 3] = swap(hkey[i + 3] ^ key[i + 3])
    return key

def ROL(x, n, bits = 32):
    n = bits - n
    mask = (2**n) - 1
    mask_bits = x & mask
    return (x >> n) | (mask_bits << (bits - n))

def generatekey1():
    key1 = "42F2D5399137E2B2813CD8ECDF2F4D72"
    key2 = "F6C50203515A2CE7D8C3E1F938B7E94C"
    key3 = "67657963787565E837D226B69A495D21"

    key1 = bytearray.fromhex(key1)
    key2 = bytearray.fromhex(key2)
    key3 = bytearray.fromhex(key3)

    key2 = keyshuffle(key2, key3)
    aeskey = bytes(hashlib.md5(key2).hexdigest()[0:16], 'utf-8')
    key1 = keyshuffle(key1, key3)
    iv = bytes(hashlib.md5(key1).hexdigest()[0:16], 'utf-8')
    return aeskey,iv

def deobfuscate(data,mask):
    ret=bytearray()
    for i in range(0, len(data)):
        v = ROL((data[i] ^ mask[i]), 4, 8)
        ret.append(v)
    return ret

def generatekey2(filename):
    keys = [
        # R9s/A57t
        ["V1.4.17/1.4.27",
         "27827963787265EF89D126B69A495A21",
         "82C50203285A2CE7D8C3E198383CE94C",
         "422DD5399181E223813CD8ECDF2E4D72"],

        # a3s
        ["V1.6.17",
         "E11AA7BB558A436A8375FD15DDD4651F",
         "77DDF6A0696841F6B74782C097835169",
         "A739742384A44E8BA45207AD5C3700EA"],

        ["V1.5.13",
         "67657963787565E837D226B69A495D21",
         "F6C50203515A2CE7D8C3E1F938B7E94C",
         "42F2D5399137E2B2813CD8ECDF2F4D72"],

         #R15 Pro CPH1831 V1.6.6 / FindX CPH1871 V1.6.9 / R17 Pro CPH1877 V1.6.17 / R17 PBEM00 V1.6.17 / A5 2020 V1.7.6 / K3 CPH1955 V1.6.26 UFS
         #Reno 5G CPH1921 V1.6.26 / Realme 3 Pro RMX1851 V1.6.17 / Reno 10X Zoom V1.6.26 / R17 CPH1879 V1.6.17 / R17 Neo CPH1893 / K1 PBCM30

        ["V1.6.6/1.6.9/1.6.17/1.6.24/1.6.26/1.7.6",
         "3C2D518D9BF2E4279DC758CD535147C3",
         "87C74A29709AC1BF2382276C4E8DF232",
         "598D92E967265E9BCABE2469FE4A915E"],

        #RM1921EX V1.7.2, Realme X RMX1901 V1.7.2, Realme 5 Pro RMX1971 V1.7.2, Realme 5 RMX1911 V1.7.2
        ["V1.7.2",
         "8FB8FB261930260BE945B841AEFA9FD4",
         "E529E82B28F5A2F8831D860AE39E425D",
         "8A09DA60ED36F125D64709973372C1CF"],

        # OW19W8AP_11_A.23_200715
        ["V2.0.3",
         "E8AE288C0192C54BF10C5707E9C4705B",
         "D64FC385DCD52A3C9B5FBA8650F92EDA",
         "79051FD8D8B6297E2E4559E997F63B7F"]

    ]

    for dkey in keys:
        key = bytearray()
        iv = bytearray()
        # "Read metadata failed"
        mc = bytearray.fromhex(dkey[1])
        userkey=bytearray.fromhex(dkey[2])
        ivec=bytearray.fromhex(dkey[3])

        #userkey=bytearray(unhexlify("A3D8D358E42F5A9E931DD3917D9A3218"))
        #ivec=bytearray(unhexlify("386935399137416B67416BECF22F519A"))
        #mc=bytearray(unhexlify("9E4F32639D21357D37D226B69A495D21"))

        key=(hashlib.md5(deobfuscate(userkey,mc)).hexdigest()[0:16]).encode()
        iv=(hashlib.md5(deobfuscate(ivec,mc)).hexdigest()[0:16]).encode()
        
        pagesize,data=extract_xml(filename,key,iv)
        if pagesize!=0:
            return pagesize,key,iv,data
    return 0,None,None,None


def extract_xml(filename,key,iv):
    filesize=os.stat(filename).st_size
    with open(filename,'rb') as rf:
        pagesize = 0
        for x in [0x200, 0x1000]:
            rf.seek(filesize-x+0x10)
            if unpack("<I",rf.read(4))[0]==0x7CEF:
                pagesize = x
                break 
        if pagesize == 0:
            print("Unknown pagesize. Aborting")
            exit(0)
            
        xmloffset=filesize-pagesize
        rf.seek(xmloffset+0x14)
        offset=unpack("<I",rf.read(4))[0]*pagesize
        length=unpack("<I",rf.read(4))[0]
        if length<200: #A57 hack
            length=xmloffset-offset-0x57
        rf.seek(offset)
        data=rf.read(length)
        dec=aes_cfb(data,key,iv)

        #h=MD5.new()
        #h.update(data)
        #print(dec.decode('utf-8'))
        #print(h.hexdigest())
        #print("Done.")
        if b"<?xml" in dec:
            return pagesize,dec
        else:
            return 0,""

def aes_cfb(data,key,iv):
    ctx = AES.new(key, AES.MODE_CFB, iv=iv, segment_size=128)
    decrypted = ctx.decrypt(data)
    return decrypted

def copysub(rf,wf,start,length):
    rf.seek(start)
    rlen=0
    while length > 0:
        if length < 0x100000:
            size = length
        else:
            size = 0x100000
        data = rf.read(size)
        wf.write(data)
        rlen+=len(data)
        length -= size
    return rlen

def copy(filename,wfilename,path, start,length,checksums):
    print(f"\nExtracting {wfilename}")
    with open(filename, 'rb') as rf:
        with open(os.path.join(path, wfilename), 'wb') as wf:
            rf.seek(start)
            data=rf.read(length)
            wf.write(data)

    checkhashfile(os.path.join(path, wfilename), checksums, True)

def decryptfile(key,iv,filename,path,wfilename,start,length,rlength,checksums,decryptsize=0x40000):
    print(f"\nExtracting {wfilename}")
    if rlength==length:
        tlen=length
        length=(length//0x4*0x4)
        if tlen%0x4!=0:
            length+=0x4

    with open(filename, 'rb') as rf:
        with open(os.path.join(path, wfilename), 'wb') as wf:
            rf.seek(start)
            size=decryptsize
            if rlength<decryptsize:
                size=rlength
            data=rf.read(size)
            if size%4:
                data+=(4-(size%4))*b'\x00'
            outp = aes_cfb(data, key, iv)
            wf.write(outp[:size])

            if rlength > decryptsize:
                copysub(rf, wf, start + size, rlength-size)

            if rlength%0x1000!=0:
                fill=bytearray([0x00 for i in range(0x1000-(rlength%0x1000))])
                #wf.write(fill)

    checkhashfile(os.path.join(path, wfilename), checksums, False)
            
def checkhashfile(wfilename, checksums, iscopy):
    sha256sum = checksums[0]
    md5sum = checksums[1]
    if iscopy:
        prefix = "Copy: "
    else:
        prefix = "Decrypt: "
    with open(wfilename,"rb") as rf:
        size = os.stat(wfilename).st_size
        md5 = hashlib.md5(rf.read(0x40000))
        sha256bad=False
        md5bad=False
        md5status="empty"
        sha256status="empty"
        if sha256sum != "":
            for x in [0x40000, size]:
                rf.seek(0)
                #sha256 = hashlib.sha256(rf.read(x))
                sha256 = hashlib.sha256()
                if x == 0x40000:
                    sha256.update(rf.read(x))
                if x == size:
                    for chunk in iter(lambda: rf.read(128 * sha256.block_size), b''):
                        sha256.update(chunk)
                if sha256sum != sha256.hexdigest():
                    sha256bad=True
                    sha256status="bad"
                else:
                    sha256status="verified"
                    break
        if md5sum != "":
            if md5sum != md5.hexdigest():
                md5bad=True
                md5status="bad"
            else:
                md5status="verified"
        if (sha256bad and md5bad) or (sha256bad and md5sum=="") or (md5bad and sha256sum==""):
            print(f"{prefix}error on hashes. File might be broken!")
        else:
            print(f"{prefix}success! (md5: {md5status} | sha256: {sha256status})")
            
def decryptitem(item, pagesize):
    sha256sum=""
    md5sum=""
    wfilename=""
    start=-1
    rlength=0
    decryptsize=0x40000
    if "Path" in item.attrib:
        wfilename = item.attrib["Path"]
    elif "filename" in item.attrib:
        wfilename = item.attrib["filename"]
    if "sha256" in item.attrib:
        sha256sum=item.attrib["sha256"]
    if "md5" in item.attrib:
        md5sum=item.attrib["md5"]
    if "FileOffsetInSrc" in item.attrib:
        start = int(item.attrib["FileOffsetInSrc"]) * pagesize
    elif "SizeInSectorInSrc" in item.attrib:
        start = int(item.attrib["SizeInSectorInSrc"]) * pagesize
    if "SizeInByteInSrc" in item.attrib:
        rlength = int(item.attrib["SizeInByteInSrc"])
    if "SizeInSectorInSrc" in item.attrib:
        length = int(item.attrib["SizeInSectorInSrc"]) * pagesize
    else:
        length=rlength
    return wfilename, start, length, rlength,[sha256sum,md5sum],decryptsize
        
def main():
    if len(sys.argv)<3:
        print("Oppo MTK QC decrypt tool 1.1 (c) B.Kerler 2020-2022\n")
        print("Usage: ./ofp_qc_extract.py [Filename.ofp] [Directory to extract files to]")
        sys.exit(1)

    filename=sys.argv[1]
    outdir=sys.argv[2]
    if not os.path.exists(outdir):
        os.mkdir(outdir)

    pk=False
    with open(filename,"rb") as rf:
        if rf.read(2)==b"PK":
            pk=True

    if pk==True:
        print("Zip file detected, trying to decrypt files")
        zippw=bytes("flash@realme$50E7F7D847732396F1582CD62DD385ED7ABB0897", 'utf-8')
        with zipfile.ZipFile(filename) as file:
            for zfile in file.namelist():
                print("Extracting "+zfile+" to "+outdir)
                file.extract(zfile,pwd=zippw,path=outdir)
            print("Files extracted to "+outdir)
            exit(0)

    #key,iv=generatekey1()
    pagesize,key,iv,data=generatekey2(filename)
    if pagesize==0:
        print("Unknown key. Aborting")
        exit(0)
    else:
        xml=data[:data.rfind(b">")+1].decode('utf-8')

    if "/" in filename:
        path = filename[:filename.rfind("/")]
    elif "\\" in filename:
        path = filename[:filename.rfind("\\")]
    else:
        path = ""

    path = os.path.join(path,outdir)

    if os.path.exists(path):
        shutil.rmtree(path)
        os.mkdir(path)
    else:
        os.mkdir(path)

    print("Saving ProFile.xml")
    file_handle = open(path + os.sep + "ProFile.xml", mode = "w")
    file_handle.write(xml)
    file_handle.close()
    
    root = ET.fromstring(xml)
    for child in root:
        for item in child:
            if "Path" not in item.attrib and "filename" not in item.attrib:
                for subitem in item:
                    wfilename, start, length, rlength, checksums, decryptsize = decryptitem(subitem, pagesize)
                    if wfilename=="" or start==-1:
                        continue
                    decryptfile(key, iv, filename, path, wfilename, start, length, rlength, checksums, decryptsize)
            wfilename, start, length, rlength, checksums, decryptsize = decryptitem(item, pagesize)
            if wfilename=="" or start==-1:
                continue
            if child.tag in ["Sahara"]:
                decryptsize=rlength
            if child.tag in ["Config","Provision","ChainedTableOfDigests","DigestsToSign", "Firmware"]:
                length=rlength
            if child.tag in ["DigestsToSign","ChainedTableOfDigests", "Firmware"]:
                copy(filename,wfilename,path,start,length,checksums)
            else:
                decryptfile(key, iv, filename, path, wfilename, start, length, rlength, checksums, decryptsize)
    print("\nDone. Extracted files to " + path)
    exit(0)


if __name__=="__main__":
    main()
