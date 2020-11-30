#!/usr/bin/env python3
# Oppo Decrypter (c) V 1.3 B.Kerler 2019-2020.
# Licensed under MIT License
"""
Usage:
    opscrypto.py --help
    opscrypto.py decryptfile <filename>
    opscrypto.py decrypt <filename>

Options:
    --projid=value          Set projid [default: "18801"]
    --firmwarename=name     Set firmware name [default: "fajita_41_J.42_191214"]
    --savename=name         Set ops filename [default: "out.ops"]

"""

from docopt import docopt
args = docopt(__doc__, version='1.3')
import shutil

import os
from binascii import unhexlify
from struct import pack,unpack
import xml.etree.ElementTree as ET
import hashlib
from pathlib import Path
key = unpack("<4I", unhexlify("d1b5e39e5eea049d671dd5abd2afcbaf"))

#guacamoles_31_O.09_190820
mbox5= [0x60,0x8a,0x3f,0x2d,0x68,0x6b,0xd4,0x23,0x51,0x0c,
              0xd0,0x95,0xbb,0x40,0xe9,0x76,0x00,0x00,0x00,0x00,
              0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
              0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
              0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
              0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
              0x0a,0x00]
#guacamolet_21_O.08_190502
mbox4=    [0xC4,0x5D,0x05,0x71,0x99,0xDD,0xBB,0xEE,0x29,0xA1,
              0x6D,0xC7,0xAD,0xBF,0xA4,0x3F,0x00,0x00,0x00,0x00,
              0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
              0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
              0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
              0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
              0x0a,0x00]

sbox=unhexlify("c66363a5c66363a5f87c7c84f87c7c84ee777799ee777799f67b7b8df67b7b8dfff2f20dfff2f20dd66b6bbdd66b6bbdde6f6fb1de6f6fb191c5c55491c5c55460303050603030500201010302010103ce6767a9ce6767a9562b2b7d562b2b7de7fefe19e7fefe19b5d7d762b5d7d7624dababe64dababe6ec76769aec76769a8fcaca458fcaca451f82829d1f82829d89c9c94089c9c940fa7d7d87fa7d7d87effafa15effafa15b25959ebb25959eb8e4747c98e4747c9fbf0f00bfbf0f00b41adadec41adadecb3d4d467b3d4d4675fa2a2fd5fa2a2fd45afafea45afafea239c9cbf239c9cbf53a4a4f753a4a4f7e4727296e47272969bc0c05b9bc0c05b75b7b7c275b7b7c2e1fdfd1ce1fdfd1c3d9393ae3d9393ae4c26266a4c26266a6c36365a6c36365a7e3f3f417e3f3f41f5f7f702f5f7f70283cccc4f83cccc4f6834345c6834345c51a5a5f451a5a5f4d1e5e534d1e5e534f9f1f108f9f1f108e2717193e2717193abd8d873abd8d87362313153623131532a15153f2a15153f0804040c0804040c95c7c75295c7c75246232365462323659dc3c35e9dc3c35e3018182830181828379696a1379696a10a05050f0a05050f2f9a9ab52f9a9ab50e0707090e07070924121236241212361b80809b1b80809bdfe2e23ddfe2e23dcdebeb26cdebeb264e2727694e2727697fb2b2cd7fb2b2cdea75759fea75759f1209091b1209091b1d83839e1d83839e582c2c74582c2c74341a1a2e341a1a2e361b1b2d361b1b2ddc6e6eb2dc6e6eb2b45a5aeeb45a5aee5ba0a0fb5ba0a0fba45252f6a45252f6763b3b4d763b3b4db7d6d661b7d6d6617db3b3ce7db3b3ce5229297b5229297bdde3e33edde3e33e5e2f2f715e2f2f711384849713848497a65353f5a65353f5b9d1d168b9d1d1680000000000000000c1eded2cc1eded2c4020206040202060e3fcfc1fe3fcfc1f79b1b1c879b1b1c8b65b5bedb65b5bedd46a6abed46a6abe8dcbcb468dcbcb4667bebed967bebed97239394b7239394b944a4ade944a4ade984c4cd4984c4cd4b05858e8b05858e885cfcf4a85cfcf4abbd0d06bbbd0d06bc5efef2ac5efef2a4faaaae54faaaae5edfbfb16edfbfb16864343c5864343c59a4d4dd79a4d4dd7663333556633335511858594118585948a4545cf8a4545cfe9f9f910e9f9f9100402020604020206fe7f7f81fe7f7f81a05050f0a05050f0783c3c44783c3c44259f9fba259f9fba4ba8a8e34ba8a8e3a25151f3a25151f35da3a3fe5da3a3fe804040c0804040c0058f8f8a058f8f8a3f9292ad3f9292ad219d9dbc219d9dbc7038384870383848f1f5f504f1f5f50463bcbcdf63bcbcdf77b6b6c177b6b6c1afdada75afdada7542212163422121632010103020101030e5ffff1ae5ffff1afdf3f30efdf3f30ebfd2d26dbfd2d26d81cdcd4c81cdcd4c180c0c14180c0c142613133526131335c3ecec2fc3ecec2fbe5f5fe1be5f5fe1359797a2359797a2884444cc884444cc2e1717392e17173993c4c45793c4c45755a7a7f255a7a7f2fc7e7e82fc7e7e827a3d3d477a3d3d47c86464acc86464acba5d5de7ba5d5de73219192b3219192be6737395e6737395c06060a0c06060a019818198198181989e4f4fd19e4f4fd1a3dcdc7fa3dcdc7f4422226644222266542a2a7e542a2a7e3b9090ab3b9090ab0b8888830b8888838c4646ca8c4646cac7eeee29c7eeee296bb8b8d36bb8b8d32814143c2814143ca7dede79a7dede79bc5e5ee2bc5e5ee2160b0b1d160b0b1daddbdb76addbdb76dbe0e03bdbe0e03b6432325664323256743a3a4e743a3a4e140a0a1e140a0a1e924949db924949db0c06060a0c06060a4824246c4824246cb85c5ce4b85c5ce49fc2c25d9fc2c25dbdd3d36ebdd3d36e43acacef43acacefc46262a6c46262a6399191a8399191a8319595a4319595a4d3e4e437d3e4e437f279798bf279798bd5e7e732d5e7e7328bc8c8438bc8c8436e3737596e373759da6d6db7da6d6db7018d8d8c018d8d8cb1d5d564b1d5d5649c4e4ed29c4e4ed249a9a9e049a9a9e0d86c6cb4d86c6cb4ac5656faac5656faf3f4f407f3f4f407cfeaea25cfeaea25ca6565afca6565aff47a7a8ef47a7a8e47aeaee947aeaee910080818100808186fbabad56fbabad5f0787888f07878884a25256f4a25256f5c2e2e725c2e2e72381c1c24381c1c2457a6a6f157a6a6f173b4b4c773b4b4c797c6c65197c6c651cbe8e823cbe8e823a1dddd7ca1dddd7ce874749ce874749c3e1f1f213e1f1f21964b4bdd964b4bdd61bdbddc61bdbddc0d8b8b860d8b8b860f8a8a850f8a8a85e0707090e07070907c3e3e427c3e3e4271b5b5c471b5b5c4cc6666aacc6666aa904848d8904848d80603030506030305f7f6f601f7f6f6011c0e0e121c0e0e12c26161a3c26161a36a35355f6a35355fae5757f9ae5757f969b9b9d069b9b9d0178686911786869199c1c15899c1c1583a1d1d273a1d1d27279e9eb9279e9eb9d9e1e138d9e1e138ebf8f813ebf8f8132b9898b32b9898b32211113322111133d26969bbd26969bba9d9d970a9d9d970078e8e89078e8e89339494a7339494a72d9b9bb62d9b9bb63c1e1e223c1e1e221587879215878792c9e9e920c9e9e92087cece4987cece49aa5555ffaa5555ff5028287850282878a5dfdf7aa5dfdf7a038c8c8f038c8c8f59a1a1f859a1a1f809898980098989801a0d0d171a0d0d1765bfbfda65bfbfdad7e6e631d7e6e631844242c6844242c6d06868b8d06868b8824141c3824141c3299999b0299999b05a2d2d775a2d2d771e0f0f111e0f0f117bb0b0cb7bb0b0cba85454fca85454fc6dbbbbd66dbbbbd62c16163a2c16163a")
def gsbox(value):
    return unpack("<I",sbox[value:value+4])[0]

def key_update(iv1,asbox):
    d = iv1[0] ^ asbox[0]  # 9EE3B5B1
    a = iv1[1] ^ asbox[1]
    b = iv1[2] ^ asbox[2]   #ABD51D58
    c= iv1[3] ^ asbox[3]    #AFCBAFFF
    e = gsbox(((b >> 0x10) & 0xff) * 8 + 2) ^ \
        gsbox(((a >> 8) & 0xff) * 8 + 3)^ \
        gsbox((c >> 0x18) * 8 + 1)^ \
        gsbox((d & 0xff) * 8)^ asbox[4] #35C2A10B

    h = gsbox(((c >> 0x10) & 0xff) * 8 + 2) ^ gsbox(((b >> 8) & 0xff) * 8 + 3) ^ \
        gsbox((d >> 0x18) * 8 + 1) ^ gsbox((a & 0xff) * 8) ^ asbox[5]   #75CF3118
    i = gsbox(((d >> 0x10) & 0xff) * 8 + 2) ^ gsbox(((c >> 8) & 0xff) * 8 + 3) ^ \
        gsbox((a >> 0x18) * 8 + 1) ^ gsbox((b & 0xff) * 8) ^ asbox[6]   #6AD3F5C4
    a = gsbox(((d >> 8) & 0xff) * 8 + 3) ^ gsbox(((a >> 0x10) & 0xff) * 8 + 2) ^ \
        gsbox((b >> 0x18) * 8 + 1) ^ gsbox((c & 0xff) * 8) ^ asbox[7] #D99AC8FB

    f = asbox[0x3c] - 2
    g = 8

    while (f > 0):
        d = e >> 0x18 #35
        m = h >> 0x10 #cf
        s = h >> 0x18
        z = e >> 0x10
        l = i >> 0x18
        t = e >> 8
        e = gsbox(((i >> 0x10) & 0xff) * 8 + 2) ^ gsbox(((h >> 8) & 0xff) * 8 + 3) ^ \
            gsbox((a >> 0x18) * 8 + 1) ^ gsbox((e & 0xff) * 8) ^ asbox[g] #B67F2106, 82508918
        h = gsbox(((a >> 0x10) & 0xff) * 8 + 2) ^ gsbox(((i >> 8) & 0xff) * 8 + 3) ^ \
            gsbox(d * 8 + 1) ^ gsbox((h & 0xff) * 8) ^ asbox[g+1] #85813F52
        i = gsbox((z & 0xff) * 8 + 2) ^ gsbox(((a >> 8) & 0xff) * 8 + 3) ^ \
            gsbox(s * 8 + 1) ^ gsbox((i & 0xff) * 8) ^ asbox[g+2] #C8022573
        a = gsbox((t & 0xff) * 8 + 3) ^ gsbox((m & 0xff) * 8 + 2) ^ \
            gsbox(l * 8 + 1) ^ gsbox((a & 0xff) * 8) ^ asbox[g+3] #AD34EC55
        g = g + 4
        f = f + -1
    iv2=[0,0,0,0]
    # a=6DB8AA0E
    # b=ABD51D58
    # c=AFCBAFFF
    # d=51
    # e=AC402324
    # h=B2D24440
    # i=CC2ADF24
    # t=510805
    iv2[0] = (gsbox(((i >> 0x10) & 0xff) * 8) & 0xff0000) ^ (gsbox(((h >> 8) & 0xff) * 8 + 1) & 0xff00) ^ \
             (gsbox((a >> 0x18) * 8 + 3) & 0xff000000) ^ gsbox((e & 0xff) * 8 + 2) & 0xFF ^ asbox[g]
    iv2[1] = (gsbox(((a >> 0x10) & 0xff) * 8) & 0xff0000) ^ (gsbox(((i >> 8) & 0xff) * 8 + 1) & 0xff00) ^ \
             (gsbox((e >> 0x18) * 8 + 3) & 0xff000000) ^ (gsbox((h & 0xff) * 8 + 2)&0xFF) ^ asbox[g+3]
    iv2[2] = (gsbox(((e >> 0x10) & 0xff) * 8) & 0xff0000) ^ (gsbox(((a >> 8) & 0xff) * 8 + 1) & 0xff00) ^ \
             (gsbox((h >> 0x18) * 8 + 3) & 0xff000000) ^ (gsbox((i & 0xff) * 8 + 2)&0xFF) ^ asbox[g+2]
    iv2[3] = (gsbox(((h >> 0x10) & 0xff) * 8) & 0xff0000) ^ (gsbox(((e >> 8) & 0xff) * 8 + 1) & 0xff00) ^ \
             (gsbox((i >> 0x18) * 8 + 3) & 0xff000000) ^ (gsbox((a & 0xff) * 8 + 2)&0xFF) ^ asbox[g+1]
    return iv2

def key_custom(inp,key,outlength=0):
    outp=bytearray()
    inp=bytearray(inp)
    pos=outlength
    ptr=0
    length=len(inp)
    if outlength!=0:
        while (pos<len(key)):
            if length==0:
                break
            buffer=inp[pos]
            outp.extend(key[pos]^buffer)
            key[pos]=buffer
            length-=1
            pos+=1

    if length>0xF:
        a2=length>>4
        while (a2!=0):
            key=key_update(key,mbox)
            if pos<0x10:
                i=((0xf-pos)>>2)+1
                j=pos
                m=0
                while(i!=0):
                    tmp=unpack("<I",inp[j+ptr:j+ptr+4])[0]
                    outp.extend(pack("<I",tmp^key[m]))
                    key[m]=tmp
                    i-=1
                    j+=4
                    m+=1
            ptr=ptr+0x10
            length=length-0x10
            a2=a2-1
    if length!=0:
        key=key_update(key,sbox)
        j=pos
        m=0
        while (length>0):
            data=inp[j + ptr:j + ptr + 4]
            if len(data)<4:
                data+=b"\x00"*(4-len(data))
            tmp = unpack("<I", data)[0]
            outp.extend(pack("<I", tmp ^ key[m]))
            if encrypt:
                key[m] = tmp ^ key[m]
            else:
                key[m] = tmp
            length -= 4
            j += 4
            m += 1
    return outp

def extractxml(filename,key):
    print(f"Extracting {filename}")
    with open(filename,'rb') as rf:
        sfilename=os.path.join(filename[:-len(os.path.basename(filename))],"extract","settings.xml")
        with open(sfilename, 'wb') as wf:
            filesize = os.stat(filename).st_size
            rf.seek(filesize-0x200)
            hdr=rf.read(0x200)
            xmllength=unpack("<I",hdr[0x18:0x18+4])[0]
            xmlpad=0x200-(xmllength%0x200)
            rf.seek(filesize-0x200-(xmllength+xmlpad))
            inp=rf.read(xmllength+xmlpad)
            outp=key_custom(inp,key)
            wf.write(outp[:xmllength])
            return outp[:xmllength].decode('utf-8')

def decryptfile(key,filename,path,wfilename,start,length):
    print(f"Extracting {wfilename}")
    with open(filename, 'rb') as rf:
        with open(os.path.join(path, wfilename), 'wb') as wf:
            rf.seek(start)
            data=rf.read(length)
            if length%4:
                data+=(4-(length%4))*b'\x00'
            outp = key_custom(data, key)
            wf.write(outp[:length])

def copysub(rf,wf,start,length):
    rf.seek(start)
    rlen=0
    while (length > 0):
        if length < 0x100000:
            size = length
        else:
            size = 0x100000
        data = rf.read(size)
        wf.write(data)
        rlen+=len(data)
        length -= size
    return rlen

def copyfile(filename,path,wfilename,start,length):
    print(f"Extracting {wfilename}")
    with open(filename, 'rb') as rf:
        with open(os.path.join(path, wfilename), 'wb') as wf:
            return copysub(rf,wf,start,length)

def copyitem(item,directory,pos,wf):
    try:
        filename = item.attrib["Path"]
    except:
        filename = item.attrib["filename"]
    if filename=="":
        return item,pos
    filename = os.path.join(directory, filename)
    start = pos // 0x200
    item.attrib["FileOffsetInSrc"] = str(start)

    size = os.stat(filename).st_size
    item.attrib["SizeInByteInSrc"]=str(size)
    sectors = size // 0x200
    if (size % 0x200) != 0:
        sectors += 1
    item.attrib["SizeInSectorInSrc"] = str(sectors)
    with open(filename, 'rb') as rf:
        rlen = copysub(rf,wf,0,size)
        pos += rlen
        if (rlen % 0x200) != 0:
            sublen = 0x200 - (rlen % 0x200)
            wf.write(b'\x00' * sublen)
            pos += sublen
    return item,pos


def main():
    global mbox
    print("Oppo CryptTools V1.2 (c) B. Kerler 2019-2020\nMIT License\n----------------------------\n")
    if args["decrypt"]:
        filename = args["<filename>"].replace("\\", "/")
        if "/" in filename:
            path = filename[:filename.rfind("/")]
        else:
            path = ""
        path = os.path.join(path,"extract")
        if os.path.exists(path):
            shutil.rmtree(path)
            os.mkdir(path)
        else:
            os.mkdir(path)
        try:
            mbox = mbox4
            xml = extractxml(filename, key)
        except:
            try:
                mbox = mbox5
                xml = extractxml(filename, key)
            except:
                 print("Unsupported key !")
                 exit(0)
        root = ET.fromstring(xml)
        for child in root:
            if child.tag == "SAHARA":
                for item in child:
                    if item.tag == "File":
                        wfilename = item.attrib["Path"]
                        start = int(item.attrib["FileOffsetInSrc"]) * 0x200
                        length = int(item.attrib["SizeInSectorInSrc"]) * 0x200
                        decryptfile(key, filename, path, wfilename, start, length)
            elif child.tag == "UFS_PROVISION":
                for item in child:
                    if item.tag == "File":
                        wfilename = item.attrib["Path"]
                        start = int(item.attrib["FileOffsetInSrc"]) * 0x200
                        length = int(item.attrib["SizeInSectorInSrc"]) * 0x200
                        copyfile(filename, path, wfilename, start, length)
            elif "Program" in child.tag:
                #if not os.path.exists(os.path.join(path, child.tag)):
                #    os.mkdir(os.path.join(path, child.tag))
                #spath = os.path.join(path, child.tag)
                for item in child:
                    if "filename" in item.attrib:
                        wfilename = item.attrib["filename"]
                        if wfilename == "":
                            continue
                        start = int(item.attrib["FileOffsetInSrc"]) * 0x200
                        length = int(item.attrib["SizeInSectorInSrc"]) * 0x200
                        copyfile(filename, path, wfilename, start, length)
                    else:
                        for subitem in item:
                            if "filename" in subitem.attrib:
                                wfilename = subitem.attrib["filename"]
                                if wfilename == "":
                                    continue
                                start = int(subitem.attrib["FileOffsetInSrc"]) * 0x200
                                length = int(subitem.attrib["SizeInSectorInSrc"]) * 0x200
                                copyfile(filename, path, wfilename, start, length)
            # else:
            #    print (child.tag, child.attrib)
        print("Done. Extracted files to " + path)
        exit(0)
    elif args["decryptfile"]:
        filename = args["<filename>"].replace("\\", "/")
        mbox = mbox5
        fsize=os.stat(filename).st_size
        decryptfile(key,filename,"",filename+".dec",0,fsize)
        print("Done.")
    else:
        print("Usage:./opsdecrypt.py decrypt [filename.ops]")
        exit(0)

if __name__=="__main__":
    main()
