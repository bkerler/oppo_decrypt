# oppo_decrypt
Oppo .ofp and Oneplus .ops Firmware decrypter
------------------------------------

* ofp_qc_decrypt.py  : Decrypts oppo qc chipset based firmware with .ofp extension (oppo)
* ofp_mtk_decrypt.py : Decrypts oppo mtk chipset based firmware with .ofp extension (oppo)
* opscrypto.py       : Decrypts and re-encrypts based firmware with .ops extension (oneplus)
* backdoor.py        : Enables hidden "readback" functionality


Installation:
-------------
- Install >= python 3.8 and pip3

In the console, run
```bash
pip3 install -r requirements.txt
```

Both Linux and Windows now supported, folks !

Usage:
-------- 
* Extract oppo ofp file:

```
python3 ofp_qc_extract.py [myops.ofp] [directory to extract]
python3 ofp_mtk_decrypt.py [myops.ofp] [directory to extract]
```

* Extract oneplus ops file:

```
python3 opscrypto.py decrypt [myops.ops]
```
File will be in the extract subdirectory

* Repack oneplus ops file:

```
python3 opscrypto.py encrypt [path to extracted firmware]
```


* Enable readback mode (use admin command prompt under windoze):
```
python3 backdoor.py "MsmDownloadTool V4.0.exe"'
```

License:
-------- 
Share, modify and use as you like, but refer the original author !
And if you like my work, please donate :)
