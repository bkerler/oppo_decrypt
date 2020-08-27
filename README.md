# oppo_decrypt
Oppo .ofp Firmware decrypter
------------------------------------

* ofp_qc_extract.py  : Decrypts oppo qc chipset based firmware with .ofp extension
* ofp_mtk_extract.py  : Decrypts oppo mtk chipset based firmware with .ofp extension
* backdoor.py : Enables hidden "readback" functionality


Based on python 3.x

Installation:
-------------
pip3 install -r requirements.txt


Both Linux and Windows now, folks !

Usage:
-------- 
* Extract ofp file:

```
python3 ofp_qc_extract.py [myops.ofp] [directory to extract]
python3 ofp_mtk_extract.py [myops.ofp] [directory to extract]
```

* Enable readback mode (use admin command prompt under windoze):
```
python3 backdoor.py "MsmDownloadTool V4.0.exe"'
```

License:
-------- 
Share, modify and use as you like, but refer the original author !
And if you like my work, please donate :)
