# oppo_decrypt
Oppo .ofp Firmware decrypter
------------------------------------
Works for oppo only, not oneplus !

* backdoor.py : Enables hidden "readback" functionality
* ofp_extract.py  : Decrypts any part of the firmware with .ofp extension


Based on python 3.x

Installation:
-------------
pip3 install pycrypto


Both Linux and Windows now, folks !

Usage:
-------- 
* Enable readback mode (use admin command prompt under windoze):
```
python3 backdoor.py "MsmDownloadTool V4.0.exe"'
```

* Extract ofp file:

```
python3 ofp_extract.py [myops.ofp]
```

License:
-------- 
Share, modify and use as you like, but refer the original author !
