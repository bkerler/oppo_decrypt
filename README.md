# oppo_decrypt
Oppo .ops Firmware decrypter
------------------------------------
Works for oppo only, not oneplus !

* backdoor.py : Enables hidden "readback" functionality
* ops_extract.py  : Decrypts any part of the firmware with .ops extension
* ofp_decrypt.py  : Decrypts any part of the firmware with .ofp extension


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

* Extract ops file:

```
python3 ops_extract.py [myops.ops]
```

License:
-------- 
Share, modify and use as you like, but refer the original author !
