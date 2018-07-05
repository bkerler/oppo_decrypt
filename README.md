# oppo_decrypt
Oppo/Oneplus .ops Firmware decrypter
------------------------------------

Tested with "MSMDownloadTool V4.0" for Oneplus 5/6, Frida >10.4 and Windoze

* backdoor.py : Enables hidden "readback" functionality
* ops_decrypt.py  : Decrypts any part of the firmware with .ops extension, needs "MsmDownload Tool" and frida
* ofp_decrypt.py  : Decrypts any part of the firmware with .ofp extension


Based on Frida.re and python 3.6

Installation:
-------------
'pip install frida'

Windows only, sorry folks !

Usage:
-------- 
* Oneplus 5 QD-Loader decryption:
'python decrypt.py "MsmDownloadTool V4.0.exe" 0 0x92880'

* Enable readback mode:
'python backdoor.py "MsmDownloadTool V4.0.exe"'

License:
-------- 
Share, modify and use as you like, but refer the original author !