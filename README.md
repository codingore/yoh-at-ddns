# yoh.at Dynamic DNS

Basic dynamic DNS server with records are updated each 30 seconds from text files.

You can add web interface for editing DNS records by:

+ Extends at.yoh.ddns.yoWeb
+ Set instance of derived pyWeb class with at.yoh.ddns.yoNamed.setWeb()
+ Call at.yoh.ddns.yoNamed.main()
