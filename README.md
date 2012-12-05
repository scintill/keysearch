keysearch
=========

Search an Android RAM dump for Linux dm-crypt (incl. LUKS/cryptsetup) keys.  95% based on [Torbjörn Pettersson's code](http://events.ccc.de/camp/2007/Fahrplan/attachments/1300-Cryptokey_forensics_A.pdf).

Very much a hackjob, not guaranteed to work reliably across multiple versions or host platforms, etc.  I was happy with the [LiME module](http://code.google.com/p/lime-forensics/) for acquiring the RAM image.

See [my blog post](http://blog.joeyhewitt.com/2012/12/cold-boot-android-phone/) for information on some informal research I did about recovering crypto keys.