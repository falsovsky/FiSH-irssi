[![Build Status](https://travis-ci.org/falsovsky/FiSH-irssi.svg?branch=master)](https://travis-ci.org/falsovsky/FiSH-irssi)

# FiSH module for irssi

* Based on official from http://fish.secure.la/ (now dead)
* No longer requires GMP/MIRACL

## Requirements

* cmake
* pkg-config
* Glib 2.0
* OpenSSL
* irssi includes or source code

## Build instructions

<pre>
# cmake .
# make
</pre>

## To run

If you installed the module in the default directory, you just need to run the following command inside irssi to load it:
<pre>
/load fish
</pre>
If not, just include the path while loading:
<pre>
/load /home/username/libfish.so
</pre>

To load automatically at startup:
<pre>
echo "load fish" >> /home/username/.irssi/startup
</pre>

## Tested on
* Linux/x86
* Linux/sparc
* OpenBSD/x86
* OpenBSD/macppc
* OpenBSD/sgi
* FreeBSD/x86
* NetBSD/x86
