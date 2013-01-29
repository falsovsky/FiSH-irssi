# FiSH module for irssi

* Based on official from http://fish.secure.la/ (DEAD?)
* Changed to use GMP instead of MIRACL by Dcoder
* Basic autoconf/automake support by falso
* Changed the blow.ini reading/writing to Glib's GKeyFile - http://developer.gnome.org/glib/stable/glib-Key-value-file-parser.html
* Multi-server support (__New! January 2013__)

You will need to edit your blow.ini manually if you want to continue using it.  
Just prefix the servertag and a ":" to the target, for example:

```
[#l33tchan]  
key=+OK awrps/takkv.
```

Needs to be changed to:  

```
[PTNet:#l33tchan]  
key=+OK awrps/takkv.
```

Also, the /setkey and /delkey commands now allow to define the network.

```
/setkey [-<server tag >] [<nick | #channel>] <key>
```

```
/delkey [-<server tag>] <nick | #channel>
```

```
</key | /showkey> [-<server tag>] [<nick | #channel>]
```

## Requirements

* autoconf >= 2.59 - http://www.gnu.org/software/autoconf/
* automake >= 1.9.6 - http://www.gnu.org/software/automake/
* GNU libtool - http://www.gnu.org/software/libtool/
* GNU MP - http://gmplib.org/
* Glib 2.x - http://www.gtk.org/
* OpenSSL - http://www.openssl.org/
* irssi source code - http://irssi.org/

## Build instructions

First download the irssi source code and extract it, for example **/home/jacinto/irssi-0.8.15**.  
Now enter the FiSH-irssi directory and run the following combo.
<pre>
# ./regen.sh
# ./configure --with-irssi-source=/home/jacinto/irssi-0.8.15
# make
# sudo cp src/.libs/libfish.so /usr/lib/irssi/modules
</pre>
## To run

If you installed the module in the default directory, you just need to run the following command inside irssi to load it:
<pre>/load fish</pre>
If not, just include the path while loading:
<pre>/load /home/jacinto/libfish.so</pre>

## Tested on
* Linux/x86
* OpenBSD/x86
* OpenBSD/macppc
* FreeBSD/x86
* NetBSD/x86
* OpenBSD/sgi (Big Endian - mips)

## BUGS
* Some crashes when the terminal is set to UTF-8 and irssi recode is enabled
