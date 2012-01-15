# FiSH module for irssi

Based on official from http://fish.secure.la/ (DEAD?)  
Changed to use GMP by Dcoder  
Basic autoconf/automake support by falso

## Requirements

* GNU MP - http://gmplib.org/
* Glib 2.x - http://www.gtk.org/
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

## BUGS
* Some crashes when the terminal is set to UTF-8 and irssi recode is enabled
