[![Build Status](https://travis-ci.org/falsovsky/FiSH-irssi.svg?branch=master)](https://travis-ci.org/falsovsky/FiSH-irssi)

# FiSH module for irssi

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

## Configurations
FiSH has a few configurations that can be defined via /set on Irssi

### process_outgoing (boolean)
FiSH outgoing messages
> default value is 1

### process_incoming (boolean)
unFiSH incoming messages
> default value is 1

### auto_keyxchange (boolean)
Do an automatic key exchange in private messages
> default value is 1

### nicktracker (boolean)

> default value is 1

### plain_prefix (string)
Prefix needed to send an unFiSHed message to an encrypted channel or private message. For example:
<pre>+p Hi there in cleartext</pre>
> default value is "+p "
 
### mark_encrypted (string)
String used to mark a FiSHed message
> default value is "\002>\002 "

### mark_position (boool)
Defines if the mark should be a prefix (1) or a suffix (0)
> default value is 1
	
### mark_broken_block (string)
> default value is "\002&\002"

## Commands
	
### topic+
### notice+
### me+
### setkey
### delkey
### key || showkey
### keyx
### setinipw
### unsetinipw
### fishlogin
### fishhelp || helpfish


## Tested on
* Linux/x86
* Linux/sparc
* OpenBSD/x86
* OpenBSD/macppc
* OpenBSD/sgi
* FreeBSD/x86
* NetBSD/x86
