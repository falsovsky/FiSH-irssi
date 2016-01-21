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

To install to /usr instead of /usr/local

<pre>
# cmake -DCMAKE_INSTALL_PREFIX:PATH=/usr .
# make
</pre>

Finally run a **make install** as a privileged user (if needed) to install it. 

Irssi looks for the modules in **/usr/lib/irssi/modules** or **/usr/local/lib/irssi/modules**. The install script copies libfish to **$PREFIX/lib/irssi/modules**.

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

- `process_outgoing` (boolean)
  > FiSH outgoing messages
  > 
  > default value is 1

- `process_incoming` (boolean)
  >unFiSH incoming messages
  >
  > default value is 1

- `auto_keyxchange` (boolean)
  > Do an automatic key exchange in private messages
  >
  > default value is 1

- `plain_prefix` (string)
  > Prefix needed to send an unFiSHed message. For example:
  > <pre>+p Hi there in cleartext</pre>
  > default value is "+p "
 
- `mark_encrypted` (string)
  > String used to mark a FiSHed message
  >
  > default value is "\002>\002 "

- `mark_position` (boolean)
  > Defines if the mark should be a prefix (1) or a suffix (0)
  > 
  > default value is 1

- `nicktracker` (boolean)
  > default value is 1
	
- `mark_broken_block` (string)
  > default value is "\002&\002"

## Commands
	
- `/topic+ <message>`
  > Sets a FiSHed topic in the current channel.

- `/topic+ TAB`
  > Allows to edit a FiSHed topic.

- `/notice+ [nick / #channel] <message>`
  > Sends a FiSHed notice to the current window or to the specified target.

- `/me+ <message>`
  > Send a FiSHed action to the current window.

- `/setkey [servertag] [nick / #channel] <key>`
  > Sets the key used to FiSH the messages for the current window or to the specified target.

- `/delkey [servertag] [nick/#channel]`
  > Unsets the key used to FiSH the messages for the current window or to the specified target.

- `/key [servertag] [nick / #channel]` or `/showkey [servertag] [nick / #channel]`
  > Shows the used key to FiSH the messages for the current window or to the specified target. The key will be printed in the target window.

- `/keyx`
  > Forces a DH key exchange in the current window.

- `/setinipw <password>`
  > Sets a custom password used to cipher the contents of blow.ini.

- `/unsetinipw`
  > Unsets the custom password used to cipher blow.ini

- `/fishlogin`
  > Used to ask again for the blow.ini password if the user inserts an invalid password at startup.

- `/fishhelp` or `/helpfish`
  > Show a little help inside Irssi

## Tested on
* Linux/x86
* Linux/sparc
* OpenBSD/x86
* OpenBSD/macppc
* OpenBSD/sgi
* FreeBSD/x86
* NetBSD/x86
