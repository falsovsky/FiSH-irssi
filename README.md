[![Build Status](https://travis-ci.org/falsovsky/FiSH-irssi.svg?branch=master)](https://travis-ci.org/falsovsky/FiSH-irssi)

# Introduction

FiSH is an encryption add-on module for [irssi](https://irssi.org/).
Uses the [Blowfish cipher](https://en.wikipedia.org/wiki/Blowfish_(cipher)) to encrypt private and public messages in **ECB** or **CBC** modes, using a specified key.
It also includes a secure Diffie-Hellman key exchange for private chat.

# Requirements

The requirements for building FiSH-irssi are:

* cmake
* pkg-config
* Glib 2.0
* OpenSSL
* irssi (with includes)

## Debian - Ubuntu

```
# apt-get install build-essential irssi-dev libglib2.0-dev libssl-dev cmake git
```

## OpenBSD

```
# pkg_add glib2 irssi cmake git
```

## FreeBSD

* [Official package](https://www.freshports.org/irc/irssi-fish/)

## Arch Linux

```
# pacman -S cmake pkg-config glib2 openssl irssi
```

* [AUR package](https://aur.archlinux.org/packages/fish-irssi-git/)

## CentOS - Fedora
```
yum install gcc pkgconfig cmake irssi irssi-devel openssl openssl-devel glib2 glib2-devel
```

* @duritong [copr repository](https://copr.fedorainfracloud.org/coprs/duritong/irssi-fish/) with binary packages

# Building

Just type in the following commands:

```
$ git clone https://github.com/falsovsky/FiSH-irssi.git
$ cd FiSH-irssi
$ cmake .
$ make
```

If you want to install to **/usr** instead of **/usr/local**

```
$ cmake -DCMAKE_INSTALL_PREFIX:PATH=/usr .
$ make
```

Run ``make install`` as a privileged user (if needed) to install it.

# Running

If you installed the module in the default directory, you just need to run the following command inside irssi to load it:

```
/load fish
```

If not, just include the path while loading:

```
/load /home/username/libfish.so
```

## Load automatically at start-up

```
echo "load fish" >> /home/username/.irssi/startup
```

# Configurations

FiSH-irssi has some configurations that can be set via ``/set`` on irssi.

```
process_outgoing
```
FiSH outgoing messages.

Default value is 1

```
process_incoming
```
unFiSH incoming messages.

Default value is 1

```
auto_keyxchange
```
Do an automatic key exchange in private messages.

Default value is 1

```
plain_prefix
```
Prefix needed to send an unFiSHed message. For example:

``+p Hi there in clear text``

Default value is ``+p ``

```
mark_encrypted
```
String used to mark a FiSHed message.

Default value is ``\002>\002 ``

```
mark_position
```
Defines if the mark should be a prefix (1) or a suffix (0).

Default value is 1

```
nicktracker
```
Allows seamless conversations when your chat partner changes his nick. This feature will copy the old key to use with his new nick. It affects nick changes for opened queries!

Default value is 1

```
mark_broken_block
```
Indicates whether a message is incomplete.

Default value is ``\002&\002``

# Commands

```
/topic+ <message>
```
Sets a FiSHed topic in the current channel.

```
/topic+ TAB
```
Allows to edit a FiSHed topic.

```
/notice+ [nick / #channel] <message>
```
Sends a FiSHed notice to the current window or to the specified target.

```
/me+ <message>
```
Send a FiSHed action to the current window.

```
/setkey [servertag] [nick / #channel] <key>
```
Sets the key used to FiSH the messages for the current window or to the specified target. To use CBC mode, prefix the key with ```cbc:```.

```
/delkey [servertag] [nick/#channel]
```
Unsets the key used to FiSH the messages for the current window or to the specified target.

```
/key|showkey [servertag] [nick / #channel]
```
Shows the used key to FiSH the messages for the current window or to the specified target. The key will appear in the target window.

```
/keyx [-ecb|-cbc] [nick]
```
Forces a DH key exchange in the current window or to the specified target. The default mode is CBC, use the ```-ecb``` parameter to force ECB mode.

```
/setinipw <password>
```
Sets a custom password used to cipher the contents of blow.ini.

```
/unsetinipw
```
Unset the custom password used to cipher blow.ini.

```
/fishlogin
```
Used to ask again for the blow.ini password if the user inserts an invalid password at start-up.

```
/fishhelp|helpfish
```
Show a little help inside irssi.

# Tested

FiSH-irssi has been tested on various OS and arches:

* Linux/x86
* Linux/sparc
* Linux/arm
* OpenBSD/x86
* OpenBSD/macppc
* OpenBSD/sgi
* FreeBSD/x86
* NetBSD/x86
