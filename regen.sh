#!/bin/sh
OS=`uname -s`
if [ $OS = "OpenBSD" ]; then
	echo "OpenBSD detected"
	if [[ -z "$AUTOCONF_VERSION" || -z "$AUTOMAKE_VERSION" ]]; then
		echo "Please define the AUTOCONF_VERSION and AUTOMAKE_VERSION environment variables"
		echo "Install at least autoconf-2.64 and automake-1.9.6p8 and run:"
		echo "export AUTOCONF_VERSION=2.64"
		echo "export AUTOMAKE_VERSION=1.9"
		exit 1
	fi
	echo "Dont forget to add --with-gmp-include=/usr/local/include --with-gmp-lib=/usr/local/lib to the configure script"
fi
aclocal
libtoolize --force
autoconf
automake -a
