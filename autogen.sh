#!/bin/sh

OS=$(uname -s)

if [ "$OS" = "OpenBSD" ];
then
    echo "OpenBSD detected"
    mkdir -p m4
    if [[ -z "$AUTOCONF_VERSION" || -z "$AUTOMAKE_VERSION" ]]; then
        echo "ERROR:"
        echo "You must define the AUTOCONF_VERSION and AUTOMAKE_VERSION environment variables"
        echo "Install at least autoconf-2.59p3 and automake-1.9.6p8 and run:"
        echo "export AUTOCONF_VERSION=2.59"
        echo "export AUTOMAKE_VERSION=1.9"
        exit 1
    fi
fi

aclocal --force

if [ "$OS" = "Darwin" ];
then
	LIBTOOLIZE='glibtoolize'
else
	LIBTOOLIZE='libtoolize'
fi

$LIBTOOLIZE --force
autoconf --force
automake -a
