#!/bin/sh

case $(uname -s) in
    OpenBSD)
        echo "OpenBSD detected"
        mkdir -p m4
        if [[ -z "$AUTOCONF_VERSION" || -z "$AUTOMAKE_VERSION" ]]; then
            echo "Please define the AUTOCONF_VERSION and AUTOMAKE_VERSION environment variables"
            echo "Install at least autoconf-2.59p3 and automake-1.9.6p8 and run:"
            echo "export AUTOCONF_VERSION=2.59"
            echo "export AUTOMAKE_VERSION=1.9"
            exit 1
        fi
        ;;
    OpenBSD|FreeBSD)
        echo "Dont forget to add --with-gmp-include=/usr/local/include --with-gmp-lib=/usr/local/lib to the configure script"
        ;;
esac

aclocal
libtoolize --force
autoconf
automake -a
