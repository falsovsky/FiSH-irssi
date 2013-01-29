.PHONY: doc
doc:
	doxygen Doxyfile
	cp -r doc/ /home/falso/public_html/

all-local:
	@echo 'Now copy src/.libs/libfish.so to /usr/lib/irssi/modules or equivalent to install the plugin'

ACLOCAL_AMFLAGS = -I m4
SUBDIRS = src
