IRSSI_CFLAGS = $(FISH_IRSSI_INCLUDES)

AM_CFLAGS = -W -g -Wall -Wno-unused-parameter $(IRSSI_CFLAGS) @GLIB_CFLAGS@

fishplugindir = $(IRSSI_MODULE_DIR)
fishplugin_LTLIBRARIES = libfish.la

libfish_la_LDFLAGS = -module -avoid-version -shared @OPENSSL_LIBS@
libfish_la_CFLAGS = $(AM_CFLAGS)
libfish_la_SOURCES = base64.c \
				 blowfish.c \
				 inifile.c \
				 DH1080.c \
				 FiSH.c \
				 password.c
