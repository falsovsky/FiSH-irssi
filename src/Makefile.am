IRSSI_PATH = @IRSSI_PATH@
IRSSI_CFLAGS = -I$(IRSSI_PATH) -I$(IRSSI_PATH)/src
IRSSI_CFLAGS += -I$(IRSSI_PATH)/src/core -I$(IRSSI_PATH)/src/fe-common/core

AM_CFLAGS = -W -g -Wall -Wno-unused-parameter $(IRSSI_CFLAGS) @GLIB_CFLAGS@

pkglib_LTLIBRARIES = libfish.la
libfish_la_SOURCES = SHA256.c \
				 base64.c \
				 blowfish.c \
				 cfgopts.c \
				 DH1080.c \
				 FiSH.c \
				 randport.c \
				 logManager.c
libfish_la_LDFLAGS = -module -avoid-version -shared @OPENSSL_LIBS@
libfish_la_CFLAGS = $(AM_CFLAGS)
