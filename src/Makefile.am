IRSSI_PATH = /usr/include/irssi
IRSSI_CFLAGS = -I$(IRSSI_PATH) -I$(IRSSI_PATH)/src
IRSSI_CFLAGS += -I$(IRSSI_PATH)/src/core -I$(IRSSI_PATH)/src/fe-common/core
IRSSI_CFLAGS += -I/usr/include/irssi/

AM_CFLAGS = -Wall $(IRSSI_CFLAGS) @GLIB_CFLAGS@

#lib_LIBRARIES = libfish.a
lib_LTLIBRARIES = libfish.la
libfish_la_SOURCES = SHA-256.c \
				 base64.c \
				 blowfish.c \
				 cfgopts.c \
				 DH1080.c \
				 FiSH.c \
				 randport.c
libfish_la_LDFLAGS = -module -avoid-version
libfish_la_CFLAGS = $(AM_CFLAGS)
