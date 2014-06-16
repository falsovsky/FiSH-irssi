IRSSI_PATH = @IRSSI_PATH@
IRSSI_CFLAGS = -I$(IRSSI_PATH) -I$(IRSSI_PATH)/src
IRSSI_CFLAGS += -I$(IRSSI_PATH)/src/core -I$(IRSSI_PATH)/src/fe-common/core

AM_CFLAGS = -W -g -Wall -Wno-unused-parameter -Werror $(IRSSI_CFLAGS) @GLIB_CFLAGS@

fishplugindir = $(IRSSI_MODULE_DIR)
fishplugin_LTLIBRARIES = libfish.la

libfish_la_LDFLAGS = -module -avoid-version -shared @OPENSSL_LIBS@
libfish_la_CFLAGS = $(AM_CFLAGS)
libfish_la_SOURCES = SHA256.c \
				 base64.c \
				 blowfish.c \
				 openssl_blowfish.c \
				 inifile.c \
				 DH1080.c \
				 FiSH.c \
				 fish2.c \
				 fish2/blowcrypt.c \
				 fish2/noop.c \
				 keyx.c \
				 random.c \
				 password.c \
				 irc_helper.c \
				 key_store.c
