irssi_inc=/usr/local/include/irssi

CC=gcc
CFLAGS= -fPIC -I/usr/local/include -I${irssi_inc} -I${irssi_inc}/src
CFLAGS+=-I${irssi_inc}/src/core -I${irssi_inc}/src/fe-common/core
CFLAGS+=`glib-config --cflags glib`
LDFLAGS=-L/usr/local/lib -lgmp `glib-config --libs glib`

TARGETS=SHA-256.o base64.o blowfish.o cfgopts.o DH1080.o FiSH.o randport.o

fish: ${TARGETS}
	${CC} -shared -o libfish.so ${TARGETS} ${LDFLAGS}

clean:
	rm -f ${TARGETS} libfish.so
