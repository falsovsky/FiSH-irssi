SRC = v2/irssi.c v2/fish.c
OBJ = ${SRC:.c=.o}

IRSSI_PATH = ~/work/contrib/irssi/lixo/include/irssi
IRSSI_CFLAGS = -I ${IRSSI_PATH} -I ${IRSSI_PATH}/src -I ${IRSSI_PATH}/src/core

CFLAGS += -Wall -fPIC \
					${IRSSI_CFLAGS} \
					$(shell pkg-config glib-2.0 --cflags)

LDFLAGS += -shared

all: options libfish.so

options:
	@echo cflags: ${CFLAGS}

libfish.so: $(OBJ)
	$(CC) -o $@ ${OBJ} ${LDFLAGS}

clean:
	rm -f ${OBJ}
