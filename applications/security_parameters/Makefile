CLIENT=crawler
CC=gcc
LD=gcc
CFLAGS=-o
CLIENT_SRC=crawler.c
OBJS=crawler.o
FLAGS=-I../openssl-1.1.1/include
LDFLAGS=-L../openssl-1.1.1/lib -lssl -lcrypto -ldl
GDB=gdb

default: crawler

crawler: ${OBJS}
	${LD} ${CFLAGS} ${CLIENT} ${OBJS} ${LDFLAGS}

%.o: %.c
	${CC} -c ${CLIENT_SRC} ${FLAGS}

clean:
	rm ${CLIENT} ${OBJS}
