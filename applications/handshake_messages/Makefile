CLIENT=crawler
CC=gcc
LD=gcc
CFLAGS=-o
CLIENT_SRC=crawler.c
OBJS=crawler.o
LBITS=$(shell getconf LONG_BIT)

FLAGS=-I../openssl-1.1.1/include
LDFLAGS=-L../openssl-1.1.1/lib -lssl -lcrypto -ldl

default: crawler

crawler: ${OBJS}
	${LD} ${CFLAGS} ${CLIENT} ${OBJS} ${LDFLAGS}

%.o: %.c
	${CC} -c ${CLIENT_SRC} ${FLAGS}

clean:
	rm ${CLIENT} ${OBJS}
