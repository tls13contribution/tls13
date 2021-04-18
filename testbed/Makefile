CC      = gcc
LD      = ld
AR      = ar
NM      = nm
OBJCOPY = objcopy
OBJDUMP = objdump
READELF = readelf

GCC=gcc

CLIENT=client
SERVER=server
ACTIVE_ADVERSARY=active_adversary
PASSIVE_ADVERSARY=passive_adversary
SIMPLE_FORWARDER=simple_forwarder

CLIENT_SRC=client.c
CLIENT_OBJ=client.o
SERVER_SRC=server.c
SERVER_OBJ=server.o
ACTIVE_ADVERSARY_SRC=active_adversary.c
ACTIVE_ADVERSARY_OBJ=active_adversary.o
PASSIVE_ADVERSARY_SRC=passive_adversary.c
PASSIVE_ADVERSARY_OBJ=passive_adversary.o
SIMPLE_FORWARDER_SRC=simple_forwarder.c
SIMPLE_FORWARDER_OBJ=simple_forwarder.o

BINS=${CLIENT} ${SERVER} ${ACTIVE_ADVERSARY} ${PASSIVE_ADVERSARY} ${SIMPLE_FORWARDER}
OBJS=${CLIENT_OBJ} ${SERVER_OBJ} ${ACTIVE_ADVERSARY_OBJ} ${PASSIVE_ADVERSARY_OBJ} ${SIMPLE_FORWARDER_OBJ}

CFLAGS=-DDEBUG -DTLS13 -DTIME_LOG -Iinclude

LDFLAGS=-L. -lcrypto -lssl -ldl -lpthread
GDB=gdb

HOST=www.bob.com
PORT=5555
NUM_OF_THREADS=1

all: client server active_adversary passive_adversary simple_forwarder

client: ${CLIENT_OBJ}
	${GCC} -o ${CLIENT} ${CLIENT_OBJ} ${LDFLAGS}

server: ${SERVER_OBJ}
	${GCC} -o ${SERVER} ${SERVER_OBJ} ${LDFLAGS} -lpthread

active_adversary: ${ACTIVE_ADVERSARY_OBJ}
	${GCC} -o ${ACTIVE_ADVERSARY} ${ACTIVE_ADVERSARY_OBJ} -lpthread

passive_adversary: ${PASSIVE_ADVERSARY_OBJ}
	${GCC} -o ${PASSIVE_ADVERSARY} ${PASSIVE_ADVERSARY_OBJ} -lpthread

simple_forwarder: ${SIMPLE_FORWARDER_OBJ}
	${GCC} -o ${SIMPLE_FORWARDER} ${SIMPLE_FORWARDER_OBJ} -lpthread

client.o: ${CLIENT_SRC}
	${GCC} ${FLAGS} ${CFLAGS} -c $<

server.o: ${SERVER_SRC}
	${GCC} ${FLAGS} ${CFLAGS} -c $<

active_adversary.o: ${ACTIVE_ADVERSARY_SRC}
	${GCC} -c $<

passive_adversary.o: ${PASSIVE_ADVERSARY_SRC}
	${GCC} -c $<

simple_forwarder.o: ${SIMPLE_FORWARDER_SRC}
	${GCC} -c $<

cstart:
	./${CLIENT} ${HOST} ${PORT} ${NUM_OF_THREADS} ${LOG_FILE}

sstart:
	./${SERVER} ${PORT} ${LABEL}

clean:
	rm ${BINS} ${OBJS}
