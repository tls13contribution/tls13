CERT_FILE=carol_cert.pem
CA_CERT_FILE=ca_carol.pem
KEY_FILE=carol_priv.key

CLIENT=client_nio
CC=gcc
LD=gcc
CFLAGS=-o
CLIENT_SRC=client_nio.c
OBJS=client_nio.o
FLAGS=-I../openssl-1.1.1/include
LDFLAGS=-L../openssl-1.1.1/lib -lssl -lcrypto -ldl
GDB=gdb

default: client

client: ${OBJS}
	${LD} ${CFLAGS} ${CLIENT} ${OBJS} ${LDFLAGS}

%.o: %.c
	${CC} -c ${CLIENT_SRC} ${FLAGS}

cstart:
	./${CLIENT} ${HOST} ${PORT} ${NUM_OF_THREADS}

debug:
	${GDB} ./${EXEC} ${PORT} ${CERT_FILE} ${CA_CERT_FILE} ${KEY_FILE} ${ORIG_CERT_FILE} ${WARRANT_FILE} -tui

clean:
	rm ${CLIENT} ${OBJS}
