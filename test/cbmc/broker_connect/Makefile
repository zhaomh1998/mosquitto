MOSQ_ROOT:=../../..

include $(MOSQ_ROOT)/config.mk

CC=goto-cc
CFLAGS:=-I$(MOSQ_ROOT)
CFLAGS:=${CFLAGS} -I$(MOSQ_ROOT)/include
CFLAGS:=${CFLAGS} -I$(MOSQ_ROOT)/lib
CFLAGS:=${CFLAGS} -I../include
CFLAGS:=${CFLAGS} -I../lib

DEPS = memory_mosq.h
OBJ = connect.o ../lib/memory_mosq.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(LDADD) $(CLIENT_CFLAGS) $(CFLAGS)

broker_connect.gb: $(OBJ)
	$(CC) -o $@ $^ $(LDADD) $(CLIENT_CFLAGS) $(CFLAGS)

clean :
	rm -f *.gb *.o
	rm -f ../lib/*.gb ../lib/*.o
