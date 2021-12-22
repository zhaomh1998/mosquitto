MOSQ_ROOT:=../../..

include $(MOSQ_ROOT)/config.mk

CC=goto-cc
CFLAGS:=-I$(MOSQ_ROOT)
CFLAGS:=${CFLAGS} -I$(MOSQ_ROOT)/include
CFLAGS:=${CFLAGS} -I$(MOSQ_ROOT)/lib
CFLAGS:=${CFLAGS} -I$(MOSQ_ROOT)/src
CFLAGS:=${CFLAGS} -I../include
CFLAGS:=${CFLAGS} -I../lib
CFLAGS:=${CFLAGS} -I../../../deps
CFLAGS:=${CFLAGS} -DWITH_BROKER

DEPS = ../../../deps/uthash.h
OBJ = handle_publish.o handle_subscribe.o \
      ../../../lib/memory_mosq.o \
      ../../../lib/utf8_mosq.o \
      ../../../lib/property_mosq.o \
      ../../../src/database.o \
      ../../../lib/util_mosq.o \
      ../../../lib/packet_datatypes.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(LDADD) $(CLIENT_CFLAGS) $(CFLAGS)

packet_datatypes.gb: $(OBJ)
	$(CC) -o $@ $^ $(LDADD) $(CLIENT_CFLAGS) $(CFLAGS)

handle_disconnect.gb: $(OBJ)
	$(CC) -o $@ $^ $(LDADD) $(CLIENT_CFLAGS) $(CFLAGS)

handle_subscribe.gb: $(OBJ)
	$(CC) -o $@ $^ $(LDADD) $(CLIENT_CFLAGS) $(CFLAGS) 

handle_publish.gb: $(OBJ)
	$(CC) -o $@ $^ $(LDADD) $(CLIENT_CFLAGS) $(CFLAGS)
clean :
	rm -f *.gb *.o
	rm -f ../lib/*.gb ../lib/*.o
