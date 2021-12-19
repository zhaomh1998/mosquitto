MOSQ_ROOT:=../../..

include $(MOSQ_ROOT)/config.mk

CC=goto-cc
CFLAGS:=-I$(MOSQ_ROOT)
CFLAGS:=${CFLAGS} -I$(MOSQ_ROOT)/include
CFLAGS:=${CFLAGS} -I$(MOSQ_ROOT)/lib
CFLAGS:=${CFLAGS} -I../lib

OBJ = connect.o \
	  ../lib/memory_mosq.o \
	  $(MOSQ_ROOT)/lib/property_mosq.o \
	  $(MOSQ_ROOT)/lib/time_mosq.o \
	  $(MOSQ_ROOT)/lib/packet_mosq.o \
	  $(MOSQ_ROOT)/lib/messages_mosq.o \
	  $(MOSQ_ROOT)/lib/net_mosq.o \
	  $(MOSQ_ROOT)/lib/util_mosq.o \
	  $(MOSQ_ROOT)/lib/util_mosq.o \
	  $(MOSQ_ROOT)/lib/send_mosq.o \

%.o: %.c
	$(CC) -c -o $@ $< $(LDADD) $(CLIENT_CFLAGS) $(CFLAGS)

broker_connect.gb: $(OBJ)
	$(CC) -o $@ $^ $(LDADD) $(CLIENT_CFLAGS) $(CFLAGS)

clean :
	rm -f *.gb *.o
	rm -f ../lib/*.gb ../lib/*.o
