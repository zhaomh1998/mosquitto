MOSQ_ROOT:=../../..

include $(MOSQ_ROOT)/config.mk

CC=goto-cc
CFLAGS:=-I$(MOSQ_ROOT)
CFLAGS:=${CFLAGS} -I$(MOSQ_ROOT)/include
CFLAGS:=${CFLAGS} -I$(MOSQ_ROOT)/lib
CFLAGS:=${CFLAGS} -I$(MOSQ_ROOT)/src
CFLAGS:=${CFLAGS} -I$(MOSQ_ROOT)/deps

OBJ = proof.o \
	  $(MOSQ_ROOT)/src/handle_subscribe.c \
	  ../lib/memory_mosq.o \
	  $(MOSQ_ROOT)/src/mosquitto.o \
	  $(MOSQ_ROOT)/src/bridge.o \
	  $(MOSQ_ROOT)/src/bridge_topic.o \
	  $(MOSQ_ROOT)/src/conf.o \
	  $(MOSQ_ROOT)/src/conf_includedir.o \
	  $(MOSQ_ROOT)/src/context.o \
	  $(MOSQ_ROOT)/src/control.o \
	  $(MOSQ_ROOT)/src/database.o \
	  $(MOSQ_ROOT)/lib/handle_auth.o \
	  $(MOSQ_ROOT)/lib/handle_connack.o \
	  $(MOSQ_ROOT)/src/handle_connect.o \
	  $(MOSQ_ROOT)/lib/handle_disconnect.o \
	  $(MOSQ_ROOT)/lib/handle_ping.o \
	  $(MOSQ_ROOT)/lib/handle_pubackcomp.o \
	  $(MOSQ_ROOT)/src/handle_publish.o \
	  $(MOSQ_ROOT)/lib/handle_pubrec.o \
	  $(MOSQ_ROOT)/lib/handle_pubrel.o \
	  $(MOSQ_ROOT)/lib/handle_suback.o \
	  $(MOSQ_ROOT)/src/handle_subscribe.o \
	  $(MOSQ_ROOT)/lib/handle_unsuback.o \
	  $(MOSQ_ROOT)/src/handle_unsubscribe.o \
	  $(MOSQ_ROOT)/src/keepalive.o \
	  $(MOSQ_ROOT)/src/logging.o \
	  $(MOSQ_ROOT)/src/loop.o \
	  $(MOSQ_ROOT)/src/memory_public.o \
	  $(MOSQ_ROOT)/lib/misc_mosq.o \
	  $(MOSQ_ROOT)/src/mux.o \
	  $(MOSQ_ROOT)/src/mux_epoll.o \
	  $(MOSQ_ROOT)/src/mux_poll.o \
	  $(MOSQ_ROOT)/src/net.o \
	  $(MOSQ_ROOT)/lib/net_mosq_ocsp.o \
	  $(MOSQ_ROOT)/lib/packet_datatypes.o \
	  $(MOSQ_ROOT)/lib/packet_mosq.o \
	  $(MOSQ_ROOT)/src/password_mosq.o \
	  $(MOSQ_ROOT)/src/property_broker.o \
	  $(MOSQ_ROOT)/lib/property_mosq.o \
	  $(MOSQ_ROOT)/src/persist_read.o \
	  $(MOSQ_ROOT)/src/persist_read_v234.o \
	  $(MOSQ_ROOT)/src/persist_read_v5.o \
	  $(MOSQ_ROOT)/src/persist_write.o \
	  $(MOSQ_ROOT)/src/persist_write_v5.o \
	  $(MOSQ_ROOT)/src/plugin.o \
	  $(MOSQ_ROOT)/src/plugin_public.o \
	  $(MOSQ_ROOT)/src/read_handle.o \
	  $(MOSQ_ROOT)/src/retain.o \
	  $(MOSQ_ROOT)/src/security.o \
	  $(MOSQ_ROOT)/src/security_default.o \
	  $(MOSQ_ROOT)/src/send_auth.o \
	  $(MOSQ_ROOT)/src/send_connack.o \
	  $(MOSQ_ROOT)/lib/send_connect.o \
	  $(MOSQ_ROOT)/lib/send_disconnect.o \
	  $(MOSQ_ROOT)/lib/send_mosq.o \
	  $(MOSQ_ROOT)/lib/send_publish.o \
	  $(MOSQ_ROOT)/src/send_suback.o \
	  $(MOSQ_ROOT)/lib/send_subscribe.o \
	  $(MOSQ_ROOT)/src/send_unsuback.o \
	  $(MOSQ_ROOT)/lib/send_unsubscribe.o \
	  $(MOSQ_ROOT)/src/service.o \
	  $(MOSQ_ROOT)/src/session_expiry.o \
	  $(MOSQ_ROOT)/src/signals.o \
	  $(MOSQ_ROOT)/lib/strings_mosq.o \
	  $(MOSQ_ROOT)/src/subs.o \
	  $(MOSQ_ROOT)/src/sys_tree.o \
	  $(MOSQ_ROOT)/lib/time_mosq.o \
	  $(MOSQ_ROOT)/src/topic_tok.o \
	  $(MOSQ_ROOT)/lib/tls_mosq.o \
	  $(MOSQ_ROOT)/lib/utf8_mosq.o \
	  $(MOSQ_ROOT)/lib/util_mosq.o \
	  $(MOSQ_ROOT)/lib/util_topic.o \
	  $(MOSQ_ROOT)/src/websockets.o \
	  $(MOSQ_ROOT)/src/will_delay.o \
	  $(MOSQ_ROOT)/lib/will_mosq.o \
	  $(MOSQ_ROOT)/src/xtreport.o \
	  ../lib/stubs.c


%.o: %.c
	$(CC) -c -o $@ $< $(LDADD) $(BROKER_CFLAGS) $(CFLAGS)

proof.gb: $(OBJ)
	$(CC) -o $@ $^ $(LDADD) $(BROKER_CFLAGS) $(CFLAGS)

clean :
	rm -f *.gb *.o
	rm -f ../lib/*.gb ../lib/*.o
