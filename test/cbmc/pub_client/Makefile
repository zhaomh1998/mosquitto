include ../../../config.mk

# $(info $$WITH_TLS is [${WITH_TLS}])

.PHONY: all test_pub clean

CFLAGS=-I../../include -Wall# -Werror

SRC = \
	pub.c \
	client_shared.c \
	client_props.c \
	pub_shared.c

TESTS = ${SRC:.c=.test}

TEST_LDADD:=../../../lib/libmosquitto.so.${SOVERSION}

all : clean test_pub

test_pub : pub.o pub_shared.o client_shared.o client_props.o
	${CROSS_COMPILE}${CC} $(CLIENT_LDFLAGS) $^ -o $@ $(TEST_LDADD)

pub.o : pub.c ${SHARED_DEP}
	${CROSS_COMPILE}${CC} $(CLIENT_CPPFLAGS) $(CLIENT_CFLAGS) -c $< -o $@

pub_shared.o : pub_shared.c ${SHARED_DEP}
	${CROSS_COMPILE}${CC} $(CLIENT_CPPFLAGS) $(CLIENT_CFLAGS) -c $< -o $@

client_shared.o : client_shared.c client_shared.h
	${CROSS_COMPILE}${CC} $(CLIENT_CPPFLAGS) $(CLIENT_CFLAGS) -c $< -o $@

client_props.o : client_props.c client_shared.h
	${CROSS_COMPILE}${CC} $(CLIENT_CPPFLAGS) $(CLIENT_CFLAGS) -c $< -o $@

clean :
	rm -f test_pub *.o
