#include "mosquitto.h"
#include "mosquitto_internal.h"
#include "mosquitto_broker_internal.h"
#include "memory_mosq.h"
#include "mqtt_protocol.h"
#include <assert.h>
#include <limits.h>

char byte_1_reference = 0x00;
char byte_2_reference = 0x00;

void verify_buffer(const void *buf) {
	char b1 = ((char *)buf)[0];
	char b2 = ((char *)buf)[1];
	assert(b1 == byte_1_reference);
	assert(b2 == byte_2_reference);
}

void harness()
{

    struct mosquitto *mosq;

    // Set up mosquitto context
    mosq = (struct mosquitto *)mosquitto__calloc(1, sizeof(struct mosquitto));
    mosq->state = mosq_cs_active;


    // Command: CONNECT. handle__pingreq should return a MALFORMED_PACKET
    mosq->in_packet.command = 0x10;
    int ret = handle__pingreq(mosq);
    assert(ret == MOSQ_ERR_MALFORMED_PACKET);

    // Command: PINGREQ. handle__pingreq should send a PINGRESP (D0 00) and return SUCCESS
    mosq->in_packet.command = 0xC0;
    byte_1_reference = 0xD0;
    byte_2_reference = 0x00;
    int ret = handle__pingreq(mosq);
    assert(ret == MOSQ_ERR_SUCCESS);

    // Clean up
    free(mosq);
}
