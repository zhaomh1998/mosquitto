#include "mosquitto.h"
#include "mosquitto_internal.h"
#include "mosquitto_broker_internal.h"
#include "memory_mosq.h"
#include "mqtt_protocol.h"
#include <assert.h>
#include <limits.h>

char byte_1_reference = 0x00;
char byte_2_reference = 0x00;
char byte_3_reference = 0x00;

void verify_buffer(const void *buf) {
	char b1 = ((char *)buf)[0];
	char b2 = ((char *)buf)[1];
	char b3 = ((char *)buf)[2];
	assert(b1 == byte_1_reference);
	assert(b2 == byte_2_reference);
	assert(b3 == byte_3_reference);
}

void harness()
{

    struct mosquitto *mosq;

    // Set up mosquitto context
    mosq = (struct mosquitto *)mosquitto__calloc(1, sizeof(struct mosquitto));
    
    // Set a wrong client state so handle__packet produces a ERR_PROTOCOL
    mosq->state = mosq_cs_disconnected;

    mosq->protocol = mosq_p_mqtt5;
    // PINGREQ, but from a disconnected client
    // Should return ERR_PROTOCOL, and send out disconnect(reason=protocol_error)
    mosq->in_packet.command = 0xC0;

    byte_1_reference = 0xE0; // disconnect (11100000)
    byte_2_reference = 0x01; // remaining length (00000001)
    byte_3_reference = 0x82; // Protocol error (10000010) with wrong mosq->state
    int ret = handle__packet(mosq);
    assert(ret == MOSQ_ERR_PROTOCOL);

    free(mosq);
}
