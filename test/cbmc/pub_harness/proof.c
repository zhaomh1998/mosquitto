#include "mosquitto.h"
#include "mosquitto_internal.h"
#include "mosquitto_broker_internal.h"
#include "memory_mosq.h"
#include "mqtt_protocol.h"
#include <assert.h>
#include <limits.h>


void harness()
{

    struct mosquitto *mosq;

    // Set up mosquitto context
    mosq = (struct mosquitto *)mosquitto__calloc(1, sizeof(struct mosquitto));
    mosq->state = mosq_cs_active;


    // mosq->in_packet.command = CMD_CONNECT;
    // int ret = handle__pingreq(mosq);
    // assert(ret == MOSQ_ERR_MALFORMED_PACKET);

    mosq->in_packet.command = CMD_PINGREQ;
    int ret = handle__pingreq(mosq);
    assert(ret != MOSQ_ERR_MALFORMED_PACKET);

}
