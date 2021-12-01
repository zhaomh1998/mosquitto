#include "../../config.h"
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <mqtt_protocol.h>
#include <mosquitto.h>
#include "client_shared.h"
#include "pub_shared.h"
#include <assert.h>


static int run = -1;
static int sent_mid;

/* Global variables for use in callbacks. See sub_client.c for an example of
 * using a struct to hold variables for use in callbacks. */
static bool first_publish = true;
static int last_mid = -1;
static int last_mid_sent = -1;
static bool disconnect_sent = false;
static int publish_count = 0;
static bool ready_for_repeat = false;
static volatile int status = STATUS_CONNECTING;
static int connack_result = 0;



// void on_connect(struct mosquitto *mosq, void *obj, int rc)
// {
// 	if(rc){
// 		exit(1);
// 	}else{
// 		mosquitto_publish(mosq, &sent_mid, "psk/test", strlen("message"), "message", 0, false);
// 	}
// }

// void on_publish(struct mosquitto *mosq, void *obj, int mid)
// {
// 	if(mid == sent_mid){
// 		mosquitto_disconnect(mosq);
// 		run = 0;
// 	}else{
// 		exit(1);
// 	}
// }

// void on_disconnect(struct mosquitto *mosq, void *obj, int rc)
// {
// 	run = rc;
// }

static void init_config(struct mosq_config *cfg, int pub_or_sub)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->port = PORT_UNDEFINED;
    cfg->max_inflight = 20;
    cfg->keepalive = 60;
    cfg->clean_session = true;
    cfg->eol = true;
    cfg->repeat_count = 1;
    cfg->repeat_delay.tv_sec = 0;
    cfg->repeat_delay.tv_usec = 0;
    cfg->random_filter = 10000;
    if(pub_or_sub == CLIENT_RR){
        cfg->protocol_version = MQTT_PROTOCOL_V5;
        cfg->msg_count = 1;
    }else{
        cfg->protocol_version = MQTT_PROTOCOL_V311;
    }
    cfg->session_expiry_interval = -1; /* -1 means unset here, the user can't set it to -1. */
}


static int cfg_add_topic(struct mosq_config *cfg, int type, char *topic, const char *arg)
{
    if(mosquitto_validate_utf8(topic, (int )strlen(topic))){
        fprintf(stderr, "Error: Malformed UTF-8 in %s argument.\n\n", arg);
        return 1;
    }
    if(type == CLIENT_PUB || type == CLIENT_RR){
        if(mosquitto_pub_topic_check(topic) == MOSQ_ERR_INVAL){
            fprintf(stderr, "Error: Invalid publish topic '%s', does it contain '+' or '#'?\n", topic);
            return 1;
        }
        cfg->topic = strdup(topic);
    }else if(type == CLIENT_RESPONSE_TOPIC){
        if(mosquitto_pub_topic_check(topic) == MOSQ_ERR_INVAL){
            fprintf(stderr, "Error: Invalid response topic '%s', does it contain '+' or '#'?\n", topic);
            return 1;
        }
        cfg->response_topic = strdup(topic);
    }else{
        if(mosquitto_sub_topic_check(topic) == MOSQ_ERR_INVAL){
            fprintf(stderr, "Error: Invalid subscription topic '%s', are all '+' and '#' wildcards correct?\n", topic);
            return 1;
        }
        cfg->topic_count++;
        cfg->topics = realloc(cfg->topics, (size_t )cfg->topic_count*sizeof(char *));
        if(!cfg->topics){
            err_printf(cfg, "Error: Out of memory.\n");
            return 1;
        }
        cfg->topics[cfg->topic_count-1] = strdup(topic);
    }
    return 0;
}


void my_disconnect_callback(struct mosquitto *mosq, void *obj, int rc, const mosquitto_property *properties)
{
    printf(">> my_disconnect_callback\n");
	UNUSED(mosq);
	UNUSED(obj);
	UNUSED(rc);
	UNUSED(properties);

	if(rc == 0){
		status = STATUS_DISCONNECTED;
	}
    printf("<< my_disconnect_callback\n");
}

int my_publish(struct mosquitto *mosq, int *mid, const char *topic, int payloadlen, void *payload, int qos, bool retain)
{
//	printf("mid: %d\ntopic: %s\npayloadlen: %d\npayload: %s\nqos: %d\nretain: %d\n", *mid, topic, payloadlen, (char *) payload, qos, retain);
	ready_for_repeat = false;
	if(cfg.protocol_version == MQTT_PROTOCOL_V5 && cfg.have_topic_alias && first_publish == false){
		return mosquitto_publish_v5(mosq, mid, NULL, payloadlen, payload, qos, retain, cfg.publish_props);
	}else{
		first_publish = false;
		return mosquitto_publish_v5(mosq, mid, topic, payloadlen, payload, qos, retain, cfg.publish_props);
	}
}


void my_connect_callback(struct mosquitto *mosq, void *obj, int result, int flags, const mosquitto_property *properties)
{
    printf(">> my_connect_callback\n");
//    printf("mid: %d\ntopic: %s\npayloadlen: %d\npayload: %s\nqos: %d\nretain: %d\n", mid_sent, cfg.topic, cfg.msglen, (char *) cfg.message, cfg.qos, cfg.retain);
    int rc = MOSQ_ERR_SUCCESS;

	UNUSED(obj);
	UNUSED(flags);
	UNUSED(properties);

	connack_result = result;

	if(!result){
		switch(cfg.pub_mode){
			case MSGMODE_CMD:
			case MSGMODE_FILE:
			case MSGMODE_STDIN_FILE:
				rc = my_publish(mosq, &mid_sent, cfg.topic, cfg.msglen, cfg.message, cfg.qos, cfg.retain);
				break;
			case MSGMODE_NULL:
				rc = my_publish(mosq, &mid_sent, cfg.topic, 0, NULL, cfg.qos, cfg.retain);
				break;
			case MSGMODE_STDIN_LINE:
				status = STATUS_CONNACK_RECVD;
				break;
		}
		if(rc){
			switch(rc){
				case MOSQ_ERR_INVAL:
					err_printf(&cfg, "Error: Invalid input. Does your topic contain '+' or '#'?\n");
					break;
				case MOSQ_ERR_NOMEM:
					err_printf(&cfg, "Error: Out of memory when trying to publish message.\n");
					break;
				case MOSQ_ERR_NO_CONN:
					err_printf(&cfg, "Error: Client not connected when trying to publish.\n");
					break;
				case MOSQ_ERR_PROTOCOL:
					err_printf(&cfg, "Error: Protocol error when communicating with broker.\n");
					break;
				case MOSQ_ERR_PAYLOAD_SIZE:
					err_printf(&cfg, "Error: Message payload is too large.\n");
					break;
				case MOSQ_ERR_QOS_NOT_SUPPORTED:
					err_printf(&cfg, "Error: Message QoS not supported on broker, try a lower QoS.\n");
					break;
			}
			mosquitto_disconnect_v5(mosq, 0, cfg.disconnect_props);
		}
	}else{
		if(result){
			if(cfg.protocol_version == MQTT_PROTOCOL_V5){
				if(result == MQTT_RC_UNSUPPORTED_PROTOCOL_VERSION){
					err_printf(&cfg, "Connection error: %s. Try connecting to an MQTT v5 broker, or use MQTT v3.x mode.\n", mosquitto_reason_string(result));
				}else{
					err_printf(&cfg, "Connection error: %s\n", mosquitto_reason_string(result));
				}
			}else{
				err_printf(&cfg, "Connection error: %s\n", mosquitto_connack_string(result));
			}
			/* let the loop know that this is an unrecoverable connection */
			status = STATUS_NOHOPE;
		}
	}
    printf("<< my_connect_callback\n");
}


void my_publish_callback(struct mosquitto *mosq, void *obj, int mid, int reason_code, const mosquitto_property *properties)
{
    printf(">> my_publish_callback\n");
	char *reason_string = NULL;
	UNUSED(obj);
	UNUSED(properties);

	last_mid_sent = mid;
	if(reason_code > 127){
		err_printf(&cfg, "Warning: Publish %d failed: %s.\n", mid, mosquitto_reason_string(reason_code));
		mosquitto_property_read_string(properties, MQTT_PROP_REASON_STRING, &reason_string, false);
		if(reason_string){
			err_printf(&cfg, "%s\n", reason_string);
			free(reason_string);
		}
	}
	publish_count++;

	if(cfg.pub_mode == MSGMODE_STDIN_LINE){
		if(mid == last_mid){
			mosquitto_disconnect_v5(mosq, 0, cfg.disconnect_props);
			disconnect_sent = true;
		}
	}else if(publish_count < cfg.repeat_count){
		ready_for_repeat = true;
		// set_repeat_time();
	}else if(disconnect_sent == false){
		mosquitto_disconnect_v5(mosq, 0, cfg.disconnect_props);
		disconnect_sent = true;
	}
    printf("<< my_publish_callback\n");
}

static int pub_other_loop(struct mosquitto *mosq)
{
    int rc;
    int loop_delay = 1000;

    if(cfg.repeat_count > 1 && (cfg.repeat_delay.tv_sec == 0 || cfg.repeat_delay.tv_usec != 0)){
        loop_delay = (int )cfg.repeat_delay.tv_usec / 2000;
    }

    do{
        rc = mosquitto_loop(mosq, loop_delay, 1);
        printf("... loop rc=%d\n", rc);
        // --- start
        rc = MOSQ_ERR_SUCCESS;
        switch(cfg.pub_mode){
            case MSGMODE_CMD:
            case MSGMODE_FILE:
            case MSGMODE_STDIN_FILE:
                rc = my_publish(mosq, &mid_sent, cfg.topic, cfg.msglen, cfg.message, cfg.qos, cfg.retain);
                break;
            case MSGMODE_NULL:
                rc = my_publish(mosq, &mid_sent, cfg.topic, 0, NULL, cfg.qos, cfg.retain);
                break;
        }
        if(rc != MOSQ_ERR_SUCCESS && rc != MOSQ_ERR_NO_CONN){
            printf("Error sending repeat publish: %s", mosquitto_strerror(rc));
        }
        // --- end
    }while(rc == MOSQ_ERR_SUCCESS);

    if(status == STATUS_DISCONNECTED){
        return MOSQ_ERR_SUCCESS;
    }else{
        return rc;
    }
}

void test_cbmc() {
    struct mosquitto *mosq = NULL;
//	struct mosq_config test_cfg;
    char host[] = "207.148.29.214";
    char message[] = "hello";
    int port = 1883;
    size_t szt;
    char topic[] = "test/topic";

    mosquitto_lib_init();
    init_config(&cfg, CLIENT_PUB);

    // ------------ Make Config ------------
    // client/client_shared.c:661 --> -h host
    cfg.host = strdup(host);
    // client/client_shared.c:801 --> -m message
    cfg.message = strdup(message);
    // szt = strlen(test_cfg.message);
    szt = 5;
    assert(szt <= MQTT_MAX_PAYLOAD);
    cfg.msglen = (int) szt;
    cfg.pub_mode = MSGMODE_CMD;
    // client/client_shared.c:850 --> -p port
    cfg.port = port;
    // client/client_shared.c:1007 --> -t topic
    cfg_add_topic(&cfg, CLIENT_PUB, topic, "-t");

    // ------------ Create mosquitto ------------
    mosq = mosquitto_new(cfg.id, cfg.clean_session, NULL);
    assert(mosq);


    mosquitto_connect_v5_callback_set(mosq, my_connect_callback);
    mosquitto_disconnect_v5_callback_set(mosq, my_disconnect_callback);
    mosquitto_publish_v5_callback_set(mosq, my_publish_callback);
    assert(!client_opts_set(mosq, &cfg));


    client_connect(mosq, &cfg);
    printf(">> shared_loop\n");
    pub_other_loop(mosq);
    printf("<< shared_loop\n");

    // ------------ Cleanup ------------
    mosquitto_destroy(mosq);
    mosquitto_lib_cleanup();
    client_config_cleanup(&cfg);
}

int main(int argc, char *argv[])
{
    test_cbmc();
    return 0;
	// int rc;
	// int port;
    struct mosquitto *mosq;
    // char host[] = "207.148.29.214";
    // char message[] = "hello";
    // int port = 1883;
    // size_t szt;
    // char topic[] = "test/topic";

    mosquitto_lib_init();
//    assert(!pub_shared_init());

//	port = atoi(argv[1]);

    mosq = mosquitto_new(NULL, true, NULL);
//	mosquitto_tls_opts_set(mosq, 1, "tlsv1", NULL);
//	rc = mosquitto_tls_psk_set(mosq, "deadbeef", "psk-id", NULL);
//	if(rc){
//		mosquitto_destroy(mosq);
//		return rc;
//	}
//	mosquitto_connect_callback_set(mosq, on_connect);
//	mosquitto_disconnect_callback_set(mosq, on_disconnect);
//	mosquitto_publish_callback_set(mosq, on_publish);
//
//	rc = mosquitto_connect(mosq, "localhost", port, 60);
//	if(rc){
//		mosquitto_destroy(mosq);
//		return rc;
//	}
//
//	while(run == -1){
//		mosquitto_loop(mosq, -1, 1);
//	}

    mosquitto_destroy(mosq);

    mosquitto_lib_cleanup();
//	return run;
    return 0;
}