/*
Copyright (c) 2016-2021 Roger Light <roger@atchoo.org>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License 2.0
and Eclipse Distribution License v1.0 which accompany this distribution.

The Eclipse Public License is available at
   https://www.eclipse.org/legal/epl-2.0/
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.

SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause

Contributors:
   Roger Light - initial implementation and documentation.
*/

#include "config.h"

#include "mosquitto_broker_internal.h"
#include "memory_mosq.h"
#include "mqtt_protocol.h"
#include "send_mosq.h"
#include "util_mosq.h"
#include "will_mosq.h"
#include "utlist.h"
#include "will_mosq.h"

#ifdef WITH_TLS
#  include <openssl/ssl.h>
#endif

int mosquitto_plugin_set_info(mosquitto_plugin_id_t *identifier,
		const char *plugin_name,
		const char *plugin_version)
{
	if(identifier == NULL || plugin_name == NULL){
		return MOSQ_ERR_INVAL;
	}

	identifier->plugin_name = mosquitto_strdup(plugin_name);
	if(plugin_version){
		identifier->plugin_version = mosquitto_strdup(plugin_version);
	}else{
		identifier->plugin_version = NULL;
	}

	return MOSQ_ERR_SUCCESS;
}


const char *mosquitto_client_address(const struct mosquitto *client)
{
	if(client){
		return client->address;
	}else{
		return NULL;
	}
}


int mosquitto_client_port(const struct mosquitto *client)
{
	if(client && client->listener){
		return client->listener->port;
	}else{
		return 0;
	}
}


bool mosquitto_client_clean_session(const struct mosquitto *client)
{
	if(client){
		return client->clean_start;
	}else{
		return true;
	}
}


const char *mosquitto_client_id(const struct mosquitto *client)
{
	if(client){
		return client->id;
	}else{
		return NULL;
	}
}


int mosquitto_client_keepalive(const struct mosquitto *client)
{
	if(client){
		return client->keepalive;
	}else{
		return -1;
	}
}


void *mosquitto_client_certificate(const struct mosquitto *client)
{
#ifdef WITH_TLS
	if(client && client->ssl){
		return SSL_get_peer_certificate(client->ssl);
	}else{
		return NULL;
	}
#else
	UNUSED(client);

	return NULL;
#endif
}


int mosquitto_client_protocol(const struct mosquitto *client)
{
#if defined(WITH_WEBSOCKETS) && WITH_WEBSOCKETS == WS_IS_LWS
	if(client && client->wsi){
		return mp_websockets;
	}else
#elif defined(WITH_WEBSOCKETS) && WITH_WEBSOCKETS == WS_IS_BUILTIN
	if(client && client->transport == mosq_t_ws){
		return mp_websockets;
	}else
#else
	UNUSED(client);
#endif
	{
		return mp_mqtt;
	}
}


int mosquitto_client_protocol_version(const struct mosquitto *client)
{
	if(client){
		switch(client->protocol){
			case mosq_p_mqtt31:
				return 3;
			case mosq_p_mqtt311:
				return 4;
			case mosq_p_mqtt5:
				return 5;
			default:
				return 0;
		}
	}else{
		return 0;
	}
}


int mosquitto_client_sub_count(const struct mosquitto *client)
{
	if(client){
		return client->sub_count;
	}else{
		return 0;
	}
}


const char *mosquitto_client_username(const struct mosquitto *client)
{
	if(client){
#ifdef WITH_BRIDGE
		if(client->bridge){
			return client->bridge->local_username;
		}else
#endif
		{
			return client->username;
		}
	}else{
		return NULL;
	}
}


int mosquitto_broker_publish(
		const char *clientid,
		const char *topic,
		int payloadlen,
		void *payload,
		int qos,
		bool retain,
		mosquitto_property *properties)
{
	struct mosquitto__message_v5 *msg;

	if(topic == NULL
			|| payloadlen < 0
			|| (payloadlen > 0 && payload == NULL)
			|| qos < 0 || qos > 2){

		return MOSQ_ERR_INVAL;
	}

	msg = mosquitto__malloc(sizeof(struct mosquitto__message_v5));
	if(msg == NULL) return MOSQ_ERR_NOMEM;

	msg->next = NULL;
	msg->prev = NULL;
	if(clientid){
		msg->clientid = mosquitto__strdup(clientid);
		if(msg->clientid == NULL){
			mosquitto__free(msg);
			return MOSQ_ERR_NOMEM;
		}
	}else{
		msg->clientid = NULL;
	}
	msg->topic = mosquitto__strdup(topic);
	if(msg->topic == NULL){
		mosquitto__free(msg->clientid);
		mosquitto__free(msg);
		return MOSQ_ERR_NOMEM;
	}
	msg->payloadlen = payloadlen;
	msg->payload = payload;
	msg->qos = qos;
	msg->retain = retain;
	msg->properties = properties;

	DL_APPEND(db.plugin_msgs, msg);

	return MOSQ_ERR_SUCCESS;
}


int mosquitto_broker_publish_copy(
		const char *clientid,
		const char *topic,
		int payloadlen,
		const void *payload,
		int qos,
		bool retain,
		mosquitto_property *properties)
{
	void *payload_out;
	int rc;

	if(topic == NULL
			|| payloadlen < 0
			|| (payloadlen > 0 && payload == NULL)
			|| qos < 0 || qos > 2){

		return MOSQ_ERR_INVAL;
	}

	payload_out = calloc(1, (size_t)(payloadlen+1));
	if(payload_out == NULL){
		return MOSQ_ERR_NOMEM;
	}
	memcpy(payload_out, payload, (size_t)payloadlen);

	rc = mosquitto_broker_publish(
			clientid,
			topic,
			payloadlen,
			payload_out,
			qos,
			retain,
			properties);

	if(rc){
		free(payload_out);
	}
	return rc;
}


int mosquitto_set_username(struct mosquitto *client, const char *username)
{
	char *u_dup;
	char *old;
	int rc;

	if(!client) return MOSQ_ERR_INVAL;

	if(username){
		u_dup = mosquitto__strdup(username);
		if(!u_dup) return MOSQ_ERR_NOMEM;
	}else{
		u_dup = NULL;
	}

	old = client->username;
	client->username = u_dup;

	rc = acl__find_acls(client);
	if(rc){
		client->username = old;
		mosquitto__free(u_dup);
		return rc;
	}else{
		mosquitto__free(old);
		return MOSQ_ERR_SUCCESS;
	}
}


/* Check to see whether durable clients still have rights to their subscriptions. */
static void check_subscription_acls(struct mosquitto *context)
{
	int i;
	int rc;
	uint8_t reason;

	for(i=0; i<context->sub_count; i++){
		if(context->subs[i] == NULL){
			continue;
		}
		rc = mosquitto_acl_check(context,
				context->subs[i]->topic_filter,
				0,
				NULL,
				0, /* FIXME */
				false,
				MOSQ_ACL_SUBSCRIBE);

		if(rc != MOSQ_ERR_SUCCESS){
			sub__remove(context, context->subs[i]->topic_filter, db.subs, &reason);
		}
	}
}



static void disconnect_client(struct mosquitto *context, bool with_will)
{
	if(context->protocol == mosq_p_mqtt5){
		send__disconnect(context, MQTT_RC_ADMINISTRATIVE_ACTION, NULL);
	}
	if(with_will == false){
		mosquitto__set_state(context, mosq_cs_disconnecting);
	}
	if(context->session_expiry_interval > 0){
		check_subscription_acls(context);
	}
	do_disconnect(context, MOSQ_ERR_ADMINISTRATIVE_ACTION);
}

int mosquitto_kick_client_by_clientid(const char *clientid, bool with_will)
{
	struct mosquitto *ctxt, *ctxt_tmp;

	if(clientid == NULL){
		HASH_ITER(hh_sock, db.contexts_by_sock, ctxt, ctxt_tmp){
			disconnect_client(ctxt, with_will);
		}
		return MOSQ_ERR_SUCCESS;
	}else{
		HASH_FIND(hh_id, db.contexts_by_id, clientid, strlen(clientid), ctxt);
		if(ctxt){
			disconnect_client(ctxt, with_will);
			return MOSQ_ERR_SUCCESS;
		}else{
			return MOSQ_ERR_NOT_FOUND;
		}
	}
}

int mosquitto_kick_client_by_username(const char *username, bool with_will)
{
	struct mosquitto *ctxt, *ctxt_tmp;

	if(username == NULL){
		HASH_ITER(hh_sock, db.contexts_by_sock, ctxt, ctxt_tmp){
			if(ctxt->username == NULL){
				disconnect_client(ctxt, with_will);
			}
		}
	}else{
		HASH_ITER(hh_sock, db.contexts_by_sock, ctxt, ctxt_tmp){
			if(ctxt->username != NULL && !strcmp(ctxt->username, username)){
				disconnect_client(ctxt, with_will);
			}
		}
	}
	return MOSQ_ERR_SUCCESS;
}


int mosquitto_persist_client_add(struct mosquitto_evt_persist_client *client)
{
	struct mosquitto *context;
	int i;
	int rc;

	if(client == NULL){
		return MOSQ_ERR_INVAL;
	}
	if(client->plugin_client_id == NULL){
		rc = MOSQ_ERR_INVAL;
		goto error;
	}

	context = NULL;
	HASH_FIND(hh_id, db.contexts_by_id, client->plugin_client_id, strlen(client->plugin_client_id), context);
	if(context){
		rc = MOSQ_ERR_INVAL;
		goto error;
	}

	context = context__init();
	if(!context){
		rc = MOSQ_ERR_NOMEM;
		goto error;
	}

	context->id = client->plugin_client_id;
	client->plugin_client_id = NULL;
	context->username = client->plugin_username;
	client->plugin_username = NULL;
	context->auth_method = client->plugin_auth_method;
	client->plugin_auth_method = NULL;

	context->clean_start = false;
	context->will_delay_time = client->will_delay_time;
	context->session_expiry_time = client->session_expiry_time;
	context->will_delay_interval = client->will_delay_interval;
	context->session_expiry_interval = client->session_expiry_interval;
	context->max_qos = client->max_qos;
	context->maximum_packet_size = client->max_packet_size;
	context->retain_available = client->retain_available;

	/* in per_listener_settings mode, try to find the listener by persisted port */
	if(db.config->per_listener_settings && client->listener_port > 0){
		for(i=0; i < db.config->listener_count; i++){
			if(db.config->listeners[i].port == client->listener_port){
				context->listener = &db.config->listeners[i];
				break;
			}
		}
	}

	context__add_to_by_id(context);

	return MOSQ_ERR_SUCCESS;
error:
	free(client->plugin_client_id);
	free(client->plugin_username);
	free(client->plugin_auth_method);
	return rc;
}


int mosquitto_persist_client_update(struct mosquitto_evt_persist_client *client)
{
	struct mosquitto *context;
	int i;
	int rc;

	if(client == NULL){
		return MOSQ_ERR_INVAL;
	}
	if(client->plugin_client_id == NULL){
		rc = MOSQ_ERR_INVAL;
		goto error;
	}

	context = NULL;
	HASH_FIND(hh_id, db.contexts_by_id, client->plugin_client_id, strlen(client->plugin_client_id), context);
	if(context == NULL){
		rc = MOSQ_ERR_NOT_FOUND;
		goto error;
	}

	mosquitto_free(context->username);
	context->username = client->plugin_username;
	client->plugin_username = NULL;

	context->clean_start = false;
	context->will_delay_time = client->will_delay_time;
	context->session_expiry_time = client->session_expiry_time;
	context->will_delay_interval = client->will_delay_interval;
	context->session_expiry_interval = client->session_expiry_interval;
	context->max_qos = client->max_qos;
	context->maximum_packet_size = client->max_packet_size;
	context->retain_available = client->retain_available;

	/* in per_listener_settings mode, try to find the listener by persisted port */
	if(db.config->per_listener_settings && client->listener_port > 0){
		for(i=0; i < db.config->listener_count; i++){
			if(db.config->listeners[i].port == client->listener_port){
				context->listener = &db.config->listeners[i];
				break;
			}
		}
	}

	return MOSQ_ERR_SUCCESS;
error:
	free(client->plugin_username);
	return rc;
}


int mosquitto_persist_client_remove(const char *client_id)
{
	struct mosquitto *context;

	if(client_id == NULL) return MOSQ_ERR_INVAL;

	context = NULL;
	HASH_FIND(hh_id, db.contexts_by_id, client_id, strlen(client_id), context);
	if(context == NULL){
		return MOSQ_ERR_SUCCESS;
	}

	session_expiry__remove(context);
	will_delay__remove(context);
	will__clear(context);

	context->clean_start = true;
	context->session_expiry_interval = 0;
	mosquitto__set_state(context, mosq_cs_duplicate);
	do_disconnect(context, MOSQ_ERR_SUCCESS);

	return MOSQ_ERR_SUCCESS;
}


struct mosquitto_msg_store *find_store_msg(uint64_t store_id)
{
	struct mosquitto_msg_store *stored;

	HASH_FIND(hh, db.msg_store, &store_id, sizeof(store_id), stored);
	return stored;
}

int mosquitto_persist_client_msg_add(struct mosquitto_evt_persist_client_msg *client_msg)
{
	struct mosquitto *context;
	struct mosquitto_msg_store *stored;

	if(client_msg == NULL || client_msg->plugin_client_id == NULL) return MOSQ_ERR_INVAL;

	HASH_FIND(hh_id, db.contexts_by_id, client_msg->plugin_client_id, strlen(client_msg->plugin_client_id), context);
	if(context == NULL){
		return MOSQ_ERR_NOT_FOUND;
	}
	stored = find_store_msg(client_msg->store_id);
	if(stored == NULL){
		return MOSQ_ERR_NOT_FOUND;
	}

	if(client_msg->direction == mosq_md_out){
		if(client_msg->qos > 0){
			context->last_mid = client_msg->mid;
		}
		return db__message_insert_outgoing(context, client_msg->cmsg_id, client_msg->mid, client_msg->qos, client_msg->retain,
				stored, client_msg->subscription_identifier, false, false);
	}else{
		return db__message_insert_incoming(context, client_msg->cmsg_id, stored, false);
	}
	return MOSQ_ERR_SUCCESS;
}


int mosquitto_persist_client_msg_remove(struct mosquitto_evt_persist_client_msg *client_msg)
{
	struct mosquitto *context;

	if(client_msg == NULL || client_msg->plugin_client_id == NULL) return MOSQ_ERR_INVAL;

	HASH_FIND(hh_id, db.contexts_by_id, client_msg->plugin_client_id, strlen(client_msg->plugin_client_id), context);
	if(context == NULL){
		return MOSQ_ERR_NOT_FOUND;
	}

	if(client_msg->direction == mosq_md_out){
		return db__message_delete_outgoing(context, client_msg->mid, client_msg->state, client_msg->qos);
	}else{
		return db__message_remove_incoming(context, client_msg->mid);
	}
	return MOSQ_ERR_SUCCESS;
}


int mosquitto_persist_client_msg_update(struct mosquitto_evt_persist_client_msg *client_msg)
{
	struct mosquitto *context;

	if(client_msg == NULL || client_msg->plugin_client_id == NULL) return MOSQ_ERR_INVAL;

	HASH_FIND(hh_id, db.contexts_by_id, client_msg->plugin_client_id, strlen(client_msg->plugin_client_id), context);
	if(context == NULL){
		return MOSQ_ERR_NOT_FOUND;
	}

	if(client_msg->direction == mosq_md_out){
		db__message_update_outgoing(context, client_msg->mid, client_msg->state, client_msg->qos, false);
	}else{
		// FIXME db__message_update_incoming(context, client_msg->mid, client_msg->state, client_msg->qos, false);
	}
	return MOSQ_ERR_SUCCESS;
}


int mosquitto_subscription_add(const char *client_id, const char *topic, uint8_t subscription_options, uint32_t subscription_identifier)
{
	struct mosquitto *context;

	if(client_id == NULL || topic == NULL || client_id[0] == '\0' || topic[0] == '\0'){
		return MOSQ_ERR_INVAL;
	}

	HASH_FIND(hh_id, db.contexts_by_id, client_id, strlen(client_id), context);

	if(context){
		return sub__add(context, topic, subscription_options&0x03, subscription_identifier, subscription_options, &db.subs);
	}else{
		return MOSQ_ERR_NOT_FOUND;
	}
}


int mosquitto_subscription_remove(const char *client_id, const char *topic)
{
	struct mosquitto *context;
	uint8_t reason;

	if(client_id == NULL || topic == NULL || client_id[0] == '\0' || topic[0] == '\0'){
		return MOSQ_ERR_INVAL;
	}

	HASH_FIND(hh_id, db.contexts_by_id, client_id, strlen(client_id), context);

	if(context){
		return sub__remove(context, topic, db.subs, &reason);
	}else{
		return MOSQ_ERR_NOT_FOUND;
	}
}


int mosquitto_persist_msg_add(struct mosquitto_evt_persist_msg *msg)
{
	struct mosquitto context;
	struct mosquitto_msg_store *stored;
	uint32_t message_expiry_interval;
	time_t message_expiry_interval_tt;
	int i;

	memset(&context, 0, sizeof(context));

	context.id = msg->plugin_source_id;
	context.username = msg->plugin_source_username;

	if(msg->expiry_time == 0){
		message_expiry_interval = 0;
	}else if(msg->expiry_time <= db.now_real_s){
		message_expiry_interval = 1;
	}else{
		message_expiry_interval_tt = msg->expiry_time - db.now_real_s;
		if(message_expiry_interval_tt > UINT32_MAX){
			message_expiry_interval = UINT32_MAX;
		}else{
			message_expiry_interval = (uint32_t)message_expiry_interval_tt;
		}
	}

	stored = mosquitto_calloc(1, sizeof(struct mosquitto_msg_store));
	if(stored == NULL){
		goto error;
	}
	stored->payloadlen = msg->payloadlen;
	stored->source_mid = msg->source_mid;
	stored->qos = msg->qos;
	stored->retain = msg->retain;

	stored->payload = msg->plugin_payload;
	msg->plugin_payload = NULL;
	stored->topic = msg->plugin_topic;
	msg->plugin_topic = NULL;
	stored->properties = msg->plugin_properties;
	msg->plugin_properties = NULL;

	if(msg->source_port){
		for(i=0; i<db.config->listener_count; i++){
			if(db.config->listeners[i].port == msg->source_port){
				stored->source_listener = &db.config->listeners[i];
				break;
			}
		}
	}
	return db__message_store(&context, stored, message_expiry_interval, msg->store_id, mosq_mo_broker);

error:
	mosquitto_property_free_all(&msg->plugin_properties);
	mosquitto_free(msg->plugin_topic);
	mosquitto_free(msg->plugin_payload);
	mosquitto_free(stored);

	return MOSQ_ERR_NOMEM;
}


int mosquitto_persist_msg_remove(uint64_t store_id)
{
	struct mosquitto_msg_store *stored;

	stored = find_store_msg(store_id);
	db__msg_store_remove(stored, false);

	return MOSQ_ERR_SUCCESS;
}


void mosquitto_complete_basic_auth(const char *client_id, int result)
{
	struct mosquitto *context;

	if(client_id == NULL) return;

	HASH_FIND(hh_id, db.contexts_by_id_delayed_auth, client_id, strlen(client_id), context);
	if(context){
		HASH_DELETE(hh_id, db.contexts_by_id_delayed_auth, context);
		if(result == MOSQ_ERR_SUCCESS){
			connect__on_authorised(context, NULL, 0);
		}else{
			if(context->protocol == mosq_p_mqtt5){
				send__connack(context, 0, MQTT_RC_NOT_AUTHORIZED, NULL);
			}else{
				send__connack(context, 0, CONNACK_REFUSED_NOT_AUTHORIZED, NULL);
			}
			context->clean_start = true;
			context->session_expiry_interval = 0;
			will__clear(context);
			do_disconnect(context, MOSQ_ERR_AUTH);
		}
	}
}

int mosquitto_broker_node_id_set(uint16_t id)
{
	if(id > 1023){
		return MOSQ_ERR_INVAL;
	}else{
		db.node_id = id;
		db.node_id_shifted = ((uint64_t)id) << 54;
		return MOSQ_ERR_SUCCESS;
	}
}
