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
#include "utlist.h"
#include "lib_load.h"


static bool check_callback_exists(struct mosquitto__callback *cb_base, MOSQ_FUNC_generic_callback cb_func)
{
	struct mosquitto__callback *tail, *tmp;

	DL_FOREACH_SAFE(cb_base, tail, tmp){
		if(tail->cb == cb_func){
			return true;
		}
	}
	return false;
}


static int remove_callback(mosquitto_plugin_id_t *identifier, int event, struct mosquitto__callback **cb_base, MOSQ_FUNC_generic_callback cb_func)
{
	struct mosquitto__callback *tail, *tmp;
	struct plugin_own_callback *own, *own_tmp;

	DL_FOREACH_SAFE(*cb_base, tail, tmp){
		if(tail->cb == cb_func){
			DL_DELETE(*cb_base, tail);
			mosquitto__free(tail);
			break;
		}
	}
	DL_FOREACH_SAFE(identifier->own_callbacks, own, own_tmp){
		if(own->cb_func == cb_func && own->event == event){
			DL_DELETE(identifier->own_callbacks, own);
			mosquitto__free(own);
			return MOSQ_ERR_SUCCESS;
		}
	}
	return MOSQ_ERR_NOT_FOUND;
}


int mosquitto_callback_register(
		mosquitto_plugin_id_t *identifier,
		int event,
		MOSQ_FUNC_generic_callback cb_func,
		const void *event_data,
		void *userdata)
{
	struct mosquitto__callback **cb_base = NULL, *cb_new;
	struct mosquitto__security_options *security_options;
	const char *event_name;
	struct plugin_own_callback *own_callback;

	if(cb_func == NULL) return MOSQ_ERR_INVAL;

	if(identifier->listener == NULL){
		security_options = &db.config->security_options;
	}else{
		security_options = &identifier->listener->security_options;
	}

	switch(event){
		case MOSQ_EVT_RELOAD:
			cb_base = &security_options->plugin_callbacks.reload;
			event_name = "reload";
			break;
		case MOSQ_EVT_ACL_CHECK:
			cb_base = &security_options->plugin_callbacks.acl_check;
			event_name = "acl-check";
			break;
		case MOSQ_EVT_BASIC_AUTH:
			cb_base = &security_options->plugin_callbacks.basic_auth;
			event_name = "basic-auth";
			break;
		case MOSQ_EVT_PSK_KEY:
			cb_base = &security_options->plugin_callbacks.psk_key;
			event_name = "psk-key";
			break;
		case MOSQ_EVT_EXT_AUTH_START:
			cb_base = &security_options->plugin_callbacks.ext_auth_start;
			event_name = "auth-start";
			break;
		case MOSQ_EVT_EXT_AUTH_CONTINUE:
			cb_base = &security_options->plugin_callbacks.ext_auth_continue;
			event_name = "auth-continue";
			break;
		case MOSQ_EVT_CONTROL:
			return control__register_callback(identifier, cb_func, event_data, userdata);
			break;
		case MOSQ_EVT_MESSAGE:
			cb_base = &security_options->plugin_callbacks.message;
			event_name = "message";
			break;
		case MOSQ_EVT_TICK:
			cb_base = &security_options->plugin_callbacks.tick;
			event_name = "tick";
			break;
		case MOSQ_EVT_DISCONNECT:
			cb_base = &security_options->plugin_callbacks.disconnect;
			event_name = "disconnect";
			break;
		case MOSQ_EVT_CONNECT:
			cb_base = &security_options->plugin_callbacks.connect;
			event_name = "connect";
			break;
		default:
			return MOSQ_ERR_NOT_SUPPORTED;
			break;
	}

	if(check_callback_exists(*cb_base, cb_func)){
		return MOSQ_ERR_ALREADY_EXISTS;
	}

	cb_new = mosquitto__calloc(1, sizeof(struct mosquitto__callback));
	if(cb_new == NULL){
		return MOSQ_ERR_NOMEM;
	}
	own_callback = mosquitto__calloc(1, sizeof(struct plugin_own_callback));
	if(own_callback == NULL){
		mosquitto__free(cb_new);
		return MOSQ_ERR_NOMEM;
	}
	own_callback->event = event;
	own_callback->cb_func = cb_func;
	DL_APPEND(identifier->own_callbacks, own_callback);

	DL_APPEND(*cb_base, cb_new);
	cb_new->cb = cb_func;
	cb_new->userdata = userdata;

	if(identifier->plugin_name){
		log__printf(NULL, MOSQ_LOG_INFO, "Plugin %s has registered to receive '%s' events.",
				identifier->plugin_name, event_name);
	}

	return MOSQ_ERR_SUCCESS;
}


int plugin__callback_unregister_all(mosquitto_plugin_id_t *identifier)
{
	struct mosquitto__callback **cb_base = NULL;
	struct mosquitto__security_options *security_options;
	struct plugin_own_callback *own, *own_tmp;

	if(identifier == NULL){
		return MOSQ_ERR_INVAL;
	}

	if(identifier->listener == NULL){
		security_options = &db.config->security_options;
	}else{
		security_options = &identifier->listener->security_options;
	}

	control__unregister_all_callbacks(identifier);

	DL_FOREACH_SAFE(identifier->own_callbacks, own, own_tmp){
		switch(own->event){
			case MOSQ_EVT_RELOAD:
				cb_base = &security_options->plugin_callbacks.reload;
				break;
			case MOSQ_EVT_ACL_CHECK:
				cb_base = &security_options->plugin_callbacks.acl_check;
				break;
			case MOSQ_EVT_BASIC_AUTH:
				cb_base = &security_options->plugin_callbacks.basic_auth;
				break;
			case MOSQ_EVT_PSK_KEY:
				cb_base = &security_options->plugin_callbacks.psk_key;
				break;
			case MOSQ_EVT_EXT_AUTH_START:
				cb_base = &security_options->plugin_callbacks.ext_auth_start;
				break;
			case MOSQ_EVT_EXT_AUTH_CONTINUE:
				cb_base = &security_options->plugin_callbacks.ext_auth_continue;
				break;
			case MOSQ_EVT_CONTROL:
				cb_base = NULL;
				break;
			case MOSQ_EVT_MESSAGE:
				cb_base = &security_options->plugin_callbacks.message;
				break;
			case MOSQ_EVT_TICK:
				cb_base = &security_options->plugin_callbacks.tick;
				break;
			case MOSQ_EVT_DISCONNECT:
				cb_base = &security_options->plugin_callbacks.disconnect;
				break;
			case MOSQ_EVT_CONNECT:
				cb_base = &security_options->plugin_callbacks.connect;
				break;
			default:
				cb_base = NULL;
				break;
		}
		if(cb_base){
			remove_callback(identifier, own->event, cb_base, own->cb_func);
		}
	}
	return MOSQ_ERR_SUCCESS;
}


int mosquitto_callback_unregister(
		mosquitto_plugin_id_t *identifier,
		int event,
		MOSQ_FUNC_generic_callback cb_func,
		const void *event_data)
{
	struct mosquitto__callback **cb_base = NULL;
	struct mosquitto__security_options *security_options;

	if(identifier == NULL || cb_func == NULL){
		return MOSQ_ERR_INVAL;
	}

	if(identifier->listener == NULL){
		security_options = &db.config->security_options;
	}else{
		security_options = &identifier->listener->security_options;
	}
	switch(event){
		case MOSQ_EVT_RELOAD:
			cb_base = &security_options->plugin_callbacks.reload;
			break;
		case MOSQ_EVT_ACL_CHECK:
			cb_base = &security_options->plugin_callbacks.acl_check;
			break;
		case MOSQ_EVT_BASIC_AUTH:
			cb_base = &security_options->plugin_callbacks.basic_auth;
			break;
		case MOSQ_EVT_PSK_KEY:
			cb_base = &security_options->plugin_callbacks.psk_key;
			break;
		case MOSQ_EVT_EXT_AUTH_START:
			cb_base = &security_options->plugin_callbacks.ext_auth_start;
			break;
		case MOSQ_EVT_EXT_AUTH_CONTINUE:
			cb_base = &security_options->plugin_callbacks.ext_auth_continue;
			break;
		case MOSQ_EVT_CONTROL:
			return control__unregister_callback(identifier, cb_func, event_data);
			break;
		case MOSQ_EVT_MESSAGE:
			cb_base = &security_options->plugin_callbacks.message;
			break;
		case MOSQ_EVT_TICK:
			cb_base = &security_options->plugin_callbacks.tick;
			break;
		case MOSQ_EVT_DISCONNECT:
			cb_base = &security_options->plugin_callbacks.disconnect;
			break;
		case MOSQ_EVT_CONNECT:
			cb_base = &security_options->plugin_callbacks.connect;
			break;
		default:
			return MOSQ_ERR_NOT_SUPPORTED;
			break;
	}

	return remove_callback(identifier, event, cb_base, cb_func);
}
