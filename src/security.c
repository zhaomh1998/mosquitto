/*
Copyright (c) 2011-2020 Roger Light <roger@atchoo.org>

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

#include <stdio.h>
#include <string.h>

#include "mosquitto_broker.h"
#include "mosquitto_broker_internal.h"
#include "mosquitto_plugin.h"
#include "memory_mosq.h"
#include "lib_load.h"
#include "utlist.h"

typedef int (*FUNC_auth_plugin_version)(void);
typedef int (*FUNC_plugin_version)(int, const int *);

static int security__cleanup_single(struct mosquitto__security_options *opts, bool reload);

void LIB_ERROR(void)
{
#ifdef WIN32
	char *buf;
	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
			NULL, GetLastError(), LANG_NEUTRAL, (LPTSTR)&buf, 0, NULL);
	log__printf(NULL, MOSQ_LOG_ERR, "Load error: %s", buf);
	LocalFree(buf);
#else
	log__printf(NULL, MOSQ_LOG_ERR, "Load error: %s", dlerror());
#endif
}


static int security__load_v2(struct mosquitto__plugin *plugin, struct mosquitto_auth_opt *auth_options, int auth_option_count, void *lib)
{
	int rc;

	if(!(plugin->plugin_init_v2 = (FUNC_auth_plugin_init_v2)LIB_SYM(lib, "mosquitto_auth_plugin_init"))){
		log__printf(NULL, MOSQ_LOG_ERR,
				"Error: Unable to load auth plugin function mosquitto_auth_plugin_init().");
		LIB_ERROR();
		LIB_CLOSE(lib);
		return MOSQ_ERR_UNKNOWN;
	}
	if(!(plugin->plugin_cleanup_v2 = (FUNC_auth_plugin_cleanup_v2)LIB_SYM(lib, "mosquitto_auth_plugin_cleanup"))){
		log__printf(NULL, MOSQ_LOG_ERR,
				"Error: Unable to load auth plugin function mosquitto_auth_plugin_cleanup().");
		LIB_ERROR();
		LIB_CLOSE(lib);
		return MOSQ_ERR_UNKNOWN;
	}

	if(!(plugin->security_init_v2 = (FUNC_auth_plugin_security_init_v2)LIB_SYM(lib, "mosquitto_auth_security_init"))){
		log__printf(NULL, MOSQ_LOG_ERR,
				"Error: Unable to load auth plugin function mosquitto_auth_security_init().");
		LIB_ERROR();
		LIB_CLOSE(lib);
		return MOSQ_ERR_UNKNOWN;
	}

	if(!(plugin->security_cleanup_v2 = (FUNC_auth_plugin_security_cleanup_v2)LIB_SYM(lib, "mosquitto_auth_security_cleanup"))){
		log__printf(NULL, MOSQ_LOG_ERR,
				"Error: Unable to load auth plugin function mosquitto_auth_security_cleanup().");
		LIB_ERROR();
		LIB_CLOSE(lib);
		return MOSQ_ERR_UNKNOWN;
	}

	if(!(plugin->acl_check_v2 = (FUNC_auth_plugin_acl_check_v2)LIB_SYM(lib, "mosquitto_auth_acl_check"))){
		log__printf(NULL, MOSQ_LOG_ERR,
				"Error: Unable to load auth plugin function mosquitto_auth_acl_check().");
		LIB_ERROR();
		LIB_CLOSE(lib);
		return MOSQ_ERR_UNKNOWN;
	}

	if(!(plugin->unpwd_check_v2 = (FUNC_auth_plugin_unpwd_check_v2)LIB_SYM(lib, "mosquitto_auth_unpwd_check"))){
		log__printf(NULL, MOSQ_LOG_ERR,
				"Error: Unable to load auth plugin function mosquitto_auth_unpwd_check().");
		LIB_ERROR();
		LIB_CLOSE(lib);
		return MOSQ_ERR_UNKNOWN;
	}

	if(!(plugin->psk_key_get_v2 = (FUNC_auth_plugin_psk_key_get_v2)LIB_SYM(lib, "mosquitto_auth_psk_key_get"))){
		log__printf(NULL, MOSQ_LOG_ERR,
				"Error: Unable to load auth plugin function mosquitto_auth_psk_key_get().");
		LIB_ERROR();
		LIB_CLOSE(lib);
		return MOSQ_ERR_UNKNOWN;
	}

	plugin->lib = lib;
	plugin->user_data = NULL;

	if(plugin->plugin_init_v2){
		rc = plugin->plugin_init_v2(&plugin->user_data, auth_options, auth_option_count);
		if(rc){
			log__printf(NULL, MOSQ_LOG_ERR,
					"Error: Authentication plugin returned %d when initialising.", rc);
			return rc;
		}
	}
	return 0;
}


static int security__load_v3(struct mosquitto__plugin *plugin, struct mosquitto_opt *auth_options, int auth_option_count, void *lib)
{
	int rc;

	if(!(plugin->plugin_init_v3 = (FUNC_auth_plugin_init_v3)LIB_SYM(lib, "mosquitto_auth_plugin_init"))){
		log__printf(NULL, MOSQ_LOG_ERR,
				"Error: Unable to load auth plugin function mosquitto_auth_plugin_init().");
		LIB_ERROR();
		LIB_CLOSE(lib);
		return MOSQ_ERR_UNKNOWN;
	}
	if(!(plugin->plugin_cleanup_v3 = (FUNC_auth_plugin_cleanup_v3)LIB_SYM(lib, "mosquitto_auth_plugin_cleanup"))){
		log__printf(NULL, MOSQ_LOG_ERR,
				"Error: Unable to load auth plugin function mosquitto_auth_plugin_cleanup().");
		LIB_ERROR();
		LIB_CLOSE(lib);
		return MOSQ_ERR_UNKNOWN;
	}

	if(!(plugin->security_init_v3 = (FUNC_auth_plugin_security_init_v3)LIB_SYM(lib, "mosquitto_auth_security_init"))){
		log__printf(NULL, MOSQ_LOG_ERR,
				"Error: Unable to load auth plugin function mosquitto_auth_security_init().");
		LIB_ERROR();
		LIB_CLOSE(lib);
		return MOSQ_ERR_UNKNOWN;
	}

	if(!(plugin->security_cleanup_v3 = (FUNC_auth_plugin_security_cleanup_v3)LIB_SYM(lib, "mosquitto_auth_security_cleanup"))){
		log__printf(NULL, MOSQ_LOG_ERR,
				"Error: Unable to load auth plugin function mosquitto_auth_security_cleanup().");
		LIB_ERROR();
		LIB_CLOSE(lib);
		return MOSQ_ERR_UNKNOWN;
	}

	if(!(plugin->acl_check_v3 = (FUNC_auth_plugin_acl_check_v3)LIB_SYM(lib, "mosquitto_auth_acl_check"))){
		log__printf(NULL, MOSQ_LOG_ERR,
				"Error: Unable to load auth plugin function mosquitto_auth_acl_check().");
		LIB_ERROR();
		LIB_CLOSE(lib);
		return MOSQ_ERR_UNKNOWN;
	}

	if(!(plugin->unpwd_check_v3 = (FUNC_auth_plugin_unpwd_check_v3)LIB_SYM(lib, "mosquitto_auth_unpwd_check"))){
		log__printf(NULL, MOSQ_LOG_ERR,
				"Error: Unable to load auth plugin function mosquitto_auth_unpwd_check().");
		LIB_ERROR();
		LIB_CLOSE(lib);
		return MOSQ_ERR_UNKNOWN;
	}

	if(!(plugin->psk_key_get_v3 = (FUNC_auth_plugin_psk_key_get_v3)LIB_SYM(lib, "mosquitto_auth_psk_key_get"))){
		log__printf(NULL, MOSQ_LOG_ERR,
				"Error: Unable to load auth plugin function mosquitto_auth_psk_key_get().");
		LIB_ERROR();
		LIB_CLOSE(lib);
		return MOSQ_ERR_UNKNOWN;
	}

	plugin->lib = lib;
	plugin->user_data = NULL;
	if(plugin->plugin_init_v3){
		rc = plugin->plugin_init_v3(&plugin->user_data, auth_options, auth_option_count);
		if(rc){
			log__printf(NULL, MOSQ_LOG_ERR,
					"Error: Authentication plugin returned %d when initialising.", rc);
			return rc;
		}
	}
	return 0;
}


static int security__load_v4(struct mosquitto__plugin *plugin, struct mosquitto_opt *auth_options, int auth_option_count, void *lib)
{
	int rc;

	if(!(plugin->plugin_init_v4 = (FUNC_auth_plugin_init_v4)LIB_SYM(lib, "mosquitto_auth_plugin_init"))){
		log__printf(NULL, MOSQ_LOG_ERR,
				"Error: Unable to load auth plugin function mosquitto_auth_plugin_init().");
		LIB_ERROR();
		LIB_CLOSE(lib);
		return MOSQ_ERR_UNKNOWN;
	}
	if(!(plugin->plugin_cleanup_v4 = (FUNC_auth_plugin_cleanup_v4)LIB_SYM(lib, "mosquitto_auth_plugin_cleanup"))){
		log__printf(NULL, MOSQ_LOG_ERR,
				"Error: Unable to load auth plugin function mosquitto_auth_plugin_cleanup().");
		LIB_ERROR();
		LIB_CLOSE(lib);
		return MOSQ_ERR_UNKNOWN;
	}

	if(!(plugin->security_init_v4 = (FUNC_auth_plugin_security_init_v4)LIB_SYM(lib, "mosquitto_auth_security_init"))){
		log__printf(NULL, MOSQ_LOG_ERR,
				"Error: Unable to load auth plugin function mosquitto_auth_security_init().");
		LIB_ERROR();
		LIB_CLOSE(lib);
		return MOSQ_ERR_UNKNOWN;
	}

	if(!(plugin->security_cleanup_v4 = (FUNC_auth_plugin_security_cleanup_v4)LIB_SYM(lib, "mosquitto_auth_security_cleanup"))){
		log__printf(NULL, MOSQ_LOG_ERR,
				"Error: Unable to load auth plugin function mosquitto_auth_security_cleanup().");
		LIB_ERROR();
		LIB_CLOSE(lib);
		return MOSQ_ERR_UNKNOWN;
	}

	if(!(plugin->acl_check_v4 = (FUNC_auth_plugin_acl_check_v4)LIB_SYM(lib, "mosquitto_auth_acl_check"))){
		log__printf(NULL, MOSQ_LOG_ERR,
				"Error: Unable to load auth plugin function mosquitto_auth_acl_check().");
		LIB_ERROR();
		LIB_CLOSE(lib);
		return MOSQ_ERR_UNKNOWN;
	}

	plugin->unpwd_check_v4 = (FUNC_auth_plugin_unpwd_check_v4)LIB_SYM(lib, "mosquitto_auth_unpwd_check");
	if(plugin->unpwd_check_v4){
		log__printf(NULL, MOSQ_LOG_INFO,
				" ├── Username/password checking enabled.");
	}else{
		log__printf(NULL, MOSQ_LOG_INFO,
				" ├── Username/password checking not enabled.");
	}

	plugin->psk_key_get_v4 = (FUNC_auth_plugin_psk_key_get_v4)LIB_SYM(lib, "mosquitto_auth_psk_key_get");
	if(plugin->psk_key_get_v4){
		log__printf(NULL, MOSQ_LOG_INFO,
				" ├── TLS-PSK checking enabled.");
	}else{
		log__printf(NULL, MOSQ_LOG_INFO,
				" ├── TLS-PSK checking not enabled.");
	}

	plugin->auth_start_v4 = (FUNC_auth_plugin_auth_start_v4)LIB_SYM(lib, "mosquitto_auth_start");
	plugin->auth_continue_v4 = (FUNC_auth_plugin_auth_continue_v4)LIB_SYM(lib, "mosquitto_auth_continue");

	if(plugin->auth_start_v4){
		if(plugin->auth_continue_v4){
			log__printf(NULL, MOSQ_LOG_INFO,
					" └── Extended authentication enabled.");
		}else{
			log__printf(NULL, MOSQ_LOG_ERR,
					"Error: Plugin has missing mosquitto_auth_continue() function.");
			LIB_CLOSE(lib);
			return MOSQ_ERR_UNKNOWN;
		}
	}else{
		log__printf(NULL, MOSQ_LOG_INFO,
				" └── Extended authentication not enabled.");
	}

	plugin->lib = lib;
	plugin->user_data = NULL;
	if(plugin->plugin_init_v4){
		rc = plugin->plugin_init_v4(&plugin->user_data, auth_options, auth_option_count);
		if(rc){
			log__printf(NULL, MOSQ_LOG_ERR,
					"Error: Authentication plugin returned %d when initialising.", rc);
			return rc;
		}
	}
	return 0;
}


static int security__module_init_single(struct mosquitto__listener *listener, struct mosquitto__security_options *opts)
{
	void *lib;
	int (*plugin_version)(int, const int*) = NULL;
	int (*plugin_auth_version)(void) = NULL;
	int version;
	int i;
	int rc;
	const int plugin_versions[] = {5, 4, 3, 2};
	int plugin_version_count = sizeof(plugin_versions)/sizeof(int);

	if(opts->plugin_config_count == 0){
		return MOSQ_ERR_SUCCESS;
	}

	for(i=0; i<opts->plugin_config_count; i++){
		if(opts->plugin_configs[i].path){
			memset(&opts->plugin_configs[i].plugin, 0, sizeof(struct mosquitto__plugin));

			log__printf(NULL, MOSQ_LOG_INFO, "Loading plugin: %s", opts->plugin_configs[i].path);

			lib = LIB_LOAD(opts->plugin_configs[i].path);
			if(!lib){
				log__printf(NULL, MOSQ_LOG_ERR,
						"Error: Unable to load plugin \"%s\".", opts->plugin_configs[i].path);
				LIB_ERROR();
				return MOSQ_ERR_UNKNOWN;
			}

			opts->plugin_configs[i].plugin.lib = NULL;
			if((plugin_version = (FUNC_plugin_version)LIB_SYM(lib, "mosquitto_plugin_version"))){
				version = plugin_version(plugin_version_count, plugin_versions);
			}else if((plugin_auth_version = (FUNC_auth_plugin_version)LIB_SYM(lib, "mosquitto_auth_plugin_version"))){
				version = plugin_auth_version();
			}else{
				log__printf(NULL, MOSQ_LOG_ERR,
						"Error: Unable to load auth plugin function mosquitto_auth_plugin_version() or mosquitto_plugin_version().");
				LIB_ERROR();
				LIB_CLOSE(lib);
				return MOSQ_ERR_UNKNOWN;
			}
			opts->plugin_configs[i].plugin.version = version;
			if(version == 5){
				rc = plugin__load_v5(
						listener,
						&opts->plugin_configs[i].plugin,
						opts->plugin_configs[i].options,
						opts->plugin_configs[i].option_count,
						lib);

				if(rc){
					return rc;
				}
			}else if(version == 4){
				rc = security__load_v4(
						&opts->plugin_configs[i].plugin,
						opts->plugin_configs[i].options,
						opts->plugin_configs[i].option_count,
						lib);

				if(rc){
					return rc;
				}
			}else if(version == 3){
				rc = security__load_v3(
						&opts->plugin_configs[i].plugin,
						opts->plugin_configs[i].options,
						opts->plugin_configs[i].option_count,
						lib);

				if(rc){
					return rc;
				}
			}else if(version == 2){
				rc = security__load_v2(
						&opts->plugin_configs[i].plugin,
						(struct mosquitto_auth_opt *)opts->plugin_configs[i].options,
						opts->plugin_configs[i].option_count,
						lib);

				if(rc){
					return rc;
				}
			}else{
				log__printf(NULL, MOSQ_LOG_ERR,
						"Error: Unsupported auth plugin version (got %d, expected %d).",
						version, MOSQ_PLUGIN_VERSION);
				LIB_ERROR();

				LIB_CLOSE(lib);
				return MOSQ_ERR_UNKNOWN;
			}
		}
	}
	return MOSQ_ERR_SUCCESS;
}


int mosquitto_security_module_init(void)
{
	int rc = MOSQ_ERR_SUCCESS;
	int i;

	if(db.config->per_listener_settings){
		for(i=0; i<db.config->listener_count; i++){
			rc = security__module_init_single(&db.config->listeners[i], &db.config->listeners[i].security_options);
			if(rc) return rc;
		}
	}else{
		rc = security__module_init_single(NULL, &db.config->security_options);
	}
	return rc;
}


static void security__module_cleanup_single(struct mosquitto__security_options *opts)
{
	int i;
	struct control_endpoint *ep, *tmp;
	struct mosquitto__plugin_config *conf;

	for(i=0; i<opts->plugin_config_count; i++){
		conf = &opts->plugin_configs[i];

		/* Run plugin cleanup function */
		if(conf->plugin.version == 5){
			if(conf->plugin.plugin_cleanup_v5){
				conf->plugin.plugin_cleanup_v5(
						conf->plugin.user_data,
						conf->options,
						conf->option_count);
			}

			plugin__callback_unregister_all(conf->plugin.identifier);
			mosquitto__free(conf->plugin.identifier->plugin_name);
			mosquitto__free(conf->plugin.identifier->plugin_version);
			DL_FOREACH_SAFE(conf->plugin.identifier->control_endpoints, ep, tmp){
				DL_DELETE(conf->plugin.identifier->control_endpoints, ep);
				mosquitto__free(ep);
			}
			mosquitto__free(conf->plugin.identifier);
			conf->plugin.identifier = NULL;

		}else if(conf->plugin.version == 4){
			conf->plugin.plugin_cleanup_v4(
					conf->plugin.user_data,
					conf->options,
					conf->option_count);

		}else if(conf->plugin.version == 3){
			conf->plugin.plugin_cleanup_v3(
					conf->plugin.user_data,
					conf->options,
					conf->option_count);

		}else if(conf->plugin.version == 2){
			conf->plugin.plugin_cleanup_v2(
					conf->plugin.user_data,
					(struct mosquitto_auth_opt *)conf->options,
					conf->option_count);
		}

		if(conf->plugin.lib){
			LIB_CLOSE(conf->plugin.lib);
		}
		memset(&conf->plugin, 0, sizeof(struct mosquitto__plugin));
	}
}


int mosquitto_security_module_cleanup(void)
{
	int i;

	mosquitto_security_cleanup(false);

	security__module_cleanup_single(&db.config->security_options);

	for(i=0; i<db.config->listener_count; i++){
		security__module_cleanup_single(&db.config->listeners[i].security_options);
	}

	return MOSQ_ERR_SUCCESS;
}


static int security__init_single(struct mosquitto__security_options *opts, bool reload)
{
	int i;
	int rc;
	struct mosquitto_evt_reload event_data;
	struct mosquitto__callback *cb_base;

	if(reload){
		DL_FOREACH(opts->plugin_callbacks.reload, cb_base){
			memset(&event_data, 0, sizeof(event_data));

			event_data.options = NULL;
			event_data.option_count = 0;
			cb_base->cb(MOSQ_EVT_RELOAD, &event_data, cb_base->userdata);
		}
	}

	for(i=0; i<opts->plugin_config_count; i++){
		if(opts->plugin_configs[i].plugin.version == 5){
			continue;
		}else if(opts->plugin_configs[i].plugin.version == 4){
			rc = opts->plugin_configs[i].plugin.security_init_v4(
					opts->plugin_configs[i].plugin.user_data,
					opts->plugin_configs[i].options,
					opts->plugin_configs[i].option_count,
					reload);

		}else if(opts->plugin_configs[i].plugin.version == 3){
			rc = opts->plugin_configs[i].plugin.security_init_v3(
					opts->plugin_configs[i].plugin.user_data,
					opts->plugin_configs[i].options,
					opts->plugin_configs[i].option_count,
					reload);

		}else if(opts->plugin_configs[i].plugin.version == 2){
			rc = opts->plugin_configs[i].plugin.security_init_v2(
					opts->plugin_configs[i].plugin.user_data,
					(struct mosquitto_auth_opt *)opts->plugin_configs[i].options,
					opts->plugin_configs[i].option_count,
					reload);
		}else{
			rc = MOSQ_ERR_INVAL;
		}
		if(rc != MOSQ_ERR_SUCCESS){
			return rc;
		}
	}
	return MOSQ_ERR_SUCCESS;
}


int mosquitto_security_init(bool reload)
{
	int i;
	int rc;

	/* Global plugins loaded first */
	rc = security__init_single(&db.config->security_options, reload);
	if(rc != MOSQ_ERR_SUCCESS) return rc;

	if(db.config->per_listener_settings){
		for(i=0; i<db.config->listener_count; i++){
			rc = security__init_single(&db.config->listeners[i].security_options, reload);
			if(rc != MOSQ_ERR_SUCCESS) return rc;
		}
	}
	return mosquitto_security_init_default(reload);
}

/* Apply security settings after a reload.
 * Includes:
 * - Disconnecting anonymous users if appropriate
 * - Disconnecting users with invalid passwords
 * - Reapplying ACLs
 */
int mosquitto_security_apply(void)
{
	return mosquitto_security_apply_default();
}


static int security__cleanup_single(struct mosquitto__security_options *opts, bool reload)
{
	int i;
	int rc;

	for(i=0; i<opts->plugin_config_count; i++){
		if(opts->plugin_configs[i].plugin.version == 5){
			rc = MOSQ_ERR_SUCCESS;
		}else if(opts->plugin_configs[i].plugin.version == 4){
			rc = opts->plugin_configs[i].plugin.security_cleanup_v4(
					opts->plugin_configs[i].plugin.user_data,
					opts->plugin_configs[i].options,
					opts->plugin_configs[i].option_count,
					reload);

		}else if(opts->plugin_configs[i].plugin.version == 3){
			rc = opts->plugin_configs[i].plugin.security_cleanup_v3(
					opts->plugin_configs[i].plugin.user_data,
					opts->plugin_configs[i].options,
					opts->plugin_configs[i].option_count,
					reload);

		}else if(opts->plugin_configs[i].plugin.version == 2){
			rc = opts->plugin_configs[i].plugin.security_cleanup_v2(
					opts->plugin_configs[i].plugin.user_data,
					(struct mosquitto_auth_opt *)opts->plugin_configs[i].options,
					opts->plugin_configs[i].option_count,
					reload);
		}else{
			rc = MOSQ_ERR_INVAL;
		}
		if(rc != MOSQ_ERR_SUCCESS){
			return rc;
		}
	}

	return MOSQ_ERR_SUCCESS;
}


int mosquitto_security_cleanup(bool reload)
{
	int i;
	int rc;

	rc = security__cleanup_single(&db.config->security_options, reload);
	if(rc != MOSQ_ERR_SUCCESS) return rc;

	for(i=0; i<db.config->listener_count; i++){
		rc = security__cleanup_single(&db.config->listeners[i].security_options, reload);
		if(rc != MOSQ_ERR_SUCCESS) return rc;
	}
	return mosquitto_security_cleanup_default(reload);
}


/* int mosquitto_acl_check(struct mosquitto *context, const char *topic, int access) */
static int acl__check_single(struct mosquitto__plugin_config *plugin, struct mosquitto *context, struct mosquitto_acl_msg *msg, int access)
{
	const char *username;
	const char *topic = msg->topic;

	username = mosquitto_client_username(context);
	if(plugin->deny_special_chars == true){
		/* Check whether the client id or username contains a +, # or / and if
		* so deny access.
		*
		* Do this check for every message regardless, we have to protect the
		* plugins against possible pattern based attacks.
		*/
		if(username && strpbrk(username, "+#")){
			log__printf(NULL, MOSQ_LOG_NOTICE, "ACL denying access to client with dangerous username \"%s\"", username);
			return MOSQ_ERR_ACL_DENIED;
		}
		if(context->id && strpbrk(context->id, "+#")){
			log__printf(NULL, MOSQ_LOG_NOTICE, "ACL denying access to client with dangerous client id \"%s\"", context->id);
			return MOSQ_ERR_ACL_DENIED;
		}
	}

	if(plugin->plugin.version == 4){
		if(access == MOSQ_ACL_UNSUBSCRIBE){
			return MOSQ_ERR_SUCCESS;
		}
		return plugin->plugin.acl_check_v4(plugin->plugin.user_data, access, context, msg);
	}else if(plugin->plugin.version == 3){
		if(access == MOSQ_ACL_UNSUBSCRIBE){
			return MOSQ_ERR_SUCCESS;
		}
		return plugin->plugin.acl_check_v3(plugin->plugin.user_data, access, context, msg);
	}else if(plugin->plugin.version == 2){
		if(access == MOSQ_ACL_SUBSCRIBE || access == MOSQ_ACL_UNSUBSCRIBE){
			return MOSQ_ERR_SUCCESS;
		}
		return plugin->plugin.acl_check_v2(plugin->plugin.user_data, context->id, username, topic, access);
	}else{
		return MOSQ_ERR_INVAL;
	}
}


static int acl__check_dollar(const char *topic, int access)
{
	int rc;
	bool match = false;

	if(topic[0] != '$') return MOSQ_ERR_SUCCESS;

	if(!strncmp(topic, "$SYS", 4)){
		if(access == MOSQ_ACL_WRITE){
			/* Potentially allow write access for bridge status, otherwise explicitly deny. */
			rc = mosquitto_topic_matches_sub("$SYS/broker/connection/+/state", topic, &match);
			if(rc == MOSQ_ERR_SUCCESS && match == true){
				return MOSQ_ERR_SUCCESS;
			}else{
				return MOSQ_ERR_ACL_DENIED;
			}
		}else{
			return MOSQ_ERR_SUCCESS;
		}
	}else if(!strncmp(topic, "$share", 6)){
		/* Only allow sub/unsub to shared subscriptions */
		if(access == MOSQ_ACL_SUBSCRIBE || access == MOSQ_ACL_UNSUBSCRIBE){
			return MOSQ_ERR_SUCCESS;
		}else{
			return MOSQ_ERR_ACL_DENIED;
		}
	}else{
		/* This is an unknown $ topic, for the moment just defer to actual tests. */
		return MOSQ_ERR_SUCCESS;
	}
}


static int plugin__acl_check(struct mosquitto__security_options *opts, struct mosquitto *context, const char *topic, uint32_t payloadlen, void* payload, uint8_t qos, bool retain, int access)
{
	int rc = MOSQ_ERR_PLUGIN_DEFER;
	struct mosquitto_acl_msg msg;
	struct mosquitto__callback *cb_base;
	struct mosquitto_evt_acl_check event_data;

	memset(&msg, 0, sizeof(msg));
	msg.topic = topic;
	msg.payloadlen = payloadlen;
	msg.payload = payload;
	msg.qos = qos;
	msg.retain = retain;

	DL_FOREACH(opts->plugin_callbacks.acl_check, cb_base){
		rc = MOSQ_ERR_PLUGIN_DEFER;
		/* FIXME - username deny special chars */

		memset(&event_data, 0, sizeof(event_data));
		event_data.client = context;
		event_data.access = access;
		event_data.topic = topic;
		event_data.payloadlen = payloadlen;
		event_data.payload = payload;
		event_data.qos = qos;
		event_data.retain = retain;
		event_data.properties = NULL;
		rc = cb_base->cb(MOSQ_EVT_ACL_CHECK, &event_data, cb_base->userdata);
		if(rc != MOSQ_ERR_PLUGIN_DEFER && rc != MOSQ_ERR_PLUGIN_IGNORE){
			return rc;
		}
	}

	return rc;
}

int mosquitto_acl_check(struct mosquitto *context, const char *topic, uint32_t payloadlen, void* payload, uint8_t qos, bool retain, int access)
{
	int rc;
	int rc_final;
	int i;
	struct mosquitto__security_options *opts;
	struct mosquitto_acl_msg msg;

	if(!context->id){
		return MOSQ_ERR_ACL_DENIED;
	}
	if(context->bridge){
		return MOSQ_ERR_SUCCESS;
	}

	rc = acl__check_dollar(topic, access);
	if(rc) return rc;

	/*
	 * If no plugins exist we should accept at this point so set rc to success.
	 */
	rc_final = MOSQ_ERR_SUCCESS;

	/* If per_listener_settings is true, these are the global plugins.
	 * If per listener_settings is false, these are global and listener plugins. */
	if(db.config->security_options.plugin_callbacks.acl_check){
		rc = plugin__acl_check(&db.config->security_options, context, topic, payloadlen,
				payload, qos, retain, access);

		if(rc == MOSQ_ERR_PLUGIN_IGNORE){
			/* Do nothing, this is as if the plugin doesn't exist */
		}else if(rc == MOSQ_ERR_PLUGIN_DEFER){
			rc_final = MOSQ_ERR_PLUGIN_DEFER;
		}else{
			return rc;
		}
	}

	if(db.config->per_listener_settings){
		if(context->listener){
			if(context->listener->security_options.plugin_callbacks.acl_check){
				rc = plugin__acl_check(&context->listener->security_options, context, topic, payloadlen,
						payload, qos, retain, access);

				if(rc == MOSQ_ERR_PLUGIN_IGNORE){
					/* Do nothing, this is as if the plugin doesn't exist */
				}else if(rc == MOSQ_ERR_PLUGIN_DEFER){
					rc_final = MOSQ_ERR_PLUGIN_DEFER;
				}else{
					return rc;
				}
			}
		}else{
			return MOSQ_ERR_ACL_DENIED;
		}
		opts = &context->listener->security_options;
	}else{
		opts = &db.config->security_options;
	}

	/* Old plugin version checks */
	memset(&msg, 0, sizeof(msg));
	msg.topic = topic;
	msg.payloadlen = payloadlen;
	msg.payload = payload;
	msg.qos = qos;
	msg.retain = retain;

	for(i=0; i<opts->plugin_config_count; i++){
		if(opts->plugin_configs[i].plugin.version < 5){
			rc = acl__check_single(&opts->plugin_configs[i], context, &msg, access);
			if(rc == MOSQ_ERR_PLUGIN_IGNORE){
				/* Do nothing, this is as if the plugin doesn't exist */
			}else if(rc == MOSQ_ERR_PLUGIN_DEFER){
				rc_final = MOSQ_ERR_PLUGIN_DEFER;
			}else{
				return rc;
			}
		}
	}

	/* If all plugins deferred, this is a denial. If rc == MOSQ_ERR_SUCCESS
	 * here, then no plugins were configured, or all plugins ignored. */
	if(rc_final == MOSQ_ERR_PLUGIN_DEFER){
		rc_final = MOSQ_ERR_ACL_DENIED;
	}
	return rc_final;
}


static int plugin__unpwd_check(struct mosquitto__security_options *opts, struct mosquitto *context)
{
	struct mosquitto_evt_basic_auth event_data;
	struct mosquitto__callback *cb_base;
	int rc;
	int rc_final = MOSQ_ERR_PLUGIN_IGNORE;

	DL_FOREACH(opts->plugin_callbacks.basic_auth, cb_base){
		memset(&event_data, 0, sizeof(event_data));
		event_data.client = context;
		event_data.username = context->username;
		event_data.password = context->password;
		rc = cb_base->cb(MOSQ_EVT_BASIC_AUTH, &event_data, cb_base->userdata);
		if(rc == MOSQ_ERR_PLUGIN_IGNORE){
			/* Do nothing, this is as if the plugin doesn't exist */
		}else if(rc == MOSQ_ERR_PLUGIN_DEFER){
			rc_final = MOSQ_ERR_PLUGIN_DEFER;
		}else{
			return rc;
		}
	}
	return rc_final;
}


int mosquitto_unpwd_check(struct mosquitto *context)
{
	int rc;
	int i;
	struct mosquitto__security_options *opts;
	bool plugin_used = false;

	if(db.config->per_listener_settings){
		if(context->listener == NULL){
			return MOSQ_ERR_AUTH;
		}
		opts = &context->listener->security_options;
	}else{
		opts = &db.config->security_options;
	}

	/* Global plugins */
	if(db.config->security_options.plugin_callbacks.basic_auth){
		rc = plugin__unpwd_check(&db.config->security_options, context);

		if(rc == MOSQ_ERR_PLUGIN_IGNORE){
			/* Do nothing */
		}else if(rc == MOSQ_ERR_PLUGIN_DEFER){
			plugin_used = true;
		}else{
			return rc;
		}
	}

	/* Per listener plugins */
	if(db.config->per_listener_settings){
		if(context->listener == NULL){
			return MOSQ_ERR_AUTH;
		}
		if(context->listener->security_options.plugin_callbacks.basic_auth){
			rc = plugin__unpwd_check(&context->listener->security_options, context);

			if(rc == MOSQ_ERR_PLUGIN_IGNORE){
				/* Do nothing */
			}else if(rc == MOSQ_ERR_PLUGIN_DEFER){
				plugin_used = true;
			}else{
				return rc;
			}
		}
	}


	/* Old plugin checks */
	for(i=0; i<opts->plugin_config_count; i++){
		if(opts->plugin_configs[i].plugin.version == 5){
			continue;
		}else if(opts->plugin_configs[i].plugin.version == 4){
			if(opts->plugin_configs[i].plugin.unpwd_check_v4){
				rc = opts->plugin_configs[i].plugin.unpwd_check_v4(
						opts->plugin_configs[i].plugin.user_data,
						context,
						context->username,
						context->password);
			}else{
				rc = MOSQ_ERR_PLUGIN_IGNORE;
			}
		}else if(opts->plugin_configs[i].plugin.version == 3){
			rc = opts->plugin_configs[i].plugin.unpwd_check_v3(
					opts->plugin_configs[i].plugin.user_data,
					context,
					context->username,
					context->password);

		}else if(opts->plugin_configs[i].plugin.version == 2){
			rc = opts->plugin_configs[i].plugin.unpwd_check_v2(
					opts->plugin_configs[i].plugin.user_data,
					context->username,
					context->password);

		}else{
			rc = MOSQ_ERR_INVAL;
		}
		if(rc == MOSQ_ERR_PLUGIN_IGNORE){
			/* Do nothing */
		}else if(rc == MOSQ_ERR_PLUGIN_DEFER){
			plugin_used = true;
		}else{
			return rc;
		}

	}
	/* If all plugins deferred, this is a denial. plugin_used == false
	 * here, then no plugins were configured.
	 * anonymous logins are allowed. */
	if(plugin_used == false){
		if((db.config->per_listener_settings && context->listener->security_options.allow_anonymous != false)
				|| (!db.config->per_listener_settings && db.config->security_options.allow_anonymous != false)){

			return MOSQ_ERR_SUCCESS;
		}else{
			return MOSQ_ERR_AUTH;
		}
	}else{
		/* Can't have got here without at least one plugin returning MOSQ_ERR_PLUGIN_DEFER.
		 * This will now be a denial, unless it is anon and allow anon is true. */
		if(context->username == NULL &&
				((db.config->per_listener_settings && context->listener->security_options.allow_anonymous != false)
				|| (!db.config->per_listener_settings && db.config->security_options.allow_anonymous != false))){

			return MOSQ_ERR_SUCCESS;
		}else{
			return MOSQ_ERR_AUTH;
		}
	}

	return rc;
}


static int plugin__psk_key_get(struct mosquitto__security_options *opts, struct mosquitto *context, const char *hint, const char *identity, char *key, int max_key_len)
{
	struct mosquitto_evt_psk_key event_data;
	struct mosquitto__callback *cb_base;
	int rc;
	int rc_final = MOSQ_ERR_SUCCESS;

	DL_FOREACH(opts->plugin_callbacks.psk_key, cb_base){
		memset(&event_data, 0, sizeof(event_data));
		event_data.client = context;
		event_data.hint = hint;
		event_data.identity = identity;
		event_data.key = key;
		event_data.max_key_len = max_key_len;
		rc = cb_base->cb(MOSQ_EVT_PSK_KEY, &event_data, cb_base->userdata);
		if(rc == MOSQ_ERR_PLUGIN_IGNORE){
			/* Do nothing */
		}else if(rc == MOSQ_ERR_PLUGIN_DEFER){
			rc_final = MOSQ_ERR_PLUGIN_DEFER;
		}else{
			return rc;
		}
	}
	return rc_final;
}


int mosquitto_psk_key_get(struct mosquitto *context, const char *hint, const char *identity, char *key, int max_key_len)
{
	int rc;
	int rc_final = MOSQ_ERR_SUCCESS;
	int i;
	struct mosquitto__security_options *opts;

	if(db.config->per_listener_settings){
		if(context->listener == NULL){
			return MOSQ_ERR_AUTH;
		}
		opts = &context->listener->security_options;
	}else{
		opts = &db.config->security_options;
	}

	/* Global plugins */
	if(db.config->security_options.plugin_callbacks.psk_key){
		rc = plugin__psk_key_get(&db.config->security_options, context,
				hint, identity, key, max_key_len);

		if(rc == MOSQ_ERR_PLUGIN_IGNORE){
			/* Do nothing */
		}else if(rc == MOSQ_ERR_PLUGIN_DEFER){
			rc_final = MOSQ_ERR_PLUGIN_DEFER;
		}else{
			return rc;
		}
	}

	/* Per listener plugins */
	if(db.config->per_listener_settings){
		if(context->listener == NULL){
			return MOSQ_ERR_AUTH;
		}
		if(context->listener->security_options.plugin_callbacks.psk_key){
			rc = plugin__psk_key_get(&context->listener->security_options, context,
					hint, identity, key, max_key_len);

			if(rc == MOSQ_ERR_PLUGIN_IGNORE){
				/* Do nothing */
			}else if(rc == MOSQ_ERR_PLUGIN_DEFER){
				rc_final = MOSQ_ERR_PLUGIN_DEFER;
			}else{
				return rc;
			}
		}
	}

	/* Old plugins */
	for(i=0; i<opts->plugin_config_count; i++){
		if(opts->plugin_configs[i].plugin.version == 4
				&& opts->plugin_configs[i].plugin.psk_key_get_v4){

			rc = opts->plugin_configs[i].plugin.psk_key_get_v4(
					opts->plugin_configs[i].plugin.user_data,
					context,
					hint,
					identity,
					key,
					max_key_len);

		}else if(opts->plugin_configs[i].plugin.version == 3){
			rc = opts->plugin_configs[i].plugin.psk_key_get_v3(
					opts->plugin_configs[i].plugin.user_data,
					context,
					hint,
					identity,
					key,
					max_key_len);

		}else if(opts->plugin_configs[i].plugin.version == 2){
			rc = opts->plugin_configs[i].plugin.psk_key_get_v2(
					opts->plugin_configs[i].plugin.user_data,
					hint,
					identity,
					key,
					max_key_len);
		}else{
			rc = MOSQ_ERR_INVAL;
		}
		if(rc == MOSQ_ERR_PLUGIN_IGNORE){
			/* Do nothing */
		}else if(rc == MOSQ_ERR_PLUGIN_DEFER){
			rc_final = MOSQ_ERR_PLUGIN_DEFER;
		}else{
			return rc;
		}
	}

	rc = mosquitto_psk_key_get_default(context, hint, identity, key, max_key_len);
	if(rc != MOSQ_ERR_PLUGIN_DEFER){
		return rc;
	}
	if(rc == MOSQ_ERR_PLUGIN_IGNORE){
		/* Do nothing */
	}else if(rc == MOSQ_ERR_PLUGIN_DEFER){
		rc_final = MOSQ_ERR_PLUGIN_DEFER;
	}else{
		return rc;
	}


	/* If all plugins deferred, this is a denial. If rc == MOSQ_ERR_SUCCESS
	 * here, then no plugins were configured. */
	if(rc_final == MOSQ_ERR_PLUGIN_DEFER){
		rc_final = MOSQ_ERR_AUTH;
	}
	return rc_final;
}


static int plugin__ext_auth_start(struct mosquitto__security_options *opts, struct mosquitto *context, bool reauth, const void *data_in, uint16_t data_in_len, void **data_out, uint16_t *data_out_len)
{
	struct mosquitto_evt_extended_auth event_data;
	struct mosquitto__callback *cb_base;
	int rc;
	int rc_final = MOSQ_ERR_PLUGIN_DEFER;

	UNUSED(reauth);

	DL_FOREACH(opts->plugin_callbacks.ext_auth_start, cb_base){
		memset(&event_data, 0, sizeof(event_data));
		event_data.client = context;
		event_data.auth_method = context->auth_method;
		event_data.data_in = data_in;
		event_data.data_out = NULL;
		event_data.data_in_len = data_in_len;
		event_data.data_out_len = 0;
		rc = cb_base->cb(MOSQ_EVT_EXT_AUTH_START, &event_data, cb_base->userdata);
		if(rc == MOSQ_ERR_PLUGIN_IGNORE){
			/* Do nothing */
		}else if(rc == MOSQ_ERR_PLUGIN_DEFER){
			rc_final = MOSQ_ERR_PLUGIN_DEFER;
		}else{
			*data_out = event_data.data_out;
			*data_out_len = event_data.data_out_len;
			return rc;
		}
	}
	return rc_final;
}


int mosquitto_security_auth_start(struct mosquitto *context, bool reauth, const void *data_in, uint16_t data_in_len, void **data_out, uint16_t *data_out_len)
{
	int rc;
	int i;
	struct mosquitto__security_options *opts;

	if(!context || !context->listener || !context->auth_method) return MOSQ_ERR_INVAL;
	if(!data_out || !data_out_len) return MOSQ_ERR_INVAL;

	if(db.config->per_listener_settings){
		if(context->listener == NULL){
			return MOSQ_ERR_AUTH;
		}
		opts = &context->listener->security_options;
	}else{
		opts = &db.config->security_options;
	}

	/* Global plugins */
	if(db.config->security_options.plugin_callbacks.ext_auth_start){
		rc = plugin__ext_auth_start(&db.config->security_options, context,
				reauth, data_in, data_in_len, data_out, data_out_len);

		if(rc == MOSQ_ERR_PLUGIN_IGNORE || rc == MOSQ_ERR_PLUGIN_DEFER){
			/* Do nothing */
		}else{
			return rc;
		}
	}

	/* Per listener plugins */
	if(db.config->per_listener_settings){
		if(context->listener == NULL){
			return MOSQ_ERR_AUTH;
		}
		if(context->listener->security_options.plugin_callbacks.ext_auth_start){
			rc = plugin__ext_auth_start(&context->listener->security_options, context,
					reauth, data_in, data_in_len, data_out, data_out_len);

			if(rc == MOSQ_ERR_PLUGIN_IGNORE || rc == MOSQ_ERR_PLUGIN_DEFER){
				/* Do nothing */
			}else{
				return rc;
			}
		}
	}

	/* Old plugins */
	for(i=0; i<opts->plugin_config_count; i++){
		if(opts->plugin_configs[i].plugin.auth_start_v4){
			*data_out = NULL;
			*data_out_len = 0;

			rc = opts->plugin_configs[i].plugin.auth_start_v4(
					opts->plugin_configs[i].plugin.user_data,
					context,
					context->auth_method,
					reauth,
					data_in, data_in_len,
					data_out, data_out_len);

			if(rc == MOSQ_ERR_SUCCESS){
				return MOSQ_ERR_SUCCESS;
			}else if(rc == MOSQ_ERR_AUTH_CONTINUE){
				return MOSQ_ERR_AUTH_CONTINUE;
			}else if(rc != MOSQ_ERR_NOT_SUPPORTED){
				return rc;
			}
		}
	}

	return MOSQ_ERR_NOT_SUPPORTED;
}


static int plugin__ext_auth_continue(struct mosquitto__security_options *opts, struct mosquitto *context, const void *data_in, uint16_t data_in_len, void **data_out, uint16_t *data_out_len)
{
	int rc;
	struct mosquitto_evt_extended_auth event_data;
	struct mosquitto__callback *cb_base;

	DL_FOREACH(opts->plugin_callbacks.ext_auth_continue, cb_base){
		memset(&event_data, 0, sizeof(event_data));
		event_data.client = context;
		event_data.data_in = data_in;
		event_data.data_out = NULL;
		event_data.data_in_len = data_in_len;
		event_data.data_out_len = 0;
		rc = cb_base->cb(MOSQ_EVT_EXT_AUTH_CONTINUE, &event_data, cb_base->userdata);
		if(rc == MOSQ_ERR_PLUGIN_IGNORE || rc == MOSQ_ERR_PLUGIN_DEFER){
			/* Do nothing */
		}else{
			*data_out = event_data.data_out;
			*data_out_len = event_data.data_out_len;
			return rc;
		}
	}

	return MOSQ_ERR_PLUGIN_DEFER;
}


int mosquitto_security_auth_continue(struct mosquitto *context, const void *data_in, uint16_t data_in_len, void **data_out, uint16_t *data_out_len)
{
	int rc;
	int i;
	struct mosquitto__security_options *opts;

	if(!context || !context->listener || !context->auth_method) return MOSQ_ERR_INVAL;
	if(!data_out || !data_out_len) return MOSQ_ERR_INVAL;

	if(db.config->per_listener_settings){
		if(context->listener == NULL){
			return MOSQ_ERR_AUTH;
		}
		opts = &context->listener->security_options;
	}else{
		opts = &db.config->security_options;
	}

	/* Global plugins */
	if(db.config->security_options.plugin_callbacks.ext_auth_continue){
		rc = plugin__ext_auth_continue(&db.config->security_options, context,
				data_in, data_in_len, data_out, data_out_len);

		if(rc == MOSQ_ERR_PLUGIN_IGNORE || rc == MOSQ_ERR_PLUGIN_DEFER){
			/* Do nothing */
		}else{
			return rc;
		}
	}

	/* Per listener plugins */
	if(db.config->per_listener_settings){
		if(context->listener == NULL){
			return MOSQ_ERR_AUTH;
		}
		if(context->listener->security_options.plugin_callbacks.ext_auth_continue){
			rc = plugin__ext_auth_continue(&context->listener->security_options, context,
					data_in, data_in_len, data_out, data_out_len);

			if(rc == MOSQ_ERR_PLUGIN_IGNORE || rc == MOSQ_ERR_PLUGIN_DEFER){
				/* Do nothing */
			}else{
				return rc;
			}
		}
	}

	/* Old plugins */
	for(i=0; i<opts->plugin_config_count; i++){
		if(opts->plugin_configs[i].plugin.auth_continue_v4){
			*data_out = NULL;
			*data_out_len = 0;

			rc = opts->plugin_configs[i].plugin.auth_continue_v4(
					opts->plugin_configs[i].plugin.user_data,
					context,
					context->auth_method,
					data_in, data_in_len,
					data_out, data_out_len);

			if(rc == MOSQ_ERR_SUCCESS){
				return MOSQ_ERR_SUCCESS;
			}else if(rc == MOSQ_ERR_AUTH_CONTINUE){
				return MOSQ_ERR_AUTH_CONTINUE;
			}else if(rc != MOSQ_ERR_NOT_SUPPORTED){
				return rc;
			}
		}
	}

	return MOSQ_ERR_NOT_SUPPORTED;
}
