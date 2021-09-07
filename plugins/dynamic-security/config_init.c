/*
Copyright (c) 2021 Roger Light <roger@atchoo.org>

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

#include <cjson/cJSON.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/rand.h>

#include "json_help.h"
#include "mosquitto.h"
#include "mosquitto_broker.h"
#include "mosquitto_plugin.h"
#include "mqtt_protocol.h"
#include "misc_mosq.h"

#include "dynamic_security.h"

const char pw_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-=_+[]{}@#~,./<>?";

static int add_default_access(cJSON *j_tree)
{
	cJSON *j_default_access;

	j_default_access = cJSON_AddObjectToObject(j_tree, "defaultACLAccess");
	if(j_default_access == NULL){
		return MOSQ_ERR_NOMEM;
	}
	/* Set default behaviour:
	 * * Client can not publish to the broker by default.
	 * * Broker *CAN* publish to the client by default.
	 * * Client con not subscribe to topics by default.
	 * * Client *CAN* unsubscribe from topics by default.
	 */
	if(cJSON_AddBoolToObject(j_default_access, "publishClientSend", false) == NULL
			|| cJSON_AddBoolToObject(j_default_access, "publishClientReceive", true) == NULL
			|| cJSON_AddBoolToObject(j_default_access, "subscribe", false) == NULL
			|| cJSON_AddBoolToObject(j_default_access, "unsubscribe", true) == NULL
			){

		return MOSQ_ERR_NOMEM;
	}
	return MOSQ_ERR_SUCCESS;
}


static int generate_password(int iterations, char **password, char **password_hash, char **salt)
{
	struct mosquitto_pw pw;
	int i;
	unsigned char vb;
	unsigned long v;
	size_t len;

	memset(&pw, 0, sizeof(struct mosquitto_pw));
	pw.hashtype = pw_sha512_pbkdf2;

	*password = malloc(21);
	if(*password == NULL){
		return MOSQ_ERR_NOMEM;
	}
	len = sizeof(pw_chars)-1;
	for(i=0; i<20; i++){
		do{
			if(RAND_bytes(&vb, 1) != 1){
				free(*password);
				return MOSQ_ERR_UNKNOWN;
			}
			v = vb;
		}while(v >= (RAND_MAX - (RAND_MAX % len)));
		(*password)[i] = pw_chars[v%len];
	}
	(*password)[20] = '\0';

	if(pw__hash(*password, &pw, true, iterations) != MOSQ_ERR_SUCCESS){
		free(*password);
		*password = NULL;
		return MOSQ_ERR_UNKNOWN;
	}

	if(base64__encode(pw.salt, (unsigned int)pw.salt_len, salt)
			|| base64__encode(pw.password_hash, sizeof(pw.password_hash), password_hash)
			){	
	
		free(*password);
		free(*password_hash);
		free(*salt);
		return MOSQ_ERR_NOMEM;
	}
	return MOSQ_ERR_SUCCESS;
}


static int client_role_add(cJSON *j_roles, const char *rolename)
{
	cJSON *j_role;

	j_role = cJSON_CreateObject();
	if(j_role == NULL){
		return MOSQ_ERR_NOMEM;
	}
	cJSON_AddItemToArray(j_roles, j_role);
	if(cJSON_AddStringToObject(j_role, "rolename", rolename) == NULL){
		return MOSQ_ERR_NOMEM;
	}else{
		return MOSQ_ERR_SUCCESS;
	}
}


static int client_add_admin(FILE *pwfile, cJSON *j_clients)
{
	cJSON *j_client, *j_roles;
	char *password = NULL;
	char *password_hash = NULL;
	char *salt = NULL;

	if(generate_password(10000, &password, &password_hash, &salt)){
		return MOSQ_ERR_UNKNOWN;
	}

	j_client = cJSON_CreateObject();
	if(j_client == NULL){
		return MOSQ_ERR_NOMEM;
	}

	cJSON_AddItemToArray(j_clients, j_client);
	if(cJSON_AddStringToObject(j_client, "username", "admin") == NULL
			|| cJSON_AddStringToObject(j_client, "textname", "Admin user") == NULL
			|| cJSON_AddStringToObject(j_client, "password", password_hash) == NULL
			|| cJSON_AddStringToObject(j_client, "salt", salt) == NULL
			|| cJSON_AddNumberToObject(j_client, "iterations", 10000) == NULL
			|| (j_roles = cJSON_AddArrayToObject(j_client, "roles")) == NULL
			){

		free(password);
		free(password_hash);
		free(salt);
		return MOSQ_ERR_NOMEM;
	}
	free(password_hash);
	free(salt);

	if(client_role_add(j_roles, "broker-admin")
			|| client_role_add(j_roles, "dynsec-admin")
			|| client_role_add(j_roles, "sys-observe")
			|| client_role_add(j_roles, "topic-observe")
			){

		free(password);
		return MOSQ_ERR_NOMEM;
	}

	fprintf(pwfile, "admin %s\n", password);
	free(password);

	return MOSQ_ERR_SUCCESS;
}

static int client_add_user(FILE *pwfile, cJSON *j_clients)
{
	cJSON *j_client, *j_roles;
	char *password = NULL;
	char *password_hash = NULL;
	char *salt = NULL;

	if(generate_password(10000, &password, &password_hash, &salt)){
		return MOSQ_ERR_UNKNOWN;
	}

	j_client = cJSON_CreateObject();
	if(j_client == NULL){
		return MOSQ_ERR_NOMEM;
	}

	cJSON_AddItemToArray(j_clients, j_client);
	if(cJSON_AddStringToObject(j_client, "username", "democlient") == NULL
			|| cJSON_AddStringToObject(j_client, "textname", "Demonstration client with full read/write access to the '#' topic hierarchy.") == NULL
			|| cJSON_AddStringToObject(j_client, "password", password_hash) == NULL
			|| cJSON_AddStringToObject(j_client, "salt", salt) == NULL
			|| cJSON_AddNumberToObject(j_client, "iterations", 10000) == NULL
			|| (j_roles = cJSON_AddArrayToObject(j_client, "roles")) == NULL
			){

		free(password);
		free(password_hash);
		free(salt);
		return MOSQ_ERR_NOMEM;
	}
	free(password_hash);
	free(salt);

	if(client_role_add(j_roles, "client")){

		free(password);
		return MOSQ_ERR_NOMEM;
	}

	fprintf(pwfile, "democlient %s\n", password);
	free(password);

	return MOSQ_ERR_SUCCESS;
}

static int add_clients(const char *filename, cJSON *j_tree)
{
	cJSON *j_clients;
	char *pwfile;
	size_t len;
	FILE *fptr;

	len = strlen(filename) + 5;
	pwfile = malloc(len);
	if(pwfile == NULL){
		return MOSQ_ERR_NOMEM;
	}
	snprintf(pwfile, len, "%s.pw", filename);
	fptr = mosquitto__fopen(pwfile, "wb", true);
	free(pwfile);
	if(fptr == NULL){
		return MOSQ_ERR_UNKNOWN;
	}

	j_clients = cJSON_AddArrayToObject(j_tree, "clients");
	if(j_clients == NULL){
		fclose(fptr);
		return MOSQ_ERR_NOMEM;
	}

	if(client_add_admin(fptr, j_clients)
			|| client_add_user(fptr, j_clients)
			){

		fclose(fptr);
		return MOSQ_ERR_NOMEM;
	}

	fclose(fptr);
	return MOSQ_ERR_SUCCESS;
}


static int add_groups(cJSON *j_tree)
{
	cJSON *j_groups;

	j_groups = cJSON_AddArrayToObject(j_tree, "groups");
	if(j_groups == NULL){
		return MOSQ_ERR_NOMEM;
	}

	return MOSQ_ERR_SUCCESS;
}


static int acl_add(cJSON *j_acls, const char *acltype, const char *topic, int priority, bool allow)
{
	cJSON *j_acl;

	j_acl = cJSON_CreateObject();
	cJSON_AddItemToArray(j_acls, j_acl);
	if(cJSON_AddStringToObject(j_acl, "acltype", acltype) == NULL
			|| cJSON_AddStringToObject(j_acl, "topic", topic) == NULL
			|| cJSON_AddNumberToObject(j_acl, "priority", priority) == NULL
			|| cJSON_AddBoolToObject(j_acl, "allow", allow) == NULL
			){
		return MOSQ_ERR_NOMEM;
	}else{
		return MOSQ_ERR_SUCCESS;
	}
}


static int role_add_client(cJSON *j_roles)
{
	cJSON *j_role, *j_acls;

	j_role = cJSON_CreateObject();
	if(j_role == NULL){
		return MOSQ_ERR_NOMEM;
	}
	cJSON_AddItemToArray(j_roles, j_role);

	if(cJSON_AddStringToObject(j_role, "rolename", "client") == NULL
			|| cJSON_AddStringToObject(j_role, "textdescription",
				"Read/write access to the full application topic hierarchy.") == NULL
			|| (j_acls = cJSON_AddArrayToObject(j_role, "acls")) == NULL
			){

		return MOSQ_ERR_NOMEM;
	}

	if(acl_add(j_acls, "publishClientSend", "#", 0, true)
			|| acl_add(j_acls, "publishClientReceive", "#", 0, true)
			|| acl_add(j_acls, "subscribePattern", "#", 0, true)
			|| acl_add(j_acls, "unsubscribePattern", "#", 0, true)
			){

		return MOSQ_ERR_NOMEM;
	}
	return MOSQ_ERR_SUCCESS;
}

static int role_add_broker_admin(cJSON *j_roles)
{
	cJSON *j_role, *j_acls;

	j_role = cJSON_CreateObject();
	if(j_role == NULL){
		return MOSQ_ERR_NOMEM;
	}
	cJSON_AddItemToArray(j_roles, j_role);

	if(cJSON_AddStringToObject(j_role, "rolename", "broker-admin") == NULL
			|| cJSON_AddStringToObject(j_role, "textdescription",
				"Grants access to administer general broker configuration.") == NULL
			|| (j_acls = cJSON_AddArrayToObject(j_role, "acls")) == NULL
			){

		return MOSQ_ERR_NOMEM;
	}

	if(acl_add(j_acls, "publishClientSend", "$CONTROL/broker/#", 0, true)
			|| acl_add(j_acls, "publishClientReceive", "$CONTROL/broker/#", 0, true)
			|| acl_add(j_acls, "subscribePattern", "$CONTROL/broker/#", 0, true)
			){

		return MOSQ_ERR_NOMEM;
	}
	return MOSQ_ERR_SUCCESS;
}

static int role_add_dynsec_admin(cJSON *j_roles)
{
	cJSON *j_role, *j_acls;

	j_role = cJSON_CreateObject();
	if(j_role == NULL){
		return MOSQ_ERR_NOMEM;
	}
	cJSON_AddItemToArray(j_roles, j_role);

	if(cJSON_AddStringToObject(j_role, "rolename", "dynsec-admin") == NULL
			|| cJSON_AddStringToObject(j_role, "textdescription",
				"Grants access to administer clients/groups/roles.") == NULL
			|| (j_acls = cJSON_AddArrayToObject(j_role, "acls")) == NULL
			){

		return MOSQ_ERR_NOMEM;
	}

	if(acl_add(j_acls, "publishClientSend", "$CONTROL/dynamic-security/#", 0, true)
			|| acl_add(j_acls, "publishClientReceive", "$CONTROL/dynamic-security/#", 0, true)
			|| acl_add(j_acls, "subscribePattern", "$CONTROL/dynamic-security/#", 0, true)
			){

		return MOSQ_ERR_NOMEM;
	}
	return MOSQ_ERR_SUCCESS;
}

static int role_add_sys_notify(cJSON *j_roles)
{
	cJSON *j_role, *j_acls;

	j_role = cJSON_CreateObject();
	if(j_role == NULL){
		return MOSQ_ERR_NOMEM;
	}
	cJSON_AddItemToArray(j_roles, j_role);

	if(cJSON_AddStringToObject(j_role, "rolename", "sys-notify") == NULL
			|| cJSON_AddStringToObject(j_role, "textdescription",
				"Allow bridges to publish connection state messages.") == NULL
			|| (j_acls = cJSON_AddArrayToObject(j_role, "acls")) == NULL
			){

		return MOSQ_ERR_NOMEM;
	}

	if(acl_add(j_acls, "publishClientSend", "$SYS/broker/connection/%c/state", 0, true)
			){

		return MOSQ_ERR_NOMEM;
	}
	return MOSQ_ERR_SUCCESS;
}

static int role_add_sys_observe(cJSON *j_roles)
{
	cJSON *j_role, *j_acls;

	j_role = cJSON_CreateObject();
	if(j_role == NULL){
		return MOSQ_ERR_NOMEM;
	}
	cJSON_AddItemToArray(j_roles, j_role);

	if(cJSON_AddStringToObject(j_role, "rolename", "sys-observe") == NULL
			|| cJSON_AddStringToObject(j_role, "textdescription",
				"Observe the $SYS topic hierarchy.") == NULL
			|| (j_acls = cJSON_AddArrayToObject(j_role, "acls")) == NULL
			){

		return MOSQ_ERR_NOMEM;
	}

	if(acl_add(j_acls, "publishClientReceive", "$SYS/#", 0, true)
			|| acl_add(j_acls, "subscribePattern", "$SYS/#", 0, true)
			){

		return MOSQ_ERR_NOMEM;
	}
	return MOSQ_ERR_SUCCESS;
}

static int role_add_topic_observe(cJSON *j_roles)
{
	cJSON *j_role, *j_acls;

	j_role = cJSON_CreateObject();
	if(j_role == NULL){
		return MOSQ_ERR_NOMEM;
	}
	cJSON_AddItemToArray(j_roles, j_role);

	if(cJSON_AddStringToObject(j_role, "rolename", "topic-observe") == NULL
			|| cJSON_AddStringToObject(j_role, "textdescription",
				"Read/write access to the full application topic hierarchy.") == NULL
			|| (j_acls = cJSON_AddArrayToObject(j_role, "acls")) == NULL
			){

		return MOSQ_ERR_NOMEM;
	}

	if(acl_add(j_acls, "publishClientReceive", "#", 0, true)
			|| acl_add(j_acls, "subscribePattern", "#", 0, true)
			|| acl_add(j_acls, "unsubscribePattern", "#", 0, true)
			){

		return MOSQ_ERR_NOMEM;
	}
	return MOSQ_ERR_SUCCESS;
}


static int add_roles(cJSON *j_tree)
{
	cJSON *j_roles;

	j_roles = cJSON_AddArrayToObject(j_tree, "roles");
	if(j_roles == NULL){
		return MOSQ_ERR_NOMEM;
	}

	if(role_add_client(j_roles)
			|| role_add_broker_admin(j_roles)
			|| role_add_dynsec_admin(j_roles)
			|| role_add_sys_notify(j_roles)
			|| role_add_sys_observe(j_roles)
			|| role_add_topic_observe(j_roles)
			){
		return MOSQ_ERR_NOMEM;
	}

	return MOSQ_ERR_SUCCESS;
}


int dynsec__config_init(const char *filename)
{
	FILE *fptr;
	cJSON *j_tree;
	char *json_str;

	j_tree = cJSON_CreateObject();
	if(j_tree == NULL){
		return MOSQ_ERR_NOMEM;
	}

	if(add_default_access(j_tree) != MOSQ_ERR_SUCCESS
			|| add_clients(filename, j_tree) != MOSQ_ERR_SUCCESS
			|| add_groups(j_tree) != MOSQ_ERR_SUCCESS
			|| add_roles(j_tree) != MOSQ_ERR_SUCCESS
			){

		cJSON_Delete(j_tree);
		return MOSQ_ERR_NOMEM;
	}

	json_str = cJSON_Print(j_tree);
	cJSON_Delete(j_tree);
	if(json_str == NULL){
		return MOSQ_ERR_NOMEM;
	}

	fptr = mosquitto__fopen(filename, "wb", true);
	if(fptr == NULL){
		return MOSQ_ERR_UNKNOWN;
	}
	fprintf(fptr, "%s", json_str);
	free(json_str);
	fclose(fptr);

	return MOSQ_ERR_SUCCESS;
}
