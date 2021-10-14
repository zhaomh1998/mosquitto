#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mosquitto.h>

static void on_pre_connect(struct mosquitto *mosq, void *userdata)
{
	(void)userdata;

	mosquitto_username_pw_set(mosq, "uname", ";'[08gn=#");
}

static int run = -1;
int main(int argc, char *argv[])
{
	int rc;
	struct mosquitto *mosq;
	int port;

	if(argc < 2){
		return 1;
	}
	port = atoi(argv[1]);

	mosquitto_lib_init();

	mosq = mosquitto_new("01-pre-connect", true, NULL);
	if(mosq == NULL){
		return 1;
	}
	mosquitto_pre_connect_callback_set(mosq, on_pre_connect);

	rc = mosquitto_connect(mosq, "localhost", port, 60);
	if(rc != MOSQ_ERR_SUCCESS) return rc;

	while(run == -1){
		mosquitto_loop(mosq, -1, 1);
	}
	mosquitto_destroy(mosq);

	mosquitto_lib_cleanup();
	return run;
}
