/*
Copyright (c) 2009-2020 Roger Light <roger@atchoo.org>

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

#include <stdlib.h>
#include <string.h>

#include "memory_mosq.h"

void *mosquitto__calloc(size_t nmemb, size_t size)
{
	void *mem;
	mem = calloc(nmemb, size);
	return mem;
}

void mosquitto__free(void *mem)
{
	free(mem);
}

void *mosquitto__malloc(size_t size)
{
	void *mem;
	mem = malloc(size);
	return mem;
}

void *mosquitto__realloc(void *ptr, size_t size)
{
	void *mem;
	mem = realloc(ptr, size);
	return mem;
}

char *mosquitto__strdup(const char *s)
{
	char *str;
	str = strdup(s);
	return str;
}
