/*
 * This file is part of the zlog Library.
 *
 * Copyright (C) 2011 by Hardy Simpson <HardySimpson1984@gmail.com>
 *
 * Licensed under the LGPL v2.1, see the file COPYING in base directory.
 */

#include <string.h>
#include <syslog.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdio.h>
#include <errno.h>

#include "zc_defs.h"

size_t zc_parse_byte_size(char *astring)
{
	/* Parse size in bytes depending on the suffix.   Valid suffixes are KB, MB and GB */
	char *p;
	char *q;
	size_t sz;
	long res;
	int c, m;

	zc_assert(astring, 0);

	/* clear space */
	for (p = q = astring; *p != '\0'; p++) {
		if (isspace(*p)) {
			continue;
		} else {
			*q = *p;
			q++;
		}
	}
	*q = '\0';

	sz = strlen(astring);
	res = strtol(astring, (char **)NULL, 10);

	if (res <= 0)
		return 0;

	if (astring[sz - 1] == 'B' || astring[sz - 1] == 'b') {
		c = astring[sz - 2];
		m = 1024;
	} else {
		c = astring[sz - 1];
		m = 1000;
	}

	switch (c) {
	case 'K':
	case 'k':
		res *= m;
		break;
	case 'M':
	case 'm':
		res *= m * m;
		break;
	case 'G':
	case 'g':
		res *= m * m * m;
		break;
	default:
		if (!isdigit(c)) {
			zc_error("Wrong suffix parsing " "size in bytes for string [%s], ignoring suffix",
				 astring);
		}
		break;
	}

	return (res);
}

/*******************************************************************************/
int zc_str_replace_env(char *str, size_t str_size)
{
	char *p;
	char *q;
	char fmt[MAXLEN_CFG_LINE + 1];
	char env_key[MAXLEN_CFG_LINE + 1];
	char env_value[MAXLEN_CFG_LINE + 1];
	int str_len;
	int env_value_len;
	int nscan;
	int nread;

	str_len = strlen(str);
	q = str;

	do {
		p = strchr(q, '%');
		if (!p) {
			/* can't find more % */
			break;
		}

		memset(fmt, 0x00, sizeof(fmt));
		memset(env_key, 0x00, sizeof(env_key));
		memset(env_value, 0x00, sizeof(env_value));
		nread = 0;
		nscan = sscanf(p + 1, "%[.0-9-]%n", fmt + 1, &nread);
		if (nscan == 1) {
			fmt[0] = '%';
			fmt[nread + 1] = 's';
		} else {
			nread = 0;
			strcpy(fmt, "%s");
		}

		q = p + 1 + nread;

		nscan = sscanf(q, "E(%[^)])%n", env_key, &nread);
		if (nscan == 0) {
			continue;
		}

		q += nread;

		if (*(q - 1) != ')') {
			zc_error("in string[%s] can't find match )", p);
			return -1;
		}

		env_value_len = snprintf(env_value, sizeof(env_value), fmt, getenv(env_key));
		if (env_value_len < 0 || env_value_len >= sizeof(env_value)) {
			zc_error("snprintf fail, errno[%d], evn_value_len[%d]",
				 errno, env_value_len);
			return -1;
		}

		str_len = str_len - (q - p) + env_value_len;
		if (str_len > str_size - 1) {
			zc_error("repalce env_value[%s] cause overlap", env_value);
			return -1;
		}

		memmove(p + env_value_len, q, strlen(q) + 1);
		memcpy(p, env_value, env_value_len);

	} while (1);

	return 0;
}
