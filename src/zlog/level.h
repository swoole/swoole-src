/*
 * This file is part of the zlog Library.
 *
 * Copyright (C) 2011 by Hardy Simpson <HardySimpson1984@gmail.com>
 *
 * Licensed under the LGPL v2.1, see the file COPYING in base directory.
 */

#ifndef __zlog_level_h
#define __zlog_level_h

#include "zc_defs.h"

typedef struct zlog_level_s {
	int int_level;
	char str_uppercase[MAXLEN_PATH + 1];
	char str_lowercase[MAXLEN_PATH + 1];
	size_t str_len;
       	int syslog_level;
} zlog_level_t;

zlog_level_t *zlog_level_new(char *line);
void zlog_level_del(zlog_level_t *a_level);
void zlog_level_profile(zlog_level_t *a_level, int flag);

#endif
