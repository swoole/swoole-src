/*
 * This file is part of the zlog Library.
 *
 * Copyright (C) 2011 by Hardy Simpson <HardySimpson1984@gmail.com>
 *
 * Licensed under the LGPL v2.1, see the file COPYING in base directory.
 */

#ifndef __zlog_conf_h
#define __zlog_conf_h

#include "zc_defs.h"
#include "format.h"
#include "rotater.h"

typedef struct zlog_conf_s {
	char file[MAXLEN_PATH + 1];
	char mtime[20 + 1];

	int strict_init;
	size_t buf_size_min;
	size_t buf_size_max;

	char rotate_lock_file[MAXLEN_CFG_LINE + 1];
	zlog_rotater_t *rotater;

	char default_format_line[MAXLEN_CFG_LINE + 1];
	zlog_format_t *default_format;

	unsigned int file_perms;
	size_t fsync_period;
	size_t reload_conf_period;

	zc_arraylist_t *levels;
	zc_arraylist_t *formats;
	zc_arraylist_t *rules;
	int time_cache_count;
} zlog_conf_t;

extern zlog_conf_t * zlog_env_conf;

zlog_conf_t *zlog_conf_new(const char *confpath);
void zlog_conf_del(zlog_conf_t * a_conf);
void zlog_conf_profile(zlog_conf_t * a_conf, int flag);

#endif
