/*
 * This file is part of the zlog Library.
 *
 * Copyright (C) 2011 by Hardy Simpson <HardySimpson1984@gmail.com>
 *
 * Licensed under the LGPL v2.1, see the file COPYING in base directory.
 */

#ifndef __zlog_format_h
#define __zlog_format_h

#include "thread.h"
#include "zc_defs.h"

typedef struct zlog_format_s zlog_format_t;

struct zlog_format_s {
	char name[MAXLEN_CFG_LINE + 1];	
	char pattern[MAXLEN_CFG_LINE + 1];
	zc_arraylist_t *pattern_specs;
};

zlog_format_t *zlog_format_new(char *line, int * time_cache_count);
void zlog_format_del(zlog_format_t * a_format);
void zlog_format_profile(zlog_format_t * a_format, int flag);

int zlog_format_gen_msg(zlog_format_t * a_format, zlog_thread_t * a_thread);

#define zlog_format_has_name(a_format, fname) \
	STRCMP(a_format->name, ==, fname)

#endif
