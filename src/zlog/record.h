/*
 * This file is part of the zlog Library.
 *
 * Copyright (C) 2011 by Hardy Simpson <HardySimpson1984@gmail.com>
 *
 * Licensed under the LGPL v2.1, see the file COPYING in base directory.
 */

#ifndef __zlog_record_h
#define __zlog_record_h

#include "zc_defs.h"

/* record is user-defined output function and it's name from configure file */
typedef struct zlog_msg_s {
	char *buf;
	size_t len;
	char *path;
} zlog_msg_t; /* 3 of this first, see need thread or not later */

typedef int (*zlog_record_fn)(zlog_msg_t * msg);

typedef struct zlog_record_s {
	char name[MAXLEN_PATH + 1];
	zlog_record_fn output;
} zlog_record_t;

zlog_record_t *zlog_record_new(const char *name, zlog_record_fn output);
void zlog_record_del(zlog_record_t *a_record);
void zlog_record_profile(zlog_record_t *a_record, int flag);

#endif
