/*
 * This file is part of the zlog Library.
 *
 * Copyright (C) 2011 by Hardy Simpson <HardySimpson1984@gmail.com>
 *
 * Licensed under the LGPL v2.1, see the file COPYING in base directory.
 */

#ifndef __zlog_thread_h
#define  __zlog_thread_h

#include "zc_defs.h"
#include "event.h"
#include "buf.h"
#include "mdc.h"

typedef struct {
	int init_version;
	zlog_mdc_t *mdc;
	zlog_event_t *event;

	zlog_buf_t *pre_path_buf;
	zlog_buf_t *path_buf;
	zlog_buf_t *archive_path_buf;
	zlog_buf_t *pre_msg_buf;
	zlog_buf_t *msg_buf;
} zlog_thread_t;


void zlog_thread_del(zlog_thread_t * a_thread);
void zlog_thread_profile(zlog_thread_t * a_thread, int flag);
zlog_thread_t *zlog_thread_new(int init_version,
			size_t buf_size_min, size_t buf_size_max, int time_cache_count);

int zlog_thread_rebuild_msg_buf(zlog_thread_t * a_thread, size_t buf_size_min, size_t buf_size_max);
int zlog_thread_rebuild_event(zlog_thread_t * a_thread, int time_cache_count);

#endif
