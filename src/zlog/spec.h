/*
 * This file is part of the zlog Library.
 *
 * Copyright (C) 2011 by Hardy Simpson <HardySimpson1984@gmail.com>
 *
 * Licensed under the LGPL v2.1, see the file COPYING in base directory.
 */

#ifndef __zlog_spec_h
#define __zlog_spec_h

#include "event.h"
#include "buf.h"
#include "thread.h"

typedef struct zlog_spec_s zlog_spec_t;

/* write buf, according to each spec's Conversion Characters */
typedef int (*zlog_spec_write_fn) (zlog_spec_t * a_spec,
			 	zlog_thread_t * a_thread,
			 	zlog_buf_t * a_buf);

/* gen a_thread->msg or gen a_thread->path by using write_fn */
typedef int (*zlog_spec_gen_fn) (zlog_spec_t * a_spec,
				zlog_thread_t * a_thread);

struct zlog_spec_s {
	char *str;
	int len;

	char time_fmt[MAXLEN_CFG_LINE + 1];
	int time_cache_index;
	char mdc_key[MAXLEN_PATH + 1];

	char print_fmt[MAXLEN_CFG_LINE + 1];
	int left_adjust;
	size_t max_width;
	size_t min_width;

	zlog_spec_write_fn write_buf;
	zlog_spec_gen_fn gen_msg;
	zlog_spec_gen_fn gen_path;
	zlog_spec_gen_fn gen_archive_path;
};

zlog_spec_t *zlog_spec_new(char *pattern_start, char **pattern_end, int * time_cache_count);
void zlog_spec_del(zlog_spec_t * a_spec);
void zlog_spec_profile(zlog_spec_t * a_spec, int flag);

#define zlog_spec_gen_msg(a_spec, a_thread) \
	a_spec->gen_msg(a_spec, a_thread)

#define zlog_spec_gen_path(a_spec, a_thread) \
	a_spec->gen_path(a_spec, a_thread)

#define zlog_spec_gen_archive_path(a_spec, a_thread) \
	a_spec->gen_archive_path(a_spec, a_thread)

#endif
