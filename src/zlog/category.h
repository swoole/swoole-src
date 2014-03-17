/*
 * This file is part of the zlog Library.
 *
 * Copyright (C) 2011 by Hardy Simpson <HardySimpson1984@gmail.com>
 *
 * Licensed under the LGPL v2.1, see the file COPYING in base directory.
 */

#ifndef __zlog_category_h
#define __zlog_category_h

#include "zc_defs.h"
#include "thread.h"

typedef struct zlog_category_s {
	char name[MAXLEN_PATH + 1];
	size_t name_len;
	unsigned char level_bitmap[32];
	unsigned char level_bitmap_backup[32];
	zc_arraylist_t *fit_rules;
	zc_arraylist_t *fit_rules_backup;
} zlog_category_t;

zlog_category_t *zlog_category_new(const char *name, zc_arraylist_t * rules);
void zlog_category_del(zlog_category_t * a_category);
void zlog_category_profile(zlog_category_t *a_category, int flag);

int zlog_category_update_rules(zlog_category_t * a_category, zc_arraylist_t * new_rules);
void zlog_category_commit_rules(zlog_category_t * a_category);
void zlog_category_rollback_rules(zlog_category_t * a_category);

int zlog_category_output(zlog_category_t * a_category, zlog_thread_t * a_thread);

#define zlog_category_needless_level(a_category, lv) \
        !((a_category->level_bitmap[lv/8] >> (7 - lv % 8)) & 0x01)


#endif
