/*
 * This file is part of the zlog Library.
 *
 * Copyright (C) 2011 by Hardy Simpson <HardySimpson1984@gmail.com>
 *
 * Licensed under the LGPL v2.1, see the file COPYING in base directory.
 */

#ifndef __zlog_category_table_h
#define __zlog_category_table_h

#include "zc_defs.h"
#include "category.h"

zc_hashtable_t *zlog_category_table_new(void);
void zlog_category_table_del(zc_hashtable_t * categories);
void zlog_category_table_profile(zc_hashtable_t * categories, int flag);

/* if none, create new and return */
zlog_category_t *zlog_category_table_fetch_category(
			zc_hashtable_t * categories,
		 	const char *category_name, zc_arraylist_t * rules);

int zlog_category_table_update_rules(zc_hashtable_t * categories, zc_arraylist_t * new_rules);
void zlog_category_table_commit_rules(zc_hashtable_t * categories);
void zlog_category_table_rollback_rules(zc_hashtable_t * categories);

#endif
