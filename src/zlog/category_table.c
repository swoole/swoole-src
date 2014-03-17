/*
 * This file is part of the zlog Library.
 *
 * Copyright (C) 2011 by Hardy Simpson <HardySimpson1984@gmail.com>
 *
 * Licensed under the LGPL v2.1, see the file COPYING in base directory.
 */

#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "zc_defs.h"
#include "category_table.h"

void zlog_category_table_profile(zc_hashtable_t * categories, int flag)
{
	zc_hashtable_entry_t *a_entry;
	zlog_category_t *a_category;

	zc_assert(categories,);
	zc_profile(flag, "-category_table[%p]-", categories);
	zc_hashtable_foreach(categories, a_entry) {
		a_category = (zlog_category_t *) a_entry->value;
		zlog_category_profile(a_category, flag);
	}
	return;
}

/*******************************************************************************/

void zlog_category_table_del(zc_hashtable_t * categories)
{
	zc_assert(categories,);
	zc_hashtable_del(categories);
	zc_debug("zlog_category_table_del[%p]", categories);
	return;
}

zc_hashtable_t *zlog_category_table_new(void)
{
	zc_hashtable_t *categories;

	categories = zc_hashtable_new(20,
			 (zc_hashtable_hash_fn) zc_hashtable_str_hash,
			 (zc_hashtable_equal_fn) zc_hashtable_str_equal,
			 NULL, (zc_hashtable_del_fn) zlog_category_del);
	if (!categories) {
		zc_error("zc_hashtable_new fail");
		return NULL;
	} else {
		zlog_category_table_profile(categories, ZC_DEBUG);
		return categories;
	}
}
/*******************************************************************************/
int zlog_category_table_update_rules(zc_hashtable_t * categories, zc_arraylist_t * new_rules)
{
	zc_hashtable_entry_t *a_entry;
	zlog_category_t *a_category;

	zc_assert(categories, -1);
	zc_hashtable_foreach(categories, a_entry) {
		a_category = (zlog_category_t *) a_entry->value;
		if (zlog_category_update_rules(a_category, new_rules)) {
			zc_error("zlog_category_update_rules fail, try rollback");
			return -1;
		}
	}
	return 0;
}

void zlog_category_table_commit_rules(zc_hashtable_t * categories)
{
	zc_hashtable_entry_t *a_entry;
	zlog_category_t *a_category;

	zc_assert(categories,);
	zc_hashtable_foreach(categories, a_entry) {
		a_category = (zlog_category_t *) a_entry->value;
		zlog_category_commit_rules(a_category);
	}
	return;
}

void zlog_category_table_rollback_rules(zc_hashtable_t * categories)
{
	zc_hashtable_entry_t *a_entry;
	zlog_category_t *a_category;

	zc_assert(categories,);
	zc_hashtable_foreach(categories, a_entry) {
		a_category = (zlog_category_t *) a_entry->value;
		zlog_category_rollback_rules(a_category);
	}
	return;
}

/*******************************************************************************/
zlog_category_t *zlog_category_table_fetch_category(zc_hashtable_t * categories,
			const char *category_name, zc_arraylist_t * rules)
{
	zlog_category_t *a_category;

	zc_assert(categories, NULL);

	/* 1st find category in global category map */
	a_category = zc_hashtable_get(categories, category_name);
	if (a_category) return a_category;

	/* else not fount, create one */
	a_category = zlog_category_new(category_name, rules);
	if (!a_category) {
		zc_error("zc_category_new fail");
		return NULL;
	}

	if(zc_hashtable_put(categories, a_category->name, a_category)) {
		zc_error("zc_hashtable_put fail");
		goto err;
	}

	return a_category;
err:
	zlog_category_del(a_category);
	return NULL;
}

/*******************************************************************************/
