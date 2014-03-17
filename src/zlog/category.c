/*
 * This file is part of the zlog Library.
 *
 * Copyright (C) 2011 by Hardy Simpson <HardySimpson1984@gmail.com>
 *
 * Licensed under the LGPL v2.1, see the file COPYING in base directory.
 */
#include "fmacros.h"
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "category.h"
#include "rule.h"
#include "zc_defs.h"

void zlog_category_profile(zlog_category_t *a_category, int flag)
{
	int i;
	zlog_rule_t *a_rule;

	zc_assert(a_category,);
	zc_profile(flag, "--category[%p][%s][%p]--",
			a_category,
			a_category->name,
			a_category->fit_rules);
	if (a_category->fit_rules) {
		zc_arraylist_foreach(a_category->fit_rules, i, a_rule) {
			zlog_rule_profile(a_rule, flag);
		}
	}
	return;
}

/*******************************************************************************/
void zlog_category_del(zlog_category_t * a_category)
{
	zc_assert(a_category,);
	if (a_category->fit_rules) zc_arraylist_del(a_category->fit_rules);
	free(a_category);
	zc_debug("zlog_category_del[%p]", a_category);
	return;
}

/* overlap one rule's level bitmap to cateogry,
 * so category can judge whether a log level will be output by itself
 * It is safe when configure is reloaded, when rule will be released an recreated
 */
static void zlog_cateogry_overlap_bitmap(zlog_category_t * a_category, zlog_rule_t *a_rule)
{
	int i;
	for(i = 0; i < sizeof(a_rule->level_bitmap); i++) {
		a_category->level_bitmap[i] |= a_rule->level_bitmap[i];
	}
}

static int zlog_category_obtain_rules(zlog_category_t * a_category, zc_arraylist_t * rules)
{
	int i;
	int count = 0;
	int fit = 0;
	zlog_rule_t *a_rule;
	zlog_rule_t *wastebin_rule = NULL;

	/* before set, clean last fit rules first */
	if (a_category->fit_rules) zc_arraylist_del(a_category->fit_rules);

	memset(a_category->level_bitmap, 0x00, sizeof(a_category->level_bitmap));

	a_category->fit_rules = zc_arraylist_new(NULL);
	if (!(a_category->fit_rules)) {
		zc_error("zc_arraylist_new fail");
		return -1;
	}

	/* get match rules from all rules */
	zc_arraylist_foreach(rules, i, a_rule) {
		fit = zlog_rule_match_category(a_rule, a_category->name);
		if (fit) {
			if (zc_arraylist_add(a_category->fit_rules, a_rule)) {
				zc_error("zc_arrylist_add fail");
				goto err;
			}
			zlog_cateogry_overlap_bitmap(a_category, a_rule);
			count++;
		}

		if (zlog_rule_is_wastebin(a_rule)) {
			wastebin_rule = a_rule;
		}
	}

	if (count == 0) {
		if (wastebin_rule) {
			zc_debug("category[%s], no match rules, use wastebin_rule", a_category->name);
			if (zc_arraylist_add(a_category->fit_rules, wastebin_rule)) {
				zc_error("zc_arrylist_add fail");
				goto err;
			}
			zlog_cateogry_overlap_bitmap(a_category, wastebin_rule);
			count++;
		} else {
			zc_debug("category[%s], no match rules & no wastebin_rule", a_category->name);
		}
	}

	return 0;
err:
	zc_arraylist_del(a_category->fit_rules);
	a_category->fit_rules = NULL;
	return -1;
}

zlog_category_t *zlog_category_new(const char *name, zc_arraylist_t * rules)
{
	size_t len;
	zlog_category_t *a_category;

	zc_assert(name, NULL);
	zc_assert(rules, NULL);

	len = strlen(name);
	if (len > sizeof(a_category->name) - 1) {
		zc_error("name[%s] too long", name);
		return NULL;
	}
	a_category = calloc(1, sizeof(zlog_category_t));
	if (!a_category) {
		zc_error("calloc fail, errno[%d]", errno);
		return NULL;
	}
	strcpy(a_category->name, name);
	a_category->name_len = len;
	if (zlog_category_obtain_rules(a_category, rules)) {
		zc_error("zlog_category_fit_rules fail");
		goto err;
	}

	zlog_category_profile(a_category, ZC_DEBUG);
	return a_category;
err:
	zlog_category_del(a_category);
	return NULL;
}
/*******************************************************************************/
/* update success: fit_rules 1, fit_rules_backup 1 */
/* update fail: fit_rules 0, fit_rules_backup 1 */
int zlog_category_update_rules(zlog_category_t * a_category, zc_arraylist_t * new_rules)
{
	zc_assert(a_category, -1);
	zc_assert(new_rules, -1);

	/* 1st, mv fit_rules fit_rules_backup */
	if (a_category->fit_rules_backup) zc_arraylist_del(a_category->fit_rules_backup);
	a_category->fit_rules_backup = a_category->fit_rules;
	a_category->fit_rules = NULL;

	memcpy(a_category->level_bitmap_backup, a_category->level_bitmap,
			sizeof(a_category->level_bitmap));
	
	/* 2nd, obtain new_rules to fit_rules */
	if (zlog_category_obtain_rules(a_category, new_rules)) {
		zc_error("zlog_category_obtain_rules fail");
		a_category->fit_rules = NULL;
		return -1;
	}

	/* keep the fit_rules_backup not change, return */
	return 0;
}

/* commit fail: fit_rules_backup != 0 */
/* commit success: fit_rules 1, fit_rules_backup 0 */
void zlog_category_commit_rules(zlog_category_t * a_category)
{
	zc_assert(a_category,);
	if (!a_category->fit_rules_backup) {
		zc_warn("a_category->fit_rules_backup is NULL, never update before");
		return;
	}

	zc_arraylist_del(a_category->fit_rules_backup);
	a_category->fit_rules_backup = NULL;
	memset(a_category->level_bitmap_backup, 0x00,
			sizeof(a_category->level_bitmap_backup));
	return;
}

/* rollback fail: fit_rules_backup != 0 */
/* rollback success: fit_rules 1, fit_rules_backup 0 */
/* so whether update succes or not, make things back to old */
void zlog_category_rollback_rules(zlog_category_t * a_category)
{
	zc_assert(a_category,);
	if (!a_category->fit_rules_backup) {
		zc_warn("a_category->fit_rules_backup in NULL, never update before");
		return;
	}

	if (a_category->fit_rules) {
		/* update success, rm new and backup */
		zc_arraylist_del(a_category->fit_rules);
		a_category->fit_rules = a_category->fit_rules_backup;
		a_category->fit_rules_backup = NULL;
	} else {
		/* update fail, just backup */
		a_category->fit_rules = a_category->fit_rules_backup;
		a_category->fit_rules_backup = NULL;
	}

	memcpy(a_category->level_bitmap, a_category->level_bitmap_backup,
			sizeof(a_category->level_bitmap));
	memset(a_category->level_bitmap_backup, 0x00,
			sizeof(a_category->level_bitmap_backup));
	
	return; /* always success */
}

/*******************************************************************************/

int zlog_category_output(zlog_category_t * a_category, zlog_thread_t * a_thread)
{
	int i;
	int rc = 0;
	zlog_rule_t *a_rule;

	/* go through all match rules to output */
	zc_arraylist_foreach(a_category->fit_rules, i, a_rule) {
		rc = zlog_rule_output(a_rule, a_thread);
	}

	return rc;
}
