/*
 * This file is part of the zlog Library.
 *
 * Copyright (C) 2011 by Hardy Simpson <HardySimpson1984@gmail.com>
 *
 * Licensed under the LGPL v2.1, see the file COPYING in base directory.
 */

#ifndef __zlog_mdc_h
#define __zlog_mdc_h

#include "zc_defs.h"

typedef struct zlog_mdc_s zlog_mdc_t;
struct zlog_mdc_s {
	zc_hashtable_t *tab;
};

zlog_mdc_t *zlog_mdc_new(void);
void zlog_mdc_del(zlog_mdc_t * a_mdc);
void zlog_mdc_profile(zlog_mdc_t *a_mdc, int flag);

void zlog_mdc_clean(zlog_mdc_t * a_mdc);
int zlog_mdc_put(zlog_mdc_t * a_mdc, const char *key, const char *value);
char *zlog_mdc_get(zlog_mdc_t * a_mdc, const char *key);
void zlog_mdc_remove(zlog_mdc_t * a_mdc, const char *key);

typedef struct zlog_mdc_kv_s {
	char key[MAXLEN_PATH + 1];
	char value[MAXLEN_PATH + 1];
	size_t value_len;
} zlog_mdc_kv_t;

zlog_mdc_kv_t *zlog_mdc_get_kv(zlog_mdc_t * a_mdc, const char *key);

#endif
