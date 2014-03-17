/*
 * This file is part of the zlog Library.
 *
 * Copyright (C) 2011 by Hardy Simpson <HardySimpson1984@gmail.com>
 *
 * Licensed under the LGPL v2.1, see the file COPYING in base directory.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>

#include "zc_profile.c"
#include "zc_hashtable.h"
#include "zc_hashtable.c"

void myfree(void *kv)
{
}

int main(void)
{
	zc_hashtable_t *a_table;
	zc_hashtable_entry_t *a_entry;

	a_table = zc_hashtable_new(20,
		zc_hashtable_str_hash,
		zc_hashtable_str_equal,
		myfree, myfree);

	zc_hashtable_put(a_table, "aaa", "bnbb");
	zc_hashtable_put(a_table, "bbb", "bnbb");
	zc_hashtable_put(a_table, "ccc", "bnbb");

	zc_hashtable_put(a_table, "aaa", "123");

	zc_hashtable_foreach(a_table, a_entry) {
		printf("k[%s],v[%s]\n", (char*)a_entry->key, (char*)a_entry->value);
	}

	printf("getv[%s]\n", (char*)zc_hashtable_get(a_table, "ccc"));

	zc_hashtable_remove(a_table, "ccc");

	zc_hashtable_foreach(a_table, a_entry) {
		printf("k[%s],v[%s]\n", (char*)a_entry->key, (char*)a_entry->value);
	}


	zc_hashtable_remove(a_table, NULL);
	zc_hashtable_del(NULL);

	zc_hashtable_del(a_table);
	return 0;
}

