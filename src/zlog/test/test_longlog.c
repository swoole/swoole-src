/*
 * This file is part of the zlog Library.
 *
 * Copyright (C) 2011 by Hardy Simpson <HardySimpson1984@gmail.com>
 *
 * Licensed under the LGPL v2.1, see the file COPYING in base directory.
 */

#include <stdio.h>
#include "zlog.h"
#include <unistd.h>
#include <stdlib.h>

#define str "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
#define str2 str str
#define str4 str2 str2
#define str8 str4 str4
#define str16 str8 str8
#define str32 str16 str16
#define str64 str32 str32

int main(int argc, char** argv)
{
	int i, k;
	int rc;
	zlog_category_t *zc;

	if (argc != 2) {
		printf("useage: test_longlog [count]\n");
		exit(1);
	}

	rc = zlog_init("test_longlog.conf");
	if (rc) {
		printf("init failed\n");
		return -1;
	}

	zc = zlog_get_category("my_cat");
	if (!zc) {
		printf("get cat fail\n");
		zlog_fini();
		return -2;
	}

	k = atoi(argv[1]);
	while (k-- > 0) {
		i = rand();
		switch (i % 3) {
		case 0:
			zlog_info(zc, str32);
			break;
		case 1:
			zlog_info(zc, str64);
			break;
		case 2:
			zlog_info(zc, str16);
			break;
		}
	}


	zlog_fini();
	
	return 0;
}
