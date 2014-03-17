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

int main(int argc, char** argv)
{
	int rc;
	zlog_category_t *zc;

	rc = zlog_init("test_tmp.conf");
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

	zlog_debug(zc, "%s%d");
	zlog_info(zc, "hello, zlog 2");

	sleep(1);

	zlog_info(zc, "hello, zlog 3");
	zlog_debug(zc, "hello, zlog 4");

//	zlog_profile();

	zlog_fini();
	
	return 0;
}
