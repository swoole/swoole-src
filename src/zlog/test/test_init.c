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

#include "zlog.h"

int main(int argc, char** argv)
{
	int rc;
	
	zlog_category_t *zc;

	rc = zlog_init("test_init.conf");
	if (rc) {
		printf("init fail");
		return -2;
	}
	zc = zlog_get_category("my_cat");
	if (!zc) {
		printf("zlog_get_category fail\n");
		zlog_fini();
		return -1;
	}
	zlog_info(zc, "before update");
	sleep(1);
	rc = zlog_reload("test_init.2.conf");
	if (rc) {
		printf("update fail\n");
	}
	zlog_info(zc, "after update");
	zlog_profile();
	zlog_fini();

	sleep(1);
	zlog_init("test_init.conf");
	zc = zlog_get_category("my_cat");
	if (!zc) {
		printf("zlog_get_category fail\n");
		zlog_fini();
		return -1;
	}
	zlog_info(zc, "init again");
	zlog_fini();
	
	return 0;
}
