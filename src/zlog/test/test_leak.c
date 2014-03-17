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
	int k;
	int i;

	if (argc != 2) {
		printf("test_leak ntime\n");
		return -1;
	}

	rc = zlog_init("test_leak.conf");

	k = atoi(argv[1]);
	while (k-- > 0) {
		i = rand();
		switch (i % 4) {
		case 0:
			rc = dzlog_init("test_leak.conf", "xxx");
			dzlog_info("init");
			break;
		case 1:
			rc = zlog_reload(NULL);
			dzlog_info("reload null");
			break;
		case 2:
			rc = zlog_reload("test_leak.2.conf");
			dzlog_info("reload 2");
			break;
		case 3:
			zlog_fini();
			printf("fini\n");
	//		printf("zlog_finish\tj=[%d], rc=[%d]\n", j, rc);
			break;
		}
	}

	zlog_fini();
	return 0;
}
