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
#include <sys/wait.h>
#include <unistd.h>
#include <syslog.h>

int work(long loop_count)
{
	while(loop_count-- > 0) {
		syslog(LOG_INFO, "loglog");
	}
	return 0;
}


int test(long process_count, long loop_count)
{
	long i;
	pid_t pid;

	for (i = 0; i < process_count; i++) {
		pid = fork();
		if (pid < 0) {
			printf("fork fail\n");
		} else if(pid == 0) {
			work(loop_count);
			return 0;
		}
	}

	for (i = 0; i < process_count; i++) {
		pid = wait(NULL);
	}

	return 0;
}


int main(int argc, char** argv)
{

	if (argc != 3) {
		fprintf(stderr, "test nprocess nloop");
		exit(1);
	}

	openlog(NULL, LOG_NDELAY|LOG_NOWAIT|LOG_PID, LOG_LOCAL0);

	test(atol(argv[1]), atol(argv[2]));

	
	return 0;
}
