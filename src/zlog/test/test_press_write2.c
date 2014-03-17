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
#include <pthread.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "zlog.h"

static long loop_count;


void * work(void *ptr)
{
	long j = loop_count;
	int rc;
static char log[] = "2012-06-14 20:30:38.481187 INFO   24536:140716226213632:test_press_zlog.c:36 loglog\n";
	char file[20];
	sprintf(file, "press.%ld.log", (long)ptr);

	int fd;
	fd = open(file, O_CREAT | O_WRONLY | O_APPEND , 0644);
	//FILE *fp;

	while(j-- > 0) {
		rc = write(fd, log, sizeof(log)-1);
		//fwrite(log, sizeof(log)-1, 1, fp);
	}
	//fclose(fp);
	close(fd);
	return 0;
}


int test(long process_count, long thread_count)
{
	long i;
	pid_t pid;
	long j;

	for (i = 0; i < process_count; i++) {
		pid = fork();
		if (pid < 0) {
			printf("fork fail\n");
		} else if(pid == 0) {
			pthread_t  tid[thread_count];

			for (j = 0; j < thread_count; j++) { 
				pthread_create(&(tid[j]), NULL, work, (void*)j);
			}
			for (j = 0; j < thread_count; j++) { 
				pthread_join(tid[j], NULL);
			}
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
	if (argc != 4) {
		fprintf(stderr, "test nprocess nthreads nloop\n");
		exit(1);
	}


	loop_count = atol(argv[3]);
	test(atol(argv[1]), atol(argv[2]));
	
	return 0;
}
