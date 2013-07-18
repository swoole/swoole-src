/*
 * mem.c
 *
 *  Created on: 2013-4-21
 *      Author: htf
 */

#include "swoole.h"
#include "tests.h"

swUnitTest(mem_test1)
{
	swShareMemory shm;
	char *mm = swShareMemory_mmap_create(&shm, 128, 0);

	int pid = fork();
	if (pid == 0)
	{
		memset(mm, 'a', 127);
		mm[127] = 0;
	}
	else
	{
		sleep(1);
		printf("str=%s\n", mm);
	}
	return 0;
}

swUnitTest(mem_test2)
{
	int size = 1024;
#define N 11
	char *buf[N];
	void *mm = malloc(size);
	swMemPool p;
	swMemPool_create(&p, mm, size, 128);
	int i;

	for (i = 0; i < N; i++)
	{
		if(i==6)
		{
			swMemPool_free(buf[0]);
			swMemPool_free(buf[1]);
		}
		buf[i] = swMemPool_fetch(&p);
		if (buf[i] == NULL)
		{
			printf("[%d][%p]fetch fail.\n", i, buf[i]);
		}
		else
		{
			memset(buf[i], 'c', 127);
			printf("[%d][%p]data=%s\n", i, buf[i], buf[i]);
		}
	}
	return 0;
}
