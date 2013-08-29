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
	swMemoryPool pool;
	swMemoryPool_create(&pool, 1028 * 8, 128);

	int i;
	char *m;
#define LOOP 80
#define LOOP2 30
	char *str[LOOP];
	bzero(str, sizeof(char *) * LOOP);

	for (i = 0; i < LOOP; i++)
	{
		m = swMemoryPool_alloc(&pool);
		if (m == NULL)
		{
			printf("Mempool Full\n");
			str[i] = NULL;
			break;
		}
		sprintf(m, "hello. index=%d\n", i);
		str[i] = m;
	}

	for (i = 0; i < LOOP; i++)
	{
		if (str[i] == NULL)
		{
			continue;
		}
		printf("DATA=%s", str[i]);
	}
	//	swMemoryPool_print(&pool);

	for (i = 10; i >= 0; i--)
	{
		if (str[i] == NULL)
		{
			break;
		}
		swMemoryPool_free(&pool, str[i]);
		//		swMemoryPool_print(&pool);
		//		sleep(1);
	}
	swMemoryPool_print(&pool);
	//	sleep(100);

	for (i = 0; i < LOOP2; i++)
	{
		m = swMemoryPool_alloc(&pool);
		if (m == NULL)
		{
			printf("Mempool Full\n");
			str[i] = NULL;
			break;
		}
		sprintf(m, "world. index=%d\n", i);
		str[i] = m;
	}

	for (i = 0; i < LOOP2; i++)
	{
		if (str[i] == NULL)
		{
			break;
		}
		printf("DATA=%s", str[i]);
	}
	swMemoryPool_print(&pool);
	return 0;
}
