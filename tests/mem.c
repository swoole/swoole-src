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
	swMemoryPool *pool = swFixedPool_new(1028 * 8, 128, 0);

	int i;
	char *m;
#define LOOP 80
#define LOOP2 30
	char *str[LOOP];
	bzero(str, sizeof(char *) * LOOP);

	for (i = 0; i < LOOP; i++)
	{
		m = pool->alloc(pool, 0);
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
		pool->free(pool, str[i]);
		//		swMemoryPool_print(&pool);
		//		sleep(1);
	}
	swFixedPool_debug(pool);
	//	sleep(100);

	for (i = 0; i < LOOP2; i++)
	{
		m = pool->alloc(pool, 0);
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
	swFixedPool_debug(pool);
	return 0;
}

swUnitTest(mem_test3)
{
	swMemoryPool *pool = swMemoryGlobal_new(8192, 0);
	if (pool == NULL)
	{
		swWarn("swMemoryGlobal_create fail");
		return 0;
	}
	int i;
	int loop = 100;
	int item_size = 120;

	char **str = pool->alloc(pool, sizeof(char*)*loop);
	if(str == NULL)
	{
		return 0;
	}

	for(i=0; i< loop; i++)
	{
		str[i] = pool->alloc(pool, item_size);
		sprintf(str[i], "memory block [%d]\n", i);
	}

	for(i=0; i< loop; i++)
	{
		printf("%s", str[i]);
	}

	pool->destroy(pool);
	return 0;
}

swUnitTest(mem_test4)
{
	swMemoryPool *pool = swRingBuffer_new(1024 * 1024, 0);

	int i;
	char *m;
#define LOOP 80
#define LOOP2 30
	char *str[LOOP];
	bzero(str, sizeof(char *) * LOOP);

	printf("Alloc #1\n-----------------------------------------------\n");
	for (i = 0; i < LOOP; i++)
	{
		m = pool->alloc(pool, 2048 + i);
		if (m == NULL)
		{
			printf("[%d]Mempool Full\n", i);
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

	printf("Free #1\n-----------------------------------------------\n");
	for (i = 0; i <= 10; i++)
	{
		if (str[i] == NULL)
		{
			continue;
		}
		pool->free(pool, str[i]);
	}

	for (i = 0; i < LOOP2; i++)
	{
		m = pool->alloc(pool, 256+i);
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
	return 0;
}
