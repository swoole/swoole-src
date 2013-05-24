/*
 * mem.c
 *
 *  Created on: 2013-4-21
 *      Author: htf
 */

#include "swoole.h"
#include "tests.h"

void mem_test1()
{
	swShareMemory shm;
	char *mm = swShareMemory_mmap_create(&shm, 128, 0);

	int pid = fork();
	if(pid == 0)
	{
		memset(mm, 'a', 127);
		mm[127] = 0;
	}
	else
	{
		sleep(1);
		printf("str=%s\n", mm);
	}
}
