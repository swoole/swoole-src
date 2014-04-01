#include "swoole.h"
#include "tests.h"

static void *myprocess(void *arg)
{
	printf("NewTask: threadid is 0x%lx, working on task %d\n", pthread_self(), *(int *) arg);
	usleep(1000);
	return NULL;
}

swUnitTest(pool_thread)
{
	swThreadPool pool;
	if(object->argc < 3)
	{
		swWarn("please input unittest pool_thread test_num");
		return SW_ERR;
	}

	int n = atoi(object->argv[2]);
	swThreadPool_create(&pool, 4);
	swThreadPool_run(&pool);

	int *workingnum = (int *) malloc(sizeof(int) * n);
	int i;

	sleep(1);
	for (i = 0; i < n; i++)
	{
		workingnum[i] = i;
		swThreadPool_dispatch(&pool, &workingnum[i], sizeof(int) * n);
	}
//	swWarn("finish.");
	sleep(10);
	swThreadPool_free(&pool);
	free(workingnum);
	return 0;
}
