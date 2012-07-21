/*
#include "swoole.h"

typedef struct _swTask
{
	swCallback func;
	void *param;
} swTaskObject;

typedef struct _swTaskThread
{
	pthread_t ptid;
	int evfd;
} swTaskThread;

static struct _swTaskReactor
{
	int task_num;
	swTaskThread *threads;
	int thread_num;
} swTaskReactor;

int swTaskAdd(swTaskObject *task)
{
	return 0;
}
*
 * Task waiter
 * @param timeout

int swTaskWait(int timeout)
{
	return 0;
}

int swTaskReactorInit(int thread_num)
{
	int i;
	int evfd;

	swTaskReactor.threads = calloc(thread_num, sizeof(swTaskThread));
	swTaskReactor.thread_num = thread_num;
	swTaskReactor.task_num = 0;
	for (i = 0; i < thread_num; i++)
	{
		swTaskReactor.threads[i].evfd = eventfd(0,0);
		if(swTaskReactor.threads[i].evfd < 0)
		{
			swTrace("create eventfd fail\n");
			return -1;
		}
		pthread_create(swTaskReactor.threads[i].ptid, NULL, swThreadTask, NULL);
	}
	return 0;
}

void swThreadTask(int pti)
{
	while(swoole_running > 0)
	{

	}
}
*/
