#include "swoole.h"
#include "Task.h"


int swTask_start(swTask *task)
{
	int ret;
	ret = swReactorSelect_create(&task->reactor);
	if(ret < 0)
	{
		swTrace("create reactor fail\n");
		return ret;
	}
	if(task->factory_mode == SW_MODE_PROCESS)
	{
		ret = swFactoryProcess_create(&task->factory, task->writer_num, task->worker_num);
	}
	//default mode SW_MODE_THREAD
	else
	{
		ret = swFactoryThread_create(&task->factory, task->writer_num);
	}
	if(ret < 0)
	{
		swTrace("create factory fail\n");
		return ret;
	}
	return SW_OK;
}

void swTask_init(swTask *task)
{
	task->factory_mode = SW_MODE_THREAD;

	task->timeout_sec = 0;
	task->timeout_usec = 300000; //300ms;

	task->writer_num = SW_CPU_NUM;
	task->worker_num = SW_CPU_NUM;
}

int swTask_add(swTask *task, swCallback cb, void *result)
{
	return SW_OK;
}

int swTask_wait()
{

}
