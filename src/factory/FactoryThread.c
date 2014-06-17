/*
  +----------------------------------------------------------------------+
  | Swoole                                                               |
  +----------------------------------------------------------------------+
  | This source file is subject to version 2.0 of the Apache license,    |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.apache.org/licenses/LICENSE-2.0.html                      |
  | If you did not receive a copy of the Apache2.0 license and are unable|
  | to obtain it through the world-wide-web, please send a note to       |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
  +----------------------------------------------------------------------+
*/

#include "swoole.h"
#include "Server.h"

typedef struct _swFactoryThread
{
	int writer_num;
	int writer_pti;
	swRingQueue *queues; //消息队列
	swWriterThread *writers;
} swFactoryThread;

static int swFactoryThread_writer_loop(swThreadParam *param);

int swFactoryThread_create(swFactory *factory, int writer_num)
{
	swFactoryThread *object;
	object = sw_calloc(writer_num, sizeof(swFactoryThread));
	if (object == NULL)
	{
		swTrace("malloc[0] fail\n");
		return SW_ERR;
	}
	object->writers = sw_calloc(writer_num, sizeof(swWriterThread));
	if (object->writers == NULL)
	{
		swTrace("malloc[1] fail\n");
		return SW_ERR;
	}
	object->queues = sw_calloc(writer_num, sizeof(swRingQueue));
	if (object->queues == NULL)
	{
		swTrace("malloc[2] fail\n");
		return SW_ERR;
	}
	object->writer_num = writer_num;
	object->writer_pti = 0;

	factory->object = object;
	factory->dispatch = swFactoryThread_dispatch;
	factory->finish = swFactory_finish;
	factory->end = swFactory_end;
	factory->start = swFactoryThread_start;
	factory->shutdown = swFactoryThread_shutdown;
	factory->notify = swFactory_notify;

	factory->onTask = NULL;
	factory->onFinish = NULL;
	return SW_OK;
}

int swFactoryThread_start(swFactory *factory)
{
	swFactoryThread *this = factory->object;
	swThreadParam *param;
	int i;
	int ret;
	pthread_t pidt;

	ret = swFactory_check_callback(factory);
	if (ret < 0)
	{
		return SW_ERR;
	}
	for (i = 0; i < this->writer_num; i++)
	{
		if (swPipeNotify_auto(&this->writers[i].evfd, 1, 1) < 0)
		{
			swWarn("create eventfd fail");
			return SW_ERR;
		}
		param = sw_malloc(sizeof(swThreadParam));
		if (param == NULL)
		{
			return SW_ERR;
		}
		param->object = factory;
		param->pti = i;
		if (pthread_create(&pidt, NULL, (void * (*)(void *)) swFactoryThread_writer_loop, (void *) param) < 0)
		{
			swTrace("pthread_create fail\n");
			return SW_ERR;
		}
		if (swRingQueue_init(&this->queues[i], SW_RINGQUEUE_LEN) < 0)
		{
			swTrace("create ring queue fail\n");
			return SW_ERR;
		}
		this->writers[i].ptid = pidt;
		//SW_START_SLEEP;
	}
	return SW_OK;
}
int swFactoryThread_shutdown(swFactory *factory)
{
	SwooleG.running = 0;
	swFactoryThread *this = factory->object;
	sw_free(this->writers);
	sw_free(this->queues);
	sw_free(this);
	return SW_OK;
}
/**
 * 写线程模式
 */
int swFactoryThread_dispatch(swFactory *factory, swEventData *buf)
{
	swFactoryThread *this = factory->object;
	int pti;
	int ret;
	uint64_t flag = 1;
	int datasize = sizeof(int)*3 + buf->info.len + 1;
	char *data;
	swServer *serv = factory->ptr;

	if(serv->dispatch_mode == SW_DISPATCH_ROUND)
	{
		//使用平均分配
		pti = this->writer_pti;
		if (this->writer_pti >= this->writer_num)
		{
			this->writer_pti = 0;
			pti = 0;
		}
		this->writer_pti++;
	} else {
		//使用fd取摸来散列
		pti = buf->info.fd % this->writer_num;
	}

	data = sw_malloc(datasize);
	if(data == NULL)
	{
		swTrace("malloc fail\n");
		return SW_ERR;
	}
	memcpy(data, buf, datasize);
	//send data ptr. use event_fd
	if (swRingQueue_push(&(this->queues[pti]), (void *) data) < 0)
	{
		swWarn("swRingQueue_push fail.Buffer is full.Writer=%d\n", pti);
		return SW_ERR;
	}
	else
	{
		ret = this->writers[pti].evfd.write(&this->writers[pti].evfd, &flag, sizeof(flag));
		if(ret < 0)
		{
			swWarn("Send queue notice fail.errno=%d\n", errno);
		}
		return ret;
	}
}

static int swFactoryThread_writer_loop(swThreadParam *param)
{
	swFactory *factory = param->object;
	swServer *serv = factory->ptr;
	swFactoryThread *this = factory->object;
	int pti = param->pti;
	int ret;
	swEventData *req;
	uint64_t flag;

	//cpu affinity setting
#if HAVE_CPU_AFFINITY
	if (serv->open_cpu_affinity)
	{
		cpu_set_t cpu_set;
		CPU_ZERO(&cpu_set);
		CPU_SET(pti % SW_CPU_NUM, &cpu_set);
		if (0 != pthread_setaffinity_np(pthread_self(), sizeof(cpu_set), &cpu_set))
		{
			swTrace("pthread_setaffinity_np set fail\n");
		}
	}
#endif

	if (serv->onWorkerStart != NULL)
	{
		serv->onWorkerStart(serv, pti);
	}
	swSignal_none();
	//main loop
	while (SwooleG.running > 0)
	{
		if (swRingQueue_pop(&(this->queues[pti]), (void **) &req) == 0)
		{
			factory->last_from_id = req->info.from_id;
			factory->onTask(factory, req);
			sw_free(req);
		}
		else
		{
			ret = this->writers[pti].evfd.read(&this->writers[pti].evfd, &flag, sizeof(flag));
			if (ret < 0)
			{
				swTrace("read fail.errno=%d", errno);
			}
		}
	}
	//shutdown
	this->writers[pti].evfd.close(&this->writers[pti].evfd);

	if (serv->onWorkerStop != NULL)
	{
		serv->onWorkerStop(serv, pti);
	}
	sw_free(param);
	pthread_exit(SW_OK);
	return SW_OK;
}
