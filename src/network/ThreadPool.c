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

#define swThreadPool_thread(p,id) (&p->threads[id])
static void *swThreadPool_loop(swThreadParam *param);

int swThreadPool_create(swThreadPool *pool, int thread_num)
{
	bzero(pool, sizeof(swThreadPool));

	pool->threads = (swThread *) sw_calloc(thread_num, sizeof(swThread));
	pool->params = sw_calloc(pool->thread_num, sizeof(swThreadParam));
	if (pool->threads == NULL || pool->params == NULL)
	{
		swWarn("swThreadPool_create malloc fail");
		return SW_ERR;
	}

	swWarn("threads=%p|params=%p", pool->threads, pool->params);
	pool->chan = swChannel_create(1024 * 256, 512, 0);
	if (pool->chan == NULL)
	{
		swWarn("swThreadPool_create create channel fail");
		return SW_ERR;
	}
	pthread_mutex_init(&(pool->mutex), NULL);
	pthread_cond_init(&(pool->cond), NULL);

	pool->thread_num = thread_num;
	return SW_OK;
}

int swThreadPool_task(swThreadPool *pool, void *(*call)(void *), void *arg)
{
	swThread_task task;
	task.call = call;
	task.arg = arg;

	pthread_mutex_lock(&(pool->mutex));
	if (swChannel_in(pool->chan, &task, sizeof(swThread_task)) < 0)
	{
		swWarn("swThreadPool push task fail");
		pthread_mutex_unlock(&(pool->mutex));
		return SW_ERR;
	}
	else
	{
		pool->task_num++;
		pthread_mutex_unlock(&(pool->mutex));
	}
	return pthread_cond_signal(&(pool->cond));
}

int swThreadPool_run(swThreadPool *pool)
{
	int i, ret;

	for (i = 0; i < pool->thread_num; i++)
	{
		pool->params[i].pti = i;
		pool->params[i].object = pool;
		if (pthread_create(&(swThreadPool_thread(pool,i)->tid), NULL, swThreadPool_loop, &pool->params[i]) < 0)
		{
			swWarn("swThreadPool_run fail.");
			return SW_ERR;
		}
	}
	return SW_OK;
}

int swThreadPool_free(swThreadPool *pool)
{
	int i;
	if (pool->shutdown)
	{
		return -1;
	}
	pool->shutdown = 1;
	pthread_cond_broadcast(&(pool->cond));

	for (i = 0; i < pool->thread_num; i++)
	{
		pthread_join((swThreadPool_thread(pool,i)->tid), NULL);
	}

	swChannel_free(pool->chan);

	pthread_mutex_destroy(&(pool->mutex));
	pthread_cond_destroy(&(pool->cond));
//这里比较奇怪,params指针已经被释放掉了
//	sw_free(pool->params);
	sw_free(pool->threads);
	return 0;
}

static void *swThreadPool_loop(swThreadParam *param)
{
	swThreadPool *pool = param->object;
	int id = param->pti;
	swThread_task task;
	int ret;

	swTrace("starting thread 0x%lx|id=%d", pthread_self(), id);
	while (SwooleG.running)
	{
		pthread_mutex_lock(&(pool->mutex));
		while (pool->task_num == 0 && !pool->shutdown)
		{
			swTrace("thread 0x%lx is waiting\n", pthread_self());
			pthread_cond_wait(&(pool->cond), &(pool->mutex));
		}

		if (pool->shutdown)
		{
			pthread_mutex_unlock(&(pool->mutex));
			swTrace("thread [%d] will exit\n", id);
			pthread_exit(NULL);
		}

		swTrace("thread [%d] is starting to work\n", id);

		pool->task_num--;
		ret = swChannel_out(pool->chan, &task, sizeof(task));
		pthread_mutex_unlock(&(pool->mutex));

		if (ret >= 0)
			task.call(task.arg);
	}
	pthread_exit(NULL);
}
