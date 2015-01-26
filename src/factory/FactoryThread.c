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

typedef struct _swWorkerThread
{
    pthread_t ptid;  //线程ID
    int pipe_num;  //writer thread's pipe num
    int *pipes;  //worker pipes
    int c_pipe;  //current pipe
    swReactor reactor;
    swShareMemory shm;  //共享内存
    swPipe evfd;  //eventfd
} swWorkerThread;

typedef struct _swFactoryThread
{
    int worker_num;
    swThreadPool workers;
} swFactoryThread;

static int swFactoryThread_onTask(swThreadPool *pool, void *data, int len);
static void swFactoryThread_onStart(swThreadPool *pool, int id);
static void swFactoryThread_onStop(swThreadPool *pool, int id);

int swFactoryThread_create(swFactory *factory, int worker_num)
{
    swFactoryThread *object;
    object = sw_calloc(worker_num, sizeof(swFactoryThread));
    if (object == NULL)
    {
        swWarn("malloc[0] failed");
        return SW_ERR;
    }

    if (swThreadPool_create(&object->workers, worker_num) < 0)
    {
        return SW_ERR;
    }

    object->worker_num = worker_num;

    factory->object = object;
    factory->dispatch = swFactoryThread_dispatch;
    factory->finish = swFactory_finish;
    factory->end = swFactory_end;
    factory->start = swFactoryThread_start;
    factory->shutdown = swFactoryThread_shutdown;
    factory->notify = swFactory_notify;

    factory->onTask = NULL;
    factory->onFinish = NULL;

    object->workers.onStart = swFactoryThread_onStart;
    object->workers.onStop = swFactoryThread_onStop;
    object->workers.onTask = swFactoryThread_onTask;

    object->workers.ptr1 = factory->ptr;
    object->workers.ptr2 = factory;

    return SW_OK;
}

int swFactoryThread_start(swFactory *factory)
{
    swFactoryThread *object = factory->object;
    swThreadParam *param;
    int i;
    int ret;
    pthread_t pidt;

    ret = swFactory_check_callback(factory);
    if (ret < 0)
    {
        return SW_ERR;
    }
    swThreadPool_run(&object->workers);

    return SW_OK;
}

int swFactoryThread_shutdown(swFactory *factory)
{
    SwooleG.running = 0;
    swFactoryThread *object = factory->object;
    swThreadPool_free(&object->workers);
    sw_free(object);
    return SW_OK;
}

/**
 * 写线程模式
 */
int swFactoryThread_dispatch(swFactory *factory, swDispatchData *task)
{
    swFactoryThread *object = factory->object;

    int mem_size = sizeof(swDataHead) + task->data.info.len + 1;
    void *data = sw_malloc(mem_size);
    if (data == NULL)
    {
        swWarn("malloc failed");
        return SW_ERR;
    }

    memcpy(data, &(task->data), mem_size);
    if (swThreadPool_dispatch(&object->workers, (void *) data, 0) < 0)
    {
        swWarn("RingQueue is full");
        return SW_ERR;
    }
    else
    {
        return SW_OK;
    }
}

static void swFactoryThread_onStart(swThreadPool *pool, int id)
{
    swServer *serv = SwooleG.serv;

    if (serv->onWorkerStart != NULL)
    {
        serv->onWorkerStart(serv, id);
    }

    swSignal_none();

    //cpu affinity setting
#ifdef HAVE_CPU_AFFINITY
    if (serv->open_cpu_affinity)
    {
        cpu_set_t cpu_set;
        CPU_ZERO(&cpu_set);
        if (serv->cpu_affinity_available_num)
        {
            CPU_SET(serv->cpu_affinity_available[id % serv->cpu_affinity_available_num], &cpu_set);
        }
        else
        {
            CPU_SET(id%SW_CPU_NUM, &cpu_set);
        }
        if (0 != pthread_setaffinity_np(pthread_self(), sizeof(cpu_set), &cpu_set))
        {
            swWarn("pthread_setaffinity_np() failed");
        }
    }
#endif

}

static void swFactoryThread_onStop(swThreadPool *pool, int id)
{
    swServer *serv = SwooleG.serv;

    if (serv->onWorkerStop != NULL)
    {
        serv->onWorkerStop(serv, id);
    }
}

static int swFactoryThread_onTask(swThreadPool *pool, void *data, int len)
{
    swFactory *factory = pool->ptr2;
    int ret = factory->onTask(factory, (swEventData*) data);
    sw_free(data);
    return ret;
}
