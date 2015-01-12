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
    int worker_pti;
    swRingQueue *queues; //消息队列
    swWorkerThread *workers;
} swFactoryThread;

static int swFactoryThread_writer_loop(swThreadParam *param);

int swFactoryThread_create(swFactory *factory, int worker_num)
{
    swFactoryThread *object;
    object = sw_calloc(worker_num, sizeof(swFactoryThread));
    if (object == NULL)
    {
        swWarn("malloc[0] failed");
        return SW_ERR;
    }
    object->workers = sw_calloc(worker_num, sizeof(swWorkerThread));
    if (object->workers == NULL)
    {
        swWarn("malloc[1] failed");
        return SW_ERR;
    }
    object->queues = sw_calloc(worker_num, sizeof(swRingQueue));
    if (object->queues == NULL)
    {
        swTrace("malloc[2] failed");
        return SW_ERR;
    }
    object->worker_num = worker_num;
    object->worker_pti = 0;

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
    for (i = 0; i < this->worker_num; i++)
    {
        if (swPipeNotify_auto(&this->workers[i].evfd, 1, 1) < 0)
        {
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
            swWarn("pthread_create failed");
            return SW_ERR;
        }
        if (swRingQueue_init(&this->queues[i], SW_RINGQUEUE_LEN) < 0)
        {
            swWarn("create ring queue failed");
            return SW_ERR;
        }
        this->workers[i].ptid = pidt;
        //SW_START_SLEEP;
    }
    return SW_OK;
}
int swFactoryThread_shutdown(swFactory *factory)
{
    SwooleG.running = 0;
    swFactoryThread *this = factory->object;
    sw_free(this->workers);
    sw_free(this->queues);
    sw_free(this);
    return SW_OK;
}
/**
 * 写线程模式
 */
int swFactoryThread_dispatch(swFactory *factory, swDispatchData *task)
{
    swFactoryThread *object = factory->object;
    int pti;
    int ret;
    uint64_t flag = 1;
    int datasize = sizeof(int) * 3 + task->data.info.len + 1;
    char *data;
    swServer *serv = factory->ptr;

    if (serv->dispatch_mode == SW_DISPATCH_ROUND)
    {
        //使用平均分配
        pti = object->worker_pti;
        if (object->worker_pti >= object->worker_num)
        {
            object->worker_pti = 0;
            pti = 0;
        }
        object->worker_pti++;
    }
    else
    {
        //使用fd取摸来散列
        pti = task->data.info.fd % object->worker_num;
    }

    data = sw_malloc(datasize);
    if (data == NULL)
    {
        swWarn("malloc failed");
        return SW_ERR;
    }
    memcpy(data, &(task->data), datasize);
    //send data ptr. use event_fd
    if (swRingQueue_push(&(object->queues[pti]), (void *) data) < 0)
    {
        swWarn("RingQueue#%d is full", pti);
        return SW_ERR;
    }
    else
    {
        ret = object->workers[pti].evfd.write(&object->workers[pti].evfd, &flag, sizeof(flag));
        if (ret < 0)
        {
            swWarn("write() to eventfd failed. Error: %s[%d]", strerror(errno), errno);
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
#ifdef HAVE_CPU_AFFINITY
    if (serv->open_cpu_affinity)
    {
        cpu_set_t cpu_set;
        CPU_ZERO(&cpu_set);
        if(serv->cpu_affinity_available_num){
            CPU_SET(serv->cpu_affinity_available[pti % serv->cpu_affinity_available_num], &cpu_set);
        }else{
            CPU_SET(pti%SW_CPU_NUM, &cpu_set);
        }
        if (0 != pthread_setaffinity_np(pthread_self(), sizeof(cpu_set), &cpu_set))
        {
            swWarn("pthread_setaffinity_np() failed");
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
            ret = this->workers[pti].evfd.read(&this->workers[pti].evfd, &flag, sizeof(flag));
            if (ret < 0)
            {
                swTrace("read() failed. Error: %s[%d]", strerror(errno), errno);
            }
        }
    }
    //shutdown
    this->workers[pti].evfd.close(&this->workers[pti].evfd);

    if (serv->onWorkerStop != NULL)
    {
        serv->onWorkerStop(serv, pti);
    }
    sw_free(param);
    pthread_exit(SW_OK);
    return SW_OK;
}
