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
 | license@swoole.com so we can mail you a copy immediately.            |
 +----------------------------------------------------------------------+
 | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
 +----------------------------------------------------------------------+
 */

#include "swoole.h"

#define swThreadPool_thread(p,id) (&p->threads[id])
static void* swThreadPool_loop(void *arg);

int swThreadPool_create(swThreadPool *pool, int thread_num)
{
    bzero(pool, sizeof(swThreadPool));

    pool->threads = (swThread *) sw_calloc(thread_num, sizeof(swThread));
    pool->params = (swThreadParam *) sw_calloc(thread_num, sizeof(swThreadParam));

    if (pool->threads == NULL || pool->params == NULL)
    {
        swWarn("swThreadPool_create malloc fail");
        return SW_ERR;
    }

    swTrace("threads=%p|params=%p", pool->threads, pool->params);

#ifdef SW_THREADPOOL_USE_CHANNEL
    pool->chan = swChannel_create(1024 * 256, 512, 0);
    if (pool->chan == NULL)
    {
        swWarn("swThreadPool_create create channel failed");
        return SW_ERR;
    }
#else
    int size = SwooleG.max_sockets >= SW_THREADPOOL_QUEUE_LEN ? SwooleG.max_sockets + 1 : SW_THREADPOOL_QUEUE_LEN;
    if (swRingQueue_init(&pool->queue, size) < 0)
    {
        return SW_ERR;
    }
#endif
    if (swCond_create(&pool->cond) < 0)
    {
        return SW_ERR;
    }
    pool->thread_num = thread_num;
    return SW_OK;
}

int swThreadPool_dispatch(swThreadPool *pool, void *task, int task_len)
{
    int ret;

    pool->cond.lock(&pool->cond);
#ifdef SW_THREADPOOL_USE_CHANNEL
    ret = swChannel_in(pool->chan, task, task_len);
#else
    ret = swRingQueue_push(&pool->queue, task);
#endif
    pool->cond.unlock(&pool->cond);

    if (ret < 0)
    {
        swoole_error_log(SW_LOG_ERROR, SW_ERROR_QUEUE_FULL, "the queue of thread pool is full.");
        return SW_ERR;
    }

    sw_atomic_t *task_num = &pool->task_num;
    sw_atomic_fetch_add(task_num, 1);

    return pool->cond.notify(&pool->cond);
}

int swThreadPool_run(swThreadPool *pool)
{
    int i;
    for (i = 0; i < pool->thread_num; i++)
    {
        pool->params[i].pti = i;
        pool->params[i].object = pool;
        if (pthread_create(&(swThreadPool_thread(pool,i)->tid), NULL, swThreadPool_loop, &pool->params[i]) < 0)
        {
            swWarn("pthread_create failed. Error: %s[%d]", strerror(errno), errno);
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

    //broadcast all thread
    pool->cond.broadcast(&(pool->cond));

    for (i = 0; i < pool->thread_num; i++)
    {
        pthread_join((swThreadPool_thread(pool,i)->tid), NULL);
    }

#ifdef SW_THREADPOOL_USE_CHANNEL
    swChannel_free(pool->chan);
#else
    swRingQueue_free(&pool->queue);
#endif

    pool->cond.free(&pool->cond);

    return SW_OK;
}

static void* swThreadPool_loop(void *arg)
{
    swThreadParam *param = arg;
    swThreadPool *pool = param->object;

    int id = param->pti;
    int ret;
    void *task;

    if (pool->onStart)
    {
        pool->onStart(pool, id);
    }

    while (SwooleG.running)
    {
        pool->cond.lock(&pool->cond);

        if (pool->shutdown)
        {
            pool->cond.unlock(&pool->cond);
            swTrace("thread [%d] will exit\n", id);
            pthread_exit(NULL);
        }

        if (pool->task_num == 0)
        {
            pool->cond.wait(&pool->cond);
        }

        swTrace("thread [%d] is starting to work\n", id);

        ret = swRingQueue_pop(&pool->queue, &task);
        pool->cond.unlock(&pool->cond);

        if (ret >= 0)
        {
            sw_atomic_t *task_num = &pool->task_num;
            sw_atomic_fetch_sub(task_num, 1);

            pool->onTask(pool, (void *) task, ret);
        }
    }

    if (pool->onStop)
    {
        pool->onStop(pool, id);
    }

    pthread_exit(NULL);
    return NULL;
}

