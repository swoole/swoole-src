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
    if (swRingQueue_init(&pool->queue, SW_THREADPOOL_QUEUE_LEN) < 0)
    {
        return SW_ERR;
    }
#endif

    pthread_mutex_init(&(pool->mutex), NULL);
    pthread_cond_init(&(pool->cond), NULL);

    pool->thread_num = thread_num;
    return SW_OK;
}

int swThreadPool_dispatch(swThreadPool *pool, void *task, int task_len)
{
    int i, ret;
    pthread_mutex_lock(&(pool->mutex));

    for (i = 0; i < 1000; i++)
    {
#ifdef SW_THREADPOOL_USE_CHANNEL
        ret = swChannel_in(pool->chan, task, task_len);
#else
        ret = swRingQueue_push(&pool->queue, task);
#endif

        if (ret < 0)
        {
            usleep(i);
            continue;
        }
        else
        {
            break;
        }
    }

    pthread_mutex_unlock(&(pool->mutex));

    if (ret < 0)
    {
        return SW_ERR;
    }
    else
    {
        sw_atomic_t *task_num = &pool->task_num;
        sw_atomic_fetch_add(task_num, 1);
    }
    return pthread_cond_signal(&(pool->cond));
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
    pthread_cond_broadcast(&(pool->cond));

    for (i = 0; i < pool->thread_num; i++)
    {
        pthread_join((swThreadPool_thread(pool,i)->tid), NULL);
    }

#ifdef SW_THREADPOOL_USE_CHANNEL
    swChannel_free(pool->chan);
#else
    swRingQueue_free(&pool->queue);
#endif

    pthread_mutex_destroy(&(pool->mutex));
    pthread_cond_destroy(&(pool->cond));

    return 0;
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
        pthread_mutex_lock(&(pool->mutex));

        if (pool->shutdown)
        {
            pthread_mutex_unlock(&(pool->mutex));
            swTrace("thread [%d] will exit\n", id);
            pthread_exit(NULL);
        }

        if (pool->task_num == 0)
        {
            pthread_cond_wait(&(pool->cond), &(pool->mutex));
        }

        swTrace("thread [%d] is starting to work\n", id);

        ret = swRingQueue_pop(&pool->queue, &task);
        pthread_mutex_unlock(&(pool->mutex));

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

