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

#include "swoole_thread_pool.h"
#include "swoole_signal.h"
#include "swoole_string.h"
#include "swoole_lock.h"
#include "swoole_log.h"

#define swThreadPool_thread(p, id) (&p->threads[id])
static void *swThreadPool_loop(void *arg);

int swThreadPool_create(swThreadPool *pool, int thread_num) {
    sw_memset_zero(pool, sizeof(swThreadPool));

    pool->threads = (swThread *) sw_calloc(thread_num, sizeof(swThread));
    if (!pool->threads) {
        swWarn("malloc[1] failed");
        return SW_ERR;
    }

    pool->params = (swThreadParam *) sw_calloc(thread_num, sizeof(swThreadParam));
    if (!pool->params) {
        sw_free(pool->threads);
        swWarn("malloc[2] failed");
        return SW_ERR;
    }

    swTrace("threads=%p|params=%p", pool->threads, pool->params);

#ifdef SW_THREADPOOL_USE_CHANNEL
    pool->chan = swChannel_create(1024 * 256, 512, 0);
    if (pool->chan == nullptr) {
        sw_free(pool->threads);
        sw_free(pool->params);
        swWarn("swThreadPool_create create channel failed");
        return SW_ERR;
    }
#else
    int size = SW_MAX(SwooleG.max_sockets + 1, SW_THREADPOOL_QUEUE_LEN);
    if (swRingQueue_init(&pool->queue, size) < 0) {
        sw_free(pool->threads);
        sw_free(pool->params);
        return SW_ERR;
    }
#endif
    if (swCond_create(&pool->cond) < 0) {
        sw_free(pool->threads);
        sw_free(pool->params);
        return SW_ERR;
    }
    pool->thread_num = thread_num;
    return SW_OK;
}

int swThreadPool_dispatch(swThreadPool *pool, const void *task, int task_len) {
    int ret;

    pool->cond.lock(&pool->cond);
#ifdef SW_THREADPOOL_USE_CHANNEL
    ret = swChannel_in(pool->chan, task, task_len);
#else
    ret = swRingQueue_push(&pool->queue, (char *) task);
#endif
    pool->cond.unlock(&pool->cond);

    if (ret < 0) {
        swoole_error_log(SW_LOG_ERROR, SW_ERROR_QUEUE_FULL, "the queue of thread pool is full");
        return SW_ERR;
    }

    sw_atomic_t *task_num = &pool->task_num;
    sw_atomic_fetch_add(task_num, 1);

    return pool->cond.notify(&pool->cond);
}

int swThreadPool_run(swThreadPool *pool) {
    pool->running = 1;
    for (int i = 0; i < pool->thread_num; i++) {
        pool->params[i].pti = i;
        pool->params[i].object = pool;
        if (pthread_create(&(swThreadPool_thread(pool, i)->tid), nullptr, swThreadPool_loop, &pool->params[i]) < 0) {
            swSysWarn("pthread_create failed");
            return SW_ERR;
        }
    }

    return SW_OK;
}

int swThreadPool_free(swThreadPool *pool) {
    int i;
    if (!pool->running) {
        return -1;
    }
    pool->running = 0;

    // broadcast all thread
    pool->cond.broadcast(&(pool->cond));

    for (i = 0; i < pool->thread_num; i++) {
        pthread_join((swThreadPool_thread(pool, i)->tid), nullptr);
    }

#ifdef SW_THREADPOOL_USE_CHANNEL
    swChannel_free(pool->chan);
#else
    swRingQueue_free(&pool->queue);
#endif

    pool->cond.free(&pool->cond);

    return SW_OK;
}

static void *swThreadPool_loop(void *arg) {
    swThreadParam *param = (swThreadParam *) arg;
    swThreadPool *pool = (swThreadPool *) param->object;

    int id = param->pti;
    int ret;
    void *task;

    SwooleTG.buffer_stack = swString_new(SW_STACK_BUFFER_SIZE);
    if (SwooleTG.buffer_stack == nullptr) {
        return nullptr;
    }

    swSignal_none();

    if (pool->onStart) {
        pool->onStart(pool, id);
    }

    while (pool->running) {
        pool->cond.lock(&pool->cond);

        if (!pool->running) {
            pool->cond.unlock(&pool->cond);
            swTrace("thread [%d] will exit", id);
            pthread_exit(nullptr);
        }

        if (pool->task_num == 0) {
            pool->cond.wait(&pool->cond);
        }

        swTrace("thread [%d] is starting to work", id);

        ret = swRingQueue_pop(&pool->queue, &task);
        pool->cond.unlock(&pool->cond);

        if (ret >= 0) {
            sw_atomic_t *task_num = &pool->task_num;
            sw_atomic_fetch_sub(task_num, 1);

            pool->onTask(pool, (void *) task, ret);
        }
    }

    if (pool->onStop) {
        pool->onStop(pool, id);
    }

    swString_free(SwooleTG.buffer_stack);
    pthread_exit(nullptr);
    return nullptr;
}
