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
  |         Twosee  <twose@qq.com>                                       |
  +----------------------------------------------------------------------+
*/

#pragma once

#include "swoole.h"
#include "swoole_string.h"
#include "lock.h"

struct swThreadPool;

enum swThread_type
{
    SW_THREAD_MASTER = 1,
    SW_THREAD_REACTOR = 2,
    SW_THREAD_WORKER = 3,
    SW_THREAD_UDP = 4,
    SW_THREAD_UNIX_DGRAM = 5,
    SW_THREAD_HEARTBEAT = 6,
};

struct swThread
{
    pthread_t tid;
    int id;
    swThreadPool *pool;
};

struct swThreadParam
{
    void *object;
    int pti;
};

struct swThreadPool
{
    swCond cond;

    swThread *threads;
    swThreadParam *params;

    void *ptr1;
    void *ptr2;

#ifdef SW_THREADPOOL_USE_CHANNEL
    swChannel *chan;
#else
    swRingQueue queue;
#endif

    int thread_num;
    uchar running;
    sw_atomic_t task_num;

    void (*onStart)(swThreadPool *pool, int id);
    void (*onStop)(swThreadPool *pool, int id);
    int (*onTask)(swThreadPool *pool, void *task, int task_len);

};

int swThreadPool_dispatch(swThreadPool *pool, const void *task, int task_len);
int swThreadPool_create(swThreadPool *pool, int max_num);
int swThreadPool_run(swThreadPool *pool);
int swThreadPool_free(swThreadPool *pool);
