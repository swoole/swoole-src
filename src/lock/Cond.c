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

static int swCond_notify(swCond *cond);
static int swCond_broadcast(swCond *cond);
static int swCond_timewait(swCond *cond, long sec, long nsec);
static int swCond_wait(swCond *cond);
static void swCond_free(swCond *cond);

int swCond_create(swCond *cond)
{
    if (pthread_cond_init(&cond->cond, NULL) < 0)
    {
        swWarn("pthread_cond_init fail. Error: %s [%d]", strerror(errno), errno);
        return SW_ERR;
    }
    if (swMutex_create(&cond->lock, 0) < 0)
    {
        return SW_ERR;
    }

    cond->notify = swCond_notify;
    cond->broadcast = swCond_broadcast;
    cond->timewait = swCond_timewait;
    cond->wait = swCond_wait;
    cond->free = swCond_free;

    return SW_OK;
}

static int swCond_notify(swCond *cond)
{
    return pthread_cond_signal(&cond->cond);
}

static int swCond_broadcast(swCond *cond)
{
    return pthread_cond_broadcast(&cond->cond);
}

static int swCond_timewait(swCond *cond, long sec, long nsec)
{
    struct timespec timeo;

    timeo.tv_sec = sec;
    timeo.tv_nsec = nsec;

    return pthread_cond_timedwait(&cond->cond, &cond->lock.object.mutex._lock, &timeo);
}

static int swCond_wait(swCond *cond)
{
    return pthread_cond_wait(&cond->cond, &cond->lock.object.mutex._lock);
}

static void swCond_free(swCond *cond)
{
    pthread_cond_destroy(&cond->cond);
    cond->lock.free(&cond->lock);
}
