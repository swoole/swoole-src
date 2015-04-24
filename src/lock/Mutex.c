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

static int swMutex_lock(swLock *lock);
static int swMutex_unlock(swLock *lock);
static int swMutex_trylock(swLock *lock);
static int swMutex_free(swLock *lock);

int swMutex_create(swLock *lock, int use_in_process)
{
    int ret;
    bzero(lock, sizeof(swLock));
    lock->type = SW_MUTEX;
    pthread_mutexattr_init(&lock->object.mutex.attr);
    if (use_in_process == 1)
    {
        pthread_mutexattr_setpshared(&lock->object.mutex.attr, PTHREAD_PROCESS_SHARED);
    }
    if ((ret = pthread_mutex_init(&lock->object.mutex._lock, &lock->object.mutex.attr)) < 0)
    {
        return SW_ERR;
    }
    lock->lock = swMutex_lock;
    lock->unlock = swMutex_unlock;
    lock->trylock = swMutex_trylock;
    lock->free = swMutex_free;
    return SW_OK;
}

static int swMutex_lock(swLock *lock)
{
    return pthread_mutex_lock(&lock->object.mutex._lock);
}

static int swMutex_unlock(swLock *lock)
{
    return pthread_mutex_unlock(&lock->object.mutex._lock);
}

static int swMutex_trylock(swLock *lock)
{
    return pthread_mutex_trylock(&lock->object.mutex._lock);
}

#ifdef HAVE_MUTEX_TIMEDLOCK
int swMutex_lockwait(swLock *lock, int timeout_msec)
{
    struct timespec timeo;
    timeo.tv_sec = timeout_msec / 1000;
    timeo.tv_nsec = (timeout_msec - timeo.tv_sec * 1000) * 1000 * 1000;
    return pthread_mutex_timedlock(&lock->object.mutex._lock, &timeo);
}
#else
int swMutex_lockwait(swLock *lock, int timeout_msec)
{
    int sub = 1;
    int sleep_ms = 1000;
    
    if (timeout_msec > 100)
    {
        sub = 10;
        sleep_ms = 10000;
    }
    
    while( timeout_msec > 0)
    {
        if (pthread_mutex_trylock(&lock->object.mutex._lock) == 0)
        {
            return 0;
        }
        else
        {
            usleep(sleep_ms);
            timeout_msec -= sub;
        }
    }
    return ETIMEDOUT;
}
#endif

static int swMutex_free(swLock *lock)
{
    return pthread_mutex_destroy(&lock->object.mutex._lock);
}
