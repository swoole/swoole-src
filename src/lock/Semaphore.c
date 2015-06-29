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
#include <sys/sem.h>

static int swSem_lock(swLock *lock);
static int swSem_unlock(swLock *lock);
static int swSem_free(swLock *lock);

int swSem_create(swLock *lock, key_t key)
{
    int ret;
    assert(key != 0);
    lock->type = SW_SEM;
    if ((ret = semget(key, 1, IPC_CREAT | 0666)) < 0)
    {
        return SW_ERR;
    }

    if (semctl(ret, 0, SETVAL, 1) == -1)
    {
        swWarn("semctl(SETVAL) failed");
        return SW_ERR;
    }
    lock->object.sem.semid = ret;

    lock->lock = swSem_lock;
    lock->unlock = swSem_unlock;
    lock->free = swSem_free;

    return SW_OK;
}

static int swSem_unlock(swLock *lock)
{
    struct sembuf sem;
    sem.sem_flg = SEM_UNDO;
    sem.sem_num = 0;
    sem.sem_op = 1;
    return semop(lock->object.sem.semid, &sem, 1);
}

static int swSem_lock(swLock *lock)
{
    struct sembuf sem;
    sem.sem_flg = SEM_UNDO;
    sem.sem_num = 0;
    sem.sem_op = -1;
    return semop(lock->object.sem.semid, &sem, 1);
}

static int swSem_free(swLock *lock)
{
    return semctl(lock->object.sem.semid, 0, IPC_RMID);
}
