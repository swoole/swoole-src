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

static int swFileLock_lock_rd(swLock *lock);
static int swFileLock_lock_rw(swLock *lock);
static int swFileLock_unlock(swLock *lock);
static int swFileLock_trylock_rw(swLock *lock);
static int swFileLock_trylock_rd(swLock *lock);
static int swFileLock_free(swLock *lock);

int swFileLock_create(swLock *lock, int fd)
{
    bzero(lock, sizeof(swLock));
    lock->type = SW_FILELOCK;
    lock->object.filelock.fd = fd;
    lock->lock_rd = swFileLock_lock_rd;
    lock->lock = swFileLock_lock_rw;
    lock->trylock_rd = swFileLock_trylock_rd;
    lock->trylock = swFileLock_trylock_rw;
    lock->unlock = swFileLock_unlock;
    lock->free = swFileLock_free;
    return 0;
}

static int swFileLock_lock_rd(swLock *lock)
{
    lock->object.filelock.lock_t.l_type = F_RDLCK;
    return fcntl(lock->object.filelock.fd, F_SETLKW, &lock->object.filelock);
}

static int swFileLock_lock_rw(swLock *lock)
{
    lock->object.filelock.lock_t.l_type = F_WRLCK;
    return fcntl(lock->object.filelock.fd, F_SETLKW, &lock->object.filelock);
}

static int swFileLock_unlock(swLock *lock)
{
    lock->object.filelock.lock_t.l_type = F_UNLCK;
    return fcntl(lock->object.filelock.fd, F_SETLKW, &lock->object.filelock);
}

static int swFileLock_trylock_rw(swLock *lock)
{
    lock->object.filelock.lock_t.l_type = F_WRLCK;
    return fcntl(lock->object.filelock.fd, F_SETLK, &lock->object.filelock);
}

static int swFileLock_trylock_rd(swLock *lock)
{
    lock->object.filelock.lock_t.l_type = F_RDLCK;
    return fcntl(lock->object.filelock.fd, F_SETLK, &lock->object.filelock);
}

static int swFileLock_free(swLock *lock)
{
    return close(lock->object.filelock.fd);
}
