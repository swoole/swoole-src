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

#include "coroutine.h"
#include "coroutine_c_api.h"

#include <fcntl.h>
#include <sys/file.h>

#include <queue>

using namespace std;
using namespace swoole;

class file_lock_manager
{
public:
    bool lock_ex = false;
    bool lock_sh = false;
    queue<Coroutine *> _queue;
};

static unordered_map<string, file_lock_manager*> lock_pool;

static inline file_lock_manager* get_manager(char *filename)
{
    string key(filename);
    auto i = lock_pool.find(key);
    file_lock_manager* lm;
    if (i == lock_pool.end())
    {
        lm = new file_lock_manager;
        lock_pool[key] = lm;
    }
    else
    {
        lm = i->second;
    }
    return lm;
}

static inline int lock_ex(char *filename, int fd)
{
    file_lock_manager*lm = get_manager(filename);
    if (lm->lock_ex || lm->lock_sh)
    {
        Coroutine *co = Coroutine::get_current();
        lm->_queue.push(co);
        co->yield();
    }
    lm->lock_ex = true;
    return ::flock(fd, LOCK_EX);
}

static inline int lock_sh(char *filename, int fd)
{
    file_lock_manager*lm = get_manager(filename);
    if (lm->lock_ex)
    {
        Coroutine *co = Coroutine::get_current();
        lm->_queue.push(co);
        co->yield();
    }
    lm->lock_sh = true;
    return ::flock(fd, LOCK_SH);
}

static inline int lock_release(char *filename, int fd)
{
    string key(filename);
    auto i = lock_pool.find(key);
    if (i == lock_pool.end())
    {
        return ::flock(fd, LOCK_UN);
    }
    file_lock_manager* lm = i->second;
    if (lm->_queue.empty())
    {
        delete lm;
        lock_pool.erase(i);
        return ::flock(fd, LOCK_UN);
    }
    else
    {
        Coroutine *co = lm->_queue.front();
        lm->_queue.pop();
        int retval = ::flock(fd, LOCK_UN);
        co->resume();
        return retval;
    }
}

#ifdef LOCK_NB
static inline int lock_nb(char *filename, int fd, int operation)
{
    int retval = ::flock(fd, operation | LOCK_NB);
    if (retval == 0)
    {
        file_lock_manager*lm = get_manager(filename);
        if (operation == LOCK_EX)
        {
            lm->lock_ex = true;
        }
        else
        {
            lm->lock_sh = true;
        }
    }
    return retval;
}
#endif

int swoole_coroutine_flock_ex(char *filename, int fd, int operation)
{
    Coroutine *co = Coroutine::get_current();
    if (sw_unlikely(SwooleTG.reactor == nullptr || !co))
    {
        return ::flock(fd, operation);
    }

    char *real = realpath(filename, SwooleTG.buffer_stack->str);
    if (real == nullptr)
    {
        errno = ENOENT;
        swoole_set_last_error(ENOENT);
        return -1;
    }

    switch (operation)
    {
    case LOCK_EX:
        return lock_ex(real, fd);
    case LOCK_SH:
        return lock_sh(real, fd);
    case LOCK_UN:
        return lock_release(real, fd);
    default:
#ifdef LOCK_NB
        if (operation & LOCK_NB)
        {
            return lock_nb(real, fd, operation & (~LOCK_NB));
        }
#endif
        return -1;
    }

    return 0;
}
