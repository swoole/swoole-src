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

#include "coroutine.h"
#include "socket.h"
#include "api.h"
#include "coroutine_c_api.h"

#include <fcntl.h>
#include <sys/file.h>

#include <queue>
#include <string>
#include <unordered_map>

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

static int lock_ex(char *filename, int fd)
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
    if (lm->lock_ex || lm->lock_sh)
    {
        Coroutine *co = Coroutine::get_current();
        lm->_queue.push(co);
        co->yield();
    }
    lm->lock_ex = true;
    return ::flock(fd, LOCK_EX);
}

static int lock_sh(char *filename, int fd)
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
    if (lm->lock_ex)
    {
        Coroutine *co = Coroutine::get_current();
        lm->_queue.push(co);
        co->yield();
    }
    lm->lock_sh = true;
    return ::flock(fd, LOCK_SH);
}

static int lock_release(char *filename, int fd)
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
        int retval = flock(fd, LOCK_UN);
        co->resume();
        return retval;
    }
}

int swoole_coroutine_flock_ex(char *filename, int fd, int operation)
{
    Coroutine *co = Coroutine::get_current();
    if (unlikely(SwooleG.main_reactor == nullptr || !co))
    {
        return flock(fd, operation);
    }

    switch (operation)
    {
    case LOCK_EX:
        return lock_ex(filename, fd);
    case LOCK_SH:
        return lock_sh(filename, fd);
    case LOCK_UN:
        return lock_release(filename, fd);
    default:
        assert(0);
        break;
    }

    return 0;
}
