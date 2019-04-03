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

#include <errno.h>
#include <fcntl.h>
#include <sys/file.h>

#include <queue>
#include <string>
#include <unordered_map>

using namespace std;
using namespace swoole;

namespace swoole
{
class FileLock
{
public:
    static int lock(char *filename, int fd, int operation)
    {
        if (operation & LOCK_UN)
        {
            return unlock(filename, fd);
        }

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
        if ((lm->lock_flag & LOCK_EX) || ((operation & LOCK_EX) && (lm->lock_flag & LOCK_SH)))
        {
            if (operation & LOCK_NB)
            {
                errno = EWOULDBLOCK;
                return -1;
            }

            Coroutine *co = Coroutine::get_current();
            lm->wait_list.emplace_back(co, operation);
            co->yield();
        }
        int ret = 0;
        if (!(lm->lock_flag & LOCK_SH))
        {
            ret = ::flock(fd, operation);
        }
        if (!ret)
        {
            if (operation & LOCK_SH)
            {
                lm->lock_flag = LOCK_SH;
                lm->locking[Coroutine::get_current()] = LOCK_SH;
            }
            else
            {
                lm->lock_flag = LOCK_EX;
                lm->locking[Coroutine::get_current()] = LOCK_EX;
            }
        }
        else if (!lm->lock_flag)
        {
            if (lm->wait_list.empty())
            {
                delete lm;
                lock_pool.erase(i);
            }
            else
            {
                resume_next(lm);
            }
        }

        return ret;
    }

private:
    struct file_lock_manager
    {
        bool lock_flag = 0;
        list<pair<Coroutine *, int>> wait_list;
        unordered_map<Coroutine *, int> locking;
    };
    static unordered_map<string, file_lock_manager*> lock_pool;

    static void resume_next(file_lock_manager *lm)
    {
        Coroutine *co = (lm->wait_list.front()).first;
        lm->wait_list.pop_front();
        co->resume();
    }

    static int unlock(char *filename, int fd)
    {
        int ret = 0;

        string key(filename);
        auto i = lock_pool.find(key);
        if (i != lock_pool.end())
        {
            file_lock_manager* lm = i->second;
            Coroutine *co = Coroutine::get_current();
            if (lm->locking.find(co) == lm->locking.end())
            {
                return ret;
            }

            if (lm->locking.size() > 1)
            {
                lm->locking.erase(co);
                return ret;
            }

            ret = ::flock(fd, LOCK_UN);
            if (!ret)
            {
                if (lm->wait_list.empty())
                {
                    delete lm;
                    lock_pool.erase(i);
                }
                else
                {
                    lm->locking.erase(co);
                    lm->lock_flag = 0;
                    resume_next(lm);
                }
            }
        }

        return ret;
    }
};
}

int swoole_coroutine_flock_ex(char *filename, int fd, int operation)
{
    Coroutine *co = Coroutine::get_current();
    if (unlikely(SwooleG.main_reactor == nullptr || !co))
    {
        return flock(fd, operation);
    }

    return FileLock::lock(filename, fd, operation);
}
