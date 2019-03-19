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

#include <queue>
#include <unordered_map>

using namespace std;
using namespace swoole;

struct wait_task
{
    Coroutine *co;
    pid_t pid;
    int status;
};

static unordered_map<int, wait_task *> waitpid_map;
static unordered_map<int, int> child_processes;
static queue<wait_task *> wait_list;

bool signal_init = false;

static void signal_handler(int signo)
{
    if (signo == SIGCHLD)
    {
        int __stat_loc;

        while (true)
        {
            pid_t __pid = waitpid(-1, &__stat_loc, WNOHANG);
            if (__pid <= 0)
            {
                break;
            }

            wait_task *task = nullptr;
            if (waitpid_map.find(__pid) != waitpid_map.end())
            {
                task = waitpid_map[__pid];
                waitpid_map.erase(__pid);
            }
            else if (!wait_list.empty())
            {
                task = wait_list.front();
                wait_list.pop();
            }
            else
            {
                child_processes[__pid] = __stat_loc;
            }

            if (task)
            {
                task->status = __stat_loc;
                task->pid = __pid;
                task->co->resume();
            }
        }
    }
}

extern "C"
{

void swoole_coroutine_signal_init()
{
    if (!signal_init)
    {
        signal_init = true;
        swSignal_add(SIGCHLD, signal_handler);
#ifdef HAVE_SIGNALFD
        if (SwooleG.use_signalfd && !swReactor_handle_isset(SwooleG.main_reactor, SW_FD_SIGNAL))
        {
            swSignalfd_setup(SwooleG.main_reactor);
        }
#endif
    }
}

pid_t swoole_coroutine_waitpid(pid_t __pid, int *__stat_loc, int __options)
{
    if (unlikely(SwooleG.main_reactor == nullptr || !Coroutine::get_current() || (__options & WNOHANG)))
    {
        return waitpid(__pid, __stat_loc, __options);
    }

    auto i = child_processes.find(__pid);
    if (i != child_processes.end())
    {
        *__stat_loc = i->second;
        child_processes.erase(i);
        return __pid;
    }

    wait_task task;
    task.pid = waitpid(__pid, __stat_loc, __options | WNOHANG);
    if (task.pid > 0)
    {
        return task.pid;
    }
    else
    {
        task.pid = 0;
    }

    task.co = Coroutine::get_current_safe();
    waitpid_map[__pid] = &task;
    task.co->yield();
    *__stat_loc = task.status;

    return task.pid;
}

pid_t swoole_coroutine_wait(int *__stat_loc)
{
    if (unlikely(SwooleG.main_reactor == nullptr || !Coroutine::get_current()))
    {
        return wait( __stat_loc);
    }

    if (!child_processes.empty())
    {
        auto i = child_processes.begin();
        pid_t __pid = i->first;
        *__stat_loc = i->second;
        child_processes.erase(i);
        return __pid;
    }

    wait_task task;
    task.co = Coroutine::get_current_safe();
    wait_list.push(&task);
    task.co->yield();
    *__stat_loc = task.status;

    return task.pid;
}

}
