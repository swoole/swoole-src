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
#include "swoole_api.h"

#include "coroutine.h"
#include "coroutine_system.h"

#include <list>
#include <unordered_map>

using namespace std;
using namespace swoole;
using swoole::coroutine::System;

struct wait_task
{
    Coroutine *co;
    pid_t pid;
    int status;
};

static list<wait_task *> wait_list;
static unordered_map<int, wait_task *> waitpid_map;
static unordered_map<int, int> child_processes;

bool signal_ready = false;

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
            }
            else if (!wait_list.empty())
            {
                task = wait_list.front();
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

static void signal_free(void *nullopt)
{
    signal_ready = false;
    swSignal_clear();
}

void sigchld_init()
{
    if (!signal_ready)
    {
        swReactor *reactor = SwooleTG.reactor;
        swSignal_add(SIGCHLD, signal_handler);
#ifdef HAVE_SIGNALFD
        if (SwooleG.use_signalfd && !swReactor_isset_handler(reactor, SW_FD_SIGNAL))
        {
            swSignalfd_setup(reactor);
        }
#endif
        swReactor_add_destroy_callback(reactor, (swCallback) signal_free, nullptr);
        signal_ready = true;
    }
}

pid_t System::wait(int *__stat_loc , double timeout)
{
    return System::waitpid(-1, __stat_loc, 0, timeout);
}

pid_t System::waitpid(pid_t __pid, int *__stat_loc, int __options, double timeout)
{
    if (__pid < 0)
    {
        if (!child_processes.empty())
        {
            auto i = child_processes.begin();
            pid_t __pid = i->first;
            *__stat_loc = i->second;
            child_processes.erase(i);
            return __pid;
        }
    }
    else
    {
        auto i = child_processes.find(__pid);
        if (i != child_processes.end())
        {
            *__stat_loc = i->second;
            child_processes.erase(i);
            return __pid;
        }
    }

    if (sw_unlikely(SwooleTG.reactor == nullptr || !Coroutine::get_current() || (__options & WNOHANG)))
    {
        pid_t pid = ::waitpid(__pid, __stat_loc, __options);
        if (pid > 0)
        {
            signal_free(nullptr);
        }
        return pid;
    }

    /* try once if failed we init the task */
    wait_task task;
    task.pid = ::waitpid(__pid, __stat_loc, __options | WNOHANG);
    if (task.pid > 0)
    {
        signal_free(nullptr);
        return task.pid;
    }

    task.pid = -1;
    task.status = 0;
    task.co = Coroutine::get_current();

    /* enqueue */
    if (__pid < 0)
    {
        wait_list.push_back(&task);
    }
    else
    {
        waitpid_map[__pid] = &task;
    }

    /* timeout controller */
    swTimer_node* timer = nullptr;
    if (timeout > 0)
    {
        timer = swoole_timer_add(timeout * 1000, 0, [](swTimer *timer, swTimer_node *tnode) {
            Coroutine *co = (Coroutine *) tnode->data;
            co->resume();
        }, task.co);
    }

    task.co->yield();

    /* dequeue */
    if (__pid < 0)
    {
        if (task.pid > 0)
        {
            wait_list.pop_front();
        }
        else
        {
            /* timeout so we should remove it from the list */
            wait_list.remove(&task);
        }
    }
    else
    {
        waitpid_map.erase(__pid);
    }

    /* clear and assign result */
    if (task.pid > 0)
    {
        if (timer)
        {
            swoole_timer_del(timer);
        }
        *__stat_loc = task.status;
    }
    else
    {
        errno = ETIMEDOUT;
    }

    return task.pid;
}

extern "C"
{

size_t swoole_coroutine_wait_count()
{
    return wait_list.size() + waitpid_map.size();
}

pid_t swoole_coroutine_wait(int *__stat_loc)
{
    return System::wait(__stat_loc);
}

pid_t swoole_coroutine_waitpid(pid_t __pid, int *__stat_loc, int __options)
{
    return System::waitpid(__pid, __stat_loc, __options);
}

}
