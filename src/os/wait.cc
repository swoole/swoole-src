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

struct wait_task
{
    coroutine_t *co;
    pid_t pid;
    int status;
};

static unordered_map<int, wait_task *> waitpid_map;
static unordered_map<int, int> child_processes;
static queue<wait_task *> wait_list;

bool signal_init = false;

extern "C"
{

static void signal_handler(int signo)
{
    if (signo == SIGCHLD)
    {
        int __stat_loc;
        wait_task *task = nullptr;

        pid_t __pid = wait(&__stat_loc);
        if (waitpid_map.find(__pid) != waitpid_map.end())
        {
            task = waitpid_map[__pid];
            waitpid_map.erase(__pid);
        }
        else if (wait_list.size() > 0)
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
            coroutine_resume((coroutine_t *) task->co);
        }
    }
}

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
    if (SwooleG.main_reactor == nullptr || coroutine_get_current_cid() == -1 || (__options & WNOHANG))
    {
        return waitpid(__pid, __stat_loc, __options);
    }

    if (child_processes.find(__pid) != child_processes.end())
    {
        *__stat_loc = child_processes[__pid];
        return __pid;
    }

    wait_task task;
    task.co = coroutine_get_current();;
    waitpid_map[__pid] = &task;
    coroutine_yield(task.co);
    *__stat_loc = task.status;

    return task.pid;
}

pid_t swoole_coroutine_wait(int *__stat_loc)
{
    if (SwooleG.main_reactor == nullptr || coroutine_get_current_cid() == -1)
    {
        return wait( __stat_loc);
    }

    pid_t __pid;
    if (child_processes.size() > 0)
    {
        unordered_map<int, int>::iterator i = child_processes.begin();
        __pid = i->first;
        *__stat_loc = i->second;
        child_processes.erase(__pid);
        return __pid;
    }

    wait_task task;
    task.co = coroutine_get_current();;
    waitpid_map[__pid] = &task;
    coroutine_yield(task.co);
    *__stat_loc = task.status;

    return task.pid;
}

}
