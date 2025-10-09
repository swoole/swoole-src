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
  | Author: Tianfeng Han  <rango@swoole.com>                             |
  +----------------------------------------------------------------------+
*/
#include "swoole.h"
#include "swoole_api.h"
#include "swoole_process_pool.h"
#include "swoole_coroutine.h"
#include "swoole_coroutine_system.h"
#include "swoole_signal.h"

#include <list>
#include <unordered_map>

using namespace swoole;
using swoole::coroutine::System;

struct WaitTask {
    Coroutine *co;
    pid_t pid;
    int status;
};

/**
 * Wait, waitpid, and signal cannot be used in a multithreaded environment;
 * they are only applicable to the main thread. There is no need to treat them as thread-local variables.
 */
static std::list<WaitTask *> wait_list;
static std::unordered_map<pid_t, WaitTask *> waitpid_map;
static std::unordered_map<pid_t, int> child_processes;

bool signal_ready = false;

static void signal_handler(int signo) {
    if (signo != SIGCHLD) {
        return;
    }

    while (true) {
        auto exit_status = swoole::wait_process(-1, WNOHANG);
        if (exit_status.get_pid() <= 0) {
            break;
        }

        WaitTask *task = nullptr;
        if (waitpid_map.find(exit_status.get_pid()) != waitpid_map.end()) {
            task = waitpid_map[exit_status.get_pid()];
        } else if (!wait_list.empty()) {
            task = wait_list.front();
        } else {
            child_processes[exit_status.get_pid()] = exit_status.get_status();
        }

        if (task) {
            task->status = exit_status.get_status();
            task->pid = exit_status.get_pid();
            task->co->resume();
        }
    }
}

static void signal_init() {
    if (!signal_ready) {
        Reactor *reactor = SwooleTG.reactor;
        swoole_signal_set(SIGCHLD, signal_handler);

        reactor->set_exit_condition(Reactor::EXIT_CONDITION_WAIT_PID, [](Reactor *reactor, size_t &event_num) -> bool {
            return swoole_coroutine_wait_count() == 0;
        });

        reactor->add_destroy_callback([](void *) {
            signal_ready = false;
            swoole_signal_clear();
        });

        signal_ready = true;
    }
}

pid_t System::wait(int *_stat_loc, double timeout) {
    return System::waitpid(-1, _stat_loc, 0, timeout);
}

pid_t System::waitpid_safe(pid_t _pid, int *_stat_loc, int _options) {
    if (sw_unlikely(SwooleTG.reactor == nullptr || !Coroutine::get_current() || (_options & WNOHANG))) {
        return ::waitpid(_pid, _stat_loc, _options);
    }

    pid_t retval = -1;
    wait_for([_pid, &retval, _stat_loc]() -> bool {
        retval = ::waitpid(_pid, _stat_loc, WNOHANG);
        return retval != 0;
    });

    return retval;
}

/**
 * @error: errno & swoole_get_last_error()
 */
pid_t System::waitpid(pid_t _pid, int *_stat_loc, int _options, double timeout) {
    if (_pid < 0) {
        if (!child_processes.empty()) {
            auto i = child_processes.begin();
            pid_t pid = i->first;
            *_stat_loc = i->second;
            child_processes.erase(i);
            return pid;
        }
    } else {
        auto i = child_processes.find(_pid);
        if (i != child_processes.end()) {
            *_stat_loc = i->second;
            child_processes.erase(i);
            return _pid;
        }
    }

    if (sw_unlikely(SwooleTG.reactor == nullptr || !Coroutine::get_current() || (_options & WNOHANG))) {
        return ::waitpid(_pid, _stat_loc, _options);
    }

    /* try once if failed to init the task, and must register SIGCHLD before try waitpid, or may lose the SIGCHLD
     */
    WaitTask task;
    signal_init();
    task.pid = ::waitpid(_pid, _stat_loc, _options | WNOHANG);
    if (task.pid != 0) {
        return task.pid;
    }

    task.pid = -1;
    task.status = 0;
    task.co = Coroutine::get_current();

    /* enqueue */
    if (_pid < 0) {
        wait_list.push_back(&task);
    } else {
        waitpid_map[_pid] = &task;
    }

    task.co->yield_ex(timeout);

    /* dequeue */
    if (_pid < 0) {
        if (task.pid > 0) {
            wait_list.pop_front();
        } else {
            /* timeout so we should remove it from the list */
            wait_list.remove(&task);
        }
    } else {
        waitpid_map.erase(_pid);
    }

    /* clear and assign result */
    if (task.pid > 0) {
        *_stat_loc = task.status;
    } else if (task.co->is_timedout()) {
        errno = ETIMEDOUT;
        swoole_set_last_error(ETIMEDOUT);
    }

    return task.pid;
}

extern "C" {
size_t swoole_coroutine_wait_count() {
    return wait_list.size() + waitpid_map.size();
}

pid_t swoole_coroutine_wait(int *_stat_loc) {
    return System::wait(_stat_loc);
}

pid_t swoole_coroutine_waitpid(pid_t _pid, int *_stat_loc, int _options) {
    return System::waitpid(_pid, _stat_loc, _options);
}
}

pid_t swoole_waitpid(pid_t _pid, int *_stat_loc, int _options) {
    pid_t retval;
    SW_LOOP {
        retval = waitpid(_pid, _stat_loc, _options);
        if (!(retval < 0 && errno == EINTR)) {
            break;
        }
        swoole_signal_dispatch();
        if (sw_timer()) {
            sw_timer()->select();
        }
    }
    return retval;
}
