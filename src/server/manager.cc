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

#include "swoole_server.h"
#include <unordered_map>
#include <vector>

#include <sys/wait.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif

namespace swoole {

using ReloadWorkerList = std::unordered_map<uint32_t, pid_t>;

struct ManagerProcess {
    bool reloading;
    bool reload_all_worker;
    bool reload_task_worker;
    bool reload_init;
    bool read_message;
    bool force_kill;
    uint32_t reload_worker_i;
    uint32_t reload_worker_num;
    pid_t reload_worker_pid;
    Worker *reload_workers;

    std::vector<pid_t> kill_workers;

    int start(Server *serv);

    static void signal_handler(int sig);
    static void timer_callback(Timer *timer, TimerNode *tnode);
    static void kill_timeout_process(Timer *timer, TimerNode *tnode);
    static void add_timeout_killer(Server *serv, Worker *workers, int n);
};

void ManagerProcess::timer_callback(Timer *timer, TimerNode *tnode) {
    Server *serv = (Server *) tnode->data;
    if (serv->hooks[Server::HOOK_MANAGER_TIMER]) {
        serv->call_hook(Server::HOOK_MANAGER_TIMER, serv);
    }
}

void ManagerProcess::kill_timeout_process(Timer *timer, TimerNode *tnode) {
    ReloadWorkerList *_list = (ReloadWorkerList *) tnode->data;

    for (auto i = _list->begin(); i != _list->end(); i++) {
        pid_t pid = i->second;
        uint32_t worker_id = i->first;
        if (swoole_kill(pid, 0) == -1) {
            continue;
        }
        if (swoole_kill(pid, SIGKILL) < 0) {
            swSysWarn("swKill(%d, SIGKILL) [%u] failed", pid, worker_id);
        } else {
            swoole_error_log(SW_LOG_WARNING,
                             SW_ERROR_SERVER_WORKER_EXIT_TIMEOUT,
                             "[Manager] Worker#%d[pid=%d] exit timeout, force kill the process",
                             worker_id,
                             pid);
        }
    }
    errno = 0;

    delete (_list);
}

void ManagerProcess::add_timeout_killer(Server *serv, Worker *workers, int n) {
    if (!serv->max_wait_time) {
        return;
    }
    /**
     * separate old workers, free memory in the timer
     */
    ReloadWorkerList *_list = new ReloadWorkerList();
    for (int i = 0; i < n; i++) {
        _list->emplace(workers[i].id, workers[i].pid);
    }
    /**
     * Multiply max_wait_time by 2 to prevent conflict with worker
     */
    swoole_timer_after((long) (serv->max_wait_time * 2 * 1000), kill_timeout_process, _list);
}

// create worker child proccess
int Server::start_manager_process() {
    uint32_t i;
    pid_t pid;

    if (task_worker_num > 0) {
        if (create_task_workers() < 0) {
            return SW_ERR;
        }

        Worker *worker;
        for (i = 0; i < task_worker_num; i++) {
            worker = &gs->task_workers.workers[i];
            create_worker(worker);
            if (task_ipc_mode == SW_TASK_IPC_UNIXSOCK) {
                store_pipe_fd(worker->pipe_object);
            }
        }
    }

    // User Worker Process
    if (user_worker_num > 0) {
        if (create_user_workers() < 0) {
            return SW_ERR;
        }

        i = 0;
        for (auto worker : *user_worker_list) {
            memcpy(&user_workers[i], worker, sizeof(user_workers[i]));
            create_worker(worker);
            i++;
        }
    }

    message_box = Channel::make(65536, sizeof(WorkerStopMessage), SW_CHAN_LOCK | SW_CHAN_SHM);
    if (message_box == nullptr) {
        return SW_ERR;
    }

    pid = swoole_fork(0);
    switch (pid) {
    // fork manager process
    case 0: {
        // wait master process
        SW_START_SLEEP;
        if (!is_started()) {
            swError("master process is not running");
            return SW_ERR;
        }
        close_port(true);

        pid_t pid;

        if (task_worker_num > 0) {
            if (gs->task_workers.start() == SW_ERR) {
                swError("failed to start task workers");
                return SW_ERR;
            }
        }

        for (uint32_t i = 0; i < worker_num; i++) {
            Worker *worker = get_worker(i);
            pid = spawn_event_worker(worker);
            if (pid < 0) {
                swError("fork() failed");
                return SW_ERR;
            } else {
                worker->pid = pid;
            }
        }

        if (user_worker_list) {
            for (auto worker : *user_worker_list) {
                if (worker->pipe_object) {
                    store_pipe_fd(worker->pipe_object);
                }
                pid = spawn_user_worker(worker);
                if (pid < 0) {
                    swError("failed to start user workers");
                    return SW_ERR;
                }
            }
        }

        SwooleG.process_type = SW_PROCESS_MANAGER;
        SwooleG.pid = getpid();
        ManagerProcess mp{};
        exit(mp.start(this));
        break;
    }
    // master process
    default:
        gs->manager_pid = pid;
        break;
    case -1:
        swError("fork() failed");
        return SW_ERR;
    }
    return SW_OK;
}

void Server::check_worker_exit_status(int worker_id, pid_t pid, int status) {
    if (status != 0) {
        swWarn("worker#%d[pid=%d] abnormal exit, status=%d, signal=%d"
               "%s",
               worker_id,
               pid,
               WEXITSTATUS(status),
               WTERMSIG(status),
               WTERMSIG(status) == SIGSEGV ? "\n" SWOOLE_BUG_REPORT : "");
        if (onWorkerError != nullptr) {
            onWorkerError(this, worker_id, pid, WEXITSTATUS(status), WTERMSIG(status));
        }
    }
}

int ManagerProcess::start(Server *serv) {
    SwooleG.use_signalfd = 0;
    SwooleTG.reactor = nullptr;
    SwooleG.enable_coroutine = 0;

    reload_workers = (Worker *) sw_calloc(serv->worker_num + serv->task_worker_num, sizeof(Worker));
    if (reload_workers == nullptr) {
        swError("malloc[reload_workers] failed");
        return SW_ERR;
    }

    // for reload
    swSignal_set(SIGHUP, nullptr);
    swSignal_set(SIGCHLD, ManagerProcess::signal_handler);
    swSignal_set(SIGTERM, ManagerProcess::signal_handler);
    swSignal_set(SIGUSR1, ManagerProcess::signal_handler);
    swSignal_set(SIGUSR2, ManagerProcess::signal_handler);
    swSignal_set(SIGIO, ManagerProcess::signal_handler);
    swSignal_set(SIGALRM, ManagerProcess::signal_handler);
#ifdef SIGRTMIN
    swSignal_set(SIGRTMIN, ManagerProcess::signal_handler);
#endif
    // swSignal_set(SIGINT, ManagerProcess::signal_handler);
#ifdef __linux__
    prctl(PR_SET_PDEATHSIG, SIGTERM);
#endif

    serv->private_data_4 = this;

    if (serv->hooks[Server::HOOK_MANAGER_START]) {
        serv->call_hook(Server::HOOK_MANAGER_START, serv);
    }

    if (serv->onManagerStart) {
        serv->onManagerStart(serv);
    }

    if (serv->manager_alarm > 0) {
        swoole_timer_add((long) (serv->manager_alarm * 1000), true, timer_callback, serv);
    }

    while (serv->running) {
        int status;
        pid_t pid = wait(&status);

        if (read_message) {
            WorkerStopMessage msg;
            while (serv->message_box->pop(&msg, sizeof(msg)) > 0) {
                if (!serv->running) {
                    continue;
                }
                if (msg.worker_id >= serv->worker_num) {
                    serv->spawn_task_worker(serv->get_worker(msg.worker_id));
                } else {
                    Worker *worker = serv->get_worker(msg.worker_id);
                    pid_t new_pid = serv->spawn_event_worker(worker);
                    if (new_pid > 0) {
                        worker->pid = new_pid;
                    }
                }
            }
            read_message = false;
        }

        if (SwooleG.signal_alarm && SwooleTG.timer) {
            SwooleG.signal_alarm = 0;
            SwooleTG.timer->select();
        }

        if (pid < 0) {
            if (!reloading) {
            _error:
                if (errno > 0 && errno != EINTR) {
                    swSysWarn("wait() failed");
                }
                continue;
            }
            // reload task & event workers
            else if (reload_all_worker) {
                swInfo("Server is reloading all workers now");
                if (serv->onBeforeReload != nullptr) {
                    serv->onBeforeReload(serv);
                }
                if (!reload_init) {
                    reload_init = true;
                    memcpy(reload_workers, serv->workers, sizeof(Worker) * serv->worker_num);

                    add_timeout_killer(serv, serv->workers, serv->worker_num);

                    reload_worker_num = serv->worker_num;
                    if (serv->task_worker_num > 0) {
                        memcpy(reload_workers + serv->worker_num,
                               serv->gs->task_workers.workers,
                               sizeof(Worker) * serv->task_worker_num);
                        reload_worker_num += serv->task_worker_num;

                        add_timeout_killer(serv, serv->gs->task_workers.workers, serv->task_worker_num);
                    }

                    reload_all_worker = false;
                    if (serv->reload_async) {
                        SW_LOOP_N(serv->worker_num) {
                            if (swoole_kill(reload_workers[i].pid, SIGTERM) < 0) {
                                swSysWarn("swKill(%d, SIGTERM) [%d] failed", reload_workers[i].pid, i);
                            }
                        }
                        reload_worker_i = serv->worker_num;
                    } else {
                        reload_worker_i = 0;
                    }
                }
                goto _kill_worker;
            }
            // only reload task workers
            else if (reload_task_worker) {
                if (serv->task_worker_num == 0) {
                    swWarn("cannot reload task workers, task workers is not started");
                    reloading = false;
                    continue;
                }
                swInfo("Server is reloading task workers now");
                if (serv->onBeforeReload != nullptr) {
                    serv->onBeforeReload(serv);
                }
                if (!reload_init) {
                    memcpy(reload_workers, serv->gs->task_workers.workers, sizeof(Worker) * serv->task_worker_num);
                    add_timeout_killer(serv, serv->gs->task_workers.workers, serv->task_worker_num);
                    reload_worker_num = serv->task_worker_num;
                    reload_worker_i = 0;
                    reload_init = true;
                    reload_task_worker = false;
                }
                goto _kill_worker;
            } else {
                goto _error;
            }
        }
        if (serv->running) {
            // event workers
            SW_LOOP_N(serv->worker_num) {
                // find worker
                if (pid != serv->workers[i].pid) {
                    continue;
                }

                // check the process return code and signal
                serv->check_worker_exit_status(i, pid, status);

                while (1) {
                    Worker *worker = serv->get_worker(i);
                    pid_t new_pid = serv->spawn_event_worker(worker);
                    if (new_pid < 0) {
                        SW_START_SLEEP;
                        continue;
                    } else {
                        worker->pid = new_pid;
                        break;
                    }
                }
            }

            // task worker
            if (serv->gs->task_workers.map_) {
                auto iter = serv->gs->task_workers.map_->find(pid);
                if (iter != serv->gs->task_workers.map_->end()) {
                    serv->check_worker_exit_status(iter->second->id, pid, status);
                    serv->spawn_task_worker(iter->second);
                }
            }
            // user process
            if (serv->user_worker_map != nullptr) {
                Server::wait_other_worker(&serv->gs->event_workers, pid, status);
            }
            if (pid == reload_worker_pid && reloading) {
                reload_worker_i++;
            }
        }
    // reload worker
    _kill_worker:
        if (reloading) {
            // reload finish
            if (reload_worker_i >= reload_worker_num) {
                reload_worker_pid = reload_worker_i = 0;
                reload_init = reloading = false;
                if (serv->onAfterReload != nullptr) {
                    serv->onAfterReload(serv);
                }
                continue;
            }
            reload_worker_pid = reload_workers[reload_worker_i].pid;
            if (swoole_kill(reload_worker_pid, SIGTERM) < 0) {
                if (errno == ECHILD || errno == ESRCH) {
                    reload_worker_i++;
                    goto _kill_worker;
                }
                swSysWarn("swKill(%d, SIGTERM) [%d] failed", reload_workers[reload_worker_i].pid, reload_worker_i);
            }
        }
    }

    sw_free(reload_workers);

    if (SwooleTG.timer) {
        swoole_timer_free();
    }
    // wait child process
    if (serv->max_wait_time) {
        force_kill = true;
        SW_LOOP_N(serv->worker_num) {
            kill_workers.push_back(serv->workers[i].pid);
        }
        if (serv->task_worker_num > 0) {
            SW_LOOP_N(serv->gs->task_workers.worker_num) {
                kill_workers.push_back(serv->gs->task_workers.workers[i].pid);
            }
        }
        if (serv->user_worker_map) {
            for (auto kv : *serv->user_worker_map) {
                kill_workers.push_back(kv.second->pid);
            }
        }
        /**
         * Multiply max_wait_time by 2 to prevent conflict with worker
         */
        alarm(serv->max_wait_time * 2);
    }
    serv->kill_event_workers();
    serv->kill_task_workers();
    serv->kill_user_workers();
    // force kill
    if (serv->max_wait_time) {
        alarm(0);
    }
    if (serv->onManagerStop) {
        serv->onManagerStop(serv);
    }

    return SW_OK;
}

void ManagerProcess::signal_handler(int sig) {
    Server *serv = sw_server();
    if (!serv) {
        return;
    }
    ManagerProcess *mp = (ManagerProcess *) serv->private_data_4;

    switch (sig) {
    case SIGTERM:
        sw_server()->running = false;
        break;
        /**
         * reload all workers
         */
    case SIGUSR1:
        if (!mp->reloading) {
            mp->reloading = true;
            mp->reload_all_worker = true;
        }
        sw_logger()->reopen();
        break;
        /**
         * only reload task workers
         */
    case SIGUSR2:
        if (!mp->reloading) {
            mp->reloading = true;
            mp->reload_task_worker = true;
        }
        sw_logger()->reopen();
        break;
    case SIGIO:
        mp->read_message = true;
        break;
    case SIGALRM:
        SwooleG.signal_alarm = 1;
        if (mp->force_kill) {
            alarm(0);
            for (auto i = mp->kill_workers.begin(); i != mp->kill_workers.end(); i++) {
                kill(*i, SIGKILL);
            }
        }
        break;
    default:
#ifdef SIGRTMIN
        if (sig == SIGRTMIN) {
            sw_logger()->reopen();
        }
#endif
        break;
    }
}

/**
 * @return: success returns pid, failure returns SW_ERR.
 */
int Server::wait_other_worker(ProcessPool *pool, pid_t pid, int status) {
    Server *serv = (Server *) pool->ptr;
    Worker *exit_worker = nullptr;
    int worker_type;

    do {
        if (serv->gs->task_workers.map_) {
            auto iter = serv->gs->task_workers.map_->find(pid);
            if (iter != serv->gs->task_workers.map_->end()) {
                worker_type = SW_PROCESS_TASKWORKER;
                exit_worker = iter->second;
                break;
            }
        }
        if (serv->user_worker_map) {
            auto iter = serv->user_worker_map->find(pid);
            if (iter != serv->user_worker_map->end()) {
                worker_type = SW_PROCESS_USERWORKER;
                exit_worker = iter->second;
                break;
            }
        }
        return SW_ERR;
    } while (0);

    serv->check_worker_exit_status(exit_worker->id, pid, status);

    pid_t new_process_pid = -1;

    switch (worker_type) {
    case SW_PROCESS_TASKWORKER:
        new_process_pid = serv->spawn_task_worker(exit_worker);
        break;
    case SW_PROCESS_USERWORKER:
        new_process_pid = serv->spawn_user_worker(exit_worker);
        break;
    default:
        /* never here */
        abort();
    }

    return new_process_pid;
}

/**
 * kill and wait all user process
 */
void Server::kill_user_workers() {
    if (!user_worker_map) {
        return;
    }

    for (auto &kv : *user_worker_map) {
        swoole_kill(kv.second->pid, SIGTERM);
    }

    for (auto &kv : *user_worker_map) {
        int __stat_loc;
        if (swoole_waitpid(kv.second->pid, &__stat_loc, 0) < 0) {
            swSysWarn("waitpid(%d) failed", kv.second->pid);
        }
    }
}

/**
 * kill and wait all child process
 */
void Server::kill_event_workers() {
    int status;

    if (worker_num == 0) {
        return;
    }

    for (uint32_t i = 0; i < worker_num; i++) {
        swTrace("[Manager]kill worker processor");
        swoole_kill(workers[i].pid, SIGTERM);
    }
    for (uint32_t i = 0; i < worker_num; i++) {
        if (swoole_waitpid(workers[i].pid, &status, 0) < 0) {
            swSysWarn("waitpid(%d) failed", workers[i].pid);
        }
    }
}

/**
 * kill and wait task process
 */
void Server::kill_task_workers() {
    if (task_worker_num == 0) {
        return;
    }
    gs->task_workers.shutdown();
}

pid_t Server::spawn_event_worker(Worker *worker) {
    pid_t pid;

    pid = swoole_fork(0);

    // fork() failed
    if (pid < 0) {
        swSysWarn("Fork Worker failed");
        return SW_ERR;
    }
    // worker child processor
    else if (pid == 0) {
        exit(start_event_worker(worker));
    }
    // parent,add to writer
    else {
        return pid;
    }
}

pid_t Server::spawn_user_worker(Worker *worker) {
    pid_t pid = swoole_fork(0);

    if (pid < 0) {
        swSysWarn("Fork Worker failed");
        return SW_ERR;
    }
    // child
    else if (pid == 0) {
        SwooleG.process_type = SW_PROCESS_USERWORKER;
        SwooleG.process_id = worker->id;
        SwooleWG.worker = worker;
        worker->pid = getpid();
        // close tcp listen socket
        if (is_base_mode()) {
            close_port(true);
        }
        onUserWorkerStart(this, worker);
        exit(0);
    }
    // parent
    else {
        if (worker->pid) {
            user_worker_map->erase(worker->pid);
        }
        /**
         * worker: local memory
         * user_workers: shared memory
         */
        get_worker(worker->id)->pid = worker->pid = pid;
        user_worker_map->emplace(std::make_pair(pid, worker));
        return pid;
    }
}

pid_t Server::spawn_task_worker(Worker *worker) {
    return gs->task_workers.spawn(worker);
}

}  // namespace swoole
