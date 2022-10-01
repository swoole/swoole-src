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

#include "swoole_server.h"
#include "swoole_util.h"

#include <unordered_map>
#include <vector>

#if defined(__linux__)
#include <sys/prctl.h>
#elif defined(__FreeBSD__)
#include <sys/procctl.h>
#endif

namespace swoole {

using ReloadWorkerList = std::unordered_map<uint32_t, pid_t>;

struct Manager {
    bool reload_all_worker;
    bool reload_task_worker;
    bool force_kill;
    uint32_t reload_worker_num;
    pid_t reload_worker_pid;
    Server *server_;

    std::vector<pid_t> kill_workers;

    void start(Server *_server);
    void add_timeout_killer(Worker *workers, int n);

    static void signal_handler(int sig);
    static void timer_callback(Timer *timer, TimerNode *tnode);
    static void kill_timeout_process(Timer *timer, TimerNode *tnode);
};

void Manager::timer_callback(Timer *timer, TimerNode *tnode) {
    Server *serv = (Server *) tnode->data;
    if (serv->isset_hook(Server::HOOK_MANAGER_TIMER)) {
        serv->call_hook(Server::HOOK_MANAGER_TIMER, serv);
    }
}

void Manager::kill_timeout_process(Timer *timer, TimerNode *tnode) {
    ReloadWorkerList *_list = (ReloadWorkerList *) tnode->data;

    for (auto i = _list->begin(); i != _list->end(); i++) {
        pid_t pid = i->second;
        uint32_t worker_id = i->first;
        if (swoole_kill(pid, 0) == -1) {
            continue;
        }
        if (swoole_kill(pid, SIGKILL) < 0) {
            swoole_sys_warning("kill(%d, SIGKILL) [%u] failed", pid, worker_id);
        } else {
            swoole_error_log(SW_LOG_WARNING,
                             SW_ERROR_SERVER_WORKER_EXIT_TIMEOUT,
                             "worker(pid=%d, id=%d) exit timeout, force kill the process",
                             pid,
                             worker_id);
        }
    }
    errno = 0;

    delete (_list);
}

void Manager::add_timeout_killer(Worker *workers, int n) {
    if (!server_->max_wait_time) {
        return;
    }
    /**
     * separate old workers, free memory in the timer
     */
    ReloadWorkerList *_list = new ReloadWorkerList();
    SW_LOOP_N(n) {
        _list->emplace(workers[i].id, workers[i].pid);
    }
    /**
     * Multiply max_wait_time by 2 to prevent conflict with worker
     */
    swoole_timer_after((long) (server_->max_wait_time * 2 * 1000), kill_timeout_process, _list);
}

// create worker child proccess
int Server::start_manager_process() {
    pid_t pid;

    if (task_worker_num > 0) {
        if (create_task_workers() < 0) {
            return SW_ERR;
        }

        Worker *worker;
        SW_LOOP_N(task_worker_num) {
            worker = &gs->task_workers.workers[i];
            create_worker(worker);
            if (task_ipc_mode == TASK_IPC_UNIXSOCK) {
                store_pipe_fd(worker->pipe_object);
            }
        }
    }

    // User Worker Process
    if (get_user_worker_num() > 0) {
        if (create_user_workers() < 0) {
            return SW_ERR;
        }

        int i = 0;
        for (auto worker : user_worker_list) {
            memcpy(&user_workers[i], worker, sizeof(user_workers[i]));
            create_worker(worker);
            i++;
        }
    }

    if (gs->event_workers.create_message_box(65536) == SW_ERR) {
        return SW_ERR;
    }

    pid = swoole_fork(0);
    switch (pid) {
    // fork manager process
    case 0: {
        // wait master process
        if (!is_started()) {
            swoole_error("master process is not running");
            return SW_ERR;
        }

        pid_t pid;

        if (task_worker_num > 0) {
            if (gs->task_workers.start() == SW_ERR) {
                swoole_error("failed to start task workers");
                return SW_ERR;
            }
        }

        SW_LOOP_N(worker_num) {
            Worker *worker = get_worker(i);
            pid = spawn_event_worker(worker);
            if (pid < 0) {
                swoole_error("fork() failed");
                return SW_ERR;
            } else {
                worker->pid = pid;
            }
        }

        if (!user_worker_list.empty()) {
            for (auto worker : user_worker_list) {
                if (worker->pipe_object) {
                    store_pipe_fd(worker->pipe_object);
                }
                pid = spawn_user_worker(worker);
                if (pid < 0) {
                    swoole_error("failed to start user workers");
                    return SW_ERR;
                }
            }
        }

        SwooleG.process_type = SW_PROCESS_MANAGER;
        SwooleG.pid = getpid();
        Manager manager{};
        manager.start(this);
        exit(0);
        break;
    }
    // master process
    default:
        gs->event_workers.master_pid = gs->manager_pid = pid;
        break;
    case -1:
        swoole_error("fork() failed");
        return SW_ERR;
    }
    return SW_OK;
}

void Server::check_worker_exit_status(int worker_id, const ExitStatus &exit_status) {
    if (exit_status.get_status() != 0) {
        swoole_warning("worker(pid=%d, id=%d) abnormal exit, status=%d, signal=%d"
                       "%s",
                       exit_status.get_pid(),
                       worker_id,
                       exit_status.get_code(),
                       exit_status.get_signal(),
                       exit_status.get_signal() == SIGSEGV ? SwooleG.bug_report_message.c_str() : "");

        if (onWorkerError != nullptr) {
            onWorkerError(this, worker_id, exit_status);
        }
    }
}

void Manager::start(Server *_server) {
    server_ = _server;
    server_->manager = this;

    ProcessPool *pool = &server_->gs->event_workers;
    pool->onWorkerMessage = Server::read_worker_message;

    SwooleG.use_signalfd = 0;
    SwooleTG.reactor = nullptr;

    pool->reload_workers = new Worker[_server->worker_num + _server->task_worker_num];
    ON_SCOPE_EXIT {
        delete[] pool->reload_workers;
        pool->reload_workers = nullptr;
        server_->manager = nullptr;
    };

    // for reload
    swoole_signal_set(SIGHUP, nullptr);
    swoole_signal_set(SIGCHLD, signal_handler);
    swoole_signal_set(SIGTERM, signal_handler);
    swoole_signal_set(SIGUSR1, signal_handler);
    swoole_signal_set(SIGUSR2, signal_handler);
    swoole_signal_set(SIGIO, signal_handler);
    swoole_signal_set(SIGALRM, signal_handler);
#ifdef SIGRTMIN
    swoole_signal_set(SIGRTMIN, signal_handler);
#endif
    // swSignal_set(SIGINT, signal_handler);
#if defined(__linux__)
    prctl(PR_SET_PDEATHSIG, SIGTERM);
#elif defined(__FreeBSD__)
    int sigid = SIGTERM;
    procctl(P_PID, 0, PROC_PDEATHSIG_CTL, &sigid);
#endif

#if defined(HAVE_PTHREAD_BARRIER) && !(defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__))
    pthread_barrier_wait(&_server->gs->manager_barrier);
#else
    SW_START_SLEEP;
#endif

    if (_server->isset_hook(Server::HOOK_MANAGER_START)) {
        _server->call_hook(Server::HOOK_MANAGER_START, _server);
    }

    if (_server->onManagerStart) {
        _server->onManagerStart(_server);
    }

    if (_server->manager_alarm > 0) {
        swoole_timer_add((long) (_server->manager_alarm * 1000), true, timer_callback, _server);
    }

    while (_server->running) {
        ExitStatus exit_status = wait_process();

        if (pool->read_message) {
            EventData msg;
            while (pool->pop_message(&msg, sizeof(msg)) > 0) {
                if (!_server->running) {
                    continue;
                }
                if (msg.info.type != SW_WORKER_MESSAGE_STOP && pool->onWorkerMessage) {
                    pool->onWorkerMessage(pool, &msg);
                    continue;
                }
                WorkerStopMessage worker_stop_msg;
                memcpy(&worker_stop_msg, msg.data, sizeof(worker_stop_msg));
                if (worker_stop_msg.worker_id >= _server->worker_num) {
                    _server->spawn_task_worker(_server->get_worker(worker_stop_msg.worker_id));
                } else {
                    Worker *worker = _server->get_worker(worker_stop_msg.worker_id);
                    pid_t new_pid = _server->spawn_event_worker(worker);
                    if (new_pid > 0) {
                        worker->pid = new_pid;
                    }
                }
            }
            pool->read_message = false;
        }

        if (SwooleG.signal_alarm && SwooleTG.timer) {
            SwooleG.signal_alarm = 0;
            swoole_timer_select();
        }

        if (exit_status.get_pid() < 0) {
            if (!pool->reloading) {
            _error:
                if (errno > 0 && errno != EINTR) {
                    swoole_sys_warning("wait() failed");
                }
                continue;
            }
            // reload task & event workers
            else if (reload_all_worker) {
                swoole_info("Server is reloading all workers now");
                if (_server->onBeforeReload != nullptr) {
                    _server->onBeforeReload(_server);
                }
                if (!pool->reload_init) {
                    pool->reload_init = true;
                    memcpy(pool->reload_workers, _server->workers, sizeof(Worker) * _server->worker_num);

                    add_timeout_killer(_server->workers, _server->worker_num);

                    reload_worker_num = _server->worker_num;
                    if (_server->task_worker_num > 0) {
                        memcpy(pool->reload_workers + _server->worker_num,
                               _server->gs->task_workers.workers,
                               sizeof(Worker) * _server->task_worker_num);
                        reload_worker_num += _server->task_worker_num;

                        add_timeout_killer(_server->gs->task_workers.workers, _server->task_worker_num);
                    }

                    reload_all_worker = false;
                    if (_server->reload_async) {
                        SW_LOOP_N(_server->worker_num) {
                            if (swoole_kill(pool->reload_workers[i].pid, SIGTERM) < 0) {
                                swoole_sys_warning("swKill(%d, SIGTERM) [%d] failed", pool->reload_workers[i].pid, i);
                            }
                        }
                        pool->reload_worker_i = _server->worker_num;
                    } else {
                        pool->reload_worker_i = 0;
                    }
                }
                goto _kill_worker;
            }
            // only reload task workers
            else if (reload_task_worker) {
                if (_server->task_worker_num == 0) {
                    swoole_warning("cannot reload task workers, task workers is not started");
                    pool->reloading = false;
                    continue;
                }
                swoole_info("Server is reloading task workers now");
                if (_server->onBeforeReload != nullptr) {
                    _server->onBeforeReload(_server);
                }
                if (!pool->reload_init) {
                    memcpy(pool->reload_workers,
                           _server->gs->task_workers.workers,
                           sizeof(Worker) * _server->task_worker_num);
                    add_timeout_killer(_server->gs->task_workers.workers, _server->task_worker_num);
                    reload_worker_num = _server->task_worker_num;
                    pool->reload_worker_i = 0;
                    pool->reload_init = true;
                    reload_task_worker = false;
                }
                goto _kill_worker;
            } else {
                goto _error;
            }
        }
        if (_server->running) {
            // event workers
            SW_LOOP_N(_server->worker_num) {
                // find worker
                if (exit_status.get_pid() != _server->workers[i].pid) {
                    continue;
                }

                // check the process return code and signal
                _server->check_worker_exit_status(i, exit_status);

                while (1) {
                    Worker *worker = _server->get_worker(i);
                    pid_t new_pid = _server->spawn_event_worker(worker);
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
            if (_server->gs->task_workers.map_) {
                auto iter = _server->gs->task_workers.map_->find(exit_status.get_pid());
                if (iter != _server->gs->task_workers.map_->end()) {
                    _server->check_worker_exit_status(iter->second->id, exit_status);
                    _server->spawn_task_worker(iter->second);
                }
            }
            // user process
            if (!_server->user_worker_map.empty()) {
                Server::wait_other_worker(&_server->gs->event_workers, exit_status);
            }
            if (exit_status.get_pid() == reload_worker_pid && pool->reloading) {
                pool->reload_worker_i++;
            }
        }
    // reload worker
    _kill_worker:
        if (pool->reloading) {
            // reload finish
            if (pool->reload_worker_i >= reload_worker_num) {
                reload_worker_pid = pool->reload_worker_i = 0;
                pool->reload_init = pool->reloading = false;
                if (_server->onAfterReload != nullptr) {
                    _server->onAfterReload(_server);
                }
                continue;
            }
            reload_worker_pid = pool->reload_workers[pool->reload_worker_i].pid;
            if (swoole_kill(reload_worker_pid, SIGTERM) < 0) {
                if (errno == ECHILD || errno == ESRCH) {
                    pool->reload_worker_i++;
                    goto _kill_worker;
                }
                swoole_sys_warning("kill(%d, SIGTERM) [%d] failed",
                                   pool->reload_workers[pool->reload_worker_i].pid,
                                   pool->reload_worker_i);
            }
        }
    }

    if (SwooleTG.timer) {
        swoole_timer_free();
    }
    // wait child process
    if (_server->max_wait_time) {
        force_kill = true;
        SW_LOOP_N(_server->worker_num) {
            kill_workers.push_back(_server->workers[i].pid);
        }
        if (_server->task_worker_num > 0) {
            SW_LOOP_N(_server->gs->task_workers.worker_num) {
                kill_workers.push_back(_server->gs->task_workers.workers[i].pid);
            }
        }
        if (!_server->user_worker_map.empty()) {
            for (auto kv : _server->user_worker_map) {
                kill_workers.push_back(kv.second->pid);
            }
        }
        /**
         * Multiply max_wait_time by 2 to prevent conflict with worker
         */
        alarm(_server->max_wait_time * 2);
    }
    _server->kill_event_workers();
    _server->kill_task_workers();
    _server->kill_user_workers();
    // force kill
    if (_server->max_wait_time) {
        alarm(0);
    }
    if (_server->onManagerStop) {
        _server->onManagerStop(_server);
    }
}

void Manager::signal_handler(int sig) {
    Server *_server = sw_server();
    if (!_server || !_server->manager) {
        return;
    }
    Manager *manager = _server->manager;
    ProcessPool *pool = &_server->gs->event_workers;

    switch (sig) {
    case SIGTERM:
        _server->running = false;
        break;
        /**
         * reload all workers
         */
    case SIGUSR1:
        if (pool->reload()) {
            manager->reload_all_worker = true;
        }
        sw_logger()->reopen();
        break;
        /**
         * only reload task workers
         */
    case SIGUSR2:
        if (pool->reload()) {
            manager->reload_task_worker = true;
        }
        sw_logger()->reopen();
        break;
    case SIGIO:
        pool->read_message = true;
        break;
    case SIGALRM:
        SwooleG.signal_alarm = 1;
        if (manager->force_kill) {
            alarm(0);
            for (auto i = manager->kill_workers.begin(); i != manager->kill_workers.end(); i++) {
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
int Server::wait_other_worker(ProcessPool *pool, const ExitStatus &exit_status) {
    Server *serv = (Server *) pool->ptr;
    Worker *exit_worker = nullptr;
    int worker_type;

    do {
        if (serv->gs->task_workers.map_) {
            auto iter = serv->gs->task_workers.map_->find(exit_status.get_pid());
            if (iter != serv->gs->task_workers.map_->end()) {
                worker_type = SW_PROCESS_TASKWORKER;
                exit_worker = iter->second;
                break;
            }
        }
        if (!serv->user_worker_map.empty()) {
            auto iter = serv->user_worker_map.find(exit_status.get_pid());
            if (iter != serv->user_worker_map.end()) {
                worker_type = SW_PROCESS_USERWORKER;
                exit_worker = iter->second;
                break;
            }
        }
        return SW_ERR;
    } while (0);

    serv->check_worker_exit_status(exit_worker->id, exit_status);

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
 * [manager]
 */
void Server::read_worker_message(ProcessPool *pool, EventData *msg) {
    if (msg->info.type != SW_SERVER_EVENT_COMMAND_REQUEST) {
        swoole_warning("unknown worker message type[%d]", msg->info.type);
        return;
    }

    Server *serv = (Server *) pool->ptr;
    int command_id = msg->info.server_fd;
    auto iter = serv->command_handlers.find(command_id);
    if (iter == serv->command_handlers.end()) {
        swoole_error_log(SW_LOG_ERROR, SW_ERROR_SERVER_INVALID_COMMAND, "Unknown command[command_id=%d]", command_id);
        return;
    }

    Server::Command::Handler handler = iter->second;
    auto result = handler(serv, std::string(msg->data, msg->info.len));

    SendData task{};
    task.info.fd = msg->info.fd;
    task.info.reactor_id = 0;
    task.info.server_fd = -1;
    task.info.type = SW_SERVER_EVENT_COMMAND_RESPONSE;
    task.info.len = result.length();
    task.data = result.c_str();

    serv->message_bus.write(serv->get_command_reply_socket(), &task);
}

/**
 * kill and wait all user process
 */
void Server::kill_user_workers() {
    if (user_worker_map.empty()) {
        return;
    }

    for (auto &kv : user_worker_map) {
        swoole_kill(kv.second->pid, SIGTERM);
    }

    for (auto &kv : user_worker_map) {
        int __stat_loc;
        if (swoole_waitpid(kv.second->pid, &__stat_loc, 0) < 0) {
            swoole_sys_warning("waitpid(%d) failed", kv.second->pid);
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

    SW_LOOP_N(worker_num) {
        swoole_trace("[Manager]kill worker processor");
        swoole_kill(workers[i].pid, SIGTERM);
    }
    SW_LOOP_N(worker_num) {
        if (swoole_waitpid(workers[i].pid, &status, 0) < 0) {
            swoole_sys_warning("waitpid(%d) failed", workers[i].pid);
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
        swoole_sys_warning("Fork Worker failed");
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
        swoole_sys_warning("Fork Worker failed");
        return SW_ERR;
    }
    // child
    else if (pid == 0) {
        SwooleG.process_type = SW_PROCESS_USERWORKER;
        SwooleG.process_id = worker->id;
        SwooleWG.worker = worker;
        worker->pid = getpid();
        onUserWorkerStart(this, worker);
        exit(0);
    }
    // parent
    else {
        if (worker->pid) {
            user_worker_map.erase(worker->pid);
        }
        /**
         * worker: local memory
         * user_workers: shared memory
         */
        get_worker(worker->id)->pid = worker->pid = pid;
        user_worker_map.emplace(std::make_pair(pid, worker));
        return pid;
    }
}

pid_t Server::spawn_task_worker(Worker *worker) {
    return gs->task_workers.spawn(worker);
}

}  // namespace swoole
