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

    void wait(Server *_server);
    void add_timeout_killer(Worker *workers, int n);
    void terminate_all_worker();

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

int Server::start_manager_process() {
    SW_LOOP_N(worker_num) {
        create_worker(get_worker(i));
    }

    if (gs->event_workers.create_message_box(SW_MESSAGE_BOX_SIZE) == SW_ERR) {
        return SW_ERR;
    }

    if (task_worker_num > 0 && create_task_workers() < 0) {
        return SW_ERR;
    }

    if (get_user_worker_num() > 0 && create_user_workers() < 0) {
        return SW_ERR;
    }

    auto fn = [this](void) {
        swoole_set_process_type(SW_PROCESS_MANAGER);
        gs->manager_pid = SwooleG.pid = getpid();

        if (task_worker_num > 0) {
            if (gs->task_workers.start() == SW_ERR) {
                swoole_sys_error("failed to start task worker");
                return;
            }
        }

        SW_LOOP_N(worker_num) {
            Worker *worker = get_worker(i);
            if (factory->spawn_event_worker(worker) < 0) {
                swoole_sys_error("failed to fork event worker");
                return;
            }
        }

        if (!user_worker_list.empty()) {
            for (auto worker : user_worker_list) {
                if (factory->spawn_user_worker(worker) < 0) {
                    swoole_sys_error("failed to fork user worker");
                    return;
                }
            }
        }

        Manager manager{};
        manager.wait(this);
    };

    if (is_base_mode()) {
        fn();
    } else {
        if (swoole_fork_exec(fn) < 0) {
            swoole_sys_warning("failed fork manager process");
            return SW_ERR;
        }
    }
    return SW_OK;
}

void Manager::wait(Server *_server) {
    server_ = _server;
    server_->manager = this;

    ProcessPool *pool = &server_->gs->event_workers;
    pool->onWorkerMessage = Server::read_worker_message;
    _server->gs->manager_pid = _server->gs->event_workers.master_pid = getpid();

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

    if (_server->is_process_mode()) {
#if defined(__linux__)
        prctl(PR_SET_PDEATHSIG, SIGTERM);
#elif defined(__FreeBSD__)
        int sigid = SIGTERM;
        procctl(P_PID, 0, PROC_PDEATHSIG_CTL, &sigid);
#endif
        _server->gs->manager_barrier.wait();
    }

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
        const auto errnoAfterWait = errno;
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
                    _server->factory->spawn_task_worker(_server->get_worker(worker_stop_msg.worker_id));
                } else {
                    Worker *worker = _server->get_worker(worker_stop_msg.worker_id);
                    _server->factory->spawn_event_worker(worker);
                }
            }
            pool->read_message = false;
        }

        if (SwooleTG.timer) {
            SwooleTG.timer->select();
        }

        if (exit_status.get_pid() < 0) {
            if (!pool->reloading) {
            _error:
                if (errnoAfterWait > 0 && errnoAfterWait != EINTR) {
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
                                swoole_sys_warning(
                                    "failed to kill(%d, SIGTERM) worker#[%d]", pool->reload_workers[i].pid, i);
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
                Worker *worker = _server->get_worker(i);
                // find worker
                if (exit_status.get_pid() != worker->pid) {
                    continue;
                }

                // check the process return code and signal
                _server->factory->check_worker_exit_status(worker, exit_status);

                do {
                    if (_server->factory->spawn_event_worker(worker) < 0) {
                        SW_START_SLEEP;
                        continue;
                    }
                } while (0);
            }

            // task worker
            if (_server->gs->task_workers.map_) {
                auto iter = _server->gs->task_workers.map_->find(exit_status.get_pid());
                if (iter != _server->gs->task_workers.map_->end()) {
                    _server->factory->check_worker_exit_status(iter->second, exit_status);
                    _server->factory->spawn_task_worker(iter->second);
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
            for (auto &kv : _server->user_worker_map) {
                kill_workers.push_back(kv.second->pid);
            }
        }
        /**
         * Multiply max_wait_time by 2 to prevent conflict with worker
         */
        alarm(_server->max_wait_time * 2);
    }
    _server->factory->kill_event_workers();
    _server->factory->kill_task_workers();
    _server->factory->kill_user_workers();
    // force kill
    if (_server->max_wait_time) {
        alarm(0);
    }
    if (_server->onManagerStop) {
        _server->onManagerStop(_server);
    }
}

void Manager::terminate_all_worker() {
    // clear the timer
    alarm(0);
    for (auto i = kill_workers.begin(); i != kill_workers.end(); i++) {
        swoole_kill(*i, SIGKILL);
    }
}

void Manager::signal_handler(int signo) {
    Server *_server = sw_server();
    if (!_server || !_server->manager) {
        return;
    }
    Manager *manager = _server->manager;
    ProcessPool *pool = &_server->gs->event_workers;

    switch (signo) {
    case SIGTERM:
        _server->running = false;
        break;
    case SIGUSR1:
    case SIGUSR2:
        _server->reload(signo == SIGUSR1);
        sw_logger()->reopen();
        break;
    case SIGIO:
        pool->read_message = true;
        break;
    case SIGALRM:
        if (manager->force_kill) {
            manager->terminate_all_worker();
        }
        break;
    default:
#ifdef SIGRTMIN
        if (signo == SIGRTMIN) {
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

    serv->factory->check_worker_exit_status(exit_worker, exit_status);

    pid_t new_process_pid = -1;

    switch (worker_type) {
    case SW_PROCESS_TASKWORKER:
        new_process_pid = serv->factory->spawn_task_worker(exit_worker);
        break;
    case SW_PROCESS_USERWORKER:
        new_process_pid = serv->factory->spawn_user_worker(exit_worker);
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

bool Server::reload(bool reload_all_workers) {
    if (is_thread_mode()) {
        return reload_worker_threads(reload_all_workers);
    }

    if (gs->manager_pid == 0) {
        swoole_error_log(SW_LOG_WARNING, SW_ERROR_OPERATION_NOT_SUPPORT, "not supported with single process mode");
        return false;
    }

    if (getpid() != gs->manager_pid) {
        return swoole_kill(get_manager_pid(), reload_all_workers ? SIGUSR1 : SIGUSR2) == 0;
    }

    ProcessPool *pool = &gs->event_workers;
    if (!pool->reload()) {
        return false;
    }

    if (reload_all_workers) {
        manager->reload_all_worker = true;
    } else {
        manager->reload_task_worker = true;
    }
    return true;
}

}  // namespace swoole
