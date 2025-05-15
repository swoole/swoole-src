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
struct Manager {
    bool reload_all_worker;
    bool reload_task_worker;
    bool force_kill;
    Server *server_;

    std::vector<pid_t> kill_workers;

    void wait(Server *_server);
    void terminate_all_worker();

    static void signal_handler(int sig);
    static void timer_callback(Timer *timer, TimerNode *tnode);
};

void Manager::timer_callback(Timer *timer, TimerNode *tnode) {
    auto *serv = (Server *) tnode->data;
    if (serv->isset_hook(Server::HOOK_MANAGER_TIMER)) {
        serv->call_hook(Server::HOOK_MANAGER_TIMER, serv);
    }
}

int Server::start_manager_process() {
    SW_LOOP_N(worker_num) {
        create_worker(get_worker(i));
    }

    if (gs->event_workers.create_message_box(SW_MESSAGE_BOX_SIZE) == SW_ERR) {
        return SW_ERR;
    }

    if (get_user_worker_num() > 0 && create_user_workers() < 0) {
        return SW_ERR;
    }

    auto fn = [this]() {
        gs->manager_pid = getpid();

        if (task_worker_num > 0) {
            if (gs->task_workers.start() == SW_ERR) {
                swoole_sys_error("failed to start task worker");
                return;
            }
        }

        /*
         * Must be set after ProcessPool:start(),
         * the default ProcessPool will set type of the main process as SW_MASTER,
         * while in server mode it should be SW_MANAGER
         */
        swoole_set_worker_type(SW_MANAGER);

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
    pool->max_wait_time = server_->max_wait_time;
    _server->gs->manager_pid = _server->gs->event_workers.master_pid = getpid();

    swoole_event_free();

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
        swoole_timer_add(sec2msec(_server->manager_alarm), true, timer_callback, _server);
    }

    while (_server->running) {
        ExitStatus exit_status = wait_process();
        const auto wait_error = errno;

        swoole_signal_dispatch();

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

        if (sw_timer()) {
            sw_timer()->select();
        }

        if (exit_status.get_pid() < 0) {
            if (!pool->reload_task) {
                if (wait_error > 0 && wait_error != EINTR) {
                    swoole_sys_warning("wait() failed");
                }
                continue;
            }
        }

        if (_server->running) {
            if (reload_all_worker) {  // reload task & event workers
                pool->reload_init = reload_all_worker = false;
                swoole_info("Server is reloading all workers now");
                if (_server->onBeforeReload != nullptr) {
                    _server->onBeforeReload(_server);
                }
                auto reload_task = pool->reload_task;
                reload_task->add_workers(_server->workers, _server->worker_num);
                if (_server->task_worker_num > 0) {
                    reload_task->add_workers(_server->gs->task_workers.workers, _server->task_worker_num);
                }
                if (_server->reload_async) {
                    for (auto elem : reload_task->workers) {
                        if (swoole_kill(elem.first, SIGTERM) < 0) {
                            swoole_sys_warning("failed to kill(%d, SIGTERM) worker#[%d]", elem.first, elem.second->id);
                        }
                    }
                }
                goto _kill_worker;
            } else if (reload_task_worker) {  // only reload task workers
                pool->reload_init = reload_task_worker = false;
                if (_server->task_worker_num == 0) {
                    swoole_warning("cannot reload task workers, task workers is not started");
                    continue;
                }
                swoole_info("Server is reloading task workers now");
                if (_server->onBeforeReload != nullptr) {
                    _server->onBeforeReload(_server);
                }
                auto reload_task = pool->reload_task;
                reload_task->add_workers(_server->gs->task_workers.workers, _server->task_worker_num);
                goto _kill_worker;
            } else if (exit_status.get_pid() < 0) {
                continue;
            }

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
                } while (false);
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
            if (pool->reload_task) {
                pool->reload_task->remove(exit_status.get_pid());
            }
        }

        if (pool->reload_task) {
            // reload finish
            if (pool->reload_task->is_completed()) {
                delete pool->reload_task;
                pool->reload_task = nullptr;
                if (_server->onAfterReload != nullptr) {
                    _server->onAfterReload(_server);
                }
            } else {
            _kill_worker:
                pool->reload_task->kill_one(SIGTERM);
            }
        }
    }

    if (pool->reload_task) {
        delete pool->reload_task;
        pool->reload_task = nullptr;
    }

    if (swoole_timer_is_available()) {
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
    for (int &kill_worker : kill_workers) {
        swoole_kill(kill_worker, SIGKILL);
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
    auto serv = (Server *) pool->ptr;
    Worker *exit_worker = nullptr;
    int worker_type;

    do {
        if (serv->gs->task_workers.map_) {
            auto iter = serv->gs->task_workers.map_->find(exit_status.get_pid());
            if (iter != serv->gs->task_workers.map_->end()) {
                worker_type = SW_TASK_WORKER;
                exit_worker = iter->second;
                break;
            }
        }
        if (!serv->user_worker_map.empty()) {
            auto iter = serv->user_worker_map.find(exit_status.get_pid());
            if (iter != serv->user_worker_map.end()) {
                worker_type = SW_USER_WORKER;
                exit_worker = iter->second;
                break;
            }
        }
        return SW_ERR;
    } while (false);

    serv->factory->check_worker_exit_status(exit_worker, exit_status);

    pid_t new_process_pid = -1;

    switch (worker_type) {
    case SW_TASK_WORKER:
        new_process_pid = serv->factory->spawn_task_worker(exit_worker);
        break;
    case SW_USER_WORKER:
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

    auto serv = (Server *) pool->ptr;
    int command_id = msg->info.server_fd;
    auto iter = serv->command_handlers.find(command_id);
    if (iter == serv->command_handlers.end()) {
        swoole_error_log(SW_LOG_ERROR, SW_ERROR_SERVER_INVALID_COMMAND, "Unknown command[command_id=%d]", command_id);
        return;
    }

    Command::Handler handler = iter->second;
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
