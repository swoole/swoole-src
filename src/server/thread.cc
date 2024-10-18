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
#include "swoole_memory.h"
#include "swoole_thread.h"

#define SW_RELOAD_SLEEP_FOR 100000

namespace swoole {
using network::Socket;

Factory *Server::create_thread_factory() {
#ifndef SW_THREAD
    swoole_error("Thread support is not enabled, cannot create server with MODE_THREAD");
    return nullptr;
#endif
    reactor_num = worker_num;
    connection_list = (Connection *) sw_calloc(max_connection, sizeof(Connection));
    if (connection_list == nullptr) {
        swoole_sys_warning("calloc[2](%d) failed", (int) (max_connection * sizeof(Connection)));
        return nullptr;
    }
    reactor_threads = new ReactorThread[reactor_num]();
    reactor_pipe_num = 1;
    return new ThreadFactory(this);
}

void Server::destroy_thread_factory() {
    sw_free(connection_list);
    delete[] reactor_threads;
}

ThreadFactory::ThreadFactory(Server *server) : BaseFactory(server) {
    threads_.resize(server_->get_all_worker_num() + 1);
    reloading = false;
    reload_all_workers = false;
    cv_timeout_ms_ = -1;
}

bool ThreadFactory::start() {
    if (!server_->create_worker_pipes()) {
        return false;
    }
    if (server_->task_worker_num > 0 &&
        (server_->create_task_workers() < 0 || server_->gs->task_workers.start_check() < 0)) {
        return false;
    }
    if (server_->get_user_worker_num() > 0 && server_->create_user_workers() < 0) {
        return false;
    }
    return true;
}

bool ThreadFactory::shutdown() {
    for (auto &thread : threads_) {
        if (thread.joinable()) {
            join_thread(thread);
        }
    }
    if (server_->heartbeat_check_interval > 0) {
        server_->join_heartbeat_thread();
    }
    return true;
}

ThreadFactory::~ThreadFactory() {}

void ThreadFactory::at_thread_exit(Worker *worker) {
    std::unique_lock<std::mutex> _lock(lock_);
    queue_.push(worker);
    cv_.notify_one();
}

void ThreadFactory::create_message_bus() {
    auto mb = new MessageBus();
    mb->set_id_generator(server_->msg_id_generator);
    mb->set_buffer_size(server_->ipc_max_size);
    mb->set_always_chunked_transfer();
    if (!mb->alloc_buffer()) {
        throw std::bad_alloc();
    }
    server_->init_pipe_sockets(mb);
    SwooleTG.message_bus = mb;
}

void ThreadFactory::destroy_message_bus() {
    SwooleTG.message_bus->clear();
    delete SwooleTG.message_bus;
    SwooleTG.message_bus = nullptr;
}

template <typename _Callable>
void ThreadFactory::create_thread(int i, _Callable fn) {
    threads_[i] = std::thread(fn);
}

void ThreadFactory::join_thread(std::thread &thread) {
    thread.join();
    if (server_->worker_thread_join) {
        server_->worker_thread_join(thread.native_handle());
    }
}

void ThreadFactory::spawn_event_worker(WorkerId i) {
    create_thread(i, [=]() {
        swoole_set_process_type(SW_PROCESS_EVENTWORKER);
        swoole_set_thread_type(Server::THREAD_WORKER);
        swoole_set_process_id(i);
        swoole_set_thread_id(i);
        Worker *worker = server_->get_worker(i);
        worker->type = SW_PROCESS_EVENTWORKER;
        worker->pid = swoole_thread_get_native_id();
        SwooleWG.worker = worker;
        server_->worker_thread_start([=]() { Server::reactor_thread_main_loop(server_, i); });
        at_thread_exit(worker);
    });
}

void ThreadFactory::spawn_task_worker(WorkerId i) {
    create_thread(i, [=]() {
        swoole_set_process_type(SW_PROCESS_TASKWORKER);
        swoole_set_thread_type(Server::THREAD_WORKER);
        swoole_set_process_id(i);
        swoole_set_thread_id(i);
        create_message_bus();
        Worker *worker = server_->get_worker(i);
        worker->type = SW_PROCESS_TASKWORKER;
        worker->pid = swoole_thread_get_native_id();
        worker->set_status_to_idle();
        SwooleWG.worker = worker;
        auto pool = &server_->gs->task_workers;
        server_->worker_thread_start([=]() {
            if (pool->onWorkerStart != nullptr) {
                pool->onWorkerStart(pool, worker);
            }
            pool->main_loop(pool, worker);
            if (pool->onWorkerStop != nullptr) {
                pool->onWorkerStop(pool, worker);
            }
        });
        destroy_message_bus();
        at_thread_exit(worker);
    });
}

void ThreadFactory::spawn_user_worker(WorkerId i) {
    create_thread(i, [=]() {
        Worker *worker = server_->get_worker(i);
        swoole_set_process_type(SW_PROCESS_USERWORKER);
        swoole_set_thread_type(Server::THREAD_WORKER);
        swoole_set_process_id(i);
        swoole_set_thread_id(i);
        create_message_bus();
        worker->type = SW_PROCESS_USERWORKER;
        worker->pid = swoole_thread_get_native_id();
        SwooleWG.worker = worker;
        server_->worker_thread_start([=]() { server_->onUserWorkerStart(server_, worker); });
        destroy_message_bus();
        at_thread_exit(worker);
    });
}

void ThreadFactory::spawn_manager_thread(WorkerId i) {
    create_thread(i, [=]() {
        swoole_set_process_type(SW_PROCESS_MANAGER);
        swoole_set_thread_type(Server::THREAD_WORKER);
        swoole_set_process_id(i);
        swoole_set_thread_id(i);
        manager.id = i;
        manager.type = SW_PROCESS_MANAGER;

        SwooleTG.timer_scheduler = [this](Timer *timer, long exec_msec) -> int {
            cv_timeout_ms_ = exec_msec;
            return SW_OK;
        };

        server_->worker_thread_start([=]() {
            if (server_->onManagerStart) {
                server_->onManagerStart(server_);
            }
            wait();
            if (server_->onManagerStop) {
                server_->onManagerStop(server_);
            }
        });

        if (server_->running) {
            swoole_warning("Fatal Error: manager thread exits abnormally");
        }

        SwooleTG.timer_scheduler = nullptr;
    });
}

void ThreadFactory::wait() {
    while (server_->running) {
        std::unique_lock<std::mutex> _lock(lock_);
        if (!queue_.empty()) {
            Worker *exited_worker = queue_.front();
            queue_.pop();

            std::thread &thread = threads_[exited_worker->id];
            int status_code = 0;
            if (server_->worker_thread_get_exit_status) {
                status_code = server_->worker_thread_get_exit_status(thread.native_handle());
            }
            if (status_code != 0) {
                ExitStatus exit_status(exited_worker->pid, status_code << 8);
                server_->call_worker_error_callback(exited_worker, exit_status);
                swoole_warning("worker(tid=%d, id=%d) abnormal exit, status=%d",
                               exit_status.get_pid(),
                               exited_worker->id,
                               exit_status.get_code());
            }

            join_thread(threads_[exited_worker->id]);

            switch (exited_worker->type) {
            case SW_PROCESS_EVENTWORKER:
                spawn_event_worker(exited_worker->id);
                break;
            case SW_PROCESS_TASKWORKER:
                spawn_task_worker(exited_worker->id);
                break;
            case SW_PROCESS_USERWORKER:
                spawn_user_worker(exited_worker->id);
                break;
            default:
                abort();
                break;
            }
            _lock.unlock();
        } else {
            if (cv_timeout_ms_ > 0) {
                cv_.wait_for(_lock, std::chrono::milliseconds(cv_timeout_ms_));
            } else {
                cv_.wait(_lock);
            }
        }
        if (sw_timer()) {
            sw_timer()->select();
        }
        if (server_->running && reloading) {
            reload(reload_all_workers);
        }
    }
}

bool ThreadFactory::reload(bool _reload_all_workers) {
    if (!server_->is_manager()) {
        // Prevent duplicate submission of reload requests.
        if (reloading) {
            swoole_set_last_error(SW_ERROR_OPERATION_NOT_SUPPORT);
            return false;
        }
        reloading = true;
        reload_all_workers = _reload_all_workers;
        std::unique_lock<std::mutex> _lock(lock_);
        cv_.notify_one();
    } else {
        swoole_info("Server is reloading %s workers now", _reload_all_workers ? "all" : "task");
        if (server_->onBeforeReload) {
            server_->onBeforeReload(server_);
        }
        SW_LOOP_N(server_->get_core_worker_num()) {
            if (i < server_->worker_num && !_reload_all_workers) {
                continue;
            }
            if (!server_->kill_worker(i, true)) {
                return false;
            }
            SW_LOOP {
                usleep(SW_RELOAD_SLEEP_FOR);
                // This worker thread has exited, proceeding to terminate the next one.
                if (threads_[i].joinable()) {
                    break;
                }
            }
        }
        reload_all_workers = false;
        reloading = false;
        if (server_->onAfterReload) {
            server_->onAfterReload(server_);
        }
    }

    return true;
}

int Server::start_worker_threads() {
    ThreadFactory *_factory = dynamic_cast<ThreadFactory *>(factory);

    if (heartbeat_check_interval > 0) {
        start_heartbeat_thread();
    }

    if (task_worker_num > 0) {
        SW_LOOP_N(task_worker_num) {
            _factory->spawn_task_worker(worker_num + i);
        }
    }

    SW_LOOP_N(worker_num) {
        _factory->spawn_event_worker(i);
    }

    if (!user_worker_list.empty()) {
        for (size_t i = 0; i < user_worker_list.size(); i++) {
            _factory->spawn_user_worker(task_worker_num + worker_num + i);
        }
    }

    int manager_thread_id = get_all_worker_num();
    _factory->spawn_manager_thread(manager_thread_id);

    if (swoole_event_init(0) < 0) {
        return SW_ERR;
    }

    Reactor *reactor = sw_reactor();
    for (auto iter = ports.begin(); iter != ports.end(); iter++) {
        auto port = *iter;
        if (port->is_dgram()) {
            continue;
        }
        if (port->listen() < 0) {
            swoole_event_free();
            return SW_ERR;
        }
        reactor->add(port->socket, SW_EVENT_READ);
    }

    SwooleTG.id = reactor->id = manager_thread_id + 1;
    store_listen_socket();

    return start_master_thread(reactor);
}

void Server::stop_worker_threads() {
    DataHead event = {};
    event.type = SW_SERVER_EVENT_SHUTDOWN;

    SW_LOOP_N(worker_num) {
        send_to_worker_from_worker(get_worker(i), &event, sizeof(event), SW_PIPE_MASTER);
    }

    if (task_worker_num > 0) {
        SW_LOOP_N(task_worker_num) {
            send_to_worker_from_worker(get_worker(worker_num + i), &event, sizeof(event), SW_PIPE_MASTER);
        }
    }
}

bool Server::reload_worker_threads(bool reload_all_workers) {
    ThreadFactory *_factory = dynamic_cast<ThreadFactory *>(factory);
    return _factory->reload(reload_all_workers);
}

}  // namespace swoole
