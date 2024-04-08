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

namespace swoole {
using network::Socket;

Factory *Server::create_thread_factory() {
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
    threads_.resize(server_->task_worker_num + server_->worker_num + server_->get_user_worker_num() + 1);
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
    return true;
}

ThreadFactory::~ThreadFactory() {
    for (auto &thread : threads_) {
        thread.join();
    }
}

void ThreadFactory::at_thread_exit(Worker *worker) {
    std::unique_lock<std::mutex> _lock(lock_);
    queue_.push(worker);
    cv_.notify_one();
}

template <typename _Callable>
void ThreadFactory::create_thread(int i, _Callable fn) {
    if (threads_[i].joinable()) {
        threads_[i].join();
    }
    threads_[i] = std::thread(fn);
}

void ThreadFactory::spawn_event_worker(int i) {
    create_thread(i, [=]() {
        swoole_set_process_type(SW_PROCESS_EVENTWORKER);
        swoole_set_thread_type(Server::THREAD_WORKER);
        swoole_set_process_id(i);
        swoole_set_thread_id(i);
        Worker *worker = server_->get_worker(i);
        g_worker_instance = worker;
        worker->type = SW_PROCESS_EVENTWORKER;
        server_->worker_thread_start([=]() { Server::reactor_thread_main_loop(server_, i); });
        at_thread_exit(worker);
    });
}

void ThreadFactory::spawn_task_worker(int i) {
    create_thread(i, [=]() {
        swoole_set_process_type(SW_PROCESS_TASKWORKER);
        swoole_set_thread_type(Server::THREAD_WORKER);
        swoole_set_process_id(i);
        swoole_set_thread_id(i);
        Worker *worker = server_->get_worker(i);
        worker->type = SW_PROCESS_TASKWORKER;
        worker->status = SW_WORKER_IDLE;
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
        at_thread_exit(worker);
    });
}

void ThreadFactory::spawn_user_worker(int i) {
    create_thread(i, [=]() {
        Worker *worker = server_->user_worker_list.at(i - server_->task_worker_num - server_->worker_num);
        swoole_set_process_type(SW_PROCESS_USERWORKER);
        swoole_set_thread_type(Server::THREAD_WORKER);
        swoole_set_process_id(i);
        swoole_set_thread_id(i);
        worker->type = SW_PROCESS_USERWORKER;
        server_->worker_thread_start([=]() { server_->onUserWorkerStart(server_, worker); });
        at_thread_exit(worker);
    });
}

void ThreadFactory::spawn_manager_thread(int i) {
    create_thread(i, [=]() {
        swoole_set_process_type(SW_PROCESS_MANAGER);
        swoole_set_thread_type(Server::THREAD_WORKER);
        swoole_set_process_id(i);
        swoole_set_thread_id(i);
        manager.id = i;
        manager.type = SW_PROCESS_MANAGER;
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
    });
}

void ThreadFactory::wait() {
    while (server_->running) {
        std::unique_lock<std::mutex> _lock(lock_);
        if (!queue_.empty()) {
            Worker *exited_worker = queue_.front();
            queue_.pop();
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
            cv_.wait(_lock);
        }
    }
}

int Server::start_worker_threads() {
    /**
     * heartbeat thread
     */
    if (heartbeat_check_interval >= 1) {
        start_heartbeat_thread();
    }

    ThreadFactory *_factory = dynamic_cast<ThreadFactory *>(factory);

    if (task_worker_num > 0) {
        SW_LOOP_N(task_worker_num) {
            _factory->spawn_task_worker(worker_num + i);
        }
    }

    SW_LOOP_N(worker_num) {
        _factory->spawn_event_worker(i);
    }

    if (!user_worker_list.empty()) {
        int i = 0;
        for (auto worker : user_worker_list) {
            _factory->spawn_user_worker(task_worker_num + worker_num + i);
            i++;
        }
    }

    int manager_thread_id = task_worker_num + worker_num + get_user_worker_num();
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
}  // namespace swoole
