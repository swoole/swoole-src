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
#include "swoole_thread.h"

#define SW_RELOAD_SLEEP_FOR 100000

namespace swoole {
using network::Socket;

Factory *Server::create_thread_factory() {
#ifndef SW_THREAD
    swoole_error_log(SW_LOG_ERROR,
                     SW_ERROR_OPERATION_NOT_SUPPORT,
                     "Thread support is not enabled, cannot create server with MODE_THREAD");
    return nullptr;
#endif
    reactor_num = worker_num;
    connection_list = static_cast<Connection *>(sw_calloc(max_connection, sizeof(Connection)));
    if (connection_list == nullptr) {
        swoole_sys_warning("calloc[2](%d) failed", static_cast<int>(max_connection * sizeof(Connection)));
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
    SW_LOOP_N(server_->get_all_worker_num() + 1) {
        threads_[i] = std::make_shared<Thread>();
    }
    reloading = false;
    reload_all_workers = false;
    cv_timeout_ms_ = -1;
}

bool ThreadFactory::start() {
    if (!server_->create_worker_pipes()) {
        return false;
    }
    if (server_->task_worker_num > 0 && server_->gs->task_workers.start_check() < 0) {
        return false;
    }
    if (server_->get_user_worker_num() > 0 && server_->create_user_workers() < 0) {
        return false;
    }
    return true;
}

bool ThreadFactory::shutdown() {
    for (auto &thread : threads_) {
        if (thread->joinable()) {
            thread->join();
        }
    }
    return true;
}

ThreadFactory::~ThreadFactory() = default;

void ThreadFactory::at_thread_enter(WorkerId id, int worker_type) {
    swoole_thread_init(false);

    swoole_set_worker_type(worker_type);
    swoole_set_worker_id(id);
    swoole_set_worker_pid(swoole_thread_get_native_id());

    swoole_set_thread_id(id);
    swoole_set_thread_type(Server::THREAD_WORKER);
}

void ThreadFactory::at_thread_exit(Worker *worker) {
    if (worker) {
        std::unique_lock<std::mutex> _lock(lock_);
        queue_.push(worker);
        cv_.notify_one();
    }
    swoole_thread_clean(false);
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

void ThreadFactory::spawn_event_worker(WorkerId i) {
    threads_[i]->start([=]() {
        at_thread_enter(i, SW_EVENT_WORKER);

        Worker *worker = server_->get_worker(i);
        worker->type = SW_EVENT_WORKER;
        worker->pid = swoole_get_worker_pid();
        SwooleWG.worker = worker;
        server_->worker_thread_start(threads_[i], [=]() { Server::reactor_thread_main_loop(server_, i); });

        at_thread_exit(worker);
    });
}

void ThreadFactory::spawn_task_worker(WorkerId i) {
    threads_[i]->start([=]() {
        at_thread_enter(i, SW_TASK_WORKER);

        create_message_bus();
        Worker *worker = server_->get_worker(i);
        worker->type = SW_TASK_WORKER;
        worker->pid = swoole_get_worker_pid();
        worker->set_status_to_idle();
        SwooleWG.worker = worker;
        auto pool = &server_->gs->task_workers;
        server_->worker_thread_start(threads_[i], [=]() {
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
    threads_[i]->start([=]() {
        at_thread_enter(i, SW_USER_WORKER);

        create_message_bus();
        Worker *worker = server_->get_worker(i);
        worker->type = SW_USER_WORKER;
        worker->pid = swoole_get_worker_pid();
        SwooleWG.worker = worker;
        server_->worker_thread_start(threads_[i], [=]() { server_->onUserWorkerStart(server_, worker); });
        destroy_message_bus();

        at_thread_exit(worker);
    });
}

void ThreadFactory::spawn_manager_thread(WorkerId i) {
    threads_[i]->start([=]() {
        at_thread_enter(i, SW_MANAGER);

        manager.id = i;
        manager.pid = swoole_get_worker_pid();
        manager.type = SW_MANAGER;

        swoole_timer_set_scheduler([this](Timer *timer, long exec_msec) -> int {
            cv_timeout_ms_ = exec_msec;
            return SW_OK;
        });

        server_->worker_thread_start(threads_[i], [=]() {
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

        /*
         * In the function that closes the timer, the scheduler is called again;
         * therefore, it is essential to set the scheduler to null after the timer has been consumed.
         */
        if (swoole_timer_is_available()) {
            swoole_timer_free();
        }
        swoole_timer_set_scheduler(nullptr);

        at_thread_exit(nullptr);
    });
}

void ThreadFactory::wait() {
    while (server_->running) {
        std::unique_lock<std::mutex> _lock(lock_);
        if (!queue_.empty()) {
            Worker *exited_worker = queue_.front();
            queue_.pop();

            swoole_trace_log(SW_TRACE_THREAD,
                             "worker(tid=%d, id=%d) exit, status=%d",
                             exited_worker->pid,
                             exited_worker->id,
                             exited_worker->status);

            if (exited_worker == &manager) {
                server_->running = false;
                _lock.unlock();
                break;
            }

            auto thread = threads_[exited_worker->id];
            int status_code = thread->get_exit_status();
            if (status_code != 0) {
                ExitStatus exit_status(exited_worker->pid, status_code << 8);
                server_->call_worker_error_callback(exited_worker, exit_status);
                swoole_warning("worker(tid=%d, id=%d) abnormal exit, status=%d",
                               exit_status.get_pid(),
                               exited_worker->id,
                               exit_status.get_code());
            }

            thread->join();

            switch (exited_worker->type) {
            case SW_EVENT_WORKER:
                spawn_event_worker(exited_worker->id);
                break;
            case SW_TASK_WORKER:
                spawn_task_worker(exited_worker->id);
                break;
            case SW_USER_WORKER:
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
                if (threads_[i]->joinable()) {
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

WorkerId ThreadFactory::get_manager_thread_id() const {
    return server_->get_all_worker_num();
}

WorkerId ThreadFactory::get_master_thread_id() const {
    return server_->get_all_worker_num() + 1;
}

void ThreadFactory::terminate_manager_thread() {
    do {
        swoole_trace_log(SW_TRACE_THREAD, "notify manager thread to exit");
        std::unique_lock<std::mutex> _lock(lock_);
        queue_.push(&manager);
        cv_.notify_one();
    } while (false);

    /**
     * When terminating the service, the management thread may still be joining other worker threads,
     * so it is essential to first reclaim the management thread to ensure it has exited.
     * During the shutdown, the running flag has already been set to false,
     * which means the management thread might not have reclaimed all worker threads and may have exited prematurely.
     * At this point, it is necessary to loop through and reclaim the remaining worker threads.
     */
    auto manager_thread_id = get_manager_thread_id();
    threads_[manager_thread_id]->join();

    swoole_trace_log(SW_TRACE_THREAD, "manager thread is exited");
}

int Server::start_worker_threads() {
    auto *_factory = dynamic_cast<ThreadFactory *>(factory);

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

    auto manager_thread_id = _factory->get_manager_thread_id();
    _factory->spawn_manager_thread(manager_thread_id);

    if (swoole_event_init(0) < 0) {
        return SW_ERR;
    }

    Reactor *reactor = sw_reactor();
    for (const auto port : ports) {
        if (port->is_dgram()) {
            continue;
        }
        if (port->listen() < 0) {
            swoole_event_free();
            return SW_ERR;
        }
        reactor->add(port->socket, SW_EVENT_READ);
    }

    SwooleTG.id = reactor->id = _factory->get_master_thread_id();
    store_listen_socket();

    return start_master_thread(reactor);
}

void Server::stop_worker_threads() {
    auto *_factory = dynamic_cast<ThreadFactory *>(factory);
    _factory->terminate_manager_thread();

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
    auto *_factory = dynamic_cast<ThreadFactory *>(factory);
    return _factory->reload(reload_all_workers);
}

}  // namespace swoole
