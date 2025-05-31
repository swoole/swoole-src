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

namespace swoole {
using network::Socket;

enum ManagerCommand {
    CMD_RELOAD = 0x1001,
    CMD_MANAGER_EXIT = 0x1002,
};

static inline Worker *cmd_ptr(const ManagerCommand cmd) {
    return reinterpret_cast<Worker *>(cmd);
}

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

void Server::destroy_thread_factory() const {
    sw_free(connection_list);
    delete[] reactor_threads;
}

ThreadFactory::ThreadFactory(Server *server) : BaseFactory(server) {
    threads_.resize(server_->get_all_worker_num() + 1);
    SW_LOOP_N(server_->get_all_worker_num() + 1) {
        threads_[i] = std::make_shared<Thread>();
    }
    cv_timeout_ms_ = -1;
}

ThreadFactory::~ThreadFactory() {
    ThreadFactory::shutdown();
}

bool ThreadFactory::start() {
    if (!server_->create_worker_pipes()) {
        return false;
    }
    if (server_->task_worker_num > 0 && server_->get_task_worker_pool()->start_check() < 0) {
        return false;
    }
    if (server_->get_user_worker_num() > 0 && server_->create_user_workers() < 0) {
        return false;
    }
    return true;
}

bool ThreadFactory::shutdown() {
    for (const auto &thread : threads_) {
        if (thread->joinable()) {
            thread->join();
        }
    }
    return true;
}

void ThreadFactory::at_thread_enter(WorkerId id, int worker_type) {
    swoole_thread_init(false);

    swoole_set_worker_type(worker_type);
    swoole_set_worker_id(id);
    swoole_set_worker_pid(swoole_thread_get_native_id());

    swoole_set_thread_id(id);
    swoole_set_thread_type(Server::THREAD_WORKER);

    swoole_info("at_thread_enter=%d join", id);
}

void ThreadFactory::push_to_wait_queue(Worker *worker) {
    lock_.lock();
    queue_.push(worker);
    lock_.unlock();
    cv_.notify_one();
    swoole_info("push [%p] to wait queue", worker);
}

void ThreadFactory::at_thread_exit(Worker *worker) {
    if (worker) {
        push_to_wait_queue(worker);
    }
    swoole_thread_clean(false);
}

void ThreadFactory::create_message_bus() const {
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
        const auto pool = server_->get_task_worker_pool();
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
    while (true) {
        std::unique_lock lock(lock_);
        if (cv_timeout_ms_ > 0) {
            cv_.wait_for(lock, std::chrono::milliseconds(cv_timeout_ms_), [this] { return !queue_.empty(); });
        } else {
            cv_.wait(lock, [this] { return !queue_.empty(); });
        }

        swoole_info("manager thread is waiting for worker exit, queue size: %zu", queue_.size());

        if (!queue_.empty()) {
            Worker *exited_worker = queue_.front();
            queue_.pop();
            lock.unlock();

            if (exited_worker == cmd_ptr(CMD_RELOAD)) {
                goto _do_reload;
            }
            if (exited_worker == cmd_ptr(CMD_MANAGER_EXIT)) {
                break;
            }

            swoole_info("worker(type=%d, tid=%d, id=%d) exit, status=%d",
                        exited_worker->type,
                        exited_worker->pid,
                        exited_worker->id,
                        exited_worker->status);

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

            swoole_info("thread=%d join", exited_worker->id);

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
        }

        if (sw_timer()) {
            sw_timer()->select();
        }
        if (server_->running && reloading) {
        _do_reload:
            do_reload();
        }
    }
}

ThreadReloadTask::ThreadReloadTask(Server *_server, bool _reload_all_workers) {
    server_ = _server;
    worker_num = server_->get_core_worker_num();
    // If only reloading task workers, skip the event workers.
    reloaded_num = _reload_all_workers ? 0 : server_->worker_num;
}

void ThreadFactory::do_reload() {
    if (!reload_task) {
        reload_task = std::make_shared<ThreadReloadTask>(server_, reload_all_workers);
        if (server_->onBeforeReload) {
            server_->onBeforeReload(server_);
        }
    }
    server_->kill_worker(reload_task->reloaded_num++);
    if (reload_task->is_completed()) {
        reload_task.reset();
        reloading = 0;
        if (server_->onAfterReload) {
            server_->onAfterReload(server_);
        }
    }
}

bool ThreadFactory::reload(bool _reload_all_workers) {
    auto _what = _reload_all_workers ? "all" : "task";

    // Prevent duplicate submission of reload requests.
    if (!sw_atomic_cmp_set(&reloading, 0, 1)) {
        swoole_set_last_error(SW_ERROR_OPERATION_NOT_SUPPORT);
        return false;
    }

    if (server_->task_worker_num == 0 && !_reload_all_workers) {
        swoole_error_log(SW_LOG_WARNING,
                         SW_ERROR_OPERATION_NOT_SUPPORT,
                         "Cannot reload %s workers, task workers are not started",
                         _what);
        reloading = 0;
        return false;
    }

    reload_all_workers = _reload_all_workers;
    if (!server_->is_manager()) {
        swoole_info("Send a notification to the manager process to prepare for restarting %s worker processes.", _what);
        push_to_wait_queue(cmd_ptr(CMD_RELOAD));
    } else {
        swoole_info("Server is reloading %s workers now", _what);
        do_reload();
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
    swoole_trace_log(SW_TRACE_THREAD, "notify manager thread to exit");
    push_to_wait_queue(cmd_ptr(CMD_MANAGER_EXIT));

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

    SW_LOOP_N(get_core_worker_num()) {
        kill_worker(i);
    }
}

bool Server::reload_worker_threads(bool reload_all_workers) const {
    auto *_factory = dynamic_cast<ThreadFactory *>(factory);
    return _factory->reload(reload_all_workers);
}

}  // namespace swoole
