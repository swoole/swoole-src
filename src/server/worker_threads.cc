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

#include <condition_variable>

namespace swoole {
using network::Socket;

struct WorkerThreads {
    std::vector<std::thread> threads_;
    std::mutex lock_;
    std::condition_variable cv_;
    std::queue<Worker *> queue_;
    Server *server_;

    WorkerThreads(Server *server) {
        server_ = server;
        threads_.resize(server_->task_worker_num + server_->worker_num + server_->get_user_worker_num());
    }

    ~WorkerThreads() {
        for (auto &thread : threads_) {
            thread.join();
        }
    }

    void worker_exit(Worker *worker) {
        std::unique_lock<std::mutex> _lock(lock_);
        queue_.push(worker);
        cv_.notify_one();
    }

    template<typename _Callable>
    void create_thread(int i, _Callable fn) {
        if (threads_[i].joinable()) {
            threads_[i].join();
        }
        threads_[i] = std::thread(fn);
    }

    void spawn_event_worker(int i) {
        create_thread(i, [=]() {
            sw_set_process_type(SW_PROCESS_EVENTWORKER);
            sw_set_process_id(i);
            Worker *worker = server_->get_worker(i);
            worker->type = SW_PROCESS_EVENTWORKER;
            server_->worker_thread_start(
                [=](void) -> bool { return server_->worker_main_loop(&server_->gs->event_workers, worker) == SW_OK; });
            worker_exit(worker);
        });
    }

    void spawn_task_worker(int i) {
        create_thread(i, [=]() {
            sw_set_process_type(SW_PROCESS_TASKWORKER);
            sw_set_process_id(i);
            Worker *worker = server_->get_worker(i);
            worker->type = SW_PROCESS_TASKWORKER;
            server_->worker_thread_start([=](void) -> bool {
                return server_->gs->task_workers.main_loop(&server_->gs->task_workers, worker) == SW_OK;
            });
            worker_exit(worker);
        });
    }

    void spawn_user_worker(int i) {
        create_thread(i, [=]() {
            Worker *worker = server_->user_worker_list.at(i - server_->task_worker_num - server_->worker_num);
            sw_set_process_type(SW_PROCESS_USERWORKER);
            sw_set_process_id(i);
            worker->type = SW_PROCESS_USERWORKER;
            server_->worker_thread_start([=](void) -> bool {
                server_->onUserWorkerStart(server_, worker);
                return SW_OK;
            });
            worker_exit(worker);
        });
    }

    void wait() {
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
};

int Server::start_worker_threads() {
    single_thread = 1;
    sw_set_process_type(SW_PROCESS_MANAGER);

    // listen TCP
    if (have_stream_sock == 1) {
        for (auto ls : ports) {
            if (ls->is_dgram()) {
                continue;
            }
#ifdef HAVE_REUSEPORT
            if (enable_reuse_port) {
                if (::close(ls->socket->fd) < 0) {
                    swoole_sys_warning("close(%d) failed", ls->socket->fd);
                }
                delete ls->socket;
                ls->socket = nullptr;
                continue;
            } else
#endif
            {
                // listen server socket
                if (ls->listen() < 0) {
                    return SW_ERR;
                }
            }
        }
    }

    ProcessPool *pool = &gs->event_workers;
    *pool = {};
    if (pool->create(worker_num, 0, SW_IPC_UNIXSOCK) < 0) {
        return SW_ERR;
    }
    pool->set_max_request(max_request, max_request_grace);

    /**
     * store to ProcessPool object
     */
    gs->event_workers.ptr = this;
    gs->event_workers.max_wait_time = max_wait_time;
    gs->event_workers.use_msgqueue = 0;
    gs->event_workers.main_loop = worker_main_loop;
    memcpy(workers, gs->event_workers.workers, sizeof(*workers) * worker_num);
    gs->event_workers.workers = workers;

    SW_LOOP_N(worker_num) {
        gs->event_workers.workers[i].pool = &gs->event_workers;
        gs->event_workers.workers[i].id = i;
        gs->event_workers.workers[i].type = SW_PROCESS_WORKER;
    }

    init_ipc_max_size();
    if (create_pipe_buffers() < 0) {
        return SW_ERR;
    }

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

    WorkerThreads worker_threads(this);

    if (task_worker_num > 0) {
        SW_LOOP_N(task_worker_num) {
            worker_threads.spawn_task_worker(worker_num + i);
        }
    }

    SW_LOOP_N(worker_num) {
        worker_threads.spawn_event_worker(i);
    }

    if (!user_worker_list.empty()) {
        int i = 0;
        for (auto worker : user_worker_list) {
            worker_threads.spawn_user_worker(task_worker_num + worker_num + i);
            i++;
        }
    }

    worker_threads.wait();

    return SW_OK;
}
}  // namespace swoole
