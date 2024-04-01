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

int Server::start_worker_threads() {
    single_thread = 1;

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

    std::vector<std::thread> threads;
    threads.resize(task_worker_num + worker_num + get_user_worker_num());

    if (task_worker_num > 0) {
        SW_LOOP_N(task_worker_num) {
            threads[worker_num + i] = std::thread([=]() {
                SwooleTG.type = Server::THREAD_WORKER;
                SwooleTG.id = worker_num + i;
                Worker *worker = gs->task_workers.get_worker(i);
                worker_thread_start(
                    [=](void) -> bool { return gs->task_workers.main_loop(&gs->task_workers, worker) == SW_OK; });
            });
        }
    }

    SW_LOOP_N(worker_num) {
        threads[i] = std::thread([=]() {
            SwooleTG.type = Server::THREAD_WORKER;
            SwooleTG.id = i;
            Worker *worker = get_worker(i);
            worker_thread_start([=](void) -> bool { return worker_main_loop(&gs->event_workers, worker) == SW_OK; });
        });
    }

    if (!user_worker_list.empty()) {
        int i = 0;
        for (auto worker : user_worker_list) {
            threads[task_worker_num + worker_num + i] = std::thread([=]() {
                SwooleTG.type = Server::THREAD_WORKER;
                SwooleTG.id = task_worker_num + worker_num + i;
                worker_thread_start([=](void) -> bool {
                    onUserWorkerStart(this, worker);
                    return SW_OK;
                });
            });
            i++;
        }
    }

    for (auto &thread : threads) {
        thread.join();
    }

    return SW_OK;
}
}  // namespace swoole
