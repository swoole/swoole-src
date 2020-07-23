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

#include "swoole_api.h"
#include "swoole_memory.h"
#include "swoole_signal.h"
#include "swoole_socket.h"
#include "swoole_string.h"
#include "swoole_log.h"
#include "msg_queue.h"
#include "pipe.h"
#include "server.h"
#include "process_pool.h"
#include "client.h"

using swoole::ProcessPool;

/**
 * call onTask
 */
static int ProcessPool_worker_loop(ProcessPool *pool, swWorker *worker);
/**
 * call onMessage
 */
static int ProcessPool_worker_loop_ex(ProcessPool *pool, swWorker *worker);

static void ProcessPool_kill_timeout_worker(swTimer *timer, swTimer_node *tnode) {
    uint32_t i;
    pid_t reload_worker_pid = 0;
    ProcessPool *pool = (ProcessPool *) tnode->data;
    pool->reloading = false;

    for (i = 0; i < pool->worker_num; i++) {
        if (i >= pool->reload_worker_i) {
            reload_worker_pid = pool->reload_workers[i].pid;
            if (swoole_kill(reload_worker_pid, 0) == -1) {
                continue;
            }
            if (swoole_kill(reload_worker_pid, SIGKILL) < 0) {
                swSysWarn("swKill(%d, SIGKILL) [%d] failed", pool->reload_workers[i].pid, i);
            } else {
                swWarn("swKill(%d, SIGKILL) [%d]", pool->reload_workers[i].pid, i);
            }
        }
    }
    errno = 0;
    pool->reload_worker_i = 0;
    pool->reload_init = false;
}
/**
 * Process manager
 */
int ProcessPool::create(ProcessPool *pool, uint32_t worker_num, key_t msgqueue_key, int ipc_mode) {
    *pool = {};
    uint32_t i;

    pool->worker_num = worker_num;

    /**
     * Shared memory is used here
     */
    pool->workers = (swWorker *) SwooleG.memory_pool->alloc(SwooleG.memory_pool, worker_num * sizeof(swWorker));
    if (pool->workers == nullptr) {
        swSysWarn("malloc[1] failed");
        return SW_ERR;
    }

    if (ipc_mode == SW_IPC_MSGQUEUE) {
        pool->use_msgqueue = 1;
        pool->msgqueue_key = msgqueue_key;

        pool->queue = (swMsgQueue *) sw_malloc(sizeof(swMsgQueue));
        if (pool->queue == nullptr) {
            swSysWarn("malloc[2] failed");
            return SW_ERR;
        }

        if (swMsgQueue_create(pool->queue, 1, pool->msgqueue_key, 0) < 0) {
            return SW_ERR;
        }
    } else if (ipc_mode == SW_IPC_UNIXSOCK) {
        pool->pipes = (swPipe *) sw_calloc(worker_num, sizeof(swPipe));
        if (pool->pipes == nullptr) {
            swWarn("malloc[2] failed");
            return SW_ERR;
        }

        swPipe *pipe;
        for (i = 0; i < worker_num; i++) {
            pipe = &pool->pipes[i];
            if (swPipeUnsock_create(pipe, 1, SOCK_DGRAM) < 0) {
                return SW_ERR;
            }
            pool->workers[i].pipe_master = pipe->getSocket(pipe, SW_PIPE_MASTER);
            pool->workers[i].pipe_worker = pipe->getSocket(pipe, SW_PIPE_WORKER);
            pool->workers[i].pipe_object = pipe;
        }
    } else if (ipc_mode == SW_IPC_SOCKET) {
        pool->use_socket = 1;
        pool->stream_info_ = new swStreamInfo();
    } else {
        ipc_mode = SW_IPC_NONE;
    }

    pool->map = new std::unordered_map<pid_t, swWorker *>;

    pool->ipc_mode = ipc_mode;
    if (ipc_mode > SW_IPC_NONE) {
        pool->main_loop = ProcessPool_worker_loop;
    }

    for (i = 0; i < worker_num; i++) {
        pool->workers[i].pool = pool;
    }

    return SW_OK;
}

int ProcessPool::create_unix_socket(const char *socket_file, int blacklog) {
    if (ipc_mode != SW_IPC_SOCKET) {
        swWarn("ipc_mode is not SW_IPC_SOCKET");
        return SW_ERR;
    }
    stream_info_->socket_file = sw_strdup(socket_file);
    if (stream_info_->socket_file == nullptr) {
        return SW_ERR;
    }
    stream_info_->socket = swSocket_create_server(SW_SOCK_UNIX_STREAM, stream_info_->socket_file, 0, blacklog);
    if (!stream_info_->socket) {
        return SW_ERR;
    }
    return SW_OK;
}

int ProcessPool::create_tcp_socket(const char *host, int port, int blacklog) {
    if (ipc_mode != SW_IPC_SOCKET) {
        swWarn("ipc_mode is not SW_IPC_SOCKET");
        return SW_ERR;
    }
    stream_info_->socket_file = sw_strdup(host);
    if (stream_info_->socket_file == nullptr) {
        return SW_ERR;
    }
    stream_info_->socket = swSocket_create_server(SW_SOCK_TCP, host, port, blacklog);
    if (!stream_info_->socket) {
        return SW_ERR;
    }
    return SW_OK;
}

/**
 * start workers
 */
int ProcessPool::start() {
    if (ipc_mode == SW_IPC_SOCKET && (stream_info_ == nullptr || stream_info_->socket == 0)) {
        swWarn("must first listen to an tcp port");
        return SW_ERR;
    }

    uint32_t i;
    running = started = true;

    for (i = 0; i < worker_num; i++) {
        workers[i].pool = this;
        workers[i].id = start_id + i;
        workers[i].type = type;
    }

    for (i = 0; i < worker_num; i++) {
        if (spawn(&(workers[i])) < 0) {
            return SW_ERR;
        }
    }

    return SW_OK;
}

int ProcessPool::schedule() {
    if (dispatch_mode == SW_DISPATCH_QUEUE) {
        return 0;
    }

    uint32_t i, target_worker_id = 0;
    uint8_t found = 0;

    for (i = 0; i < worker_num + 1; i++) {
        target_worker_id = sw_atomic_fetch_add(&round_id, 1) % worker_num;
        if (workers[target_worker_id].status == SW_WORKER_IDLE) {
            found = 1;
            break;
        }
    }
    if (found == 0) {
        scheduler_warning = 1;
    }
    return target_worker_id;
}

int ProcessPool::response(const char *data, int length) {
    if (stream_info_ == nullptr || stream_info_->last_connection == nullptr ||
        stream_info_->response_buffer == nullptr) {
        swoole_set_last_error(SW_ERROR_INVALID_PARAMS);
        return SW_ERR;
    }
    return swString_append_ptr(stream_info_->response_buffer, data, length);
}

/**
 * dispatch data to worker
 */
int ProcessPool::dispatch(swEventData *data, int *dst_worker_id) {
    int ret = 0;
    swWorker *worker;

    if (use_socket) {
        swStream *stream = swStream_new(stream_info_->socket_file, 0, SW_SOCK_UNIX_STREAM);
        if (stream == nullptr) {
            return SW_ERR;
        }
        stream->response = nullptr;
        if (swStream_send(stream, (char *) data, sizeof(data->info) + data->info.len) < 0) {
            stream->cancel = 1;
            return SW_ERR;
        }
        return SW_OK;
    }

    if (*dst_worker_id < 0) {
        *dst_worker_id = schedule();
    }

    *dst_worker_id += start_id;
    worker = get_worker(*dst_worker_id);

    int sendn = sizeof(data->info) + data->info.len;
    ret = swWorker_send_pipe_message(worker, data, sendn, SW_PIPE_MASTER | SW_PIPE_NONBLOCK);

    if (ret >= 0) {
        sw_atomic_fetch_add(&worker->tasking_num, 1);
    } else {
        swWarn("send %d bytes to worker#%d failed", sendn, *dst_worker_id);
    }

    return ret;
}

/**
 * dispatch data to worker
 */
int ProcessPool::dispatch_blocking(swEventData *data, int *dst_worker_id) {
    int ret = 0;
    int sendn = sizeof(data->info) + data->info.len;

    if (use_socket) {
        swClient _socket;
        if (swClient_create(&_socket, SW_SOCK_UNIX_STREAM, SW_SOCK_SYNC) < 0) {
            return SW_ERR;
        }
        if (_socket.connect(&_socket, stream_info_->socket_file, 0, -1, 0) < 0) {
            return SW_ERR;
        }
        if (_socket.send(&_socket, (char *) data, sendn, 0) < 0) {
            return SW_ERR;
        }
        _socket.close(&_socket);
        return SW_OK;
    }

    if (*dst_worker_id < 0) {
        *dst_worker_id = schedule();
    }

    *dst_worker_id += start_id;
    swWorker *worker = get_worker(*dst_worker_id);

    ret = swWorker_send_pipe_message(worker, data, sendn, SW_PIPE_MASTER);
    if (ret < 0) {
        swWarn("send %d bytes to worker#%d failed", sendn, *dst_worker_id);
    } else {
        sw_atomic_fetch_add(&worker->tasking_num, 1);
    }

    return ret;
}

void ProcessPool::shutdown() {
    uint32_t i;
    int status;
    swWorker *worker;
    running = 0;

    swSignal_none();
    // concurrent kill
    for (i = 0; i < worker_num; i++) {
        worker = &workers[i];
        if (swoole_kill(worker->pid, SIGTERM) < 0) {
            swSysWarn("swKill(%d) failed", worker->pid);
            continue;
        }
    }
    for (i = 0; i < worker_num; i++) {
        worker = &workers[i];
        if (swoole_waitpid(worker->pid, &status, 0) < 0) {
            swSysWarn("waitpid(%d) failed", worker->pid);
        }
    }
    destroy();
    started = false;
}

pid_t ProcessPool::spawn(swWorker *worker) {
    pid_t pid = swoole_fork(0);
    int ret_code = 0;

    switch (pid) {
    // child
    case 0:
        /**
         * Process start
         */
        if (onWorkerStart != nullptr) {
            onWorkerStart(this, worker->id);
        }
        /**
         * Process main loop
         */
        if (main_loop) {
            ret_code = main_loop(this, worker);
        }
        /**
         * Process stop
         */
        if (onWorkerStop != nullptr) {
            onWorkerStop(this, worker->id);
        }
        exit(ret_code);
        break;
    case -1:
        swSysWarn("fork() failed");
        break;
        // parent
    default:
        // remove old process
        if (worker->pid) {
            map->erase(worker->pid);
        }
        worker->pid = pid;
        // insert new process
        map->emplace(std::make_pair(pid, worker));
        break;
    }
    return pid;
}

int ProcessPool::get_max_request() {
    int task_n;
    if (max_request < 1) {
        return -1;
    } else {
        task_n = max_request;
        if (max_request_grace > 0) {
            task_n += swoole_system_random(1, max_request_grace);
        }
    }
    return task_n;
}

void ProcessPool::set_max_request(uint32_t _max_request, uint32_t _max_request_grace) {
    max_request = _max_request;
    max_request_grace = _max_request_grace;
}

static int ProcessPool_worker_loop(ProcessPool *pool, swWorker *worker) {
    struct {
        long mtype;
        swEventData buf;
    } out;

    int n = 0, ret, worker_task_always = 0;
    int task_n = pool->get_max_request();
    if (task_n <= 0) {
        worker_task_always = 1;
        task_n = 1;
    }

    /**
     * Use from_fd save the task_worker->id
     */
    out.buf.info.server_fd = worker->id;

    if (pool->dispatch_mode == SW_DISPATCH_QUEUE) {
        out.mtype = 0;
    } else {
        out.mtype = worker->id + 1;
    }

    while (pool->running && !SwooleWG.shutdown && task_n > 0) {
        /**
         * fetch task
         */
        if (pool->use_msgqueue) {
            n = swMsgQueue_pop(pool->queue, (swQueue_data *) &out, sizeof(out.buf));
            if (n < 0 && errno != EINTR) {
                swSysWarn("[Worker#%d] msgrcv() failed", worker->id);
                break;
            }
        } else if (pool->use_socket) {
            swSocketAddress sa;
            swSocket *conn = swSocket_accept(pool->stream_info_->socket, &sa);
            if (conn == nullptr) {
                if (errno == EAGAIN || errno == EINTR) {
                    continue;
                } else {
                    swSysWarn("accept(%d) failed", pool->stream_info_->socket);
                    break;
                }
            }

            n = swStream_recv_blocking(conn, (void *) &out.buf, sizeof(out.buf));
            if (n == SW_CLOSE) {
                swSocket_free(conn);
                continue;
            }
            pool->stream_info_->last_connection = conn;
        } else {
            n = read(worker->pipe_worker->fd, &out.buf, sizeof(out.buf));
            if (n < 0 && errno != EINTR) {
                swSysWarn("[Worker#%d] read(%d) failed", worker->id, worker->pipe_worker->fd);
            }
        }

        /**
         * timer
         */
        if (n < 0) {
            if (errno == EINTR && SwooleG.signal_alarm && SwooleTG.timer) {
            _alarm_handler:
                SwooleG.signal_alarm = false;
                SwooleTG.timer->select();
            }
            continue;
        }

        /**
         * do task
         */
        worker->status = SW_WORKER_BUSY;
        ret = pool->onTask(pool, &out.buf);
        worker->status = SW_WORKER_IDLE;

        if (pool->use_socket && pool->stream_info_->last_connection) {
            int _end = 0;
            swSocket_write_blocking(pool->stream_info_->last_connection, (void *) &_end, sizeof(_end));
            swSocket_free(pool->stream_info_->last_connection);
            pool->stream_info_->last_connection = nullptr;
        }

        /**
         * timer
         */
        if (SwooleG.signal_alarm) {
            goto _alarm_handler;
        }

        if (ret >= 0 && !worker_task_always) {
            task_n--;
        }
    }
    return SW_OK;
}

int ProcessPool::set_protocol(int task_protocol, uint32_t max_packet_size) {
    if (task_protocol) {
        main_loop = ProcessPool_worker_loop;
    } else {
        packet_buffer = (char *) sw_malloc(max_packet_size);
        if (packet_buffer == nullptr) {
            swSysWarn("malloc(%d) failed", max_packet_size);
            return SW_ERR;
        }
        if (stream_info_) {
            stream_info_->response_buffer = swString_new(SW_BUFFER_SIZE_STD);
            if (stream_info_->response_buffer == nullptr) {
                sw_free(packet_buffer);
                return SW_ERR;
            }
        }
        max_packet_size_ = max_packet_size;
        main_loop = ProcessPool_worker_loop_ex;
    }

    return SW_OK;
}

static int ProcessPool_worker_loop_ex(ProcessPool *pool, swWorker *worker) {
    uint32_t n;
    char *data;

    swQueue_data *outbuf = (swQueue_data *) pool->packet_buffer;
    outbuf->mtype = 0;

    while (pool->running) {
        /**
         * fetch task
         */
        if (pool->use_msgqueue) {
            n = swMsgQueue_pop(pool->queue, outbuf, SW_MSGMAX);
            if (n < 0 && errno != EINTR) {
                swSysWarn("[Worker#%d] msgrcv() failed", worker->id);
                break;
            }
            data = outbuf->mdata;
            outbuf->mtype = 0;
        } else if (pool->use_socket) {
            swSocketAddress sa;
            swSocket *conn = swSocket_accept(pool->stream_info_->socket, &sa);
            if (conn == nullptr) {
                if (errno == EAGAIN || errno == EINTR) {
                    continue;
                } else {
                    swSysWarn("accept(%d) failed", pool->stream_info_->socket);
                    break;
                }
            }
            int tmp = 0;
            if (swSocket_recv_blocking(conn, &tmp, sizeof(tmp), MSG_WAITALL) <= 0) {
                goto _close;
            }
            n = ntohl(tmp);
            if (n <= 0) {
                goto _close;
            } else if (n > pool->max_packet_size_) {
                goto _close;
            }
            if (swSocket_recv_blocking(conn, pool->packet_buffer, n, MSG_WAITALL) <= 0) {
            _close:
                swSocket_free(conn);
                continue;
            }
            data = pool->packet_buffer;
            pool->stream_info_->last_connection = conn;
        } else {
            n = read(worker->pipe_worker->fd, pool->packet_buffer, pool->max_packet_size_);
            if (n < 0 && errno != EINTR) {
                swSysWarn("[Worker#%d] read(%d) failed", worker->id, worker->pipe_worker->fd);
            }
            data = pool->packet_buffer;
        }

        /**
         * timer
         */
        if (n < 0) {
            if (errno == EINTR && SwooleG.signal_alarm && SwooleTG.timer) {
            _alarm_handler:
                SwooleG.signal_alarm = false;
                SwooleTG.timer->select();
            }
            continue;
        }

        pool->onMessage(pool, data, n);

        if (pool->use_socket && pool->stream_info_->last_connection) {
            swString *resp_buf = pool->stream_info_->response_buffer;
            if (resp_buf && resp_buf->length > 0) {
                int _l = htonl(resp_buf->length);
                swSocket_write_blocking(pool->stream_info_->last_connection, &_l, sizeof(_l));
                swSocket_write_blocking(pool->stream_info_->last_connection, resp_buf->str, resp_buf->length);
                swString_clear(resp_buf);
            }
            swSocket_free(pool->stream_info_->last_connection);
            pool->stream_info_->last_connection = nullptr;
        }

        /**
         * timer
         */
        if (SwooleG.signal_alarm) {
            goto _alarm_handler;
        }
    }
    return SW_OK;
}

/**
 * add a worker to pool
 */
int ProcessPool_add_worker(ProcessPool *pool, swWorker *worker) {
    pool->map->emplace(std::make_pair(worker->pid, worker));
    return SW_OK;
}

int ProcessPool::wait() {
    int pid, new_pid;
    pid_t reload_worker_pid = 0;
    int ret;
    int status;

    reload_workers = (swWorker *) sw_calloc(worker_num, sizeof(swWorker));
    if (reload_workers == nullptr) {
        swError("malloc[reload_workers] failed");
        return SW_ERR;
    }

    while (running) {
        pid = ::wait(&status);
        if (SwooleG.signal_alarm && SwooleTG.timer) {
            SwooleG.signal_alarm = false;
            SwooleTG.timer->select();
        }
        if (pid < 0) {
            if (!running) {
                break;
            }
            if (!reloading) {
                if (errno > 0 && errno != EINTR) {
                    swSysWarn("[Manager] wait failed");
                }
                continue;
            } else {
                if (!reload_init) {
                    swInfo("reload workers");
                    reload_init = true;
                    memcpy(reload_workers, workers, sizeof(swWorker) * worker_num);
                    if (max_wait_time) {
                        swoole_timer_add(
                            (long) (max_wait_time * 1000), false, ProcessPool_kill_timeout_worker, this);
                    }
                }
                goto _kill_worker;
            }
        }

        if (running) {
            auto iter = map->find(pid);
            if (iter == map->end()) {
                if (onWorkerNotFound) {
                    onWorkerNotFound(this, pid, status);
                } else {
                    swWarn("[Manager]unknow worker[pid=%d]", pid);
                }
                continue;
            }

            swWorker *exit_worker = iter->second;
            if (!WIFEXITED(status)) {
                swWarn("worker#%d abnormal exit, status=%d, signal=%d"
                       "%s",
                       exit_worker->id,
                       WEXITSTATUS(status),
                       WTERMSIG(status),
                       WTERMSIG(status) == SIGSEGV ? "\n" SWOOLE_BUG_REPORT : "");
            }
            new_pid = spawn(exit_worker);
            if (new_pid < 0) {
                swSysWarn("Fork worker process failed");
                sw_free(reload_workers);
                return SW_ERR;
            }
            map->erase(pid);
            if (pid == reload_worker_pid) {
                reload_worker_i++;
            }
        }
    // reload worker
    _kill_worker:
        if (reloading) {
            // reload finish
            if (reload_worker_i >= worker_num) {
                reloading = reload_init = false;
                reload_worker_pid = reload_worker_i = 0;
                continue;
            }
            reload_worker_pid = reload_workers[reload_worker_i].pid;
            ret = swoole_kill(reload_worker_pid, SIGTERM);
            if (ret < 0) {
                if (errno == ECHILD) {
                    reload_worker_i++;
                    goto _kill_worker;
                }
                swSysWarn("[Manager]swKill(%d) failed", reload_workers[reload_worker_i].pid);
                continue;
            }
        }
    }
    sw_free(reload_workers);
    reload_workers = nullptr;
    return SW_OK;
}

void ProcessPool::destroy() {
    uint32_t i;
    swPipe *_pipe;

    if (pipes) {
        for (i = 0; i < worker_num; i++) {
            _pipe = &pipes[i];
            _pipe->close(_pipe);
        }
        sw_free(pipes);
    }

    if (use_msgqueue == 1 && msgqueue_key == 0) {
        swMsgQueue_free(queue);
    }

    if (stream_info_) {
        if (stream_info_->socket) {
            unlink(stream_info_->socket_file);
            sw_free((void *) stream_info_->socket_file);
        }
        if (stream_info_->socket) {
            swSocket_free(stream_info_->socket);
            stream_info_->socket = nullptr;
        }
        if (stream_info_->response_buffer) {
            swString_free(stream_info_->response_buffer);
        }
        delete stream_info_;
    }

    if (packet_buffer) {
        sw_free(packet_buffer);
    }

    if (map) {
        delete map;
    }

    SwooleG.memory_pool->free(SwooleG.memory_pool, workers);
}
