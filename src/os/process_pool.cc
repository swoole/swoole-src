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
#include "swoole_msg_queue.h"
#include "swoole_pipe.h"
#include "swoole_server.h"
#include "swoole_util.h"
#include "swoole_process_pool.h"
#include "swoole_client.h"

namespace swoole {

using network::Socket;
using network::Stream;

/**
 * call onTask
 */
static int ProcessPool_worker_loop(ProcessPool *pool, Worker *worker);
/**
 * call onMessage
 */
static int ProcessPool_worker_loop_ex(ProcessPool *pool, Worker *worker);

static void ProcessPool_kill_timeout_worker(Timer *timer, TimerNode *tnode) {
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
int ProcessPool::create(uint32_t _worker_num, key_t _msgqueue_key, swIPC_type _ipc_mode) {
    worker_num = _worker_num;
    /**
     * Shared memory is used here
     */
    workers = (Worker *) sw_mem_pool()->alloc(_worker_num * sizeof(Worker));
    if (workers == nullptr) {
        swSysWarn("malloc[1] failed");
        return SW_ERR;
    }

    if (_ipc_mode == SW_IPC_MSGQUEUE) {
        use_msgqueue = 1;
        msgqueue_key = _msgqueue_key;
        queue = new MsgQueue(msgqueue_key);
        if (!queue->ready()) {
            delete queue;
            queue = nullptr;
            return SW_ERR;
        }
    } else if (_ipc_mode == SW_IPC_UNIXSOCK) {
        pipes = new std::vector<std::shared_ptr<UnixSocket>>;
        SW_LOOP_N(_worker_num) {
            auto sock = new UnixSocket(true, SOCK_DGRAM);
            if (!sock->ready()) {
                delete sock;
                delete pipes;
                pipes = nullptr;
                return SW_ERR;
            }
            pipes->emplace_back(sock);
            workers[i].pipe_master = sock->get_socket(true);
            workers[i].pipe_worker = sock->get_socket(false);
            workers[i].pipe_object = sock;
        }
    } else if (_ipc_mode == SW_IPC_SOCKET) {
        use_socket = 1;
        stream_info_ = new StreamInfo();
    } else {
        _ipc_mode = SW_IPC_NONE;
    }

    map_ = new std::unordered_map<pid_t, Worker *>;

    ipc_mode = _ipc_mode;
    if (_ipc_mode > SW_IPC_NONE) {
        main_loop = ProcessPool_worker_loop;
    }

    SW_LOOP_N(_worker_num) {
        workers[i].pool = this;
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
    stream_info_->socket_port = 0;
    stream_info_->socket = make_server_socket(SW_SOCK_UNIX_STREAM, stream_info_->socket_file, 0, blacklog);
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
    stream_info_->socket_port = port;
    stream_info_->socket = make_server_socket(SW_SOCK_TCP, host, port, blacklog);
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
    master_pid = getpid();

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
    return stream_info_->response_buffer->append(data, length);
}

/**
 * dispatch data to worker
 */
int ProcessPool::dispatch(EventData *data, int *dst_worker_id) {
    int ret = 0;
    Worker *worker;

    if (use_socket) {
        Stream *stream = Stream::create(stream_info_->socket_file, 0, SW_SOCK_UNIX_STREAM);
        if (!stream) {
            return SW_ERR;
        }
        stream->response = nullptr;
        if (stream->send((char *) data, sizeof(data->info) + data->info.len) < 0) {
            stream->cancel = 1;
            delete stream;
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
    ret = worker->send_pipe_message(data, sendn, SW_PIPE_MASTER | SW_PIPE_NONBLOCK);

    if (ret >= 0) {
        sw_atomic_fetch_add(&worker->tasking_num, 1);
    } else {
        swWarn("send %d bytes to worker#%d failed", sendn, *dst_worker_id);
    }

    return ret;
}

int ProcessPool::dispatch_blocking(const char *data, uint32_t len) {
    assert(use_socket);

    network::Client _socket(stream_info_->socket->socket_type, false);
    if (!_socket.socket) {
        return SW_ERR;
    }
    if (_socket.connect(&_socket, stream_info_->socket_file, stream_info_->socket_port, -1, 0) < 0) {
        return SW_ERR;
    }
    uint32_t packed_len = htonl(len);
    if (_socket.send(&_socket, (char *) &packed_len, 4, 0) < 0) {
        return SW_ERR;
    }
    if (_socket.send(&_socket, (char *) data, len, 0) < 0) {
        return SW_ERR;
    }
    _socket.close();
    return SW_OK;
}

/**
 * dispatch data to worker
 * @return SW_OK/SW_ERR
 */
int ProcessPool::dispatch_blocking(EventData *data, int *dst_worker_id) {
    int ret = 0;
    int sendn = sizeof(data->info) + data->info.len;

    if (use_socket) {
        return dispatch_blocking((char *) data, sendn);
    }

    if (*dst_worker_id < 0) {
        *dst_worker_id = schedule();
    }

    *dst_worker_id += start_id;
    Worker *worker = get_worker(*dst_worker_id);

    ret = worker->send_pipe_message(data, sendn, SW_PIPE_MASTER);
    if (ret < 0) {
        swWarn("send %d bytes to worker#%d failed", sendn, *dst_worker_id);
    } else {
        sw_atomic_fetch_add(&worker->tasking_num, 1);
    }

    return ret > 0 ? SW_OK : SW_ERR;
}

void ProcessPool::shutdown() {
    uint32_t i;
    int status;
    Worker *worker;
    running = 0;

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
    started = false;
}

pid_t ProcessPool::spawn(Worker *worker) {
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
            map_->erase(worker->pid);
        }
        worker->pid = pid;
        // insert new process
        map_->emplace(std::make_pair(pid, worker));
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

static int ProcessPool_worker_loop(ProcessPool *pool, Worker *worker) {
    struct {
        long mtype;
        EventData buf;
    } out{};

    ssize_t n = 0, ret, worker_task_always = 0;
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
            n = pool->queue->pop((QueueNode *) &out, sizeof(out.buf));
            if (n < 0 && errno != EINTR) {
                swSysWarn("[Worker#%d] msgrcv() failed", worker->id);
                break;
            }
        } else if (pool->use_socket) {
            Socket *conn = pool->stream_info_->socket->accept();
            if (conn == nullptr) {
                if (errno == EAGAIN || errno == EINTR) {
                    continue;
                } else {
                    swSysWarn("accept(%d) failed", pool->stream_info_->socket->get_fd());
                    break;
                }
            }
            n = Stream::recv_blocking(conn, (void *) &out.buf, sizeof(out.buf));
            if (n < 0) {
                conn->free();
                continue;
            }
            pool->stream_info_->last_connection = conn;
        } else {
            n = worker->pipe_worker->read(&out.buf, sizeof(out.buf));
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

        if (n != (ssize_t)(out.buf.info.len + sizeof(out.buf.info))) {
            swWarn("bad task packet, The received data-length[%ld] is inconsistent with the packet-length[%ld]",
                   n,
                   out.buf.info.len + sizeof(out.buf.info));
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
            pool->stream_info_->last_connection->send_blocking((void *) &_end, sizeof(_end));
            pool->stream_info_->last_connection->free();
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
        packet_buffer = new char[max_packet_size];
        if (stream_info_) {
            stream_info_->response_buffer = new String(SW_BUFFER_SIZE_STD);
        }
        max_packet_size_ = max_packet_size;
        main_loop = ProcessPool_worker_loop_ex;
    }

    return SW_OK;
}

static int ProcessPool_worker_loop_ex(ProcessPool *pool, Worker *worker) {
    ssize_t n;
    char *data;

    QueueNode *outbuf = (QueueNode *) pool->packet_buffer;
    outbuf->mtype = 0;

    while (pool->running) {
        /**
         * fetch task
         */
        if (pool->use_msgqueue) {
            n = pool->queue->pop(outbuf, SW_MSGMAX);
            if (n < 0 && errno != EINTR) {
                swSysWarn("[Worker#%d] msgrcv() failed", worker->id);
                break;
            }
            data = outbuf->mdata;
            outbuf->mtype = 0;
        } else if (pool->use_socket) {
            Socket *conn = pool->stream_info_->socket->accept();
            if (conn == nullptr) {
                if (errno == EAGAIN || errno == EINTR) {
                    continue;
                } else {
                    swSysWarn("accept(%d) failed", pool->stream_info_->socket->get_fd());
                    break;
                }
            }
            int tmp = 0;
            if (conn->recv_blocking(&tmp, sizeof(tmp), MSG_WAITALL) <= 0) {
                goto _close;
            }
            n = ntohl(tmp);
            if (n <= 0) {
                goto _close;
            } else if (n > pool->max_packet_size_) {
                goto _close;
            }
            if (conn->recv_blocking(pool->packet_buffer, n, MSG_WAITALL) <= 0) {
            _close:
                conn->free();
                continue;
            }
            data = pool->packet_buffer;
            pool->stream_info_->last_connection = conn;
        } else {
            n = worker->pipe_worker->read(pool->packet_buffer, pool->max_packet_size_);
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
            String *resp_buf = pool->stream_info_->response_buffer;
            if (resp_buf && resp_buf->length > 0) {
                int _l = htonl(resp_buf->length);
                pool->stream_info_->last_connection->send_blocking(&_l, sizeof(_l));
                pool->stream_info_->last_connection->send_blocking(resp_buf->str, resp_buf->length);
                resp_buf->clear();
            }
            pool->stream_info_->last_connection->free();
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
int ProcessPool_add_worker(ProcessPool *pool, Worker *worker) {
    pool->map_->emplace(std::make_pair(worker->pid, worker));
    return SW_OK;
}

int ProcessPool::wait() {
    pid_t new_pid, reload_worker_pid = 0;
    int ret;

    reload_workers = new Worker[worker_num]();
    ON_SCOPE_EXIT {
        delete[] reload_workers;
        reload_workers = nullptr;
    };

    while (running) {
        ExitStatus exit_status = wait_process();

        if (SwooleG.signal_alarm && SwooleTG.timer) {
            SwooleG.signal_alarm = false;
            SwooleTG.timer->select();
        }
        if (exit_status.get_pid() < 0) {
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
                    memcpy(reload_workers, workers, sizeof(Worker) * worker_num);
                    if (max_wait_time) {
                        swoole_timer_add((long) (max_wait_time * 1000), false, ProcessPool_kill_timeout_worker, this);
                    }
                }
                goto _kill_worker;
            }
        }

        if (running) {
            auto iter = map_->find(exit_status.get_pid());
            if (iter == map_->end()) {
                if (onWorkerNotFound) {
                    onWorkerNotFound(this, exit_status);
                } else {
                    swWarn("[Manager]unknow worker[pid=%d]", exit_status.get_pid());
                }
                continue;
            }

            Worker *exit_worker = iter->second;
            if (!exit_status.is_normal_exit()) {
                swWarn("worker#%d abnormal exit, status=%d, signal=%d"
                       "%s",
                       exit_worker->id,
                       exit_status.get_code(),
                       exit_status.get_signal(),
                       exit_status.get_signal() == SIGSEGV ? "\n" SWOOLE_BUG_REPORT : "");
            }
            new_pid = spawn(exit_worker);
            if (new_pid < 0) {
                swSysWarn("Fork worker process failed");
                return SW_ERR;
            }
            map_->erase(exit_status.get_pid());
            if (exit_status.get_pid() == reload_worker_pid) {
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
    return SW_OK;
}

void ProcessPool::destroy() {
    if (pipes) {
        delete pipes;
        pipes = nullptr;
    }

    if (queue) {
        delete queue;
        queue = nullptr;
    }

    if (stream_info_) {
        if (stream_info_->socket) {
            unlink(stream_info_->socket_file);
            sw_free((void *) stream_info_->socket_file);
        }
        if (stream_info_->socket) {
            stream_info_->socket->free();
            stream_info_->socket = nullptr;
        }
        if (stream_info_->response_buffer) {
            delete stream_info_->response_buffer;
        }
        delete stream_info_;
    }

    if (packet_buffer) {
        delete[] packet_buffer;
    }

    if (map_) {
        delete map_;
    }

    sw_mem_pool()->free(workers);
}

}  // namespace swoole
