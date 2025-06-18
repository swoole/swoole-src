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

#include "swoole_api.h"
#include "swoole_memory.h"
#include "swoole_socket.h"
#include "swoole_string.h"
#include "swoole_msg_queue.h"
#include "swoole_pipe.h"
#include "swoole_server.h"
#include "swoole_util.h"
#include "swoole_process_pool.h"
#include "swoole_client.h"

#include <pwd.h>
#include <grp.h>

SW_THREAD_LOCAL swoole::WorkerGlobal SwooleWG = {};

namespace swoole {

using network::Socket;
using network::Stream;

static inline swReturnCode catch_system_error(int error) {
    switch (error) {
    case SW_SUCCESS:
    case EAGAIN:
    case EINTR:
        return SW_CONTINUE;
    default:
        return SW_ERROR;
    }
}

static inline void worker_end_callback() {
    swoole_timer_select();
    swoole_signal_dispatch();
}

/**
 * Process manager
 */
int ProcessPool::create(uint32_t _worker_num, key_t _msgqueue_key, swIPCMode _ipc_mode) {
    worker_num = _worker_num;
    /**
     * Shared memory is used here
     */
    workers = static_cast<Worker *>(sw_mem_pool()->alloc(_worker_num * sizeof(Worker)));
    if (workers == nullptr) {
        swoole_sys_warning("malloc[1] failed");
        return SW_ERR;
    }

    if (create_message_box(SW_MESSAGE_BOX_SIZE) < 0) {
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
    main_loop = run_with_task_protocol;
    protocol_type_ = SW_PROTOCOL_TASK;
    max_packet_size_ = SW_INPUT_BUFFER_SIZE;
    max_wait_time = SW_WORKER_MAX_WAIT_TIME;

    SW_LOOP_N(_worker_num) {
        workers[i].pool = this;
    }

    return SW_OK;
}

int ProcessPool::create_message_box(size_t memory_size) {
    message_box = Channel::make(memory_size, sizeof(EventData), SW_CHAN_LOCK | SW_CHAN_SHM);
    if (message_box == nullptr) {
        return SW_ERR;
    }
    return SW_OK;
}

int ProcessPool::create_message_bus() {
    if (ipc_mode != SW_IPC_UNIXSOCK) {
        swoole_error_log(
            SW_LOG_WARNING, SW_ERROR_OPERATION_NOT_SUPPORT, "not support, ipc_mode must be SW_IPC_UNIXSOCK");
        return SW_ERR;
    }
    if (message_bus) {
        swoole_error_log(SW_LOG_WARNING, SW_ERROR_WRONG_OPERATION, "the message bus has been created");
        return SW_ERR;
    }
    auto *msg_id = static_cast<sw_atomic_long_t *>(sw_mem_pool()->alloc(sizeof(sw_atomic_long_t)));
    if (msg_id == nullptr) {
        swoole_sys_warning("malloc[1] failed");
        return SW_ERR;
    }
    *msg_id = 1;
    message_bus = new MessageBus();
    message_bus->set_id_generator([msg_id]() { return sw_atomic_fetch_add(msg_id, 1); });
    size_t ipc_max_size;
#ifndef __linux__
    ipc_max_size = SW_IPC_MAX_SIZE;
#else
    int bufsize;
    /**
     * Get the maximum ipc[unix socket with dgram] transmission length
     */
    if (workers[0].pipe_master->get_option(SOL_SOCKET, SO_SNDBUF, &bufsize) != 0) {
        bufsize = SW_IPC_MAX_SIZE;
    }
    ipc_max_size = SW_MIN(bufsize, SW_IPC_BUFFER_MAX_SIZE) - SW_DGRAM_HEADER_SIZE;
#endif
    message_bus->set_buffer_size(ipc_max_size);
    if (!message_bus->alloc_buffer()) {
        return SW_ERR;
    }
    return SW_OK;
}

int ProcessPool::listen(const char *socket_file, int backlog) const {
    if (ipc_mode != SW_IPC_SOCKET) {
        swoole_error_log(SW_LOG_WARNING, SW_ERROR_OPERATION_NOT_SUPPORT, "not support, ipc_mode must be SW_IPC_SOCKET");
        return SW_ERR;
    }
    stream_info_->socket_file = sw_strdup(socket_file);
    if (stream_info_->socket_file == nullptr) {
        return SW_ERR;
    }
    stream_info_->socket_port = 0;
    stream_info_->socket = make_server_socket(SW_SOCK_UNIX_STREAM, stream_info_->socket_file, 0, backlog);
    if (!stream_info_->socket) {
        return SW_ERR;
    }
    return SW_OK;
}

int ProcessPool::listen(const char *host, int port, int backlog) const {
    if (ipc_mode != SW_IPC_SOCKET) {
        swoole_error_log(SW_LOG_WARNING, SW_ERROR_OPERATION_NOT_SUPPORT, "not support, ipc_mode must be SW_IPC_SOCKET");
        return SW_ERR;
    }
    stream_info_->socket_file = sw_strdup(host);
    if (stream_info_->socket_file == nullptr) {
        return SW_ERR;
    }
    stream_info_->socket_port = port;
    stream_info_->socket = make_server_socket(SW_SOCK_TCP, host, port, backlog);
    if (!stream_info_->socket) {
        return SW_ERR;
    }
    return SW_OK;
}

void ProcessPool::set_protocol(ProtocolType _protocol_type) {
    switch (_protocol_type) {
    case SW_PROTOCOL_TASK:
        main_loop = run_with_task_protocol;
        break;
    case SW_PROTOCOL_STREAM:
        main_loop = run_with_stream_protocol;
        break;
    case SW_PROTOCOL_MESSAGE:
        main_loop = run_with_message_protocol;
        break;
    default:
        abort();
        break;
    }
    protocol_type_ = _protocol_type;
}

int ProcessPool::start_check() {
    if (ipc_mode == SW_IPC_SOCKET && (stream_info_ == nullptr || stream_info_->socket == nullptr)) {
        swoole_error_log(SW_LOG_WARNING, SW_ERROR_WRONG_OPERATION, "must first listen to an tcp port");
        return SW_ERR;
    }

    running = started = true;
    master_pid = getpid();
    swoole_set_worker_type(SW_MASTER);

    if (async) {
        main_loop = run_async;
    }

    SW_LOOP_N(worker_num) {
        workers[i].pool = this;
        workers[i].id = start_id + i;
        workers[i].type = type;
        if (workers[i].pipe_worker) {
            workers[i].pipe_worker->buffer_size = UINT_MAX;
        }
        if (workers[i].pipe_master) {
            workers[i].pipe_master->buffer_size = UINT_MAX;
        }
    }

    return SW_OK;
}

/**
 * start workers
 */
int ProcessPool::start() {
    if (start_check() < 0) {
        return SW_ERR;
    }

    if (onStart) {
        onStart(this);
    }

    SW_LOOP_N(worker_num) {
        if (spawn(&(workers[i])) < 0) {
            return SW_ERR;
        }
    }

    return SW_OK;
}

int ProcessPool::schedule() {
    // schedule by system message queue
    if (schedule_by_sysvmsg) {
        return 0;
    }

    uint32_t target_worker_id = 0;
    uint8_t found = 0;

    for (uint32_t i = 0; i < worker_num + 1; i++) {
        target_worker_id = sw_atomic_fetch_add(&round_id, 1) % worker_num;
        if (workers[target_worker_id].is_idle()) {
            found = 1;
            break;
        }
    }
    if (found == 0) {
        scheduler_warning = 1;
    }
    return target_worker_id;
}

int ProcessPool::response(const char *data, uint32_t length) const {
    if (data == nullptr || length == 0 || stream_info_ == nullptr || stream_info_->last_connection == nullptr ||
        stream_info_->response_buffer == nullptr) {
        swoole_set_last_error(SW_ERROR_INVALID_PARAMS);
        return SW_ERR;
    }
    return stream_info_->response_buffer->append(data, length);
}

bool ProcessPool::send_message(WorkerId worker_id, const char *message, size_t l_message) const {
    Worker *worker = get_worker(worker_id);
    if (message_bus) {
        SendData _task{};
        _task.info.reactor_id = swoole_get_worker_id();
        _task.info.len = l_message;
        _task.data = message;
        return message_bus->write(worker->pipe_master, &_task);
    } else {
        return worker->pipe_master->send_async(message, l_message);
    }
}

int ProcessPool::push_message(const EventData *msg) const {
    if (message_box->push(msg, msg->size()) < 0) {
        return SW_ERR;
    }
    return swoole_kill(master_pid, SIGIO);
}

int ProcessPool::push_message(uint8_t type, const void *data, size_t length) const {
    if (!message_box) {
        return SW_ERR;
    }

    EventData msg;
    assert(length < sizeof(msg.data));

    msg.info = {};
    msg.info.type = type;
    msg.info.len = length;
    memcpy(msg.data, data, length);

    return push_message(&msg);
}

int ProcessPool::pop_message(void *data, size_t size) {
    if (!message_box) {
        return SW_ERR;
    }
    return message_box->pop(data, size);
}

swResultCode ProcessPool::dispatch(EventData *data, int *dst_worker_id) {
    if (use_socket) {
        Stream *stream = Stream::create(stream_info_->socket_file, 0, SW_SOCK_UNIX_STREAM);
        if (!stream) {
            return SW_ERR;
        }
        stream->response = nullptr;
        if (stream->send(reinterpret_cast<char *>(data), data->size()) < 0) {
            stream->cancel = true;
            delete stream;
            return SW_ERR;
        }
        return SW_OK;
    }

    if (*dst_worker_id < 0) {
        *dst_worker_id = schedule();
    }

    *dst_worker_id += start_id;
    Worker *worker = get_worker(*dst_worker_id);

    if (worker->send_pipe_message(data, data->size(), SW_PIPE_MASTER | SW_PIPE_NONBLOCK) < 0) {
        swoole_warning("send %d bytes to worker#%d failed", data->size(), *dst_worker_id);
        return SW_ERR;
    }

    return SW_OK;
}

swResultCode ProcessPool::dispatch_sync(const char *data, uint32_t len) {
    assert(use_socket);

    network::Client client(stream_info_->socket->socket_type, false);
    if (!client.ready()) {
        return SW_ERR;
    }
    if (client.connect(stream_info_->socket_file, stream_info_->socket_port, -1, 0) < 0) {
        return SW_ERR;
    }
    uint32_t packed_len = htonl(len);
    if (client.send((char *) &packed_len, 4, 0) < 0) {
        return SW_ERR;
    }
    if (client.send(data, len, 0) < 0) {
        return SW_ERR;
    }
    client.close();
    return SW_OK;
}

swResultCode ProcessPool::dispatch_sync(EventData *data, int *dst_worker_id) {
    if (use_socket) {
        return dispatch_sync(reinterpret_cast<char *>(data), data->size());
    }

    if (*dst_worker_id < 0) {
        *dst_worker_id = schedule();
    }

    *dst_worker_id += start_id;
    Worker *worker = get_worker(*dst_worker_id);

    if (worker->send_pipe_message(data, data->size(), SW_PIPE_MASTER) < 0) {
        swoole_warning("send %d bytes to worker#%d failed", data->size(), *dst_worker_id);
        return SW_ERR;
    }
    return SW_OK;
}

bool ProcessPool::reload() {
    if (reload_task) {
        return false;
    }
    if (onBeforeReload) {
        onBeforeReload(this);
    }
    reload_task = new ReloadTask();
    if (max_wait_time) {
        reload_task->add_timeout_killer(max_wait_time);
    }
    reload_count++;
    reload_init = true;
    reload_last_time = ::time(nullptr);
    return true;
}

void ProcessPool::stop(Worker *worker) {
    worker->shutdown();

    if (!swoole_event_is_available()) {
        return;
    }

    auto reactor = sw_reactor();
    if (worker->pipe_worker && !worker->pipe_worker->removed) {
        swoole_event_del(worker->pipe_worker);
    }

    if (onWorkerExit) {
        reactor->set_end_callback(Reactor::PRIORITY_TRY_EXIT, [this, worker](Reactor *reactor) {
            onWorkerExit(this, worker);
            if (reactor->if_exit()) {
                reactor->running = false;
            }
        });
    }
}

void ProcessPool::reopen_logger() {
    sw_logger()->reopen();

    if (is_master()) {
        kill_all_workers(SIGWINCH);
    }
}

void ProcessPool::kill_all_workers(int signo) {
    SW_LOOP_N(worker_num) {
        swoole_kill(workers[i].pid, signo);
    }
}

bool ProcessPool::shutdown() {
    if (is_master()) {
        running = false;
        return true;
    } else {
        return swoole_kill(master_pid, SIGTERM) == 0;
    }
}

pid_t ProcessPool::spawn(Worker *worker) {
    pid_t pid = swoole_fork(0);
    int ret_code = 0;

    switch (pid) {
    // child
    case 0:
        worker->init();
        worker->pid = getpid();
        swoole_set_worker_type(SW_WORKER);
        swoole_set_worker_id(worker->id);
        swoole_set_worker_pid(worker->pid);
        SwooleWG.worker = worker;
        if (async) {
            if (swoole_event_init(SW_EVENTLOOP_WAIT_EXIT) < 0) {
                exit(254);
            }
            sw_reactor()->ptr = this;
        }
        if (onWorkerStart != nullptr) {
            onWorkerStart(this, worker);
        }
        if (main_loop) {
            ret_code = main_loop(this, worker);
        }
        if (onWorkerStop != nullptr) {
            onWorkerStop(this, worker);
        }
        exit(ret_code);
        break;
    case -1:
        swoole_sys_warning("fork() failed");
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

void ProcessPool::set_max_request(uint32_t _max_request, uint32_t _max_request_grace) {
    max_request = _max_request;
    max_request_grace = _max_request_grace;
}

bool ProcessPool::is_worker_running(Worker *worker) {
    return running && !worker->is_shutdown() && !worker->has_exceeded_max_request();
}

void ProcessPool::at_worker_enter(Worker *worker) {
    if (worker->pipe_worker) {
        worker->pipe_worker->dont_restart = 1;
    }
    if (ipc_mode == SW_IPC_UNIXSOCK) {
        if (swoole_timer_is_available()) {
            sw_timer()->reinit(true);
        } else {
            swoole_timer_create(true);
        }
    }
}

void ProcessPool::at_worker_exit(Worker *worker) {
    if (swoole_timer_is_available()) {
        swoole_timer_free();
    }
}

int ProcessPool::run_with_task_protocol(ProcessPool *pool, Worker *worker) {
    struct {
        long mtype;
        EventData buf;
    } out{};

    ssize_t n = 0;

    out.buf.info.server_fd = worker->id;

    if (pool->schedule_by_sysvmsg) {
        out.mtype = 0;
    } else {
        out.mtype = worker->id + 1;
    }

    pool->at_worker_enter(worker);
    while (pool->is_worker_running(worker)) {
        /**
         * fetch task
         */
        if (pool->use_msgqueue) {
            n = pool->queue->pop((QueueNode *) &out, sizeof(out.buf));
            if (n < 0 && catch_system_error(errno) == SW_ERROR) {
                swoole_sys_warning("[Worker#%d] msgrcv(%d) failed", worker->id, pool->queue->get_id());
                break;
            }
        } else if (pool->use_socket) {
            Socket *conn = pool->stream_info_->socket->accept();
            if (conn == nullptr) {
                if (catch_system_error(errno) == SW_ERROR) {
                    swoole_sys_warning(
                        "[Worker#%d] accept(%d) failed", worker->id, pool->stream_info_->socket->get_fd());
                    break;
                } else {
                    goto _end;
                }
            }
            n = Stream::recv_sync(conn, &out.buf, sizeof(out.buf));
            if (n <= 0) {
                conn->free();
                goto _end;
            }
            pool->stream_info_->last_connection = conn;
        } else {
            worker->pipe_worker->set_timeout(msec2sec(swoole_timer_get_next_msec()), SW_TIMEOUT_READ);
            n = worker->pipe_worker->read_sync(&out.buf, sizeof(out.buf));
            if (n < 0 && catch_system_error(errno) == SW_ERROR) {
                swoole_sys_warning("[Worker#%d] read(%d) failed", worker->id, worker->pipe_worker->fd);
                break;
            }
        }

        if (n < 0) {
            goto _end;
        }
        if (n != (ssize_t) out.buf.size()) {
            swoole_warning("[Worker#%d] bad task packet, The received data-length[%ld] is inconsistent with the "
                           "packet-length[%ld]",
                           worker->id,
                           n,
                           out.buf.info.len + sizeof(out.buf.info));
        }
        if (pool->onTask(pool, worker, &out.buf) < 0) {
            swoole_warning("[Worker#%d] the execution of task#%ld has failed", worker->id, pool->get_task_id(&out.buf));
        }
        if (pool->use_socket && pool->stream_info_->last_connection) {
            int _end = 0;
            pool->stream_info_->last_connection->send_sync((void *) &_end, sizeof(_end));
            pool->stream_info_->last_connection->free();
            pool->stream_info_->last_connection = nullptr;
        }

    _end:
        worker_end_callback();
    }
    pool->at_worker_exit(worker);

    return SW_OK;
}

int ProcessPool::recv_packet(Reactor *reactor, Event *event) {
    auto *pool = static_cast<ProcessPool *>(reactor->ptr);
    ssize_t n = event->socket->read(pool->packet_buffer, pool->max_packet_size_);
    if (n < 0 && errno != EINTR) {
        swoole_sys_warning("failed to read(%d) pipe", event->fd);
    }
    RecvData msg{};
    msg.info.reactor_id = -1;
    msg.info.len = n;
    msg.data = pool->packet_buffer;
    pool->onMessage(pool, &msg);
    return SW_OK;
}

int ProcessPool::recv_message(Reactor *reactor, Event *event) {
    auto *pool = static_cast<ProcessPool *>(reactor->ptr);
    if (pool->message_bus->read(event->socket) <= 0) {
        return SW_OK;
    }
    auto pipe_buffer = pool->message_bus->get_buffer();
    auto packet = pool->message_bus->get_packet();
    RecvData msg;
    msg.info = pipe_buffer->info;
    msg.info.len = packet.length;
    msg.data = packet.data;
    pool->onMessage(pool, &msg);
    pool->message_bus->pop();
    return SW_OK;
}

int ProcessPool::run_async(ProcessPool *pool, Worker *worker) {
    if (pool->ipc_mode == SW_IPC_UNIXSOCK && pool->onMessage) {
        swoole_event_add(worker->pipe_worker, SW_EVENT_READ);
        if (pool->message_bus) {
            swoole_event_set_handler(SW_FD_PIPE, SW_EVENT_READ, recv_message);
        } else {
            pool->packet_buffer = new char[pool->max_packet_size_];
            if (pool->stream_info_) {
                pool->stream_info_->response_buffer = new String(SW_BUFFER_SIZE_STD);
            }
            swoole_event_set_handler(SW_FD_PIPE, SW_EVENT_READ, recv_packet);
        }
    }
    return swoole_event_wait();
}

int ProcessPool::run_with_stream_protocol(ProcessPool *pool, Worker *worker) {
    ssize_t n;
    RecvData msg{};
    msg.info.reactor_id = -1;

    pool->packet_buffer = new char[pool->max_packet_size_];
    if (pool->stream_info_) {
        pool->stream_info_->response_buffer = new String(SW_BUFFER_SIZE_STD);
    }

    auto *outbuf = reinterpret_cast<QueueNode *>(pool->packet_buffer);
    outbuf->mtype = 0;

    pool->at_worker_enter(worker);
    while (pool->is_worker_running(worker)) {
        /**
         * fetch task
         */
        if (pool->use_msgqueue) {
            n = pool->queue->pop(outbuf, SW_MSGMAX);
            /**
             * A fatal error has occurred; the message queue is no longer available, and the loop must be exited.
             */
            if (n < 0 && catch_system_error(errno) == SW_ERROR) {
                swoole_sys_warning("[Worker#%d] msgrcv(%d) failed", worker->id, pool->queue->get_id());
                break;
            }
            swoole_trace_log(SW_TRACE_WORKER, "pop from MsgQ#%d %lu bytes", pool->queue->get_id(), (ulong_t) n);
            msg.info.len = n - sizeof(msg.info);
            msg.data = outbuf->mdata;
            outbuf->mtype = 0;
        } else if (pool->use_socket) {
            Socket *conn = pool->stream_info_->socket->accept();
            if (conn == nullptr) {
                if (catch_system_error(errno) == SW_ERROR) {
                    swoole_sys_warning(
                        "[Worker#%d] accept(%d) failed", worker->id, pool->stream_info_->socket->get_fd());
                    break;
                } else {
                    goto _end;
                }
            }
            uint32_t packet_len = 0;
            if (conn->recv_sync(&packet_len, sizeof(packet_len), MSG_WAITALL) <= 0) {
                goto _close;
            }
            n = ntohl(packet_len);
            /**
             * Errors occurring during client connections do not affect subsequent requests,
             * they continue after closure.
             */
            if (n <= 0) {
                goto _close;
            } else if (n > pool->max_packet_size_) {
                goto _close;
            }
            if (conn->recv_sync(pool->packet_buffer, n, MSG_WAITALL) <= 0) {
            _close:
                conn->free();
                goto _end;
            }
            msg.data = pool->packet_buffer;
            pool->stream_info_->last_connection = conn;
        } else {
            worker->pipe_worker->set_timeout(msec2sec(swoole_timer_get_next_msec()), SW_TIMEOUT_READ);
            n = worker->pipe_worker->read_sync(pool->packet_buffer, pool->max_packet_size_);
            if (n < 0 && catch_system_error(errno) == SW_ERROR) {
                swoole_sys_warning("[Worker#%d] read(%d) failed", worker->id, worker->pipe_worker->fd);
                break;
            }
            msg.data = pool->packet_buffer;
        }

        if (n < 0) {
            goto _end;
        }

        msg.info.len = n;
        pool->onMessage(pool, &msg);

        if (pool->use_socket && pool->stream_info_->last_connection) {
            String *resp_buf = pool->stream_info_->response_buffer;
            if (resp_buf && resp_buf->length > 0) {
                int _l = htonl(resp_buf->length);
                pool->stream_info_->last_connection->send_sync(&_l, sizeof(_l));
                pool->stream_info_->last_connection->send_sync(resp_buf->str, resp_buf->length);
                resp_buf->clear();
            }
            pool->stream_info_->last_connection->free();
            pool->stream_info_->last_connection = nullptr;
        }

    _end:
        worker_end_callback();
    }
    pool->at_worker_exit(worker);

    return SW_OK;
}

int ProcessPool::run_with_message_protocol(ProcessPool *pool, Worker *worker) {
    if (pool->ipc_mode != SW_IPC_UNIXSOCK) {
        swoole_error_log(
            SW_LOG_WARNING, SW_ERROR_OPERATION_NOT_SUPPORT, "not support, ipc_mode must be SW_IPC_UNIXSOCK");
        return SW_ERR;
    }

    auto fn = [&]() -> ReturnCode {
        while (true) {
            if (worker->pipe_worker->wait_event(swoole_timer_get_next_msec(), SW_EVENT_READ) < 0) {
                return errno == EINTR ? SW_CONTINUE : SW_ERROR;
            }
            auto rv = pool->message_bus->read(worker->pipe_worker);
            if (rv < 0) {
                return errno == EINTR ? SW_CONTINUE : SW_ERROR;
            } else if (rv > 0) {
                auto pipe_buffer = pool->message_bus->get_buffer();
                auto packet = pool->message_bus->get_packet();
                RecvData msg;
                msg.info = pipe_buffer->info;
                msg.info.len = packet.length;
                msg.data = packet.data;
                pool->onMessage(pool, &msg);
                pool->message_bus->pop();
                return SW_READY;
            }
        }
    };

    if (pool->message_bus == nullptr) {
        pool->create_message_bus();
    }

    pool->at_worker_enter(worker);
    while (pool->is_worker_running(worker)) {
        switch (fn()) {
        case SW_CONTINUE:
            worker_end_callback();
            break;
        case SW_READY:
            break;
        case SW_ERROR:
        default:
            swoole_sys_warning("[Worker #%d]failed to read data from pipe", worker->id);
            worker->shutdown();
            break;
        }
    }
    pool->at_worker_exit(worker);

    return SW_OK;
}

void ProcessPool::add_worker(Worker *worker) const {
    map_->emplace(worker->pid, worker);
}

bool ProcessPool::del_worker(const Worker *worker) const {
    return map_->erase(worker->pid) > 0;
}

Worker *ProcessPool::get_worker_by_pid(pid_t pid) const {
    const auto iter = map_->find(pid);
    if (iter == map_->end()) {
        return nullptr;
    }
    return iter->second;
}

void ProcessPool::set_type(int _type) {
    uint32_t i;
    type = _type;
    for (i = 0; i < worker_num; i++) {
        workers[i].type = type;
    }
}

void ProcessPool::set_start_id(int _start_id) {
    uint32_t i;
    start_id = _start_id;
    for (i = 0; i < worker_num; i++) {
        workers[i].id = start_id + i;
    }
}

bool ProcessPool::wait_detached_worker(std::unordered_set<pid_t> &detached_workers, pid_t pid) {
    auto iter = detached_workers.find(pid);
    if (iter == detached_workers.end()) {
        swoole_warning("received an exit signal from an unknown child process[pid=%d]", pid);
        return false;
    }
    detached_workers.erase(iter);
    return true;
}

bool ProcessPool::detach() {
    if (!running || !message_box) {
        return false;
    }

    auto worker = SwooleWG.worker;
    worker->shutdown();
    if (async) {
        swoole_event_del(worker->pipe_worker);
    }

    WorkerStopMessage msg;
    msg.pid = worker->pid;
    msg.worker_id = worker->id;
    if (push_message(SW_WORKER_MESSAGE_STOP, &msg, sizeof(msg)) < 0) {
        return false;
    }

    running = false;

    return true;
}

int ProcessPool::wait() {
    std::unordered_set<pid_t> detached_workers;

    while (running) {
        ExitStatus exit_status = wait_process();
        const auto wait_error = errno;

        swoole_signal_dispatch();

        if (sw_timer()) {
            sw_timer()->select();
        }

        if (read_message) {
            EventData msg;
            while (pop_message(&msg, sizeof(msg)) > 0) {
                if (!running) {
                    continue;
                }
                if (msg.info.type != SW_WORKER_MESSAGE_STOP && onWorkerMessage) {
                    onWorkerMessage(this, &msg);
                    continue;
                }
                WorkerStopMessage worker_stop_msg;
                memcpy(&worker_stop_msg, msg.data, sizeof(worker_stop_msg));
                Worker *exit_worker = get_worker_by_pid(worker_stop_msg.pid);
                if (exit_worker == nullptr) {
                    continue;
                }
                pid_t new_pid = spawn(exit_worker);
                if (new_pid < 0) {
                    swoole_sys_warning("fork worker process failed");
                    return SW_ERR;
                }
                detached_workers.insert(worker_stop_msg.pid);
                map_->erase(worker_stop_msg.pid);
            }
            read_message = false;
        }

        if (exit_status.get_pid() < 0) {
            if (!running) {
                break;
            }
            if (!reload_task) {
                if (wait_error > 0 && wait_error != EINTR) {
                    swoole_sys_warning("wait() failed");
                }
                continue;
            }
        }

        if (running) {
            if (reload_init) {
                reload_init = false;
                reload_task->add_workers(workers, worker_num);
                goto _kill_worker;
            } else if (exit_status.get_pid() < 0) {
                continue;
            }

            Worker *exit_worker = get_worker_by_pid(exit_status.get_pid());
            if (exit_worker == nullptr) {
                if (onWorkerNotFound) {
                    onWorkerNotFound(this, exit_status);
                } else {
                    wait_detached_worker(detached_workers, exit_status.get_pid());
                }
                continue;
            }

            if (!exit_status.is_normal_exit()) {
                exit_worker->report_error(exit_status);
                if (onWorkerError) {
                    onWorkerError(this, exit_worker, exit_status);
                }
            }
            pid_t new_pid = spawn(exit_worker);
            if (new_pid < 0) {
                swoole_sys_warning("Fork worker process failed");
                return SW_ERR;
            }
            map_->erase(exit_status.get_pid());
            if (reload_task) {
                reload_task->remove(exit_status.get_pid());
            }
        }

        if (reload_task) {
            if (reload_task->is_completed()) {
                delete reload_task;
                reload_task = nullptr;
                if (onAfterReload) {
                    onAfterReload(this);
                }
            } else {
            _kill_worker:
                reload_task->kill_one();
            }
        }
    }

    uint32_t i;
    int status;
    Worker *worker;
    running = false;

    delete reload_task;

    if (onShutdown) {
        onShutdown(this);
    }

    // concurrent kill
    for (i = 0; i < worker_num; i++) {
        worker = &workers[i];
        if (swoole_kill(worker->pid, SIGTERM) < 0) {
            swoole_sys_warning("kill(%d, SIGTERM) failed", worker->pid);
            continue;
        }
    }
    if (max_wait_time) {
        swoole_timer_add((long) max_wait_time * 1000, false, [this](Timer *, TimerNode *) { kill_all_workers(); });
    }
    for (i = 0; i < worker_num; i++) {
        worker = &workers[i];
        if (swoole_waitpid(worker->pid, &status, 0) < 0) {
            swoole_sys_warning("waitpid(%d) failed", worker->pid);
        }
        break;
    }
    started = false;

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
        stream_info_ = nullptr;
    }

    if (packet_buffer) {
        delete[] packet_buffer;
        packet_buffer = nullptr;
    }

    if (map_) {
        delete map_;
        map_ = nullptr;
    }

    if (message_box) {
        message_box->destroy();
        message_box = nullptr;
    }

    if (message_bus) {
        delete message_bus;
        message_bus = nullptr;
    }

    sw_mem_pool()->free(workers);
}

void Worker::init() {
    start_time = ::time(nullptr);
    request_count = 0;
    set_status_to_idle();
    SwooleWG.running = true;
    SwooleWG.shutdown = false;
}

void Worker::set_max_request(uint32_t max_request, uint32_t max_request_grace) {
    if (max_request > 0 && max_request_grace > 0) {
        max_request += swoole_system_random(1, max_request_grace);
    }
    SwooleWG.max_request = max_request;
}

void Worker::set_isolation(const std::string &group_, const std::string &user_, const std::string &chroot_) {
    group *_group = nullptr;
    passwd *_passwd = nullptr;
    // get group info
    if (!group_.empty()) {
        _group = getgrnam(group_.c_str());
        if (!_group) {
            swoole_warning("get group [%s] info failed", group_.c_str());
        }
    }
    // get user info
    if (!user_.empty()) {
        _passwd = getpwnam(user_.c_str());
        if (!_passwd) {
            swoole_warning("get user [%s] info failed", user_.c_str());
        }
    }
    // set process group
    if (_group && setgid(_group->gr_gid) < 0) {
        swoole_sys_warning("setgid to [%s] failed", group_.c_str());
    }
    // set process user
    if (_passwd && setuid(_passwd->pw_uid) < 0) {
        swoole_sys_warning("setuid to [%s] failed", user_.c_str());
    }
    // chroot
    if (!chroot_.empty()) {
        if (::chroot(chroot_.c_str()) == 0) {
            if (chdir("/") < 0) {
                swoole_sys_warning("chdir('/') failed");
            }
        } else {
            swoole_sys_warning("chroot('%s') failed", chroot_.c_str());
        }
    }
}

bool Worker::has_exceeded_max_request() const {
    return SwooleWG.max_request > 0 && request_count >= SwooleWG.max_request;
}

void Worker::shutdown() {
    status = SW_WORKER_EXIT;
    SwooleWG.shutdown = true;
}

bool Worker::is_shutdown() {
    return SwooleWG.shutdown;
}

bool Worker::is_running() {
    return SwooleWG.running;
}

ssize_t Worker::send_pipe_message(const void *buf, size_t n, int flags) const {
    Socket *pipe_sock;

    if (flags & SW_PIPE_MASTER) {
        pipe_sock = pipe_master;
    } else {
        pipe_sock = pipe_worker;
    }

    // message-queue
    if (pool->use_msgqueue) {
        struct {
            long mtype;
            EventData buf;
        } msg;

        msg.mtype = id + 1;
        memcpy(&msg.buf, buf, n);

        swoole_trace_log(SW_TRACE_WORKER, "push to MsgQ#%d %lu bytes", pool->queue->get_id(), (ulong_t) n);

        return pool->queue->push((QueueNode *) &msg, n) ? n : -1;
    }

    if ((flags & SW_PIPE_NONBLOCK) && swoole_event_is_available()) {
        return swoole_event_write(pipe_sock, buf, n);
    } else {
        return pipe_sock->send_sync(buf, n);
    }
}

void Worker::report_error(const ExitStatus &exit_status) {
    swoole_warning("worker(pid=%d, id=%d) abnormal exit, status=%d, signal=%d"
                   "%s",
                   exit_status.get_pid(),
                   id,
                   exit_status.get_code(),
                   exit_status.get_signal(),
                   exit_status.get_signal() == SIGSEGV ? SwooleG.bug_report_message.c_str() : "");
}

void ReloadTask::add_workers(Worker *list, size_t n) {
    SW_LOOP_N(n) {
        workers[list[i].pid] = &list[i];
        kill_queue.push(list[i].pid);
    }
}

void ReloadTask::add_timeout_killer(int timeout) {
    timer = swoole_timer_add(sec2msec(timeout), false, [this](Timer *, TimerNode *) {
        kill_all();
        timer = nullptr;
    });
}

bool ReloadTask::remove(pid_t pid) {
    auto iter = workers.find(pid);
    if (iter != workers.end()) {
        workers.erase(iter);
        return true;
    } else {
        return false;
    }
}

ReloadTask::~ReloadTask() {
    if (timer) {
        swoole_timer_del(timer);
        timer = nullptr;
    }
}

void ReloadTask::kill_all(int signal_number) {
    for (auto &kv : workers) {
        if (swoole_kill(kv.first, signal_number) < 0) {
            if (errno == ECHILD || errno == ESRCH) {
                continue;
            }
            swoole_sys_warning("kill(%d, SIGTERM) [%d] failed", kv.first, kv.second->id);
        } else {
            swoole_warning("force kill worker process(pid=%d, id=%d)", kv.first, kv.second->id);
        }
    }

    while (!kill_queue.empty()) {
        kill_queue.pop();
    }
}

void ReloadTask::kill_one(int signal_number) {
    while (!kill_queue.empty()) {
        auto pid = kill_queue.front();
        kill_queue.pop();
        auto iter = workers.find(pid);
        if (iter == workers.end()) {
            continue;
        }
        if (swoole_kill(pid, signal_number) < 0) {
            if (errno == ECHILD || errno == ESRCH) {
                workers.erase(iter);
                continue;
            }
            swoole_sys_warning("kill(%d, SIGTERM) [%d] failed", pid, iter->second->id);
        }
        break;
    }
}
}  // namespace swoole

swoole::WorkerId swoole_get_worker_id() {
    return SwooleWG.id;
}

pid_t swoole_get_worker_pid() {
    return SwooleWG.pid;
}

int swoole_get_worker_type() {
    return SwooleWG.type;
}

void swoole_set_worker_id(swoole::WorkerId worker_id) {
    SwooleWG.id = worker_id;
}

void swoole_set_worker_pid(pid_t pid) {
    SwooleWG.pid = pid;
}

void swoole_set_worker_type(int type) {
    SwooleWG.type = type;
}

char swoole_get_worker_symbol() {
    switch (swoole_get_worker_type()) {
    case SW_MASTER:
        return '#';
    case SW_MANAGER:
        return '$';
    case SW_WORKER:
        return '*';
    case SW_TASK_WORKER:
        return '^';
    case SW_USER_WORKER:
        return '@';
    default:
        return '%';
    }
}
