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

#include <assert.h>
#include <pwd.h>
#include <grp.h>
#include <sys/uio.h>
#include <sys/mman.h>

#include "server.h"
#include "swoole_memory.h"
#include "swoole_log.h"
#include "msg_queue.h"
#include "client.h"
#include "swoole_async.h"

using namespace swoole;

swWorkerGlobal SwooleWG = {};

static int swWorker_onPipeReceive(swReactor *reactor, swEvent *event);
static int swWorker_onStreamAccept(swReactor *reactor, swEvent *event);
static int swWorker_onStreamRead(swReactor *reactor, swEvent *event);
static int swWorker_onStreamPackage(swProtocol *proto, swSocket *sock, const char *data, uint32_t length);
static int swWorker_onStreamClose(swReactor *reactor, swEvent *event);
static void swWorker_reactor_try_to_exit(swReactor *reactor);

void swWorker_signal_init(void) {
    /**
     * use user settings
     */
    SwooleG.use_signalfd = SwooleG.enable_signalfd;

    swSignal_set(SIGHUP, nullptr);
    swSignal_set(SIGPIPE, nullptr);
    swSignal_set(SIGUSR1, nullptr);
    swSignal_set(SIGUSR2, nullptr);
    // swSignal_set(SIGINT, swWorker_signal_handler);
    swSignal_set(SIGTERM, swWorker_signal_handler);
    // for test
    swSignal_set(SIGVTALRM, swWorker_signal_handler);
#ifdef SIGRTMIN
    swSignal_set(SIGRTMIN, swWorker_signal_handler);
#endif
}

void swWorker_signal_handler(int signo) {
    if (!SwooleG.running or !sw_server()) {
        return;
    }
    switch (signo) {
    case SIGTERM:
        /**
         * Event worker
         */
        if (SwooleTG.reactor) {
            sw_server()->stop_async_worker(SwooleWG.worker);
        }
        /**
         * Task worker
         */
        else {
            SwooleWG.shutdown = true;
        }
        break;
    /**
     * for test
     */
    case SIGVTALRM:
        swWarn("SIGVTALRM coming");
        break;
    case SIGUSR1:
    case SIGUSR2:
        sw_logger()->reopen();
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

static sw_inline int swWorker_discard_data(swServer *serv, swConnection *conn, swEventData *task) {
    if (conn == nullptr) {
        if (serv->disable_notify && !serv->discard_timeout_request) {
            return SW_FALSE;
        }
        goto _discard_data;
    } else {
        if (conn->closed) {
            goto _discard_data;
        } else {
            return SW_FALSE;
        }
    }
_discard_data : {
    swoole_error_log(SW_LOG_WARNING,
                     SW_ERROR_SESSION_DISCARD_TIMEOUT_DATA,
                     "[2] received the wrong data[%d bytes] from socket#%d",
                     task->info.len,
                     task->info.fd);
}
    return SW_TRUE;
}

static int swWorker_onStreamAccept(swReactor *reactor, swEvent *event) {
    swSocketAddress client_addr;
    swSocket *sock = swSocket_accept(event->socket, &client_addr);
    if (sock == nullptr) {
        switch (errno) {
        case EINTR:
        case EAGAIN:
            return SW_OK;
        default:
            swSysWarn("accept() failed");
            return SW_OK;
        }
    }

    sock->fdtype = SW_FD_STREAM;
    sock->socket_type = SW_SOCK_UNIX_STREAM;

    return reactor->add(reactor, sock, SW_EVENT_READ);
}

static int swWorker_onStreamRead(swReactor *reactor, swEvent *event) {
    swSocket *conn = event->socket;
    swServer *serv = (swServer *) reactor->ptr;
    swProtocol *protocol = &serv->stream_protocol;
    swString *buffer;

    if (!event->socket->recv_buffer) {
        if (serv->buffer_pool->empty()) {
            buffer = swString_new(8192);
            if (!buffer) {
                return SW_ERR;
            }
        } else {
            buffer = serv->buffer_pool->front();
            serv->buffer_pool->pop();
        }
        event->socket->recv_buffer = buffer;
    } else {
        buffer = event->socket->recv_buffer;
    }

    if (swProtocol_recv_check_length(protocol, conn, buffer) < 0) {
        swWorker_onStreamClose(reactor, event);
    }

    return SW_OK;
}

static int swWorker_onStreamClose(swReactor *reactor, swEvent *event) {
    swSocket *sock = event->socket;
    swServer *serv = (swServer *) reactor->ptr;

    swString_clear(sock->recv_buffer);
    serv->buffer_pool->push(sock->recv_buffer);
    sock->recv_buffer = nullptr;

    reactor->del(reactor, sock);
    reactor->close(reactor, sock);

    if (serv->last_stream_socket == sock) {
        serv->last_stream_socket = nullptr;
    }

    return SW_OK;
}

static int swWorker_onStreamPackage(swProtocol *proto, swSocket *sock, const char *data, uint32_t length) {
    swServer *serv = (swServer *) proto->private_data_2;

    /**
     * passing memory pointer
     */
    swPacket_ptr task;
    memcpy(&task.info, data + 4, sizeof(task.info));
    task.info.flags = SW_EVENT_DATA_PTR;

    sw_memset_zero(&task.data, sizeof(task.data));
    task.data.length = length - (uint32_t) sizeof(task.info) - 4;
    task.data.str = (char *) (data + 4 + sizeof(task.info));

    /**
     * do task
     */
    serv->last_stream_socket = sock;
    serv->accept_task((swEventData *) &task);
    serv->last_stream_socket = nullptr;

    /**
     * stream end
     */
    int _end = 0;
    SwooleTG.reactor->write(SwooleTG.reactor, sock, (void *) &_end, sizeof(_end));

    return SW_OK;
}

typedef std::function<int(swServer *, swRecvData *)> task_callback;

static sw_inline void swWorker_do_task(swServer *serv,
                                       swWorker *worker,
                                       swEventData *task,
                                       const task_callback &callback) {
    swRecvData recv_data;
    recv_data.info = task->info;
    recv_data.info.len = serv->get_packet(serv, task, const_cast<char **>(&recv_data.data));
#ifdef SW_BUFFER_RECV_TIME
    serv->last_receive_usec = task->info.time;
#endif
    callback(serv, &recv_data);
#ifdef SW_BUFFER_RECV_TIME
    serv->last_receive_usec = 0;
#endif
    worker->request_count++;
    sw_atomic_fetch_add(&serv->gs->request_count, 1);
}

int Server::accept_task(swEventData *task) {
    swWorker *worker = SwooleWG.worker;
    // worker busy
    worker->status = SW_WORKER_BUSY;

    switch (task->info.type) {
    case SW_SERVER_EVENT_RECV_DATA: {
        swConnection *conn = get_connection_verify(task->info.fd);
        if (conn && max_queued_bytes && task->info.len > 0) {
            sw_atomic_fetch_sub(&conn->queued_bytes, task->info.len);
            swTraceLog(SW_TRACE_SERVER, "[Worker] len=%d, qb=%d\n", task->info.len, conn->queued_bytes);
        }
        // discard data
        if (swWorker_discard_data(this, conn, task) == SW_TRUE) {
            break;
        }
        swWorker_do_task(this, worker, task, onReceive);
        break;
    }
    case SW_SERVER_EVENT_RECV_DGRAM: {
        swWorker_do_task(this, worker, task, onPacket);
        break;
    }
    case SW_SERVER_EVENT_CLOSE: {
#ifdef SW_USE_OPENSSL
        swConnection *conn = get_connection_verify_no_ssl(task->info.fd);
        if (conn && conn->ssl_client_cert && conn->ssl_client_cert_pid == SwooleG.pid) {
            sw_free(conn->ssl_client_cert);
            conn->ssl_client_cert = nullptr;
        }
#endif
        factory.end(&factory, task->info.fd);
        break;
    }
    case SW_SERVER_EVENT_CONNECT: {
#ifdef SW_USE_OPENSSL
        // SSL client certificate
        if (task->info.len > 0) {
            swConnection *conn = get_connection_verify_no_ssl(task->info.fd);
            char *cert_data = nullptr;
            size_t length = get_packet(this, task, &cert_data);
            conn->ssl_client_cert = new String(cert_data, length);
            conn->ssl_client_cert_pid = SwooleG.pid;
        }
#endif
        if (onConnect) {
            onConnect(this, &task->info);
        }
        break;
    }

    case SW_SERVER_EVENT_BUFFER_FULL: {
        if (onBufferFull) {
            onBufferFull(this, &task->info);
        }
        break;
    }
    case SW_SERVER_EVENT_BUFFER_EMPTY: {
        if (onBufferEmpty) {
            onBufferEmpty(this, &task->info);
        }
        break;
    }
    case SW_SERVER_EVENT_FINISH: {
        onFinish(this, task);
        break;
    }
    case SW_SERVER_EVENT_PIPE_MESSAGE: {
        onPipeMessage(this, task);
        break;
    }
    default:
        swWarn("[Worker] error event[type=%d]", (int) task->info.type);
        break;
    }

    // worker idle
    worker->status = SW_WORKER_IDLE;

    // maximum number of requests, process will exit.
    if (!SwooleWG.run_always && worker->request_count >= SwooleWG.max_request) {
        stop_async_worker(worker);
    }
    return SW_OK;
}

void Server::worker_start_callback() {
    if (SwooleG.process_id >= worker_num) {
        SwooleG.process_type = SW_PROCESS_TASKWORKER;
    } else {
        SwooleG.process_type = SW_PROCESS_WORKER;
    }

    if (enable_coroutine) {
        SwooleG.enable_coroutine = 1;
    }

    int is_root = !geteuid();
    struct passwd *_passwd = nullptr;
    struct group *_group = nullptr;

    if (is_root) {
        // get group info
        if (!group.empty()) {
            _group = getgrnam(group.c_str());
            if (!_group) {
                swWarn("get group [%s] info failed", group.c_str());
            }
        }
        // get user info
        if (!user.empty()) {
            _passwd = getpwnam(user.c_str());
            if (!_passwd) {
                swWarn("get user [%s] info failed", user.c_str());
            }
        }
        // chroot
        if (!chroot.empty() && ::chroot(chroot.c_str()) != 0) {
            swSysWarn("chroot to [%s] failed", chroot.c_str());
        }
        // set process group
        if (_group && setgid(_group->gr_gid) < 0) {
            swSysWarn("setgid to [%s] failed", group.c_str());
        }
        // set process user
        if (_passwd && setuid(_passwd->pw_uid) < 0) {
            swSysWarn("setuid to [%s] failed", user.c_str());
        }
    }

    for (uint32_t i = 0; i < worker_num + task_worker_num; i++) {
        swWorker *worker = get_worker(i);
        if (SwooleG.process_id == i) {
            continue;
        }
        if (swIsWorker() && worker->pipe_master) {
            swSocket_set_nonblock(worker->pipe_master);
        }
    }

    if (sw_logger()->is_opened()) {
        sw_logger()->reopen();
    }

    SwooleWG.worker = get_worker(SwooleG.process_id);
    SwooleWG.worker->status = SW_WORKER_IDLE;

    if (factory_mode == SW_MODE_PROCESS) {
        sw_shm_protect(session_list, PROT_READ);
        /**
         * Use only the first block of pipe_buffer memory in worker process
         */
        for (uint32_t i = 1; i < reactor_num; i++) {
            sw_free(pipe_buffers[i]);
        }
    }

#ifdef HAVE_SIGNALFD
    if (SwooleG.use_signalfd && SwooleTG.reactor && SwooleG.signal_fd == 0) {
        swSignalfd_setup(SwooleTG.reactor);
    }
#endif

    call_worker_start_callback(SwooleWG.worker);
}

void Server::worker_stop_callback() {
    if (onWorkerStop) {
        onWorkerStop(this, SwooleG.process_id);
    }
    if (worker_input_buffers) {
        free_buffers(this, get_worker_buffer_num(), worker_input_buffers);
    }
}

void Server::stop_async_worker(swWorker *worker) {
    swServer *serv = (swServer *) worker->pool->ptr;
    worker->status = SW_WORKER_BUSY;

    swReactor *reactor = SwooleTG.reactor;

    /**
     * force to end.
     */
    if (serv->reload_async == 0) {
        serv->running = false;
        reactor->running = false;
        return;
    }

    // The worker process is shutting down now.
    if (reactor->wait_exit) {
        return;
    }

    if (serv->stream_socket) {
        reactor->del(reactor, serv->stream_socket);
        swSocket_free(serv->stream_socket);
        serv->stream_socket = nullptr;
    }

    if (worker->pipe_worker) {
        swReactor_remove_read_event(reactor, worker->pipe_worker);
    }

    if (serv->factory_mode == SW_MODE_BASE && swIsWorker()) {
        for (auto ls : serv->ports) {
            reactor->del(reactor, ls->socket);
        }
        if (worker->pipe_master) {
            swReactor_remove_read_event(reactor, worker->pipe_master);
        }
        int fd;
        int serv_max_fd = serv->get_maxfd();
        int serv_min_fd = serv->get_minfd();

        for (fd = serv_min_fd; fd <= serv_max_fd; fd++) {
            swConnection *conn = serv->get_connection(fd);
            if (conn && conn->socket && conn->active && !conn->peer_closed && conn->socket->fdtype == SW_FD_SESSION) {
                swReactor_remove_read_event(reactor, conn->socket);
            }
        }
        serv->clear_timer();
        goto _try_to_exit;
    }

    WorkerStopMessage msg;
    msg.pid = SwooleG.pid;
    msg.worker_id = SwooleG.process_id;

    // send message to manager
    if (serv->message_box && serv->message_box->push(&msg, sizeof(msg)) < 0) {
        serv->running = 0;
    } else {
        swoole_kill(serv->gs->manager_pid, SIGIO);
    }

_try_to_exit:
    swReactor_wait_exit(reactor, true);
    reactor->set_end_callback(SW_REACTOR_PRIORITY_TRY_EXIT, swWorker_reactor_try_to_exit);
    SwooleWG.exit_time = time(nullptr);

    swWorker_reactor_try_to_exit(reactor);
    if (!reactor->running) {
        serv->running = false;
    }
}

static void swWorker_reactor_try_to_exit(swReactor *reactor) {
    swServer *serv;
    if (SwooleG.process_type == SW_PROCESS_TASKWORKER) {
        swProcessPool *pool = (swProcessPool *) reactor->ptr;
        serv = (swServer *) pool->ptr;
    } else {
        serv = (swServer *) reactor->ptr;
    }
    uint8_t call_worker_exit_func = 0;

    while (1) {
        if (reactor->if_exit()) {
            reactor->running = false;
            break;
        } else {
            if (serv->onWorkerExit && call_worker_exit_func == 0) {
                serv->onWorkerExit(serv, SwooleG.process_id);
                call_worker_exit_func = 1;
                continue;
            }
            int remaining_time = serv->max_wait_time - (time(nullptr) - SwooleWG.exit_time);
            if (remaining_time <= 0) {
                swoole_error_log(
                    SW_LOG_WARNING, SW_ERROR_SERVER_WORKER_EXIT_TIMEOUT, "worker exit timeout, forced to terminate");
                reactor->running = false;
                break;
            } else {
                int timeout_msec = remaining_time * 1000;
                if (reactor->timeout_msec < 0 || reactor->timeout_msec > timeout_msec) {
                    reactor->timeout_msec = timeout_msec;
                }
            }
        }
        break;
    }
}

void Server::drain_worker_pipe() {
    for (uint32_t i = 0; i < worker_num + task_worker_num; i++) {
        swWorker *worker = get_worker(i);
        if (SwooleTG.reactor) {
            if (worker->pipe_worker) {
                swReactor_drain_write_buffer(SwooleTG.reactor, worker->pipe_worker);
            }
            if (worker->pipe_master) {
                swReactor_drain_write_buffer(SwooleTG.reactor, worker->pipe_master);
            }
        }
    }
}

/**
 * main loop [Worker]
 */
int Server::start_event_worker(swWorker *worker) {
    // worker_id
    SwooleG.process_id = worker->id;

    init_worker(worker);

    if (swoole_event_init(0) < 0) {
        return SW_ERR;
    }

    swReactor *reactor = SwooleTG.reactor;
    /**
     * set pipe buffer size
     */
    for (uint32_t i = 0; i < worker_num + task_worker_num; i++) {
        swWorker *_worker = get_worker(i);
        if (_worker->pipe_master) {
            _worker->pipe_master->buffer_size = UINT_MAX;
        }
        if (_worker->pipe_worker) {
            _worker->pipe_worker->buffer_size = UINT_MAX;
        }
    }

    swSocket_set_nonblock(worker->pipe_worker);
    reactor->ptr = this;
    reactor->add(reactor, worker->pipe_worker, SW_EVENT_READ);
    reactor->set_handler(SW_FD_PIPE, swWorker_onPipeReceive);

    if (dispatch_mode == SW_DISPATCH_STREAM) {
        reactor->add(reactor, stream_socket, SW_EVENT_READ);
        reactor->set_handler(SW_FD_STREAM_SERVER, swWorker_onStreamAccept);
        reactor->set_handler(SW_FD_STREAM, swWorker_onStreamRead);
        swStream_set_protocol(&stream_protocol);
        stream_protocol.private_data_2 = this;
        stream_protocol.package_max_length = UINT_MAX;
        stream_protocol.onPackage = swWorker_onStreamPackage;
        buffer_pool = new std::queue<swString *>;
    }

    worker->status = SW_WORKER_IDLE;
    worker_start_callback();

    // main loop
    reactor->wait(reactor, nullptr);
    // drain pipe buffer
    drain_worker_pipe();
    // reactor free
    swoole_event_free();
    // worker shutdown
    worker_stop_callback();

    if (buffer_pool) {
        delete buffer_pool;
    }

    return SW_OK;
}

/**
 * Send data to ReactorThread
 */
int Server::send_to_reactor_thread(swEventData *ev_data, size_t sendn, int session_id) {
    swSocket *pipe_sock = get_reactor_thread_pipe(session_id, ev_data->info.reactor_id);
    if (SwooleTG.reactor) {
        return SwooleTG.reactor->write(SwooleTG.reactor, pipe_sock, ev_data, sendn);
    } else {
        return swSocket_write_blocking(pipe_sock, ev_data, sendn);
    }
}

/**
 * send message from worker to another worker
 */
int Server::send_to_worker_from_worker(swWorker *dst_worker, const void *buf, size_t len, int flags) {
    return swWorker_send_pipe_message(dst_worker, buf, len, flags);
}

/**
 * receive data from reactor
 */
static int swWorker_onPipeReceive(swReactor *reactor, swEvent *event) {
    ssize_t recv_n = 0;
    swServer *serv = (swServer *) reactor->ptr;
    swPipeBuffer *pipe_buffer = serv->pipe_buffers[0];
    void *buffer;
    struct iovec buffers[2];
    int recv_chunk_count = 0;

_read_from_pipe:
    recv_n = recv(event->fd, &pipe_buffer->info, sizeof(pipe_buffer->info), MSG_PEEK);
    if (recv_n < 0) {
        if (errno == EAGAIN) {
            return SW_OK;
        }
        return SW_ERR;
    }

    if (pipe_buffer->info.flags & SW_EVENT_DATA_CHUNK) {
        buffer = serv->get_buffer(serv, &pipe_buffer->info);
        size_t remain_len = pipe_buffer->info.len - serv->get_buffer_len(serv, &pipe_buffer->info);

        buffers[0].iov_base = &pipe_buffer->info;
        buffers[0].iov_len = sizeof(pipe_buffer->info);
        buffers[1].iov_base = buffer;
        buffers[1].iov_len = SW_MIN(serv->ipc_max_size - sizeof(pipe_buffer->info), remain_len);

        recv_n = readv(event->fd, buffers, 2);
        assert(recv_n != 0);
        if (recv_n < 0 && errno == EAGAIN) {
            return SW_OK;
        }
        if (recv_n > 0) {
            serv->add_buffer_len(serv, &pipe_buffer->info, recv_n - sizeof(pipe_buffer->info));
        }

        recv_chunk_count++;

        if (!(pipe_buffer->info.flags & SW_EVENT_DATA_END)) {
            /**
             * if the reactor thread sends too many chunks to the worker process,
             * the worker process may receive chunks all the time,
             * resulting in the worker process being unable to handle other tasks.
             * in order to make the worker process handle tasks fairly,
             * the maximum number of consecutive chunks received by the worker is limited.
             */
            if (recv_chunk_count >= SW_WORKER_MAX_RECV_CHUNK_COUNT) {
                swTraceLog(SW_TRACE_WORKER,
                           "worker process[%lu] receives the chunk data to the maximum[%d], return to event loop",
                           SwooleG.process_id,
                           recv_chunk_count);
                return SW_OK;
            }
            goto _read_from_pipe;
        } else {
            pipe_buffer->info.flags |= SW_EVENT_DATA_OBJ_PTR;
            /**
             * Because we don't want to split the swEventData parameters into swDataHead and data,
             * we store the value of the worker_buffer pointer in swEventData.data.
             * The value of this pointer will be fetched in the swServer_worker_get_packet function.
             */
            serv->move_buffer(serv, pipe_buffer);
        }
    } else {
        recv_n = read(event->fd, pipe_buffer, serv->ipc_max_size);
    }

    if (recv_n > 0) {
        return serv->accept_task((swEventData *) pipe_buffer);
    }

    return SW_ERR;
}

int swWorker_send_pipe_message(swWorker *dst_worker, const void *buf, size_t n, int flags) {
    swSocket *pipe_sock;

    if (flags & SW_PIPE_MASTER) {
        pipe_sock = dst_worker->pipe_master;
    } else {
        pipe_sock = dst_worker->pipe_worker;
    }

    // message-queue
    if (dst_worker->pool->use_msgqueue) {
        struct {
            long mtype;
            swEventData buf;
        } msg;

        msg.mtype = dst_worker->id + 1;
        memcpy(&msg.buf, buf, n);

        return swMsgQueue_push(dst_worker->pool->queue, (swQueue_data *) &msg, n);
    }

    if ((flags & SW_PIPE_NONBLOCK) && SwooleTG.reactor) {
        return SwooleTG.reactor->write(SwooleTG.reactor, pipe_sock, buf, n);
    } else {
        return swSocket_write_blocking(pipe_sock, buf, n);
    }
}
