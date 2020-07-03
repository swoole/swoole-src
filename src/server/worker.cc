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

#include "server.h"
#include "client.h"
#include "async.h"

#include <pwd.h>
#include <grp.h>
#include <sys/uio.h>

static int swWorker_onPipeReceive(swReactor *reactor, swEvent *event);
static int swWorker_onStreamAccept(swReactor *reactor, swEvent *event);
static int swWorker_onStreamRead(swReactor *reactor, swEvent *event);
static int swWorker_onStreamPackage(swProtocol *proto, swSocket *sock, const char *data, uint32_t length);
static int swWorker_onStreamClose(swReactor *reactor, swEvent *event);
static int swWorker_reactor_is_empty(swReactor *reactor);

void swWorker_signal_init(void)
{
    /**
     * use user settings
     */
    SwooleG.use_signalfd = SwooleG.enable_signalfd;

    swSignal_add(SIGHUP, nullptr);
    swSignal_add(SIGPIPE, nullptr);
    swSignal_add(SIGUSR1, nullptr);
    swSignal_add(SIGUSR2, nullptr);
    //swSignal_add(SIGINT, swWorker_signal_handler);
    swSignal_add(SIGTERM, swWorker_signal_handler);
    swSignal_add(SIGALRM, swSystemTimer_signal_handler);
    //for test
    swSignal_add(SIGVTALRM, swWorker_signal_handler);
#ifdef SIGRTMIN
    swSignal_add(SIGRTMIN, swWorker_signal_handler);
#endif
}

void swWorker_signal_handler(int signo)
{
    switch (signo)
    {
    case SIGTERM:
        /**
         * Event worker
         */
        if (SwooleTG.reactor)
        {
            swWorker_stop(SwooleWG.worker);
        }
        /**
         * Task worker
         */
        else
        {
            SwooleWG.shutdown = 1;
        }
        break;
    case SIGALRM:
        swSystemTimer_signal_handler(SIGALRM);
        break;
    /**
     * for test
     */
    case SIGVTALRM:
        swWarn("SIGVTALRM coming");
        break;
    case SIGUSR1:
    case SIGUSR2:
        swLog_reopen();
        break;
    default:
#ifdef SIGRTMIN
        if (signo == SIGRTMIN)
        {
            swLog_reopen();
        }
#endif
        break;
    }
}

static sw_inline int swWorker_discard_data(swServer *serv, swConnection *conn, swEventData *task)
{
    if (conn == nullptr)
    {
        if (serv->disable_notify && !serv->discard_timeout_request)
        {
            return SW_FALSE;
        }
        goto _discard_data;
    }
    else
    {
        if (conn->closed)
        {
            goto _discard_data;
        }
        else
        {
            return SW_FALSE;
        }
    }
    _discard_data:
    {
        swoole_error_log(
            SW_LOG_WARNING, SW_ERROR_SESSION_DISCARD_TIMEOUT_DATA,
            "[2] received the wrong data[%d bytes] from socket#%d",
            task->info.len, task->info.fd
        );
    }
    return SW_TRUE;
}

static int swWorker_onStreamAccept(swReactor *reactor, swEvent *event)
{
    swSocketAddress client_addr;
    swSocket *sock = swSocket_accept(event->socket, &client_addr);
    if (sock == nullptr)
    {
        switch (errno)
        {
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

static int swWorker_onStreamRead(swReactor *reactor, swEvent *event)
{
    swSocket *conn = event->socket;
    swServer *serv = (swServer *) reactor->ptr;
    swProtocol *protocol = &serv->stream_protocol;
    swString *buffer;

    if (!event->socket->recv_buffer)
    {
        if (serv->buffer_pool->empty())
        {
            buffer = swString_new(8192);
            if (!buffer)
            {
                return SW_ERR;
            }
        }
        else
        {
            buffer = serv->buffer_pool->front();
            serv->buffer_pool->pop();
        }
        event->socket->recv_buffer = buffer;
    }
    else
    {
        buffer = event->socket->recv_buffer;
    }

    if (swProtocol_recv_check_length(protocol, conn, buffer) < 0)
    {
        swWorker_onStreamClose(reactor, event);
    }

    return SW_OK;
}

static int swWorker_onStreamClose(swReactor *reactor, swEvent *event)
{
    swSocket *sock = event->socket;
    swServer *serv = (swServer *) reactor->ptr;

    swString_clear(sock->recv_buffer);
    serv->buffer_pool->push(sock->recv_buffer);
    sock->recv_buffer = nullptr;

    reactor->del(reactor, sock);
    reactor->close(reactor, sock);

    if (serv->last_stream_socket == sock)
    {
        serv->last_stream_socket = nullptr;
    }

    return SW_OK;
}

static int swWorker_onStreamPackage(swProtocol *proto, swSocket *sock, const char *data, uint32_t length)
{
    swServer *serv = (swServer *) proto->private_data_2;

    /**
     * passing memory pointer
     */
    swPacket_ptr task;
    memcpy(&task.info, data + 4, sizeof(task.info));
    task.info.flags = SW_EVENT_DATA_PTR;

    sw_memset_zero(&task.data, sizeof(task.data));
    task.data.length = length - (uint32_t) sizeof(task.info) - 4;
    task.data.str = (char*) (data + 4 + sizeof(task.info));

    /**
     * do task
     */
    serv->last_stream_socket = sock;
    swWorker_onTask(&serv->factory, (swEventData *) &task);
    serv->last_stream_socket = nullptr;

    /**
     * stream end
     */
    int _end = 0;
    SwooleTG.reactor->write(SwooleTG.reactor, sock, (void *) &_end, sizeof(_end));

    return SW_OK;
}

typedef int (*task_callback)(swServer *, swEventData *);

static sw_inline void swWorker_do_task(swServer *serv, swWorker *worker, swEventData *task, task_callback callback)
{
#ifdef SW_BUFFER_RECV_TIME
    serv->last_receive_usec = task->info.time;
#endif
    callback(serv, task);
#ifdef SW_BUFFER_RECV_TIME
    serv->last_receive_usec = 0;
#endif
    worker->request_count++;
    sw_atomic_fetch_add(&serv->stats->request_count, 1);
}

int swWorker_onTask(swFactory *factory, swEventData *task)
{
    swServer *serv = (swServer *) factory->ptr;

    swWorker *worker = SwooleWG.worker;
    //worker busy
    worker->status = SW_WORKER_BUSY;

    switch (task->info.type)
    {
    case SW_SERVER_EVENT_SEND_DATA:
    {
        swConnection *conn = swServer_connection_verify(serv, task->info.fd);
        if (conn && serv->max_queued_bytes && task->info.len > 0)
        {
            sw_atomic_fetch_sub(&conn->queued_bytes, task->info.len);
            swTraceLog(SW_TRACE_SERVER, "[Worker] len=%d, qb=%d\n",  task->info.len, conn->queued_bytes);
        }
        //discard data
        if (swWorker_discard_data(serv, conn, task) == SW_TRUE)
        {
            break;
        }
        swWorker_do_task(serv, worker, task, serv->onReceive);
        break;
    }
    case SW_SERVER_EVENT_SNED_DGRAM:
    {
        swWorker_do_task(serv, worker, task, serv->onPacket);
        break;
    }
    case SW_SERVER_EVENT_CLOSE:
    {
#ifdef SW_USE_OPENSSL
        swConnection *conn = swServer_connection_verify_no_ssl(serv, task->info.fd);
        if (conn && conn->ssl_client_cert && conn->ssl_client_cert_pid == SwooleG.pid)
        {
            sw_free(conn->ssl_client_cert);
            conn->ssl_client_cert = nullptr;
        }
#endif
        factory->end(factory, task->info.fd);
        break;
    }
    case SW_SERVER_EVENT_CONNECT:
    {
#ifdef SW_USE_OPENSSL
        //SSL client certificate
        if (task->info.len > 0)
        {
            swConnection *conn = swServer_connection_verify_no_ssl(serv, task->info.fd);
            char *cert_data = nullptr;
            size_t length = serv->get_packet(serv, task, &cert_data);
            conn->ssl_client_cert = swString_dup(cert_data, length);
            conn->ssl_client_cert_pid = SwooleG.pid;
        }
#endif
        if (serv->onConnect)
        {
            serv->onConnect(serv, &task->info);
        }
        break;
    }

    case SW_SERVER_EVENT_BUFFER_FULL:
    {
        if (serv->onBufferFull)
        {
            serv->onBufferFull(serv, &task->info);
        }
        break;
    }
    case SW_SERVER_EVENT_BUFFER_EMPTY:
    {
        if (serv->onBufferEmpty)
        {
            serv->onBufferEmpty(serv, &task->info);
        }
        break;
    }
    case SW_SERVER_EVENT_FINISH:
    {
        serv->onFinish(serv, task);
        break;
    }
    case SW_SERVER_EVENT_PIPE_MESSAGE:
    {
        serv->onPipeMessage(serv, task);
        break;
    }
    default:
        swWarn("[Worker] error event[type=%d]", (int )task->info.type);
        break;
    }

    //worker idle
    worker->status = SW_WORKER_IDLE;

    //maximum number of requests, process will exit.
    if (!SwooleWG.run_always && worker->request_count >= SwooleWG.max_request)
    {
        swWorker_stop(worker);
    }
    return SW_OK;
}

void swWorker_onStart(swServer *serv)
{
    if (SwooleWG.id >= serv->worker_num)
    {
        SwooleG.process_type = SW_PROCESS_TASKWORKER;
    }
    else
    {
        SwooleG.process_type = SW_PROCESS_WORKER;
    }

    if (serv->enable_coroutine)
    {
        SwooleG.enable_coroutine = 1;
    }

    int is_root = !geteuid();
    struct passwd *passwd = nullptr;
    struct group *group = nullptr;

    if (is_root)
    {
        //get group info
        if (!serv->group.empty())
        {
            group = getgrnam(serv->group.c_str());
            if (!group)
            {
                swWarn("get group [%s] info failed", serv->group);
            }
        }
        //get user info
        if (!serv->user.empty())
        {
            passwd = getpwnam(serv->user.c_str());
            if (!passwd)
            {
                swWarn("get user [%s] info failed", serv->user.c_str());
            }
        }
        //chroot
        if (!serv->chroot.empty() && chroot(serv->chroot.c_str()) != 0)
        {
            swSysWarn("chroot to [%s] failed", serv->chroot.c_str());
        }
        //set process group
        if (group && setgid(group->gr_gid) < 0)
        {
            swSysWarn("setgid to [%s] failed", serv->group.c_str());
        }
        //set process user
        if (passwd && setuid(passwd->pw_uid) < 0)
        {
            swSysWarn("setuid to [%s] failed", serv->user.c_str());
        }
    }

    for (uint32_t i = 0; i < serv->worker_num + serv->task_worker_num; i++)
    {
        swWorker *worker = swServer_get_worker(serv, i);
        if (SwooleWG.id == i)
        {
            continue;
        }
        if (swIsWorker() && worker->pipe_master)
        {
            swSocket_set_nonblock(worker->pipe_master);
        }
    }

    if (swLog_is_opened())
    {
        swLog_reopen();
    }

    SwooleWG.worker = swServer_get_worker(serv, SwooleWG.id);
    SwooleWG.worker->status = SW_WORKER_IDLE;

    if (serv->factory_mode == SW_MODE_PROCESS)
    {
        sw_shm_protect(serv->session_list, PROT_READ);
        /**
         * Use only the first block of pipe_buffer memory in worker process
         */
        for (uint32_t i = 1; i < serv->reactor_num; i++)
        {
            sw_free(serv->pipe_buffers[i]);
        }
    }

#ifdef HAVE_SIGNALFD
    if (SwooleG.use_signalfd && SwooleTG.reactor && SwooleG.signal_fd == 0)
    {
        swSignalfd_setup(SwooleTG.reactor);
    }
#endif

    swServer_worker_start(serv, SwooleWG.worker);
}

void swWorker_onStop(swServer *serv)
{
    if (serv->onWorkerStop)
    {
        serv->onWorkerStop(serv, SwooleWG.id);
    }
}

void swWorker_stop(swWorker *worker)
{
    swServer *serv = (swServer *) worker->pool->ptr;
    worker->status = SW_WORKER_BUSY;

    swReactor *reactor = SwooleTG.reactor;

    /**
     * force to end.
     */
    if (serv->reload_async == 0)
    {
        serv->running = 0;
        reactor->running = 0;
        return;
    }

    //The worker process is shutting down now.
    if (reactor->wait_exit)
    {
        return;
    }

    if (serv->stream_socket)
    {
        reactor->del(reactor, serv->stream_socket);
        swSocket_free(serv->stream_socket);
        serv->stream_socket = nullptr;
    }

    if (worker->pipe_worker)
    {
        swReactor_remove_read_event(reactor, worker->pipe_worker);
    }

    if (serv->factory_mode == SW_MODE_BASE && swIsWorker())
    {
        for (auto ls : serv->ports)
        {
            reactor->del(reactor, ls->socket);
        }
        if (worker->pipe_master)
        {
            swReactor_remove_read_event(reactor, worker->pipe_master);
        }
        int fd;
        int serv_max_fd = swServer_get_maxfd(serv);
        int serv_min_fd = swServer_get_minfd(serv);

        for (fd = serv_min_fd; fd <= serv_max_fd; fd++)
        {
            swConnection *conn = swServer_connection_get(serv, fd);
            if (conn && conn->socket && conn->active && !conn->peer_closed && conn->socket->fdtype == SW_FD_SESSION)
            {
                swReactor_remove_read_event(reactor, conn->socket);
            }
        }
        swServer_clear_timer(serv);
        goto _try_to_exit;
    }

    swWorkerStopMessage msg;
    msg.pid = SwooleG.pid;
    msg.worker_id = SwooleWG.id;

    //send message to manager
    if (serv->message_box && swChannel_push(serv->message_box, &msg, sizeof(msg)) < 0)
    {
        serv->running = 0;
    }
    else
    {
        swoole_kill(serv->gs->manager_pid, SIGIO);
    }

    _try_to_exit: swReactor_wait_exit(reactor, 1);
    reactor->is_empty = swWorker_reactor_is_empty;
    SwooleWG.exit_time = time(nullptr);

    if (swWorker_reactor_is_empty(reactor))
    {
        serv->running = reactor->running = 0;
    }
}

static int swWorker_reactor_is_empty(swReactor *reactor)
{
    swServer *serv;
    if (SwooleG.process_type == SW_PROCESS_TASKWORKER)
    {
        swProcessPool *pool = (swProcessPool *) reactor->ptr;
        serv = (swServer *) pool->ptr;
    }
    else
    {
        serv = (swServer *) reactor->ptr;
    }
    uint8_t call_worker_exit_func = 0;

    while (1)
    {
        if (swReactor_empty(reactor))
        {
            return SW_TRUE;
        }
        else
        {
            if (serv->onWorkerExit && call_worker_exit_func == 0)
            {
                serv->onWorkerExit(serv, SwooleWG.id);
                call_worker_exit_func = 1;
                continue;
            }
            int remaining_time = serv->max_wait_time - (time(nullptr) - SwooleWG.exit_time);
            if (remaining_time <= 0)
            {
                swoole_error_log(SW_LOG_WARNING, SW_ERROR_SERVER_WORKER_EXIT_TIMEOUT, "worker exit timeout, forced to terminate");
                return SW_TRUE;
            }
            else
            {
                int timeout_msec = remaining_time * 1000;
                if (reactor->timeout_msec < 0 || reactor->timeout_msec > timeout_msec)
                {
                    reactor->timeout_msec = timeout_msec;
                }
            }
        }
        break;
    }

    return SW_FALSE;
}

void swWorker_clean_pipe_buffer(swServer *serv)
{
    uint32_t i;
    for (i = 0; i < serv->worker_num + serv->task_worker_num; i++)
    {
        swWorker *worker = swServer_get_worker(serv, i);
        if (SwooleTG.reactor)
        {
            if (worker->pipe_worker)
            {
                swReactor_wait_write_buffer(SwooleTG.reactor, worker->pipe_worker);
            }
            if (worker->pipe_master)
            {
                swReactor_wait_write_buffer(SwooleTG.reactor, worker->pipe_master);
            }
        }
    }
}

/**
 * main loop [Worker]
 */
int swWorker_loop(swServer *serv, swWorker *worker)
{
    //worker_id
    SwooleWG.id = worker->id;

    swServer_worker_init(serv, worker);

    if (swoole_event_init(0) < 0)
    {
        return SW_ERR;
    }

    swReactor *reactor = SwooleTG.reactor;
    /**
     * set pipe buffer size
     */
    for (uint32_t i = 0; i < serv->worker_num + serv->task_worker_num; i++)
    {
        swWorker *_worker = swServer_get_worker(serv, i);
        if (_worker->pipe_master)
        {
            _worker->pipe_master->buffer_size = UINT_MAX;
        }
        if (_worker->pipe_worker)
        {
            _worker->pipe_worker->buffer_size = UINT_MAX;
        }
    }

    swSocket_set_nonblock(worker->pipe_worker);
    reactor->ptr = serv;
    reactor->add(reactor, worker->pipe_worker, SW_EVENT_READ);
    swReactor_set_handler(reactor, SW_FD_PIPE, swWorker_onPipeReceive);

    if (serv->dispatch_mode == SW_DISPATCH_STREAM)
    {
        reactor->add(reactor, serv->stream_socket, SW_EVENT_READ);
        swReactor_set_handler(reactor, SW_FD_STREAM_SERVER, swWorker_onStreamAccept);
        swReactor_set_handler(reactor, SW_FD_STREAM, swWorker_onStreamRead);
        swStream_set_protocol(&serv->stream_protocol);
        serv->stream_protocol.private_data_2 = serv;
        serv->stream_protocol.package_max_length = UINT_MAX;
        serv->stream_protocol.onPackage = swWorker_onStreamPackage;
        serv->buffer_pool = new std::queue<swString*>;
    }

    worker->status = SW_WORKER_IDLE;
    swWorker_onStart(serv);

    //main loop
    reactor->wait(reactor, nullptr);
    //clear pipe buffer
    swWorker_clean_pipe_buffer(serv);
    //reactor free
    swoole_event_free();
    //worker shutdown
    swWorker_onStop(serv);

    if (serv->buffer_pool)
    {
        delete serv->buffer_pool;
    }

    return SW_OK;
}

/**
 * Send data to ReactorThread
 */
int swWorker_send2reactor(swServer *serv, swEventData *ev_data, size_t sendn, int session_id)
{
    swSocket *pipe_sock = swServer_get_send_pipe(serv, session_id, ev_data->info.reactor_id);
    if (SwooleTG.reactor)
    {
        return SwooleTG.reactor->write(SwooleTG.reactor, pipe_sock, ev_data, sendn);
    }
    else
    {
        return swSocket_write_blocking(pipe_sock, ev_data, sendn);
    }
}

/**
 * receive data from reactor
 */
static int swWorker_onPipeReceive(swReactor *reactor, swEvent *event)
{
    ssize_t recv_n = 0;
    swServer *serv = (swServer *) reactor->ptr;
    swFactory *factory = &serv->factory;
    swPipeBuffer *pipe_buffer = serv->pipe_buffers[0];
    void *buffer;
    struct iovec buffers[2];
    int recv_chunk_count = 0;

    _read_from_pipe:
    recv_n = recv(event->fd, &pipe_buffer->info, sizeof(pipe_buffer->info), MSG_PEEK);
    if (recv_n < 0)
    {
        if (errno == EAGAIN)
        {
            return SW_OK;
        }
        return SW_ERR;
    }
    
    if (pipe_buffer->info.flags & SW_EVENT_DATA_CHUNK)
    {
        buffer = serv->get_buffer(serv, &pipe_buffer->info);
        size_t remain_len = pipe_buffer->info.len - serv->get_buffer_len(serv, &pipe_buffer->info);

        buffers[0].iov_base = &pipe_buffer->info;
        buffers[0].iov_len = sizeof(pipe_buffer->info);
        buffers[1].iov_base = buffer;
        buffers[1].iov_len = SW_MIN(serv->ipc_max_size - sizeof(pipe_buffer->info), remain_len);
        
        recv_n = readv(event->fd, buffers, 2);
        assert(recv_n != 0);
        if (recv_n < 0 && errno == EAGAIN)
        {
            return SW_OK;
        }
        if (recv_n > 0)
        {
            serv->add_buffer_len(serv, &pipe_buffer->info, recv_n - sizeof(pipe_buffer->info));
        }

        recv_chunk_count++;

        if (!(pipe_buffer->info.flags & SW_EVENT_DATA_END))
        {
            /**
             * if the reactor thread sends too many chunks to the worker process,
             * the worker process may receive chunks all the time,
             * resulting in the worker process being unable to handle other tasks.
             * in order to make the worker process handle tasks fairly, 
             * the maximum number of consecutive chunks received by the worker is limited.
             */
            if (recv_chunk_count >= SW_WORKER_MAX_RECV_CHUNK_COUNT)
            {
                swTraceLog(
                    SW_TRACE_WORKER,
                    "worker process[%lu] receives the chunk data to the maximum[%d], return to event loop",
                    SwooleWG.id, recv_chunk_count
                );
                return SW_OK;
            }
            goto _read_from_pipe;
        }
        else
        {
            pipe_buffer->info.flags |= SW_EVENT_DATA_OBJ_PTR;
            /**
             * Because we don't want to split the swEventData parameters into swDataHead and data, 
             * we store the value of the worker_buffer pointer in swEventData.data. 
             * The value of this pointer will be fetched in the swServer_worker_get_packet function.
             */
            serv->move_buffer(serv, pipe_buffer);
        }
    }
    else
    {
        recv_n = read(event->fd, pipe_buffer, serv->ipc_max_size);
    }

    if (recv_n > 0)
    {
        return swWorker_onTask(factory, (swEventData *) pipe_buffer);
    }

    return SW_ERR;
}

int swWorker_send2worker(swWorker *dst_worker, const void *buf, int n, int flag)
{
    swSocket *pipe_sock;

    if (flag & SW_PIPE_MASTER)
    {
        pipe_sock = dst_worker->pipe_master;
    }
    else
    {
        pipe_sock = dst_worker->pipe_worker;
    }

    //message-queue
    if (dst_worker->pool->use_msgqueue)
    {
        struct
        {
            long mtype;
            swEventData buf;
        } msg;

        msg.mtype = dst_worker->id + 1;
        memcpy(&msg.buf, buf, n);

        return swMsgQueue_push(dst_worker->pool->queue, (swQueue_data *) &msg, n);
    }

    if ((flag & SW_PIPE_NONBLOCK) && SwooleTG.reactor)
    {
        return SwooleTG.reactor->write(SwooleTG.reactor, pipe_sock, buf, n);
    }
    else
    {
        return swSocket_write_blocking(pipe_sock, buf, n);
    }
}
