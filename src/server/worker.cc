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

#include "swoole.h"
#include "server.h"
#include "client.h"
#include "async.h"

#include <pwd.h>
#include <grp.h>

static int swWorker_onPipeReceive(swReactor *reactor, swEvent *event);
static int swWorker_onStreamAccept(swReactor *reactor, swEvent *event);
static int swWorker_onStreamRead(swReactor *reactor, swEvent *event);
static int swWorker_onStreamPackage(swProtocol *proto, swConnection *conn, char *data, uint32_t length);
static int swWorker_onStreamClose(swReactor *reactor, swEvent *event);
static int swWorker_reactor_is_empty(swReactor *reactor);

void swWorker_free(swWorker *worker)
{
    if (worker->send_shm)
    {
        sw_shm_free(worker->send_shm);
    }
}

void swWorker_signal_init(void)
{
    /**
     * use user settings
     */
    SwooleG.use_signalfd = SwooleG.enable_signalfd;

    swSignal_add(SIGHUP, NULL);
    swSignal_add(SIGPIPE, NULL);
    swSignal_add(SIGUSR1, NULL);
    swSignal_add(SIGUSR2, NULL);
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
        if (SwooleG.main_reactor)
        {
            swWorker_stop(SwooleWG.worker);
        }
        /**
         * Task worker
         */
        else
        {
            SwooleG.running = 0;
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
        break;
    case SIGUSR2:
        break;
    default:
#ifdef SIGRTMIN
        if (signo == SIGRTMIN)
        {
            swLog_reopen(SwooleG.serv->daemonize ? SW_TRUE : SW_FALSE);
        }
#endif
        break;
    }
}

static sw_inline int swWorker_discard_data(swServer *serv, swEventData *task)
{
    int session_id = task->info.fd;
    //check connection
    swConnection *conn = swServer_connection_verify(serv, session_id);
    if (conn == NULL)
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
        swoole_error_log(SW_LOG_WARNING, SW_ERROR_SESSION_DISCARD_TIMEOUT_DATA, "[1]received the wrong data[%d bytes] from socket#%d", task->info.len, session_id);
    }
    return SW_TRUE;
}

static int swWorker_onStreamAccept(swReactor *reactor, swEvent *event)
{
    swSocketAddress client_addr;
    int fd =  swSocket_accept(event->fd, &client_addr);

    if (fd < 0)
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

    swConnection *conn = swReactor_get(reactor, fd);
    bzero(conn, sizeof(swConnection));
    conn->fd = fd;
    conn->active = 1;
    conn->socket_type = SW_SOCK_UNIX_STREAM;
    conn->nonblock = 1;
    memcpy(&conn->info.addr, &client_addr, sizeof(client_addr));

    if (reactor->add(reactor, fd, SW_FD_STREAM | SW_EVENT_READ) < 0)
    {
        return SW_ERR;
    }

    return SW_OK;
}

static int swWorker_onStreamRead(swReactor *reactor, swEvent *event)
{
    swConnection *conn = event->socket;
    swServer *serv = (swServer *) reactor->ptr;
    swProtocol *protocol = &serv->stream_protocol;
    swString *buffer;

    if (!event->socket->recv_buffer)
    {
        buffer = (swString *) swLinkedList_shift(serv->buffer_pool);
        if (buffer == NULL)
        {
            buffer = swString_new(8192);
            if (!buffer)
            {
                return SW_ERR;
            }

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
    swConnection *conn = event->socket;
    swServer *serv = (swServer *) reactor->ptr;

    swString_clear(conn->recv_buffer);
    swLinkedList_append(serv->buffer_pool, conn->recv_buffer);
    conn->recv_buffer = NULL;

    reactor->del(reactor, conn->fd);
    reactor->close(reactor, conn->fd);

    return SW_OK;
}

static int swWorker_onStreamPackage(swProtocol *proto, swConnection *conn, char *data, uint32_t length)
{
    swServer *serv = (swServer *) proto->private_data_2;

    /**
     * passing memory pointer
     */
    swPackagePtr task;
    memcpy(&task.info, data + 4, sizeof(task.info));
    task.info.flags = SW_EVENT_DATA_PTR;

    bzero(&task.data, sizeof(task.data));
    task.data.length = length - (uint32_t) sizeof(task.info) - 4;
    task.data.str = data + 4 + sizeof(task.info);

    /**
     * do task
     */
    serv->last_stream_fd = conn->fd;
    swWorker_onTask(&serv->factory, (swEventData *) &task);
    serv->last_stream_fd = -1;

    /**
     * stream end
     */
    int _end = 0;
    SwooleG.main_reactor->write(SwooleG.main_reactor, conn->fd, (void *) &_end, sizeof(_end));

    return SW_OK;
}

typedef int (*task_callback)(swServer *, swEventData *);

static sw_inline void swWorker_do_task(swServer *serv, swWorker *worker, swEventData *task, task_callback callback)
{
    worker->request_time = serv->gs->now;
#ifdef SW_BUFFER_RECV_TIME
    serv->last_receive_usec = task->info.time;
#endif
    callback(serv, task);
    worker->request_time = 0;
#ifdef SW_BUFFER_RECV_TIME
    serv->last_receive_usec = 0;
#endif
    worker->traced = 0;
    worker->request_count++;
    sw_atomic_fetch_add(&serv->stats->request_count, 1);
}

int swWorker_onTask(swFactory *factory, swEventData *task)
{
    swServer *serv = (swServer *) factory->ptr;
    swString *package = NULL;

#ifdef SW_USE_OPENSSL
    swConnection *conn;
#endif

    swWorker *worker = SwooleWG.worker;
    //worker busy
    worker->status = SW_WORKER_BUSY;
    //packet chunk
    if (task->info.flags & SW_EVENT_DATA_CHUNK)
    {
        package = swWorker_get_buffer(serv, task->info.reactor_id);
        //merge data to package buffer
        swString_append_ptr(package, task->data, task->info.len);
        //wait more data
        if (!(task->info.flags & SW_EVENT_DATA_END))
        {
            return SW_OK;
        }
    }

    switch (task->info.type)
    {
    case SW_EVENT_TCP6:
    case SW_EVENT_TCP:
    case SW_EVENT_UNIX_STREAM:
        //discard data
        if (swWorker_discard_data(serv, task) == SW_TRUE)
        {
            break;
        }
        swWorker_do_task(serv, worker, task, serv->onReceive);
        break;

    case SW_EVENT_UDP:
    case SW_EVENT_UDP6:
    case SW_EVENT_UNIX_DGRAM:
        swWorker_do_task(serv, worker, task, serv->onPacket);
        break;

    case SW_EVENT_CLOSE:
#ifdef SW_USE_OPENSSL
        conn = swServer_connection_verify_no_ssl(serv, task->info.fd);
        if (conn && conn->ssl_client_cert && conn->ssl_client_cert_pid == SwooleG.pid)
        {
            sw_free(conn->ssl_client_cert);
            conn->ssl_client_cert = nullptr;
        }
#endif
        factory->end(factory, task->info.fd);
        break;

    case SW_EVENT_CONNECT:
#ifdef SW_USE_OPENSSL
        //SSL client certificate
        if (task->info.len > 0)
        {
            conn = swServer_connection_verify_no_ssl(serv, task->info.fd);
            char *cert_data = NULL;
            size_t length = swWorker_get_data(serv, task, &cert_data);
            conn->ssl_client_cert = swString_dup(cert_data, length);
            conn->ssl_client_cert_pid = SwooleG.pid;
        }
#endif
        if (serv->onConnect)
        {
            serv->onConnect(serv, &task->info);
        }
        break;

    case SW_EVENT_BUFFER_FULL:
        if (serv->onBufferFull)
        {
            serv->onBufferFull(serv, &task->info);
        }
        break;

    case SW_EVENT_BUFFER_EMPTY:
        if (serv->onBufferEmpty)
        {
            serv->onBufferEmpty(serv, &task->info);
        }
        break;

    case SW_EVENT_FINISH:
        serv->onFinish(serv, task);
        break;

    case SW_EVENT_PIPE_MESSAGE:
        serv->onPipeMessage(serv, task);
        break;

    default:
        swWarn("[Worker] error event[type=%d]", (int )task->info.type);
        break;
    }

    //worker idle
    worker->status = SW_WORKER_IDLE;

    if (task->info.flags & SW_EVENT_DATA_END)
    {
        swString_clear(package);
    }

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
    struct passwd *passwd = NULL;
    struct group *group = NULL;

    if (is_root)
    {
        //get group info
        if (SwooleG.group)
        {
            group = getgrnam(SwooleG.group);
            if (!group)
            {
                swWarn("get group [%s] info failed", SwooleG.group);
            }
        }
        //get user info
        if (SwooleG.user)
        {
            passwd = getpwnam(SwooleG.user);
            if (!passwd)
            {
                swWarn("get user [%s] info failed", SwooleG.user);
            }
        }
        //chroot
        if (SwooleG.chroot)
        {
            if (0 > chroot(SwooleG.chroot))
            {
                swSysWarn("chroot to [%s] failed", SwooleG.chroot);
            }
        }
        //set process group
        if (SwooleG.group && group)
        {
            if (setgid(group->gr_gid) < 0)
            {
                swSysWarn("setgid to [%s] failed", SwooleG.group);
            }
        }
        //set process user
        if (SwooleG.user && passwd)
        {
            if (setuid(passwd->pw_uid) < 0)
            {
                swSysWarn("setuid to [%s] failed", SwooleG.user);
            }
        }
    }

    uint32_t i;
    for (i = 0; i < serv->worker_num + serv->task_worker_num; i++)
    {
        swWorker *worker = swServer_get_worker(serv, i);
        if (SwooleWG.id == i)
        {
            continue;
        }
        else
        {
            swWorker_free(worker);
        }
        if (swIsWorker())
        {
            swSocket_set_nonblock(worker->pipe_master);
        }
    }

    SwooleWG.worker = swServer_get_worker(serv, SwooleWG.id);
    SwooleWG.worker->status = SW_WORKER_IDLE;

    if (serv->factory_mode == SW_MODE_PROCESS)
    {
        sw_shm_protect(serv->session_list, PROT_READ);
        /**
         * Use only the first block of pipe_buffer memory in worker process
         */
        for (i = 1; i < serv->reactor_num; i++)
        {
            sw_free(serv->pipe_buffers[i]);
        }
    }

#ifdef HAVE_SIGNALFD
    if (SwooleG.use_signalfd && SwooleG.main_reactor && SwooleG.signal_fd == 0)
    {
        swSignalfd_setup(SwooleG.main_reactor);
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

    swReactor *reactor = SwooleG.main_reactor;

    /**
     * force to end
     */
    if (serv->reload_async == 0)
    {
        SwooleG.running = 0;
        reactor->running = 0;
        return;
    }

    //The worker process is shutting down now.
    if (reactor->wait_exit)
    {
        return;
    }

    if (serv->stream_fd > 0)
    {
        reactor->del(reactor, serv->stream_fd);
        close(serv->stream_fd);
        serv->stream_fd = 0;
    }

    if (worker->pipe_worker)
    {
        swReactor_remove_read_event(reactor, worker->pipe_worker);
    }

    if (serv->factory_mode == SW_MODE_BASE)
    {
        swListenPort *port;
        LL_FOREACH(serv->listen_list, port)
        {
            reactor->del(reactor, port->sock);
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
            if (conn != NULL && conn->active && !conn->removed && conn->fdtype == SW_FD_TCP)
            {
                swReactor_remove_read_event(reactor, fd);
            }
        }
        //clear timer
        if (serv->master_timer)
        {
            swTimer_del(&SwooleG.timer, serv->master_timer);
            serv->master_timer = NULL;
        }
        if (serv->heartbeat_timer)
        {
            swTimer_del(&SwooleG.timer, serv->heartbeat_timer);
            serv->heartbeat_timer = NULL;
        }
        goto _try_to_exit;
    }
    
    swWorkerStopMessage msg;
    msg.pid = SwooleG.pid;
    msg.worker_id = SwooleWG.id;

    //send message to manager
    if (swChannel_push(serv->message_box, &msg, sizeof(msg)) < 0)
    {
        SwooleG.running = 0;
    }
    else
    {
        swoole_kill(serv->gs->manager_pid, SIGIO);
    }

    _try_to_exit: reactor->wait_exit = 1;
    reactor->is_empty = swWorker_reactor_is_empty;
    SwooleWG.exit_time = serv->gs->now;

    if (swWorker_reactor_is_empty(reactor))
    {
        reactor->running = 0;
        SwooleG.running = 0;
    }
}

static int swWorker_reactor_is_empty(swReactor *reactor)
{
    swServer *serv = (swServer *) reactor->ptr;
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
            int remaining_time = serv->max_wait_time - (time(NULL) - SwooleWG.exit_time);
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
    int i;
    for (i = 0; i < serv->worker_num + serv->task_worker_num; i++)
    {
        swWorker *worker = swServer_get_worker(serv, i);
        if (SwooleG.main_reactor)
        {
            if (worker->pipe_worker)
            {
                swReactor_wait_write_buffer(SwooleG.main_reactor, worker->pipe_worker);
            }
            if (worker->pipe_master)
            {
                swReactor_wait_write_buffer(SwooleG.main_reactor, worker->pipe_master);
            }
        }
    }
}

/**
 * main loop [Worker]
 */
int swWorker_loop(swServer *serv, int worker_id)
{
    //worker_id
    SwooleWG.id = worker_id;

    swWorker *worker = swServer_get_worker(serv, worker_id);
    swServer_worker_init(serv, worker);

    swReactor *reactor = (swReactor *) sw_malloc(sizeof(swReactor));
    if (reactor == NULL)
    {
        swError("[Worker] malloc for reactor failed");
        return SW_ERR;
    }

    if (swReactor_create(reactor, SW_REACTOR_MAXEVENTS) < 0)
    {
        swError("[Worker] create worker_reactor failed");
        sw_free(reactor);
        return SW_ERR;
    }
    SwooleG.main_reactor = reactor;

    /**
     * set pipe buffer size
     */
    for (int i = 0; i < serv->worker_num + serv->task_worker_num; i++)
    {
        swWorker *_worker = swServer_get_worker(serv, i);
        swConnection *pipe_socket;
        pipe_socket = swReactor_get(reactor, _worker->pipe_master);
        pipe_socket->buffer_size = INT_MAX;
        pipe_socket->fdtype = SW_FD_PIPE;
        pipe_socket = swReactor_get(reactor, _worker->pipe_worker);
        pipe_socket->buffer_size = INT_MAX;
        pipe_socket->fdtype = SW_FD_PIPE;
    }

    int pipe_worker = worker->pipe_worker;

    swSocket_set_nonblock(pipe_worker);
    reactor->ptr = serv;
    reactor->add(reactor, pipe_worker, SW_FD_PIPE | SW_EVENT_READ);
    swReactor_set_handler(reactor, SW_FD_PIPE, swWorker_onPipeReceive);
    swReactor_set_handler(reactor, SW_FD_WRITE, swReactor_onWrite);

    if (serv->dispatch_mode == SW_DISPATCH_STREAM)
    {
        reactor->add(reactor, serv->stream_fd, SW_FD_LISTEN | SW_EVENT_READ);
        swReactor_set_handler(reactor, SW_FD_LISTEN, swWorker_onStreamAccept);
        swReactor_set_handler(reactor, SW_FD_STREAM, swWorker_onStreamRead);
        swStream_set_protocol(&serv->stream_protocol);
        serv->stream_protocol.private_data_2 = serv;
        serv->stream_protocol.package_max_length = INT_MAX;
        serv->stream_protocol.onPackage = swWorker_onStreamPackage;
        serv->buffer_pool = swLinkedList_new(0, NULL);
        if (serv->buffer_pool == nullptr)
        {
            return SW_ERR;
        }
    }

    worker->status = SW_WORKER_IDLE;
    swWorker_onStart(serv);

    //main loop
    reactor->wait(reactor, NULL);
    //clear pipe buffer
    swWorker_clean_pipe_buffer(serv);
    //destroy reactor
    swReactor_destory(reactor);
    SwooleG.main_reactor = NULL;
    sw_free(reactor);
    //worker shutdown
    swWorker_onStop(serv);
    return SW_OK;
}

/**
 * Send data to ReactorThread
 */
int swWorker_send2reactor(swServer *serv, swEventData *ev_data, size_t sendn, int session_id)
{
    int ret;
    int _pipe_fd = swWorker_get_send_pipe(serv, session_id, ev_data->info.reactor_id);

    if (SwooleG.main_reactor)
    {
        ret = SwooleG.main_reactor->write(SwooleG.main_reactor, _pipe_fd, ev_data, sendn);
    }
    else
    {
        ret = swSocket_write_blocking(_pipe_fd, ev_data, sendn);
    }
    return ret;
}

/**
 * receive data from reactor
 */
static int swWorker_onPipeReceive(swReactor *reactor, swEvent *event)
{
    swServer *serv = (swServer *) reactor->ptr;
    swFactory *factory = &serv->factory;
    swPipeBuffer *buffer = serv->pipe_buffers[0];
    int ret;

    _read_from_pipe:

    if (read(event->fd, buffer, serv->ipc_max_size) > 0)
    {
        ret = swWorker_onTask(factory, (swEventData *) buffer);
#ifndef SW_WORKER_RECV_AGAIN
        /**
         * Big package
         */
        if (buffer->info.flags & SW_EVENT_DATA_CHUNK)
#endif
        {
            //no data
            if (ret < 0 && errno == EAGAIN)
            {
                return SW_OK;
            }
            else if (ret > 0)
            {
                goto _read_from_pipe;
            }
        }
        return ret;
    }
    return SW_ERR;
}

int swWorker_send2worker(swWorker *dst_worker, const void *buf, int n, int flag)
{
    int pipefd, ret;

    if (flag & SW_PIPE_MASTER)
    {
        pipefd = dst_worker->pipe_master;
    }
    else
    {
        pipefd = dst_worker->pipe_worker;
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

    if ((flag & SW_PIPE_NONBLOCK) && SwooleG.main_reactor)
    {
        return SwooleG.main_reactor->write(SwooleG.main_reactor, pipefd, buf, n);
    }
    else
    {
        ret = swSocket_write_blocking(pipefd, buf, n);
    }

    return ret;
}
