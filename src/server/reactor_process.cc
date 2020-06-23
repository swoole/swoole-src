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

static int swReactorProcess_loop(swProcessPool *pool, swWorker *worker);
static int swReactorProcess_onPipeRead(swReactor *reactor, swEvent *event);
static int swReactorProcess_onClose(swReactor *reactor, swEvent *event);
static int swReactorProcess_send2client(swFactory *, swSendData *data);
static int swReactorProcess_send2worker(swSocket *socket, const void *data, size_t length);
static void swReactorProcess_onTimeout(swTimer *timer, swTimer_node *tnode);

#ifdef HAVE_REUSEPORT
static int swReactorProcess_reuse_port(swListenPort *ls);
#endif

static uint32_t heartbeat_check_lasttime = 0;

static bool swServer_is_single(swServer *serv)
{
    return serv->worker_num == 1 && serv->task_worker_num == 0 && serv->max_request == 0 && serv->user_worker_list == nullptr;
}

int swReactorProcess_create(swServer *serv)
{
    serv->reactor_num = serv->worker_num;
    serv->connection_list = (swConnection *) sw_calloc(serv->max_connection, sizeof(swConnection));
    if (serv->connection_list == nullptr)
    {
        swSysWarn("calloc[2](%d) failed", (int )(serv->max_connection * sizeof(swConnection)));
        return SW_ERR;
    }
    //create factry object
    if (swFactory_create(&(serv->factory)) < 0)
    {
        swError("create factory failed");
        return SW_ERR;
    }
    serv->factory.finish = swReactorProcess_send2client;
    return SW_OK;
}

void swReactorProcess_free(swServer *serv)
{
    serv->factory.free(&serv->factory);
    sw_free(serv->connection_list);
}

int swReactorProcess_start(swServer *serv)
{
    serv->single_thread = 1;

    //listen TCP
    if (serv->have_stream_sock == 1)
    {
        for (auto ls : *serv->listen_list)
        {
            if (swSocket_is_dgram(ls->type))
            {
                continue;
            }
#ifdef HAVE_REUSEPORT
            if (serv->enable_reuse_port)
            {
                if (close(ls->socket->fd) < 0)
                {
                    swSysWarn("close(%d) failed", ls->socket->fd);
                }
                continue;
            }
            else
#endif
            {
                //listen server socket
                if (swPort_listen(ls) < 0)
                {
                    return SW_ERR;
                }
            }
        }
    }

    swProcessPool *pool = &serv->gs->event_workers;
    if (swProcessPool_create(pool, serv->worker_num, 0, SW_IPC_UNIXSOCK) < 0)
    {
        return SW_ERR;
    }
    swProcessPool_set_max_request(pool, serv->max_request, serv->max_request_grace);

    /**
     * store to swProcessPool object
     */
    serv->gs->event_workers.ptr = serv;
    serv->gs->event_workers.max_wait_time = serv->max_wait_time;
    serv->gs->event_workers.use_msgqueue = 0;
    serv->gs->event_workers.main_loop = swReactorProcess_loop;
    serv->gs->event_workers.onWorkerNotFound = swManager_wait_other_worker;

    uint32_t i;
    for (i = 0; i < serv->worker_num; i++)
    {
        serv->gs->event_workers.workers[i].pool = &serv->gs->event_workers;
        serv->gs->event_workers.workers[i].id = i;
        serv->gs->event_workers.workers[i].type = SW_PROCESS_WORKER;
    }

    //single worker
    if (swServer_is_single(serv))
    {
        return swReactorProcess_loop(&serv->gs->event_workers, &serv->gs->event_workers.workers[0]);
    }

    for (i = 0; i < serv->worker_num; i++)
    {
        if (swServer_worker_create(serv, &serv->gs->event_workers.workers[i]) < 0)
        {
            return SW_ERR;
        }
    }

    //task workers
    if (serv->task_worker_num > 0)
    {
        if (swServer_create_task_workers(serv) < 0)
        {
            return SW_ERR;
        }
        swTaskWorker_init(serv);
        if (swProcessPool_start(&serv->gs->task_workers) < 0)
        {
            return SW_ERR;
        }
    }

    /**
     * create user worker process
     */
    if (serv->user_worker_list)
    {
        serv->user_workers = (swWorker *) sw_malloc(serv->user_worker_num * sizeof(swWorker));
        if (serv->user_workers == nullptr)
        {
            swSysWarn("gmalloc[server->user_workers] failed");
            return SW_ERR;
        }
        for (auto worker : *serv->user_worker_list)
        {
            /**
             * store the pipe object
             */
            if (worker->pipe_object)
            {
                swServer_store_pipe_fd(serv, worker->pipe_object);
            }
            swManager_spawn_user_worker(serv, worker);
        }
    }

    /**
     * manager process is the same as the master process
     */
    SwooleG.pid = serv->gs->manager_pid = getpid();
    SwooleG.process_type = SW_PROCESS_MANAGER;

    /**
     * manager process can not use signalfd
     */
    SwooleG.use_signalfd = 0;

    swProcessPool_start(&serv->gs->event_workers);
    swServer_signal_init(serv);

    if (serv->onStart)
    {
        swWarn("The onStart event with SWOOLE_BASE is deprecated");
        serv->onStart(serv);
    }

    if (serv->onManagerStart)
    {
        serv->onManagerStart(serv);
    }

    swProcessPool_wait(&serv->gs->event_workers);
    swProcessPool_shutdown(&serv->gs->event_workers);

    swManager_kill_user_workers(serv);

    if (serv->onManagerStop)
    {
        serv->onManagerStop(serv);
    }

    return SW_OK;
}

static int swReactorProcess_onPipeRead(swReactor *reactor, swEvent *event)
{
    swEventData task;
    swSendData _send;
    swServer *serv = (swServer *) reactor->ptr;
    swFactory *factory = &serv->factory;
    swString *output_buffer;

    if (read(event->fd, &task, sizeof(task)) <= 0)
    {
        return SW_ERR;
    }

    switch (task.info.type)
    {
    case SW_SERVER_EVENT_PIPE_MESSAGE:
        serv->onPipeMessage(serv, &task);
        break;
    case SW_SERVER_EVENT_FINISH:
        serv->onFinish(serv, &task);
        break;
    case SW_SERVER_EVENT_SEND_FILE:
        memcpy(&_send.info, &task.info, sizeof(_send.info));
        _send.data = task.data;
        factory->finish(factory, &_send);
        break;
    case SW_SERVER_EVENT_PROXY_START:
    case SW_SERVER_EVENT_PROXY_END:
        output_buffer = SwooleWG.output_buffer[task.info.reactor_id];
        swString_append_ptr(output_buffer, task.data, task.info.len);
        if (task.info.type == SW_SERVER_EVENT_PROXY_END)
        {
            memcpy(&_send.info, &task.info, sizeof(_send.info));
            _send.info.type = SW_SERVER_EVENT_SEND_DATA;
            _send.data = output_buffer->str;
            _send.info.len = output_buffer->length;
            factory->finish(factory, &_send);
            swString_clear(output_buffer);
        }
        break;
    default:
        break;
    }
    return SW_OK;
}

static int swReactorProcess_alloc_output_buffer(int n_buffer)
{
    SwooleWG.output_buffer = (swString **) sw_malloc(sizeof(swString*) * n_buffer);
    if (SwooleWG.output_buffer == nullptr)
    {
        swError("malloc for SwooleWG.output_buffer failed");
        return SW_ERR;
    }

    int i;
    for (i = 0; i < n_buffer; i++)
    {
        SwooleWG.output_buffer[i] = swString_new(SW_BUFFER_SIZE_BIG);
        if (SwooleWG.output_buffer[i] == nullptr)
        {
            swError("output_buffer init failed");
            return SW_ERR;
        }
    }
    return SW_OK;
}

static void swReactor_free_output_buffer(int n_buffer)
{
    int i;
    for (i = 0; i < n_buffer; i++)
    {
        swString_free(SwooleWG.output_buffer[i]);
    }
    sw_free(SwooleWG.output_buffer);
}

static int swReactorProcess_loop(swProcessPool *pool, swWorker *worker)
{
    swServer *serv = (swServer *) pool->ptr;

    SwooleG.process_type = SW_PROCESS_WORKER;
    SwooleG.pid = getpid();

    SwooleWG.id = worker->id;
    if (serv->max_request > 0)
    {
        SwooleWG.run_always = 0;
    }
    SwooleWG.max_request = serv->max_request;
    SwooleWG.worker = worker;

    SwooleTG.id = 0;
    if (worker->id == 0)
    {
        SwooleTG.update_time = 1;
    }

    swServer_worker_init(serv, worker);

    //create reactor
    if (!SwooleTG.reactor)
    {
        if (swoole_event_init() < 0)
        {
            return SW_ERR;
        }
    }
    swReactor *reactor = SwooleTG.reactor;

    if (SwooleTG.timer && SwooleTG.timer->reactor == nullptr)
    {
        swTimer_reinit(SwooleTG.timer, reactor);
    }

    int n_buffer = serv->worker_num + serv->task_worker_num + serv->user_worker_num;
    if (swReactorProcess_alloc_output_buffer(n_buffer))
    {
        return SW_ERR;
    }

    int fdtype;

    for (auto ls : *serv->listen_list)
    {
        fdtype = swSocket_is_dgram(ls->type) ? SW_FD_DGRAM_SERVER : SW_FD_STREAM_SERVER;
#ifdef HAVE_REUSEPORT
        if (fdtype == SW_FD_STREAM_SERVER && serv->enable_reuse_port)
        {
            if (swReactorProcess_reuse_port(ls) < 0)
            {
                swReactor_free_output_buffer(n_buffer);
                swoole_event_free();
                return SW_ERR;
            }
        }
#endif
        if (reactor->add(reactor, ls->socket, SW_EVENT_READ) < 0)
        {
            return SW_ERR;
        }
    }

    reactor->id = worker->id;
    reactor->ptr = serv;

#ifdef HAVE_SIGNALFD
    if (SwooleG.use_signalfd)
    {
        swSignalfd_setup(SwooleTG.reactor);
    }
#endif

    reactor->max_socket = serv->max_connection;

    reactor->close = swReactorThread_close;

    //set event handler
    //connect
    swReactor_set_handler(reactor, SW_FD_STREAM_SERVER, swServer_master_onAccept);
    //close
    reactor->default_error_handler = swReactorProcess_onClose;
    //pipe
    swReactor_set_handler(reactor, SW_FD_PIPE | SW_EVENT_READ, swReactorProcess_onPipeRead);

    swServer_store_listen_socket(serv);

    if (worker->pipe_worker)
    {
        swSocket_set_nonblock(worker->pipe_worker);
        swSocket_set_nonblock(worker->pipe_master);
        if (reactor->add(reactor, worker->pipe_worker, SW_EVENT_READ) < 0)
        {
            return SW_ERR;
        }
        if (reactor->add(reactor, worker->pipe_master, SW_EVENT_READ) < 0)
        {
            return SW_ERR;
        }
    }

    //task workers
    if (serv->task_worker_num > 0)
    {
        if (serv->task_ipc_mode == SW_TASK_IPC_UNIXSOCK)
        {
            for (uint32_t i = 0; i < serv->gs->task_workers.worker_num; i++)
            {
                swSocket_set_nonblock(serv->gs->task_workers.workers[i].pipe_master);
            }
        }
    }

    //set protocol function point
    swReactorThread_set_protocol(serv, reactor);

    //single server trigger onStart event
    if (swServer_is_single(serv))
    {
        if (serv->onStart)
        {
            serv->onStart(serv);
        }
    }

    /**
     * 1 second timer
     */
    if ((serv->master_timer = swoole_timer_add(1000, SW_TRUE, swServer_master_onTimer, serv)) == nullptr)
    {
        _fail:
        swReactor_free_output_buffer(n_buffer);
        swoole_event_free();
        return SW_ERR;
    }

    swWorker_onStart(serv);

    /**
     * for heartbeat check
     */
    if (serv->heartbeat_check_interval > 0)
    {
        serv->heartbeat_timer = swoole_timer_add((long) (serv->heartbeat_check_interval * 1000), SW_TRUE, swReactorProcess_onTimeout, reactor);
        if (serv->heartbeat_timer == nullptr)
        {
            goto _fail;
        }
    }

    int retval = reactor->wait(reactor, nullptr);

    /**
     * Close all connections
     */
    int fd;
    int serv_max_fd = swServer_get_maxfd(serv);
    int serv_min_fd = swServer_get_minfd(serv);

    for (fd = serv_min_fd; fd <= serv_max_fd; fd++)
    {
        swConnection *conn = swServer_connection_get(serv, fd);
        if (conn != nullptr && conn->active && conn->socket->fdtype == SW_FD_SESSION)
        {
            serv->close(serv, conn->session_id, 1);
        }
    }

    /**
     * call internal serv hooks
     */
    if (serv->hooks[SW_SERVER_HOOK_WORKER_CLOSE])
    {
        void *hook_args[2];
        hook_args[0] = serv;
        hook_args[1] = (void *)(uintptr_t)SwooleWG.id;
        swServer_call_hook(serv, SW_SERVER_HOOK_WORKER_CLOSE, hook_args);
    }

    swoole_event_free();

    if (serv->onWorkerStop)
    {
        serv->onWorkerStop(serv, worker->id);
    }

    return retval;
}

static int swReactorProcess_onClose(swReactor *reactor, swEvent *event)
{
    int fd = event->fd;
    swServer *serv = (swServer *) reactor->ptr;
    swConnection *conn = swServer_connection_get(serv, fd);
    if (conn == nullptr || conn->active == 0)
    {
        return SW_ERR;
    }
    if (reactor->del(reactor, event->socket) == 0)
    {
        if (conn->close_queued)
        {
            swReactorThread_close(reactor, event->socket);
            return SW_OK; 
        }
        else 
        {
            return serv->notify(serv, conn, SW_SERVER_EVENT_CLOSE);
        }
    }
    else
    {
        return SW_ERR;
    }
}

static int swReactorProcess_send2worker(swSocket *socket, const void *data, size_t length)
{
    if (!SwooleTG.reactor)
    {
        return swSocket_write_blocking(socket, data, length);
    }
    else
    {
        return SwooleTG.reactor->write(SwooleTG.reactor, socket, data, length);
    }
}

static int swReactorProcess_send2client(swFactory *factory, swSendData *data)
{
    swServer *serv = (swServer *) factory->ptr;
    int session_id = data->info.fd;

    swSession *session = swServer_get_session(serv, session_id);
    if (session->fd == 0)
    {
        swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SESSION_NOT_EXIST, "send %d byte failed, session#%d does not exist",
                data->info.len, session_id);
        return SW_ERR;
    }
    //proxy
    if (session->reactor_id != SwooleWG.id)
    {
        swTrace("session->reactor_id=%d, SwooleWG.id=%d", session->reactor_id, SwooleWG.id);
        swWorker *worker = swProcessPool_get_worker(&serv->gs->event_workers, session->reactor_id);
        swEventData proxy_msg;
        sw_memset_zero(&proxy_msg.info, sizeof(proxy_msg.info));

        if (data->info.type == SW_SERVER_EVENT_SEND_DATA)
        {
            proxy_msg.info.fd = session_id;
            proxy_msg.info.reactor_id = SwooleWG.id;
            proxy_msg.info.type = SW_SERVER_EVENT_PROXY_START;

            size_t send_n = data->info.len;
            size_t offset = 0;

            while (send_n > 0)
            {
                if (send_n > SW_IPC_BUFFER_SIZE)
                {
                    proxy_msg.info.len = SW_IPC_BUFFER_SIZE;
                }
                else
                {
                    proxy_msg.info.type = SW_SERVER_EVENT_PROXY_END;
                    proxy_msg.info.len = send_n;
                }
                memcpy(proxy_msg.data, data->data + offset, proxy_msg.info.len);
                send_n -= proxy_msg.info.len;
                offset += proxy_msg.info.len;
                swReactorProcess_send2worker(worker->pipe_master, (const char *) &proxy_msg, sizeof(proxy_msg.info) + proxy_msg.info.len);
            }

            swTrace("proxy message, fd=%d, len=%ld",worker->pipe_master, sizeof(proxy_msg.info) + proxy_msg.info.len);
        }
        else if (data->info.type == SW_SERVER_EVENT_SEND_FILE)
        {
            memcpy(&proxy_msg.info, &data->info, sizeof(proxy_msg.info));
            memcpy(proxy_msg.data, data->data, data->info.len);
            return swReactorProcess_send2worker(worker->pipe_master, (const char *) &proxy_msg, sizeof(proxy_msg.info) + proxy_msg.info.len);
        }
        else
        {
            swWarn("unkown event type[%d]", data->info.type);
            return SW_ERR;
        }
        return SW_OK;
    }
    else
    {
        return swFactory_finish(factory, data);
    }
}

static void swReactorProcess_onTimeout(swTimer *timer, swTimer_node *tnode)
{
    swReactor *reactor = (swReactor *) tnode->data;
    swServer *serv = (swServer *) reactor->ptr;
    swEvent notify_ev;
    swConnection *conn;
    time_t now = time(nullptr);

    if (now < heartbeat_check_lasttime + 10)
    {
        return;
    }

    int fd;
    int checktime;

    sw_memset_zero(&notify_ev, sizeof(notify_ev));
    notify_ev.type = SW_FD_SESSION;

    int serv_max_fd = swServer_get_maxfd(serv);
    int serv_min_fd = swServer_get_minfd(serv);

    checktime = now - serv->heartbeat_idle_time;

    for (fd = serv_min_fd; fd <= serv_max_fd; fd++)
    {
        conn = swServer_connection_get(serv, fd);
        if (swServer_connection_valid(serv, conn))
        {
            if (conn->protect || conn->last_time > checktime)
            {
                continue;
            }
#ifdef SW_USE_OPENSSL
            if (conn->socket->ssl && conn->socket->ssl_state != SW_SSL_STATE_READY)
            {
                swReactorThread_close(reactor, conn->socket);
                continue;
            }
#endif
            notify_ev.fd = fd;
            notify_ev.socket = conn->socket;
            notify_ev.reactor_id = conn->reactor_id;
            swReactorProcess_onClose(reactor, &notify_ev);
        }
    }
}

#ifdef HAVE_REUSEPORT
static int swReactorProcess_reuse_port(swListenPort *ls)
{
    int sock = swSocket_create(ls->type, 1, 1);
    if (sock < 0)
    {
        swSysWarn("create socket failed");
        return SW_ERR;
    }
    int option = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &option, sizeof(int)) != 0)
    {
        close(sock);
        return SW_ERR;
    }
    ls->socket->fd = sock;
    //bind address and port
    if (swSocket_bind(ls->socket, ls->host, &ls->port) < 0)
    {
        close(ls->socket->fd);
        return SW_ERR;
    }
    ls->socket->nonblock = 1;
    ls->socket->cloexec = 1;
    return swPort_listen(ls);
}
#endif
