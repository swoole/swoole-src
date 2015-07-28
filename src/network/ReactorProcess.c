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

#include "Server.h"

static int swReactorProcess_loop(swProcessPool *pool, swWorker *worker);
static int swReactorProcess_onPipeRead(swReactor *reactor, swEvent *event);
static int swReactorProcess_send2client(swFactory *, swSendData *);

int swReactorProcess_create(swServer *serv)
{
    serv->reactor_num = serv->worker_num;
    serv->reactor_threads = sw_calloc(1, sizeof(swReactorThread));
    if (serv->reactor_threads == NULL)
    {
        swSysError("calloc[1](%d) failed.", (int )(serv->reactor_num * sizeof(swReactorThread)));
        return SW_ERR;
    }
    serv->connection_list = sw_calloc(serv->max_connection, sizeof(swConnection));
    if (serv->connection_list == NULL)
    {
        swSysError("calloc[2](%d) failed.", (int )(serv->max_connection * sizeof(swConnection)));
        return SW_ERR;
    }
    //create factry object
    if (swFactory_create(&(serv->factory)) < 0)
    {
        swError("create factory failed.");
        return SW_ERR;
    }
    serv->factory.finish = swReactorProcess_send2client;
    return SW_OK;
}

/**
 * base模式
 * 在worker进程中直接accept连接
 */
int swReactorProcess_start(swServer *serv)
{
    if (serv->onStart != NULL)
    {
        serv->onStart(serv);
    }
    //listen UDP
    if (serv->have_udp_sock == 1)
    {
        swListenPort *listen_host;
        LL_FOREACH(serv->listen_list, listen_host)
        {
            //UDP
            if (listen_host->type == SW_SOCK_UDP || listen_host->type == SW_SOCK_UDP6
                    || listen_host->type == SW_SOCK_UNIX_DGRAM)
            {
                serv->connection_list[listen_host->sock].info.addr.inet_v4.sin_port = htons(listen_host->port);
                serv->connection_list[listen_host->sock].fd = listen_host->sock;
                serv->connection_list[listen_host->sock].object = listen_host;
            }
        }
    }
    //listen TCP
    if (serv->have_tcp_sock == 1)
    {
        swListenPort *ls;
        LL_FOREACH(serv->listen_list, ls)
        {
#ifdef HAVE_REUSEPORT
            if (SwooleG.reuse_port)
            {
                continue;
            }
#endif
            //listen server socket
            if (swServer_listen(serv, ls) < 0)
            {
                return SW_ERR;
            }
        }
    }

    if (swProcessPool_create(&SwooleGS->event_workers, serv->worker_num, serv->max_request, 0, 1) < 0)
    {
        return SW_ERR;
    }

    SwooleGS->event_workers.ptr = serv;
    SwooleGS->event_workers.main_loop = swReactorProcess_loop;
    SwooleGS->event_workers.type = SW_PROCESS_WORKER;
    SwooleGS->event_workers.run_worker_num = serv->worker_num;

    //no worker
    if (serv->worker_num == 1 && SwooleG.task_worker_num == 0 && serv->max_request == 0)
    {
        swWorker single_worker;
        bzero(&single_worker, sizeof(single_worker));
        return swReactorProcess_loop(&SwooleGS->event_workers, &single_worker);
    }

    //task workers
    if (SwooleG.task_worker_num > 0)
    {
        key_t key = 0;
        int create_pipe = 1;

        if (SwooleG.task_ipc_mode == SW_IPC_MSGQUEUE)
        {
            key = serv->message_queue_key;
            create_pipe = 0;
        }

        if (swProcessPool_create(&SwooleGS->task_workers, SwooleG.task_worker_num, SwooleG.task_max_request, key, create_pipe) < 0)
        {
            swWarn("[Master] create task_workers failed.");
            return SW_ERR;
        }

        swTaskWorker_init(&SwooleGS->task_workers);
        swProcessPool_start(&SwooleGS->task_workers);

        int i;
        for (i = 0; i < SwooleGS->task_workers.worker_num; i++)
        {
            swProcessPool_add_worker(&SwooleGS->event_workers, &SwooleGS->task_workers.workers[i]);
        }
    }
    /**
     * BASE模式，管理进程就是主进程
     */
    SwooleG.pid = SwooleGS->manager_pid = getpid();
    SwooleG.process_type = SW_PROCESS_MASTER;

    SwooleG.use_timerfd = 0;
    SwooleG.use_signalfd = 0;
    SwooleG.use_timer_pipe = 0;
    swServer_signal_init();

    swProcessPool_start(&SwooleGS->event_workers);
    swProcessPool_wait(&SwooleGS->event_workers);

    swProcessPool_shutdown(&SwooleGS->event_workers);

    return SW_OK;
}

static int swReactorProcess_onPipeRead(swReactor *reactor, swEvent *event)
{
    swEventData task;
    swSendData _send;
    swServer *serv = reactor->ptr;
    swFactory *factory = &serv->factory;
    swString *buffer_output;

    if (read(event->fd, &task, sizeof(task)) > 0)
    {
        switch(task.info.type )
        {
        case SW_EVENT_PIPE_MESSAGE:
            serv->onPipeMessage(serv, &task);
            break;
        case SW_EVENT_SENDFILE:
            memcpy(&_send.info, &task.info, sizeof(_send.info));
            _send.data = task.data;
            factory->finish(factory, &_send);
            break;
        case SW_EVENT_PROXY_START:
        case SW_EVENT_PROXY_END:
            buffer_output = SwooleWG.buffer_output[task.info.from_id];
            swString_append_ptr(buffer_output, task.data, task.info.len);
            if (task.info.type == SW_EVENT_PROXY_END)
            {
                memcpy(&_send.info, &task.info, sizeof(_send.info));
                _send.info.type = SW_EVENT_TCP;
                _send.data = buffer_output->str;
                _send.length = buffer_output->length;
                factory->finish(factory, &_send);
                swString_clear(buffer_output);
            }
            break;
        default:
            break;
        }
        return SW_OK;
    }
    return SW_ERR;
}

static int swReactorProcess_loop(swProcessPool *pool, swWorker *worker)
{
    swServer *serv = pool->ptr;
    swReactor *reactor = &(serv->reactor_threads[0].reactor);

    SwooleG.process_type = SW_PROCESS_WORKER;
    SwooleG.pid = getpid();

    SwooleWG.id = worker->id;
    SwooleWG.max_request = serv->max_request;
    SwooleWG.request_count = 0;
    
    SwooleTG.id = 0;

    swServer_worker_init(serv, worker);

    SwooleWG.buffer_output = sw_malloc(sizeof(swString*) * serv->reactor_num);
    if (SwooleWG.buffer_output == NULL)
    {
        swError("malloc for SwooleWG.buffer_output failed.");
        return SW_ERR;
    }

    int i;
    for (i = 0; i < serv->reactor_num; i++)
    {
        SwooleWG.buffer_output[i] = swString_new(SW_BUFFER_SIZE_BIG);
        if (SwooleWG.buffer_output[i] == NULL)
        {
            swError("buffer_output init failed.");
            return SW_ERR;
        }
    }

    //create reactor
    if (swReactor_create(reactor, SW_REACTOR_MAXEVENTS) < 0)
    {
        swWarn("ReactorProcess create failed.");
        return SW_ERR;
    }

    swListenPort *ls;
    int fdtype;

    //listen the all tcp port
    LL_FOREACH(serv->listen_list, ls)
    {
        fdtype = (ls->type == SW_SOCK_UDP || ls->type == SW_SOCK_UDP6 || ls->type == SW_SOCK_UNIX_DGRAM) ?
                        SW_FD_UDP : SW_FD_LISTEN;

#ifdef HAVE_REUSEPORT
        if (SwooleG.reuse_port)
        {
            if (swServer_listen(serv, ls) < 0)
            {
                return SW_ERR;
            }
        }
#endif
        serv->connection_list[ls->sock].fd = ls->sock;
        serv->connection_list[ls->sock].socket_type = ls->type;
        serv->connection_list[ls->sock].fdtype = fdtype;

        reactor->add(reactor, ls->sock, fdtype);
    }
    SwooleG.main_reactor = reactor;

    reactor->id = worker->id;
    reactor->ptr = serv;

#ifdef SW_USE_RINGBUFFER
    serv->reactor_threads[0].buffer_input = swMalloc_new();
    if (serv->reactor_threads[0].buffer_input == NULL)
    {
        return SW_ERR;
    }
#endif

#ifdef HAVE_SIGNALFD
    if (SwooleG.use_signalfd)
    {
        swSignalfd_setup(SwooleG.main_reactor);
    }
#endif

    reactor->thread = 1;
    reactor->socket_list = serv->connection_list;
    reactor->max_socket = serv->max_connection;
    
    reactor->disable_accept = 0;
    reactor->enable_accept = swServer_enable_accept;
    reactor->close = swReactorThread_close;

    //set event handler
    //connect
    reactor->setHandle(reactor, SW_FD_LISTEN, swServer_master_onAccept);
    //close
    reactor->setHandle(reactor, SW_FD_CLOSE, swReactorProcess_onClose);
    //pipe
    reactor->setHandle(reactor, SW_FD_PIPE | SW_EVENT_WRITE, swReactor_onWrite);

    if (worker->pipe_worker)
    {
        //proxy or pipe message
        reactor->add(reactor, worker->pipe_worker, SW_FD_PIPE);
    }
    //close
    reactor->setHandle(reactor, SW_FD_PIPE, swReactorProcess_onPipeRead);
    //set protocol function point
    swReactorThread_set_protocol(serv, reactor);

    if (serv->onWorkerStart)
    {
        serv->onWorkerStart(serv, worker->id);
    }

    /**
     * for heartbeat check
     */
    if (serv->heartbeat_check_interval > 0)
    {
        swHeartbeatThread_start(serv);
    }

    struct timeval timeo;
    timeo.tv_sec = 1;
    timeo.tv_usec = 0;
    return reactor->wait(reactor, &timeo);
}

int swReactorProcess_onClose(swReactor *reactor, swEvent *event)
{
    int fd = event->fd;
    swDataHead notify_ev;
    bzero(&notify_ev, sizeof(notify_ev));

    notify_ev.from_id = reactor->id;
    notify_ev.fd = fd;
    notify_ev.type = SW_EVENT_CLOSE;

    swConnection *conn = swServer_connection_get(SwooleG.serv, fd);
    if (conn == NULL || conn->active == 0)
    {
        return SW_ERR;
    }
    if (reactor->del(reactor, fd) == 0)
    {
        return SwooleG.factory->notify(SwooleG.factory, &notify_ev);
    }
    else
    {
        return SW_ERR;
    }
}

static int swReactorProcess_send2client(swFactory *factory, swSendData *_send)
{
    swServer *serv = SwooleG.serv;
    int session_id = _send->info.fd;

    swSession *session = swServer_get_session(serv, session_id);
    if (session->fd == 0)
    {
        swWarn("send[%d] failed, session#%d has expired.", _send->info.type, session_id);
        return SW_ERR;
    }
    //proxy
    if (session->reactor_id != SwooleWG.id)
    {
        swWarn("session->reactor_id=%d, SwooleWG.id=%d", session->reactor_id, SwooleWG.id);
        swWorker *worker = swProcessPool_get_worker(&SwooleGS->event_workers, session->reactor_id);
        swEventData proxy_msg;

        if (_send->info.type == SW_EVENT_TCP)
        {
            proxy_msg.info.fd = session_id;
            proxy_msg.info.from_id = SwooleWG.id;
            proxy_msg.info.type = SW_EVENT_PROXY_START;

            if (_send->length == 0)
            {
                _send->length = _send->info.len;
            }

            size_t send_n = _send->length;
            size_t offset = 0;

            while (send_n > 0)
            {
                if (send_n > SW_BUFFER_SIZE)
                {
                    proxy_msg.info.len = SW_BUFFER_SIZE;
                }
                else
                {
                    proxy_msg.info.type = SW_EVENT_PROXY_END;
                    proxy_msg.info.len = send_n;
                }

                memcpy(proxy_msg.data, _send->data + offset, proxy_msg.info.len);

                send_n -= proxy_msg.info.len;
                offset += proxy_msg.info.len;

                SwooleG.main_reactor->write(SwooleG.main_reactor, worker->pipe_master, &proxy_msg, sizeof(proxy_msg.info) + proxy_msg.info.len);
            }
            swTrace("proxy message, fd=%d, len=%ld",worker->pipe_master, sizeof(proxy_msg.info) + proxy_msg.info.len);
        }
        else if (_send->info.type == SW_EVENT_SENDFILE)
        {
            memcpy(&proxy_msg.info, &_send->info, sizeof(proxy_msg.info));
            memcpy(proxy_msg.data, _send->data, _send->length);
            return SwooleG.main_reactor->write(SwooleG.main_reactor, worker->pipe_master, &proxy_msg, sizeof(proxy_msg.info) + proxy_msg.info.len);
        }
        else
        {
            swWarn("unkown event type[%d].", _send->info.type);
            return SW_ERR;
        }
        return SW_OK;
    }
    else
    {
        return swFactory_finish(factory, _send);
    }
}
