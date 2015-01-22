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
 | license@php.net so we can mail you a copy immediately.               |
 +----------------------------------------------------------------------+
 | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
 +----------------------------------------------------------------------+
 */

#include "swoole.h"
#include "Server.h"

static int swReactorProcess_loop(swProcessPool *pool, swWorker *worker);
static int swReactorProcess_onPipeRead(swReactor *reactor, swEvent *event);

int swReactorProcess_create(swServer *serv)
{
    serv->reactor_num = 1;
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
        swListenList_node *listen_host;
        LL_FOREACH(serv->listen_list, listen_host)
        {
            //UDP
            if (listen_host->type == SW_SOCK_UDP || listen_host->type == SW_SOCK_UDP6
                    || listen_host->type == SW_SOCK_UNIX_DGRAM)
            {
                serv->connection_list[listen_host->sock].addr.sin_port = listen_host->port;
                serv->connection_list[listen_host->sock].fd = listen_host->sock;
                serv->connection_list[listen_host->sock].object = listen_host;
            }
        }
    }
    //listen TCP
    if (serv->have_tcp_sock == 1)
    {
        //listen server socket
        if (swServer_listen(serv, NULL) < 0)
        {
            return SW_ERR;
        }
    }

    int create_pipe = serv->onPipeMessage ? 1 : 0;

    if (swProcessPool_create(&SwooleGS->event_workers, serv->worker_num, serv->max_request, 0, create_pipe) < 0)
    {
        return SW_ERR;
    }

    SwooleGS->event_workers.ptr = serv;
    SwooleGS->event_workers.main_loop = swReactorProcess_loop;
    SwooleGS->event_workers.type = SW_PROCESS_WORKER;

    //no worker
    if (serv->worker_num == 1 && SwooleG.task_worker_num == 0 && serv->max_request == 0)
    {
        swWorker single_worker;
        single_worker.id = 0;
        return swReactorProcess_loop(&SwooleGS->event_workers, &single_worker);
    }

    //task workers
    if (SwooleG.task_worker_num > 0)
    {
        if (swProcessPool_create(&SwooleGS->task_workers, SwooleG.task_worker_num, serv->task_max_request, serv->message_queue_key + 2, 1) < 0)
        {
            swWarn("[Master] create task_workers failed.");
            return SW_ERR;
        }

        int i;
        swWorker *worker;
        for (i = 0; i < SwooleG.task_worker_num; i++)
        {
            worker = swServer_get_worker(serv, serv->worker_num + i);
            if (swWorker_create(worker) < 0)
            {
                return SW_ERR;
            }
        }

        swTaskWorker_init(&SwooleGS->task_workers);
        swProcessPool_start(&SwooleGS->task_workers);

        //将taskworker也加入到wait中来
        for (i = 0; i < SwooleGS->task_workers.worker_num; i++)
        {
            swProcessPool_add_worker(&SwooleGS->event_workers, &SwooleGS->task_workers.workers[i]);
        }
    }
    /**
     * BASE模式，管理进程就是主进程
     */
    SwooleGS->manager_pid = getpid();

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
    swServer *serv = reactor->ptr;

    if (read(event->fd, &task, sizeof(task)) > 0)
    {
        serv->onPipeMessage(serv, &task);
        return SW_OK;
    }
    return SW_ERR;
}

static int swReactorProcess_loop(swProcessPool *pool, swWorker *worker)
{
    swServer *serv = pool->ptr;
    swReactor *reactor = &(serv->reactor_threads[0].reactor);

    SwooleG.process_type = SW_PROCESS_WORKER;
    SwooleWG.id = worker->id;

    swServer_worker_init(serv, worker);

    //create reactor
    if (swReactor_auto(reactor, SW_REACTOR_MAXEVENTS) < 0)
    {
        swWarn("ReactorProcess create failed.");
        return SW_ERR;
    }

    swListenList_node *listen_host;
    int type;

    //listen the all tcp port
    LL_FOREACH(serv->listen_list, listen_host)
    {
        type = (listen_host->type == SW_SOCK_UDP || listen_host->type == SW_SOCK_UDP6) ? SW_FD_UDP : SW_FD_LISTEN;
        reactor->add(reactor, listen_host->sock, type);
    }
    SwooleG.main_reactor = reactor;

    reactor->id = 0;
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
    reactor->sockets = serv->connection_list;
    reactor->max_socket = serv->max_connection;

    reactor->close = swReactorThread_close;

    reactor->onFinish = NULL;
    reactor->onTimeout = NULL;

    //set event handler
    //connect
    reactor->setHandle(reactor, SW_FD_LISTEN, swServer_master_onAccept);
    //close
    reactor->setHandle(reactor, SW_FD_CLOSE, swReactorProcess_onClose);

    if (serv->onPipeMessage)
    {
        reactor->add(reactor, worker->pipe_worker, SW_FD_PIPE);
        //close
        reactor->setHandle(reactor, SW_FD_PIPE, swReactorProcess_onPipeRead);
    }

    //set protocol function point
    swReactorThread_set_protocol(serv, reactor);

    if (serv->onWorkerStart)
    {
        serv->onWorkerStart(serv, worker->id);
    }

    struct timeval timeo;
    timeo.tv_sec = SW_MAINREACTOR_TIMEO;
    timeo.tv_usec = 0;
    reactor->wait(reactor, &timeo);

    return SW_OK;
}

int swReactorProcess_onClose(swReactor *reactor, swEvent *event)
{
    swServer *serv = reactor->ptr;
    if (serv->onClose != NULL)
    {
        serv->onClose(serv, event->fd, event->from_id);
    }
    return reactor->close(reactor, event->fd);
}
