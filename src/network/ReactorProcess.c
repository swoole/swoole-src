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

    swProcessPool pool;
    if (swProcessPool_create(&pool, serv->worker_num, serv->max_request, 0, 0) < 0)
    {
        return SW_ERR;
    }
    pool.ptr = serv;
    pool.main_loop = swReactorProcess_loop;
    SwooleG.event_workers = &pool;

    //no worker
    if (serv->worker_num == 1 && SwooleG.task_worker_num == 0 && serv->max_request == 0)
    {
        return swReactorProcess_loop(&pool, NULL);
    }
    //task workers
    if (SwooleG.task_worker_num > 0)
    {
        if (swProcessPool_create(&SwooleG.task_workers, SwooleG.task_worker_num, serv->task_max_request, serv->message_queue_key + 2, 1) < 0)
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

        swTaskWorker_init(&SwooleG.task_workers);

        swProcessPool_start(&SwooleG.task_workers);

        //将taskworker也加入到wait中来
        for (i = 0; i < SwooleG.task_workers.worker_num; i++)
        {
            swProcessPool_add_worker(&pool, &SwooleG.task_workers.workers[i]);
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

    swProcessPool_start(&pool);
    swProcessPool_wait(&pool);
    swProcessPool_shutdown(&pool);

    return SW_OK;
}

static int swReactorProcess_loop(swProcessPool *pool, swWorker *worker)
{
    swServer *serv = pool->ptr;
    swReactor *reactor = &(serv->reactor_threads[0].reactor);

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

    //set event handler
    //connect
    reactor->setHandle(reactor, SW_FD_LISTEN, swServer_master_onAccept);
    //close
    reactor->setHandle(reactor, SW_FD_CLOSE, swReactorProcess_onClose);
    //udp receive
    reactor->setHandle(reactor, SW_FD_UDP, swReactorThread_onPackage);
    //write
    reactor->setHandle(reactor, SW_FD_TCP | SW_EVENT_WRITE, swReactorThread_onWrite);
    //tcp receive
    if (serv->open_eof_check)
    {
        reactor->setHandle(reactor, SW_FD_TCP, swReactorThread_onReceive_buffer_check_eof);
    }
    else if (serv->open_length_check)
    {
        reactor->setHandle(reactor, SW_FD_TCP, swReactorThread_onReceive_buffer_check_length);
    }
    else if (serv->open_http_protocol)
    {
        reactor->setHandle(reactor, SW_FD_TCP, swReactorThread_onReceive_http_request);
    }
    else
    {
        reactor->setHandle(reactor, SW_FD_TCP, swReactorThread_onReceive_no_buffer);
    }

#ifdef HAVE_SIGNALFD
    if (SwooleG.use_timerfd)
    {
        swSignalfd_setup(reactor);
    }
#endif

    struct timeval timeo;

    if (serv->onWorkerStart)
    {
        serv->onWorkerStart(serv, worker->id);
    }

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
    return swServer_connection_close(serv, event->fd);
}
