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
#include "http.h"
#include "Connection.h"

#if SW_REACTOR_SCHEDULE == 3
static sw_inline void swServer_reactor_schedule(swServer *serv)
{
    //以第1个为基准进行排序，取出最小值
    int i, event_num = serv->reactor_threads[0].reactor.event_num;
    serv->reactor_next_i = 0;
    for (i = 1; i < serv->reactor_num; i++)
    {
        if (serv->reactor_threads[i].reactor.event_num < event_num)
        {
            serv->reactor_next_i = i;
            event_num = serv->reactor_threads[i].reactor.event_num;
        }
    }
}
#endif

static int swServer_start_check(swServer *serv);
static void swServer_signal_hanlder(int sig);
static int swServer_start_proxy(swServer *serv);
static void swServer_disable_accept(swReactor *reactor);

static void swHeartbeatThread_start(swServer *serv);
static void swHeartbeatThread_loop(swThreadParam *param);

static swConnection* swServer_connection_new(swServer *serv, swListenPort *ls, int fd, int from_fd, int reactor_id);

swServerG SwooleG;
swServerGS *SwooleGS;
swWorkerG SwooleWG;
swServerStats *SwooleStats;
__thread swThreadG SwooleTG;

int16_t sw_errno;
char sw_error[SW_ERROR_MSG_SIZE];

static void swServer_disable_accept(swReactor *reactor)
{
    swListenPort *ls;

    LL_FOREACH(SwooleG.serv->listen_list, ls)
    {
        //UDP
        if (ls->type == SW_SOCK_UDP || ls->type == SW_SOCK_UDP6 || ls->type == SW_SOCK_UNIX_DGRAM)
        {
            continue;
        }
        reactor->del(reactor, ls->sock);
    }
}

void swServer_enable_accept(swReactor *reactor)
{
    swListenPort *ls;

    LL_FOREACH(SwooleG.serv->listen_list, ls)
    {
        //UDP
        if (ls->type == SW_SOCK_UDP || ls->type == SW_SOCK_UDP6 || ls->type == SW_SOCK_UNIX_DGRAM)
        {
            continue;
        }
        reactor->add(reactor, ls->sock, SW_FD_LISTEN);
    }
}

void swServer_close_port(swServer *serv, enum swBool_type only_stream_port)
{
    swListenPort *ls;
    LL_FOREACH(serv->listen_list, ls)
    {
        //dgram socket
        if (only_stream_port && (ls->type == SW_SOCK_UDP || ls->type == SW_SOCK_UDP6 || ls->type == SW_SOCK_UNIX_DGRAM))
        {
            continue;
        }
        //stream socket
        close(ls->sock);
    }
}

int swServer_master_onAccept(swReactor *reactor, swEvent *event)
{
    swServer *serv = reactor->ptr;
    swReactor *sub_reactor;
    swSocketAddress client_addr;
    socklen_t client_addrlen = sizeof(client_addr);
    swListenPort *listen_host = serv->connection_list[event->fd].object;

    int new_fd = 0, ret = 0, reactor_id = 0, i;

    //SW_ACCEPT_AGAIN
    for (i = 0; i < SW_ACCEPT_MAX_COUNT; i++)
    {
#ifdef HAVE_ACCEPT4
        new_fd = accept4(event->fd, (struct sockaddr *) &client_addr, &client_addrlen, SOCK_NONBLOCK | SOCK_CLOEXEC);
#else
        new_fd = accept(event->fd, (struct sockaddr *) &client_addr, &client_addrlen);
#endif
        if (new_fd < 0)
        {
            switch (errno)
            {
            case EAGAIN:
                return SW_OK;
            case EINTR:
                continue;
            default:
                if (errno == EMFILE || errno == ENFILE)
                {
                    swServer_disable_accept(reactor);
                    reactor->disable_accept = 1;
                }
                swoole_error_log(SW_LOG_ERROR, SW_ERROR_SYSTEM_CALL_FAIL, "accept() failed. Error: %s[%d]", strerror(errno), errno);
                return SW_OK;
            }
        }
#ifndef HAVE_ACCEPT4
        else
        {
            swoole_fcntl_set_option(new_fd, 1, 1);
        }
#endif

        swTrace("[Master] Accept new connection. maxfd=%d|reactor_id=%d|conn=%d", swServer_get_maxfd(serv), reactor->id, new_fd);

        //too many connection
        if (new_fd >= serv->max_connection)
        {
            swoole_error_log(SW_LOG_WARNING, SW_ERROR_SERVER_TOO_MANY_SOCKET, "Too many connections [now: %d].", new_fd);
            close(new_fd);
            return SW_OK;
        }

        if (serv->factory_mode == SW_MODE_SINGLE)
        {
            reactor_id = 0;
        }
        else
        {
            reactor_id = new_fd % serv->reactor_num;
        }

        //add to connection_list
        swConnection *conn = swServer_connection_new(serv, listen_host, new_fd, event->fd, reactor_id);
        memcpy(&conn->info.addr, &client_addr, sizeof(client_addr));
        sub_reactor = &serv->reactor_threads[reactor_id].reactor;
        conn->socket_type = listen_host->type;

#ifdef SW_USE_OPENSSL
        if (listen_host->ssl)
        {
            if (swSSL_create(conn, listen_host->ssl_context, 0) < 0)
            {
                bzero(conn, sizeof(swConnection));
                close(new_fd);
                return SW_OK;
            }
        }
        else
        {
            conn->ssl = NULL;
        }
#endif
        /*
         * [!!!] new_connection function must before reactor->add
         */
        if (serv->factory_mode != SW_MODE_SINGLE)
        {
            int events;
            if (serv->onConnect && !listen_host->ssl)
            {
                conn->connect_notify = 1;
                events = SW_EVENT_WRITE;
            }
            else
            {
                events = SW_EVENT_READ;
            }
            ret = sub_reactor->add(sub_reactor, new_fd, SW_FD_TCP | events);
        }
        else
        {
            if (!serv->enable_delay_receive)
            {
                ret = sub_reactor->add(sub_reactor, new_fd, SW_FD_TCP | SW_EVENT_READ);
            }
            if (ret >= 0 && serv->onConnect && !listen_host->ssl)
            {
                swServer_tcp_notify(serv, conn, SW_EVENT_CONNECT);
            }
        }

        if (ret < 0)
        {
            bzero(conn, sizeof(swConnection));
            close(new_fd);
            return SW_OK;
        }

#ifdef SW_ACCEPT_AGAIN
        continue;
#else
        break;
#endif
    }
    return SW_OK;
}

static int swServer_start_check(swServer *serv)
{
    if (serv->onReceive == NULL && serv->onPacket == NULL)
    {
        swWarn("onReceive and onPacket event callback must be set.");
        return SW_ERR;
    }
    if (serv->have_tcp_sock && serv->onReceive == NULL)
    {
        swWarn("onReceive event callback must be set.");
        return SW_ERR;
    }
    //UDP
    if (!serv->onPacket)
    {
        serv->onPacket = serv->onReceive;
    }
    //disable notice when use SW_DISPATCH_ROUND and SW_DISPATCH_QUEUE
    if (serv->factory_mode == SW_MODE_PROCESS)
    {
        if (serv->dispatch_mode == SW_DISPATCH_ROUND || serv->dispatch_mode == SW_DISPATCH_QUEUE)
        {
            if (!serv->enable_unsafe_event)
            {
                serv->onConnect = NULL;
                serv->onClose = NULL;
                serv->disable_notify = 1;
            }
        }
    }
    //AsyncTask
    if (SwooleG.task_worker_num > 0)
    {
        if (serv->onTask == NULL)
        {
            swWarn("onTask is null");
            return SW_ERR;
        }
        if (serv->onFinish == NULL)
        {
            swWarn("onFinish is null");
            return SW_ERR;
        }
    }
    //check thread num
    if (serv->reactor_num > SW_CPU_NUM * SW_MAX_THREAD_NCPU)
    {
        serv->reactor_num = SW_CPU_NUM * SW_MAX_THREAD_NCPU;
    }
    if (serv->worker_num > SW_CPU_NUM * SW_MAX_WORKER_NCPU)
    {
        swWarn("serv->worker_num > %d, Too many processes, the system will be slow", SW_CPU_NUM * SW_MAX_WORKER_NCPU);
        serv->worker_num = SW_CPU_NUM * SW_MAX_WORKER_NCPU;
    }
    if (serv->worker_num < serv->reactor_num)
    {
        serv->reactor_num = serv->worker_num;
    }
    if (SwooleG.max_sockets > 0 && serv->max_connection > SwooleG.max_sockets)
    {
        swWarn("serv->max_connection is exceed the maximum value[%d].", SwooleG.max_sockets);
        serv->max_connection = SwooleG.max_sockets;
    }
    if (serv->max_connection < (serv->worker_num + SwooleG.task_worker_num) * 2 + 32)
    {
        swWarn("serv->max_connection is too small.");
        serv->max_connection = SwooleG.max_sockets;
    }
    SwooleGS->session_round = 1;
    return SW_OK;
}

/**
 * proxy模式
 * 在单独的n个线程中接受维持TCP连接
 */
static int swServer_start_proxy(swServer *serv)
{
    int ret;
    swReactor *main_reactor = SwooleG.memory_pool->alloc(SwooleG.memory_pool, sizeof(swReactor));

    ret = swReactor_create(main_reactor, SW_REACTOR_MAXEVENTS);
    if (ret < 0)
    {
        swWarn("Reactor create failed");
        return SW_ERR;
    }

    main_reactor->thread = 1;
    main_reactor->socket_list = serv->connection_list;
    main_reactor->disable_accept = 0;
    main_reactor->enable_accept = swServer_enable_accept;

#ifdef HAVE_SIGNALFD
    if (SwooleG.use_signalfd)
    {
        swSignalfd_setup(main_reactor);
    }
#endif

    //set listen socket options
    swListenPort *ls;
    LL_FOREACH(serv->listen_list, ls)
    {
        if (swSocket_is_dgram(ls->type))
        {
            continue;
        }
        if (swPort_listen(ls) < 0)
        {
            return SW_ERR;
        }
    }

    /**
     * create reactor thread
     */
    ret = swReactorThread_start(serv, main_reactor);
    if (ret < 0)
    {
        swWarn("ReactorThread start failed");
        return SW_ERR;
    }

    /**
     * heartbeat thread
     */
    if (serv->heartbeat_check_interval >= 1 && serv->heartbeat_check_interval <= serv->heartbeat_idle_time)
    {
        swTrace("hb timer start, time: %d live time:%d", serv->heartbeat_check_interval, serv->heartbeat_idle_time);
        swHeartbeatThread_start(serv);
    }

    /**
     * master thread loop
     */
    SwooleTG.type = SW_THREAD_MASTER;
    SwooleTG.factory_target_worker = -1;
    SwooleTG.factory_lock_target = 0;
    SwooleTG.id = 0;
    SwooleTG.update_time = 1;

    SwooleG.main_reactor = main_reactor;
    SwooleG.pid = getpid();
    SwooleG.process_type = SW_PROCESS_MASTER;

    /**
     * set a special id
     */
    main_reactor->id = serv->reactor_num;
    main_reactor->ptr = serv;
    main_reactor->setHandle(main_reactor, SW_FD_LISTEN, swServer_master_onAccept);

    if (serv->onStart != NULL)
    {
        serv->onStart(serv);
    }

    struct timeval tmo;
    tmo.tv_sec = 1; //for seconds timer
    tmo.tv_usec = 0;
    return main_reactor->wait(main_reactor, &tmo);
}

void swServer_store_listen_socket(swServer *serv)
{
    swListenPort *ls;
    int sockfd;
    LL_FOREACH(serv->listen_list, ls)
    {
        sockfd = ls->sock;
        //save server socket to connection_list
        serv->connection_list[sockfd].fd = sockfd;
        //socket type
        serv->connection_list[sockfd].socket_type = ls->type;
        //save listen_host object
        serv->connection_list[sockfd].object = ls;

        if (swSocket_is_dgram(ls->type))
        {
            if (ls->type == SW_SOCK_UDP)
            {
                serv->connection_list[sockfd].info.addr.inet_v4.sin_port = htons(ls->port);
            }
            else if (ls->type == SW_SOCK_UDP6)
            {
                SwooleG.serv->udp_socket_ipv6 = sockfd;
                serv->connection_list[sockfd].info.addr.inet_v6.sin6_port = htons(ls->port);
            }
        }
        else
        {
            //IPv4
            if (ls->type == SW_SOCK_TCP)
            {
                serv->connection_list[sockfd].info.addr.inet_v4.sin_port = htons(ls->port);
            }
            //IPv6
            else if (ls->type == SW_SOCK_TCP6)
            {
                serv->connection_list[sockfd].info.addr.inet_v6.sin6_port = htons(ls->port);
            }
        }
        if (sockfd >= 0)
        {
            swServer_set_minfd(serv, sockfd);
            swServer_set_maxfd(serv, sockfd);
        }
    }
}

swString** swServer_create_worker_buffer(swServer *serv)
{
    int i;
    int buffer_input_size;
    if (serv->listen_list->open_eof_check || serv->listen_list->open_length_check || serv->listen_list->open_http_protocol)
    {
        buffer_input_size = serv->listen_list->protocol.package_max_length;
    }
    else
    {
        buffer_input_size = SW_BUFFER_SIZE_BIG;
    }

    int buffer_num;
    if (serv->factory_mode == SW_MODE_SINGLE || serv->factory_mode == SW_MODE_BASE)
    {
        buffer_num = 1;
    }
    else
    {
        buffer_num = serv->reactor_num + serv->dgram_port_num;
    }

    swString **buffers = sw_malloc(sizeof(swString*) * buffer_num);
    if (buffers == NULL)
    {
        swError("malloc for worker buffer_input failed.");
        return NULL;
    }

    for (i = 0; i < buffer_num; i++)
    {
        buffers[i] = swString_new(buffer_input_size);
        if (buffers[i] == NULL)
        {
            swError("worker buffer_input init failed.");
            return NULL;
        }
    }

    return buffers;
}

int swServer_create_task_worker(swServer *serv)
{
    key_t key = 0;
    int ipc_type;

    if (SwooleG.task_ipc_mode > SW_TASK_IPC_UNIXSOCK)
    {
        key = serv->message_queue_key;
        ipc_type = SW_IPC_MSGQUEUE;
    }
    else
    {
        ipc_type = SW_IPC_UNIXSOCK;
    }

    if (swProcessPool_create(&SwooleGS->task_workers, SwooleG.task_worker_num, SwooleG.task_max_request, key, ipc_type) < 0)
    {
        swWarn("[Master] create task_workers failed.");
        return SW_ERR;
    }
    else
    {
        return SW_OK;
    }
}

int swServer_worker_init(swServer *serv, swWorker *worker)
{
#ifdef HAVE_CPU_AFFINITY
    if (serv->open_cpu_affinity)
    {
        cpu_set_t cpu_set;
        CPU_ZERO(&cpu_set);
        if (serv->cpu_affinity_available_num)
        {
            CPU_SET(serv->cpu_affinity_available[SwooleWG.id % serv->cpu_affinity_available_num], &cpu_set);
        }
        else
        {
            CPU_SET(SwooleWG.id % SW_CPU_NUM, &cpu_set);
        }
        if (sched_setaffinity(getpid(), sizeof(cpu_set), &cpu_set) < 0)
        {
            swSysError("sched_setaffinity() failed.");
        }
    }
#endif

    //signal init
    swWorker_signal_init();

    SwooleWG.buffer_input = swServer_create_worker_buffer(serv);
    if (!SwooleWG.buffer_input)
    {
        return SW_ERR;
    }

    if (serv->max_request < 1)
    {
        SwooleWG.run_always = 1;
    }
    else
    {
        SwooleWG.max_request = serv->max_request;
        if (SwooleWG.max_request > 10)
        {
            SwooleWG.max_request += swoole_system_random(1, 100);
        }
    }

    return SW_OK;
}

void swServer_reopen_log_file(swServer *serv)
{
    if (!SwooleG.log_file)
    {
        return;
    }
    /**
     * reopen log file
     */
    close(SwooleG.log_fd);
    swLog_init(SwooleG.log_file);
    /**
     * redirect STDOUT & STDERR to log file
     */
    if (serv->daemonize)
    {
        swoole_redirect_stdout(SwooleG.log_fd);
    }
}

int swServer_start(swServer *serv)
{
    swFactory *factory = &serv->factory;
    int ret;

    ret = swServer_start_check(serv);
    if (ret < 0)
    {
        return SW_ERR;
    }
    //init loggger
    if (SwooleG.log_file)
    {
        swLog_init(SwooleG.log_file);
    }
    //run as daemon
    if (serv->daemonize > 0)
    {
        /**
         * redirect STDOUT to log file
         */
        if (SwooleG.log_fd > STDOUT_FILENO)
        {
            swoole_redirect_stdout(SwooleG.log_fd);
        }
        /**
         * redirect STDOUT_FILENO/STDERR_FILENO to /dev/null
         */
        else
        {
            SwooleG.null_fd = open("/dev/null", O_WRONLY);
            if (SwooleG.null_fd > 0)
            {
                swoole_redirect_stdout(SwooleG.null_fd);
            }
            else
            {
                swoole_error_log(SW_LOG_ERROR, SW_ERROR_SYSTEM_CALL_FAIL, "open(/dev/null) failed. Error: %s[%d]", strerror(errno), errno);
            }
        }

        if (daemon(0, 1) < 0)
        {
            return SW_ERR;
        }
    }

    //master pid
    SwooleGS->master_pid = getpid();
    SwooleGS->start = 1;
    SwooleGS->now = SwooleStats->start_time = time(NULL);

    serv->send = swServer_tcp_send;
    serv->sendwait = swServer_tcp_sendwait;
    serv->sendfile = swServer_tcp_sendfile;
    serv->close = swServer_tcp_close;

    serv->workers = SwooleG.memory_pool->alloc(SwooleG.memory_pool, serv->worker_num * sizeof(swWorker));
    if (serv->workers == NULL)
    {
        swoole_error_log(SW_LOG_ERROR, SW_ERROR_SYSTEM_CALL_FAIL, "gmalloc[object->workers] failed");
        return SW_ERR;
    }

    /**
     * store to swProcessPool object
     */
    SwooleGS->event_workers.workers = serv->workers;
    SwooleGS->event_workers.worker_num = serv->worker_num;
    SwooleGS->event_workers.use_msgqueue = 0;

    int i;
    for (i = 0; i < serv->worker_num; i++)
    {
        SwooleGS->event_workers.workers[i].pool = &SwooleGS->event_workers;
    }

#ifdef SW_USE_RINGBUFFER
    for (i = 0; i < serv->reactor_num; i++)
    {
        serv->reactor_threads[i].buffer_input = swRingBuffer_new(SwooleG.serv->buffer_input_size, 1);
        if (!serv->reactor_threads[i].buffer_input)
        {
            return SW_ERR;
        }
    }
#endif

    /*
     * For swoole_server->taskwait, create notify pipe and result shared memory.
     */
    if (SwooleG.task_worker_num > 0 && serv->worker_num > 0)
    {
        SwooleG.task_result = sw_shm_calloc(serv->worker_num, sizeof(swEventData));
        SwooleG.task_notify = sw_calloc(serv->worker_num, sizeof(swPipe));
        for (i = 0; i < serv->worker_num; i++)
        {
            if (swPipeNotify_auto(&SwooleG.task_notify[i], 1, 0))
            {
                return SW_ERR;
            }
        }
    }

    /**
     * user worker process
     */
    if (serv->user_worker_list)
    {
        swUserWorker_node *user_worker;
        i = 0;
        LL_FOREACH(serv->user_worker_list, user_worker)
        {
            user_worker->worker->id = serv->worker_num + SwooleG.task_worker_num + i;
            i++;
        }
    }

    //factory start
    if (factory->start(factory) < 0)
    {
        return SW_ERR;
    }
    //signal Init
    swServer_signal_init(serv);

    //write PID file
    if (serv->pid_file)
    {
        ret = snprintf(SwooleG.module_stack->str, SwooleG.module_stack->size, "%d", getpid());
        swoole_file_put_contents(serv->pid_file, SwooleG.module_stack->str, ret);
    }
    if (serv->factory_mode == SW_MODE_SINGLE)
    {
        ret = swReactorProcess_start(serv);
    }
    else
    {
        ret = swServer_start_proxy(serv);
    }
    swServer_free(serv);
    SwooleGS->start = 0;
    //remove PID file
    if (serv->pid_file)
    {
        unlink(serv->pid_file);
    }
    return SW_OK;
}

/**
 * initializing server config, set default
 */
void swServer_init(swServer *serv)
{
    swoole_init();
    bzero(serv, sizeof(swServer));

    serv->factory_mode = SW_MODE_BASE;

    serv->reactor_num = SW_REACTOR_NUM > SW_REACTOR_MAX_THREAD ? SW_REACTOR_MAX_THREAD : SW_REACTOR_NUM;

    serv->dispatch_mode = SW_DISPATCH_FDMOD;
    serv->ringbuffer_size = SW_QUEUE_SIZE;

    serv->timeout_sec = SW_REACTOR_TIMEO_SEC;
    serv->timeout_usec = SW_REACTOR_TIMEO_USEC;  //300ms;

    serv->worker_num = SW_CPU_NUM;
    serv->max_connection = SwooleG.max_sockets;
    serv->max_request = 0;

    //http server
    serv->http_parse_post = 1;
    serv->upload_tmp_dir = "/tmp";

    //heartbeat check
    serv->heartbeat_idle_time = SW_HEARTBEAT_IDLE;
    serv->heartbeat_check_interval = SW_HEARTBEAT_CHECK;

    serv->buffer_input_size = SW_BUFFER_INPUT_SIZE;
    serv->buffer_output_size = SW_BUFFER_OUTPUT_SIZE;

    serv->pipe_buffer_size = SW_PIPE_BUFFER_SIZE;

    SwooleG.serv = serv;
}

int swServer_create(swServer *serv)
{
    if (SwooleG.main_reactor)
    {
        swoole_error_log(SW_LOG_ERROR, SW_ERROR_SERVER_MUST_CREATED_BEFORE_CLIENT, "The swoole_server must create before client");
        return SW_ERR;
    }

    SwooleG.factory = &serv->factory;

    serv->factory.ptr = serv;

#ifdef SW_REACTOR_USE_SESSION
    serv->session_list = sw_shm_calloc(SW_SESSION_LIST_SIZE, sizeof(swSession));
    if (serv->session_list == NULL)
    {
        swError("sw_shm_calloc(%ld) for session_list failed", SW_SESSION_LIST_SIZE * sizeof(swSession));
        return SW_ERR;
    }
#endif

    if (serv->factory_mode == SW_MODE_SINGLE)
    {
        return swReactorProcess_create(serv);
    }
    else
    {
        return swReactorThread_create(serv);
    }
}

int swServer_shutdown(swServer *serv)
{
    //stop all thread
    SwooleG.main_reactor->running = 0;
    return SW_OK;
}

int swServer_free(swServer *serv)
{
    /**
     * shutdown workers
     */
    if (serv->factory.shutdown != NULL)
    {
        serv->factory.shutdown(&(serv->factory));
    }
    /**
     * Shutdown heartbeat thread
     */
    if (SwooleG.heartbeat_pidt)
    {
        if (pthread_cancel(SwooleG.heartbeat_pidt) < 0)
        {
            swSysError("pthread_cancel(%ld) failed.", (ulong_t )SwooleG.heartbeat_pidt);
        }
        //wait thread
        if (pthread_join(SwooleG.heartbeat_pidt, NULL) < 0)
        {
            swSysError("pthread_join(%ld) failed.", (ulong_t )SwooleG.heartbeat_pidt);
        }
    }
    if (serv->factory_mode == SW_MODE_SINGLE)
    {
        if (SwooleG.task_worker_num > 0)
        {
            swProcessPool_shutdown(&SwooleGS->task_workers);
        }
    }
    else
    {
        /**
         * Wait until all the end of the thread
         */
        swReactorThread_free(serv);
    }

    swListenPort *port;
    LL_FOREACH(serv->listen_list, port)
    {
        swPort_free(port);
    }
    //reactor free
    if (serv->reactor.free != NULL)
    {
        serv->reactor.free(&(serv->reactor));
    }
    //close log file
    if (SwooleG.log_file != 0)
    {
        swLog_free();
    }
    if (SwooleG.null_fd > 0)
    {
        close(SwooleG.null_fd);
    }
    if (SwooleGS->start > 0 && serv->onShutdown != NULL)
    {
        serv->onShutdown(serv);
    }
    swoole_clean();
    return SW_OK;
}

int swServer_udp_send(swServer *serv, swSendData *resp)
{
    struct sockaddr_in addr_in;
    int sock = resp->info.from_fd;

    addr_in.sin_family = AF_INET;
    addr_in.sin_port = htons((uint16_t) resp->info.from_id); //from_id is remote port
    addr_in.sin_addr.s_addr = (uint32_t) resp->info.fd; //fd is remote ip address

    int ret = swSocket_sendto_blocking(sock, resp->data, resp->info.len, 0, (struct sockaddr*) &addr_in, sizeof(addr_in));
    if (ret < 0)
    {
        swWarn("sendto to client[%s:%d] failed. Error: %s [%d]", inet_ntoa(addr_in.sin_addr), resp->info.from_id,
                strerror(errno), errno);
    }
    return ret;
}

int swServer_confirm(swServer *serv, int fd)
{
    swConnection *conn = swServer_connection_verify(serv, fd);
    if (!conn && !conn->listen_wait)
    {
        return SW_ERR;
    }

    swSendData _send;
    bzero(&_send, sizeof(_send));
    _send.info.type = SW_EVENT_CONFIRM;
    _send.info.fd = fd;
    _send.info.from_id = conn->from_id;

    if (serv->factory_mode == SW_MODE_PROCESS)
    {
        return swWorker_send2reactor((swEventData *) &_send.info, sizeof(_send.info), fd);
    }
    else
    {
        return swReactorThread_send(&_send);
    }
}

void swServer_store_pipe_fd(swServer *serv, swPipe *p)
{
    int master_fd = p->getFd(p, SW_PIPE_MASTER);

    serv->connection_list[p->getFd(p, SW_PIPE_WORKER)].object = p;
    serv->connection_list[master_fd].object = p;

    if (master_fd > swServer_get_minfd(serv))
    {
        swServer_set_minfd(serv, master_fd);
    }
}

void swServer_close_listen_port(swServer *serv)
{
    swListenPort *ls;
    LL_FOREACH(serv->listen_list, ls)
    {
        if (swSocket_is_stream(ls->type))
        {
            close(ls->sock);
        }
    }
}

swPipe * swServer_get_pipe_object(swServer *serv, int pipe_fd)
{
    return (swPipe *) serv->connection_list[pipe_fd].object;
}

int swServer_tcp_send(swServer *serv, int fd, void *data, uint32_t length)
{
    swSendData _send;
    swFactory *factory = &(serv->factory);
    /**
     * More than the output buffer
     */
    if (length >= serv->buffer_output_size)
    {
        swoole_error_log(SW_LOG_WARNING, SW_ERROR_OUTPUT_BUFFER_OVERFLOW, "More than the output buffer size[%d], please use the sendfile.", serv->buffer_output_size);
        return SW_ERR;
    }
    else
    {
        _send.info.fd = fd;
        _send.info.type = SW_EVENT_TCP;
        _send.data = data;

        if (length >= SW_IPC_MAX_SIZE - sizeof(swDataHead))
        {
            _send.length = length;
        }
        else
        {
            _send.info.len = length;
            _send.length = 0;
        }
        return factory->finish(factory, &_send);
    }
    return SW_OK;
}

int swServer_tcp_notify(swServer *serv, swConnection *conn, int event)
{
    swDataHead notify_event;
    notify_event.type = event;
    notify_event.from_id = conn->from_id;
    notify_event.fd = conn->fd;
    notify_event.from_fd = conn->from_fd;
    return serv->factory.notify(&serv->factory, &notify_event);
}

int swServer_tcp_sendfile(swServer *serv, int session_id, char *filename, uint32_t len, off_t offset)
{
#ifdef SW_USE_OPENSSL
    swConnection *conn = swServer_connection_verify(serv, session_id);
    if (conn && conn->ssl)
    {
        swoole_error_log(SW_LOG_WARNING, SW_ERROR_SSL_CANNOT_USE_SENFILE, "SSL session#%d cannot use sendfile().", session_id);
        return SW_ERR;
    }
#endif

    swSendData send_data;
    char buffer[SW_BUFFER_SIZE];

    //file name size
    if (len > SW_BUFFER_SIZE - sizeof(offset) - 1)
    {
        swoole_error_log(SW_LOG_WARNING, SW_ERROR_NAME_TOO_LONG, "sendfile name too long. [MAX_LENGTH=%d]",
                (int) SW_BUFFER_SIZE - 1);
        return SW_ERR;
    }

    send_data.info.fd = session_id;
    send_data.info.type = SW_EVENT_SENDFILE;
    memcpy(buffer, &offset, sizeof(off_t));
    memcpy(buffer + sizeof(off_t), filename, len);
    buffer[sizeof(off_t) + len] = 0;
    send_data.info.len = sizeof(off_t) + len + 1;
    send_data.length = 0;
    send_data.data = buffer;

    return serv->factory.finish(&serv->factory, &send_data);
}

int swServer_tcp_sendwait(swServer *serv, int fd, void *data, uint32_t length)
{
    swConnection *conn = swServer_connection_verify(serv, fd);
    if (!conn)
    {
        swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SESSION_CLOSED, "send %d byte failed, because session#%d is closed.", length, fd);
        return SW_ERR;
    }
    return swSocket_write_blocking(conn->fd, data, length);
}

int swServer_tcp_close(swServer *serv, int fd, int reset)
{
    swConnection *conn = swServer_connection_verify_no_ssl(serv, fd);
    if (!conn)
    {
        return SW_ERR;
    }
    //Reset send buffer, Immediately close the connection.
    if (reset)
    {
        conn->close_reset = 1;
    }
    int ret;
    if (!swIsWorker())
    {
        swWorker *worker = swServer_get_worker(serv, conn->fd % serv->worker_num);
        swDataHead ev;
        ev.type = SW_EVENT_CLOSE;
        ev.fd = fd;
        ev.from_id = conn->from_id;
        ret = swWorker_send2worker(worker, &ev, sizeof(ev), SW_PIPE_MASTER);
    }
    else
    {
        ret = serv->factory.end(&serv->factory, fd);
    }
    return ret;
}

void swServer_signal_init(swServer *serv)
{
    swSignal_add(SIGPIPE, NULL);
    swSignal_add(SIGHUP, NULL);
    if (serv->factory_mode != SW_MODE_PROCESS)
    {
        swSignal_add(SIGCHLD, swServer_signal_hanlder);
    }
    swSignal_add(SIGUSR1, swServer_signal_hanlder);
    swSignal_add(SIGUSR2, swServer_signal_hanlder);
    swSignal_add(SIGTERM, swServer_signal_hanlder);
#ifdef SIGRTMIN
    swSignal_add(SIGRTMIN, swServer_signal_hanlder);
#endif
    swSignal_add(SIGALRM, swSystemTimer_signal_handler);
    //for test
    swSignal_add(SIGVTALRM, swServer_signal_hanlder);
    swServer_set_minfd(SwooleG.serv, SwooleG.signal_fd);
}

int swServer_add_worker(swServer *serv, swWorker *worker)
{
    swUserWorker_node *user_worker = sw_malloc(sizeof(swUserWorker_node));
    if (!user_worker)
    {
        return SW_ERR;
    }

    serv->user_worker_num++;
    user_worker->worker = worker;

    LL_APPEND(serv->user_worker_list, user_worker);
    if (!serv->user_worker_map)
    {
        serv->user_worker_map = swHashMap_new(SW_HASHMAP_INIT_BUCKET_N, NULL);
    }

    return worker->id;
}

swListenPort* swServer_add_port(swServer *serv, int type, char *host, int port)
{
    if (serv->listen_port_num >= SW_MAX_LISTEN_PORT)
    {
        swoole_error_log(SW_LOG_ERROR, SW_ERROR_SERVER_TOO_MANY_LISTEN_PORT, "allows up to %d ports to listen", SW_MAX_LISTEN_PORT);
        return NULL;
    }
    if (!(type == SW_SOCK_UNIX_DGRAM || type == SW_SOCK_UNIX_STREAM) && (port < 0 || port > 65535))
    {
        swoole_error_log(SW_LOG_ERROR, SW_ERROR_SERVER_INVALID_LISTEN_PORT, "invalid port [%d]", port);
        return NULL;
    }

    swListenPort *ls = SwooleG.memory_pool->alloc(SwooleG.memory_pool, sizeof(swListenPort));
    if (ls == NULL)
    {
        swError("alloc failed");
        return NULL;
    }

    swPort_init(ls);
    ls->type = type;
    ls->port = port;
    bzero(ls->host, SW_HOST_MAXSIZE);
    strncpy(ls->host, host, SW_HOST_MAXSIZE);

    if (type & SW_SOCK_SSL)
    {
        type = type & (~SW_SOCK_SSL);
        if (swSocket_is_stream(type))
        {
            ls->type = type;
            ls->ssl = 1;
#ifdef SW_USE_OPENSSL
            ls->ssl_config.prefer_server_ciphers = 1;
            ls->ssl_config.session_tickets = 0;
            ls->ssl_config.stapling = 1;
            ls->ssl_config.stapling_verify = 1;
            ls->ssl_config.ciphers = SW_SSL_CIPHER_LIST;
            ls->ssl_config.ecdh_curve = SW_SSL_ECDH_CURVE;
#endif
        }
    }

    //create server socket
    int sock = swSocket_create(ls->type);
    if (sock < 0)
    {
        swSysError("create socket failed.");
        return NULL;
    }
    //bind address and port
    if (swSocket_bind(sock, ls->type, ls->host, &ls->port) < 0)
    {
        close(sock);
        return NULL;
    }
    //dgram socket, setting socket buffer size
    if (swSocket_is_dgram(ls->type))
    {
        setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &ls->socket_buffer_size, sizeof(int));
        setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &ls->socket_buffer_size, sizeof(int));
    }
    //O_NONBLOCK & O_CLOEXEC
    swoole_fcntl_set_option(sock, 1, 1);
    ls->sock = sock;

    if (swSocket_is_dgram(ls->type))
    {
        serv->have_udp_sock = 1;
        serv->dgram_port_num++;
        if (ls->type == SW_SOCK_UDP)
        {
            serv->udp_socket_ipv4 = sock;
        }
        else if (ls->type == SW_SOCK_UDP6)
        {
            serv->udp_socket_ipv6 = sock;
        }
    }
    else
    {
        serv->have_tcp_sock = 1;
    }

    LL_APPEND(serv->listen_list, ls);
    serv->listen_port_num++;
    return ls;
}

int swServer_get_manager_pid(swServer *serv)
{
    if (SW_MODE_PROCESS != serv->factory_mode)
    {
        return SW_ERR;
    }
    return SwooleGS->manager_pid;
}

int swServer_get_socket(swServer *serv, int port)
{
    swListenPort *ls;
    LL_FOREACH(serv->listen_list, ls)
    {
        if (ls->port == port || port == 0)
        {
            return ls->sock;
        }
    }
    return SW_ERR;
}

static void swServer_signal_hanlder(int sig)
{
    int status;
    pid_t pid;
    switch (sig)
    {
    case SIGTERM:
        if (SwooleG.main_reactor)
        {
            SwooleG.main_reactor->running = 0;
        }
        else
        {
            SwooleG.running = 0;
        }
        swNotice("Server is shutdown now.");
        break;
    case SIGALRM:
        swSystemTimer_signal_handler(SIGALRM);
        break;
    case SIGCHLD:
        if (!SwooleG.running)
        {
            break;
        }
        pid = waitpid(-1, &status, WNOHANG);
        if (pid > 0 && pid == SwooleGS->manager_pid)
        {
            swWarn("Fatal Error: manager process exit. status=%d, signal=%d.", WEXITSTATUS(status), WTERMSIG(status));
        }
        break;
        /**
         * for test
         */
    case SIGVTALRM:
        swWarn("SIGVTALRM coming");
        break;
        /**
         * proxy the restart signal
         */
    case SIGUSR1:
    case SIGUSR2:
        if (SwooleG.serv->factory_mode == SW_MODE_SINGLE)
        {
            SwooleGS->event_workers.reloading = 1;
            SwooleGS->event_workers.reload_flag = 0;
        }
        else
        {
            kill(SwooleGS->manager_pid, sig);
        }
        break;
    default:
#ifdef SIGRTMIN
        if (sig == SIGRTMIN)
        {
            int i;
            swWorker *worker;
            for (i = 0; i < SwooleG.serv->worker_num + SwooleG.task_worker_num + SwooleG.serv->user_worker_num; i++)
            {
                worker = swServer_get_worker(SwooleG.serv, i);
                kill(worker->pid, SIGRTMIN);
            }
            if (SwooleG.serv->factory_mode == SW_MODE_PROCESS)
            {
                kill(SwooleGS->manager_pid, SIGRTMIN);
            }
            swServer_reopen_log_file(SwooleG.serv);
        }
#endif
        break;
    }
}

static void swHeartbeatThread_start(swServer *serv)
{
    swThreadParam *param;
    pthread_t thread_id;
    param = SwooleG.memory_pool->alloc(SwooleG.memory_pool, sizeof(swThreadParam));
    if (param == NULL)
    {
        swError("heartbeat_param malloc fail\n");
        return;
    }

    param->object = serv;
    param->pti = 0;

    if (pthread_create(&thread_id, NULL, (void * (*)(void *)) swHeartbeatThread_loop, (void *) param) < 0)
    {
        swWarn("pthread_create[hbcheck] fail");
    }
    SwooleG.heartbeat_pidt = thread_id;
}

static void swHeartbeatThread_loop(swThreadParam *param)
{
    swSignal_none();

    swServer *serv = param->object;
    swConnection *conn;
    swReactor *reactor;

    int fd;
    int serv_max_fd;
    int serv_min_fd;
    int checktime;

    SwooleTG.type = SW_THREAD_HEARTBEAT;
    SwooleTG.id = serv->reactor_num;

    while (SwooleG.running)
    {
        serv_max_fd = swServer_get_maxfd(serv);
        serv_min_fd = swServer_get_minfd(serv);

        checktime = (int) time(NULL) - serv->heartbeat_idle_time;

        for (fd = serv_min_fd; fd <= serv_max_fd; fd++)
        {
            swTrace("check fd=%d", fd);
            conn = swServer_connection_get(serv, fd);

            if (conn != NULL && conn->active == 1 && conn->closed == 0 && conn->fdtype == SW_FD_TCP)
            {
                if (conn->protect || conn->last_time > checktime)
                {
                    continue;
                }

                conn->close_force = 1;
                conn->close_notify = 1;
                conn->close_wait = 1;

                if (serv->factory_mode != SW_MODE_PROCESS)
                {
                    if (serv->factory_mode == SW_MODE_SINGLE)
                    {
                        reactor = SwooleG.main_reactor;
                    }
                    else
                    {
                        reactor = &serv->reactor_threads[conn->from_id].reactor;
                    }
                }
                else
                {
                    reactor = &serv->reactor_threads[conn->from_id].reactor;
                }
                //notify to reactor thread
                if (conn->removed)
                {
                    swServer_tcp_notify(serv, conn, SW_EVENT_CLOSE);
                }
                else
                {
                    reactor->set(reactor, fd, SW_FD_TCP | SW_EVENT_WRITE);
                }
            }
        }
        sleep(serv->heartbeat_check_interval);
    }
    pthread_exit(0);
}

/**
 * new connection
 */
static swConnection* swServer_connection_new(swServer *serv, swListenPort *ls, int fd, int from_fd, int reactor_id)
{
    swConnection* connection = NULL;

    SwooleStats->accept_count++;
    sw_atomic_fetch_add(&SwooleStats->connection_num, 1);

    if (fd > swServer_get_maxfd(serv))
    {
        swServer_set_maxfd(serv, fd);
    }

    connection = &(serv->connection_list[fd]);
    bzero(connection, sizeof(swConnection));

    //TCP Nodelay
    if (ls->open_tcp_nodelay)
    {
        int sockopt = 1;
        if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &sockopt, sizeof(sockopt)) < 0)
        {
            swSysError("setsockopt(TCP_NODELAY) failed.");
        }
        connection->tcp_nodelay = 1;
    }

#ifdef HAVE_TCP_NOPUSH
    //TCP NOPUSH
    if (ls->open_tcp_nopush)
    {
        connection->tcp_nopush = 1;
    }
#endif

    connection->fd = fd;
    connection->from_id = serv->factory_mode == SW_MODE_SINGLE ? SwooleWG.id : reactor_id;
    connection->from_fd = (sw_atomic_t) from_fd;
    connection->connect_time = SwooleGS->now;
    connection->last_time = SwooleGS->now;
    connection->active = 1;
    connection->buffer_size = ls->socket_buffer_size;

#ifdef SW_REACTOR_SYNC_SEND
    if (serv->factory_mode != SW_MODE_THREAD && !ls->ssl)
    {
        connection->direct_send = 1;
    }
#endif

#ifdef SW_REACTOR_USE_SESSION
    uint32_t session_id = 1;
    swSession *session;
    sw_spinlock(&SwooleGS->spinlock);
    int i;
    //get session id
    for (i = 0; i < serv->max_connection; i++)
    {
        session_id = SwooleGS->session_round++;
        if (session_id == 0)
        {
            session_id = 1;
            SwooleGS->session_round = 1;
        }
        session = swServer_get_session(serv, session_id);
        //vacancy
        if (session->fd == 0)
        {
            session->fd = fd;
            session->id = session_id;
            session->reactor_id = connection->from_id;
            break;
        }
    }
    sw_spinlock_release(&SwooleGS->spinlock);
    connection->session_id = session_id;
#endif

    return connection;
}

void swServer_set_callback(swServer *serv, int type, void *callback)
{
    switch(type)
    {
    case SW_SERVER_CALLBACK_onConnect:
        serv->onConnect = callback;
        break;
    case SW_SERVER_CALLBACK_onReceive:
        serv->onReceive = callback;
        break;
    case SW_SERVER_CALLBACK_onClose:
        serv->onClose = callback;
        break;
    default:
        swError("unkown callback type.");
        break;
    }
}

static void (*onConnect_callback)(swServer *, int, int);
static int (*onReceive_callback)(swServer *, char *, int, int, int);
static void (*onClose_callback)(swServer *, int, int);

static void swServer_scalar_onConnect_callback(swServer *serv, swDataHead *info)
{
    onConnect_callback(serv, info->fd, info->from_id);
}

static int swServer_scalar_onReceive_callback(swServer *serv, swEventData *req)
{
    return onReceive_callback(serv, req->data, req->info.len, req->info.fd, req->info.from_id);
}

static void swServer_scalar_onClose_callback(swServer *serv, swDataHead *info)
{
    onClose_callback(serv, info->fd, info->from_id);
}

void swServer_set_callback_onConnect(swServer *serv, void (*callback)(swServer *, int, int))
{
    onConnect_callback = callback;
    serv->onConnect = swServer_scalar_onConnect_callback;
}

void swServer_set_callback_onReceive(swServer *serv, int (*callback)(swServer *, char *, int, int, int))
{
    onReceive_callback = callback;
    serv->onReceive = swServer_scalar_onReceive_callback;
}

void swServer_set_callback_onClose(swServer *serv, void (*callback)(swServer *, int, int))
{
    onClose_callback = callback;
    serv->onClose = swServer_scalar_onClose_callback;
}
