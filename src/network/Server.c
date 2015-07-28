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
#include "Http.h"
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

static void swHeartbeatThread_loop(swThreadParam *param);
static int swServer_send1(swServer *serv, swSendData *resp);
static int swServer_send2(swServer *serv, swSendData *resp);

static swConnection* swServer_connection_new(swServer *serv, int fd, int from_fd, int reactor_id);

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

int swServer_master_onAccept(swReactor *reactor, swEvent *event)
{
    swServer *serv = reactor->ptr;
    swReactor *sub_reactor;
    swSocketAddress client_addr;
    socklen_t client_addrlen = sizeof(client_addr);
    swListenPort *listen_host = serv->connection_list[event->fd].object;

    int new_fd = 0, ret, reactor_id = 0, i;

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
                swWarn("accept() failed. Error: %s[%d]", strerror(errno), errno);
                return SW_OK;
            }
        }
#ifndef HAVE_ACCEPT4
        else
        {
            swSetNonBlock(new_fd);
        }
#endif

        swTrace("[Master] Accept new connection. maxfd=%d|reactor_id=%d|conn=%d", swServer_get_maxfd(serv), reactor->id, new_fd);

        //too many connection
        if (new_fd >= serv->max_connection)
        {
            swWarn("Too many connections [now: %d].", new_fd);
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
        swConnection *conn = swServer_connection_new(serv, new_fd, event->fd, reactor_id);
        memcpy(&conn->info.addr, &client_addr, sizeof(client_addr));
        sub_reactor = &serv->reactor_threads[reactor_id].reactor;
        conn->socket_type = listen_host->type;

#ifdef SW_USE_OPENSSL
        if (serv->open_ssl)
        {
            if (listen_host->ssl)
            {
                if (swSSL_create(conn, 0) < 0)
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
        }
#endif
        /*
         * [!!!] new_connection function must before reactor->add
         */
        if (serv->factory_mode == SW_MODE_PROCESS)
        {
            int events;
            if (serv->onConnect)
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
            ret = sub_reactor->add(sub_reactor, new_fd, SW_FD_TCP | SW_EVENT_READ);
            
            if (ret >= 0 && serv->onConnect)
            {
                swDataHead connect_event;
                connect_event.type = SW_EVENT_CONNECT;
                connect_event.from_id = reactor->id;
                connect_event.fd = new_fd;

                if (serv->factory.notify(&serv->factory, &connect_event) < 0)
                {
                    swWarn("send notification [fd=%d] failed.", new_fd);
                }
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

void swServer_onTimer(swTimer *timer, swTimer_node *event)
{
    swServer *serv = SwooleG.serv;
    serv->onTimer(serv, event->interval);
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
    //Timer
    if (SwooleG.timer.interval > 0 && serv->onTimer == NULL)
    {
        swWarn("onTimer is null");
        return SW_ERR;
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

#ifdef SW_USE_OPENSSL
    if (serv->open_ssl)
    {
        if (serv->ssl_cert_file == NULL || serv->ssl_key_file == NULL)
        {
            swWarn("SSL error, require ssl_cert_file and ssl_key_file.");
            return SW_ERR;
        }
    }
#endif
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

    ret = swReactor_create(main_reactor, SW_REACTOR_MINEVENTS);
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

    SwooleWG.buffer_input = sw_malloc(sizeof(swString*) * serv->reactor_num);
    if (SwooleWG.buffer_input == NULL)
    {
        swError("malloc for SwooleWG.buffer_input failed.");
        return SW_ERR;
    }

#ifndef SW_USE_RINGBUFFER
    int i;
    int buffer_input_size;
    if (serv->open_eof_check || serv->open_length_check || serv->open_http_protocol)
    {
        buffer_input_size = serv->protocol.package_max_length;
    }
    else
    {
        buffer_input_size = SW_BUFFER_SIZE_BIG;
    }

    for (i = 0; i < serv->reactor_num; i++)
    {
        SwooleWG.buffer_input[i] = swString_new(buffer_input_size);
        if (SwooleWG.buffer_input[i] == NULL)
        {
            swError("buffer_input init failed.");
            return SW_ERR;
        }
    }
#endif

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

int swServer_start(swServer *serv)
{
    swFactory *factory = &serv->factory;
    int ret;

    ret = swServer_start_check(serv);
    if (ret < 0)
    {
        return SW_ERR;
    }

    if (serv->message_queue_key == 0)
    {
        char path_buf[128];
        char *path_ptr = getcwd(path_buf, 128);
        serv->message_queue_key = ftok(path_ptr, 1);
    }

#ifdef SW_USE_OPENSSL
    if (serv->open_ssl)
    {
        if (swSSL_init(serv->ssl_cert_file, serv->ssl_key_file) < 0)
        {
            return SW_ERR;
        }
    }
#endif

    //run as daemon
    if (serv->daemonize > 0)
    {
        /**
         * redirect STDOUT to log file
         */
        if (SwooleG.log_fd > STDOUT_FILENO)
        {
            if (dup2(SwooleG.log_fd, STDOUT_FILENO) < 0)
            {
                swWarn("dup2() failed. Error: %s[%d]", strerror(errno), errno);
            }
        }
        /**
         * redirect STDOUT_FILENO/STDERR_FILENO to /dev/null
         */
        else
        {
            SwooleG.null_fd = open("/dev/null", O_WRONLY);
            if (SwooleG.null_fd > 0)
            {
                if (dup2(SwooleG.null_fd, STDOUT_FILENO) < 0)
                {
                    swWarn("dup2(STDOUT_FILENO) failed. Error: %s[%d]", strerror(errno), errno);
                }
                if (dup2(SwooleG.null_fd, STDERR_FILENO) < 0)
                {
                    swWarn("dup2(STDERR_FILENO) failed. Error: %s[%d]", strerror(errno), errno);
                }
            }
            else
            {
                swWarn("open(/dev/null) failed. Error: %s[%d]", strerror(errno), errno);
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

    if (serv->have_udp_sock == 1 && serv->factory_mode != SW_MODE_PROCESS)
    {
        serv->send = swServer_send2;
    }
    else
    {
        serv->send = swServer_send1;
    }

    serv->workers = SwooleG.memory_pool->alloc(SwooleG.memory_pool, serv->worker_num * sizeof(swWorker));
    if (serv->workers == NULL)
    {
        swWarn("[Master] malloc[object->workers] failed");
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

    //factory start
    if (factory->start(factory) < 0)
    {
        return SW_ERR;
    }
    //Signal Init
    swServer_signal_init();

    if (serv->factory_mode == SW_MODE_SINGLE)
    {
        ret = swReactorProcess_start(serv);
    }
    else
    {
        ret = swServer_start_proxy(serv);
    }

    if (ret < 0)
    {
        SwooleGS->start = 0;
    }

    swServer_free(serv);
    return SW_OK;
}

/**
 * initializing server config, set default
 */
void swServer_init(swServer *serv)
{
    swoole_init();
    bzero(serv, sizeof(swServer));

    serv->backlog = SW_BACKLOG;
    serv->factory_mode = SW_MODE_BASE;

    serv->reactor_num = SW_REACTOR_NUM > SW_REACTOR_MAX_THREAD ? SW_REACTOR_MAX_THREAD : SW_REACTOR_NUM;

    serv->dispatch_mode = SW_DISPATCH_FDMOD;
    serv->ringbuffer_size = SW_QUEUE_SIZE;

    serv->timeout_sec = SW_REACTOR_TIMEO_SEC;
    serv->timeout_usec = SW_REACTOR_TIMEO_USEC;  //300ms;

    serv->worker_num = SW_CPU_NUM;
    serv->max_connection = SwooleG.max_sockets;

    serv->max_request = 0;

    serv->open_tcp_nopush = 1;
    serv->http_parse_post = 1;

    //tcp keepalive
    serv->tcp_keepcount = SW_TCP_KEEPCOUNT;
    serv->tcp_keepinterval = SW_TCP_KEEPINTERVAL;
    serv->tcp_keepidle = SW_TCP_KEEPIDLE;

    //heartbeat check
    serv->heartbeat_idle_time = SW_HEARTBEAT_IDLE;
    serv->heartbeat_check_interval = SW_HEARTBEAT_CHECK;

    char eof[] = SW_DATA_EOF;
    serv->protocol.package_eof_len = sizeof(SW_DATA_EOF) - 1;
    serv->protocol.package_length_type = 'N';
    serv->protocol.package_length_size = 4;
    serv->protocol.package_body_offset = 0;

    serv->protocol.package_max_length = SW_BUFFER_INPUT_SIZE;

    serv->buffer_input_size = SW_BUFFER_INPUT_SIZE;
    serv->buffer_output_size = SW_BUFFER_OUTPUT_SIZE;

    serv->pipe_buffer_size = SW_PIPE_BUFFER_SIZE;

    memcpy(serv->protocol.package_eof, eof, serv->protocol.package_eof_len);
}

int swServer_create(swServer *serv)
{
    //EOF最大长度为8字节
    if (serv->protocol.package_eof_len > sizeof(serv->protocol.package_eof))
    {
        serv->protocol.package_eof_len = sizeof(serv->protocol.package_eof);
    }

    //初始化日志
    if (serv->log_file[0] != 0)
    {
        swLog_init(serv->log_file);
    }

    //保存指针到全局变量中去
    //TODO 未来全部使用此方式访问swServer/swFactory对象
    SwooleG.serv = serv;
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

    //单进程单线程模式
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
    swNotice("Server is shutdown now.");

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
        pthread_cancel(SwooleG.heartbeat_pidt);
        pthread_join(SwooleG.heartbeat_pidt, NULL);
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

    //reactor free
    if (serv->reactor.free != NULL)
    {
        serv->reactor.free(&(serv->reactor));
    }

#ifdef SW_USE_OPENSSL
    if (serv->open_ssl)
    {
        swSSL_free();
        free(serv->ssl_cert_file);
        free(serv->ssl_key_file);
    }
#endif

    //release connection_list
    if (serv->factory_mode == SW_MODE_SINGLE)
    {
        sw_free(serv->connection_list);
    }
    else
    {
        sw_shm_free(serv->connection_list);
    }
    //release session_list
    if (serv->session_list)
    {
        sw_shm_free(serv->session_list);
    }
    //close log file
    if (serv->log_file[0] != 0)
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

/**
 * only tcp
 */
static int swServer_send1(swServer *serv, swSendData *resp)
{
    return swWrite(resp->info.fd, resp->data, resp->info.len);
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

void swServer_pipe_set(swServer *serv, swPipe *p)
{
    int master_fd = p->getFd(p, SW_PIPE_MASTER);

    serv->connection_list[p->getFd(p, SW_PIPE_WORKER)].object = p;
    serv->connection_list[master_fd].object = p;

    if (master_fd > swServer_get_minfd(serv))
    {
        swServer_set_minfd(serv, master_fd);
    }
}

swPipe * swServer_pipe_get(swServer *serv, int pipe_fd)
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
        swWarn("More than the output buffer size[%d], please use the sendfile.", serv->buffer_output_size);
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

int swServer_tcp_sendwait(swServer *serv, int fd, void *data, uint32_t length)
{
    swConnection *conn = swServer_connection_verify(serv, fd);
    if (!conn)
    {
        swWarn("send %d byte failed, session#%d is closed.", length, fd);
        return SW_ERR;
    }
    return swSocket_write_blocking(conn->fd, data, length);
}

/**
 * for udp + tcp
 */
int swServer_send2(swServer *serv, swSendData *resp)
{
    int ret;

    //UDP
    if (resp->info.from_id >= serv->reactor_num)
    {
        ret = swServer_udp_send(serv, resp);
    }
    else
    {
        ret = swWrite(resp->info.fd, resp->data, resp->info.len);
    }
    if (ret < 0)
    {
        swWarn("[Writer]sendto client failed. errno=%d", errno);
    }
    return ret;
}

void swServer_signal_init(void)
{
    swSignal_add(SIGPIPE, NULL);
    swSignal_add(SIGHUP, NULL);
    swSignal_add(SIGCHLD, swServer_signal_hanlder);
    swSignal_add(SIGUSR1, swServer_signal_hanlder);
    swSignal_add(SIGUSR2, swServer_signal_hanlder);
    swSignal_add(SIGTERM, swServer_signal_hanlder);
    swSignal_add(SIGALRM, swTimer_signal_handler);
    //for test
    swSignal_add(SIGVTALRM, swServer_signal_hanlder);
    swServer_set_minfd(SwooleG.serv, SwooleG.signal_fd);
}

static int user_worker_list_i = 0;

int swServer_add_worker(swServer *serv, swWorker *worker)
{
    swUserWorker_node *user_worker = sw_malloc(sizeof(swUserWorker_node));
    if (!user_worker)
    {
        return SW_ERR;
    }

    worker->id = user_worker_list_i++;
    user_worker->worker = worker;

    LL_APPEND(serv->user_worker_list, user_worker);

    if (!serv->user_worker_map)
    {
        serv->user_worker_map = swHashMap_new(SW_HASHMAP_INIT_BUCKET_N, NULL);
    }

    return worker->id;
}

int swServer_add_listener(swServer *serv, int type, char *host, int port)
{
    if (serv->listen_port_num >= SW_MAX_LISTEN_PORT)
    {
        swWarn("allows up to %d ports to listen", SW_MAX_LISTEN_PORT);
        return SW_ERR;
    }

    if (!(type == SW_SOCK_UNIX_DGRAM || type == SW_SOCK_UNIX_STREAM) && (port < 1 || port > 65535))
    {
        swWarn("invalid port [%d]", port);
        return SW_ERR;
    }

    swListenPort *ls = SwooleG.memory_pool->alloc(SwooleG.memory_pool, sizeof(swListenPort));

    ls->type = type;
    ls->port = port;
    ls->sock = 0;
    ls->ssl = 0;

    bzero(ls->host, SW_HOST_MAXSIZE);
    strncpy(ls->host, host, SW_HOST_MAXSIZE);
    LL_APPEND(serv->listen_list, ls);

    //UDP需要提前创建好
    if (type == SW_SOCK_UDP || type == SW_SOCK_UDP6 || type == SW_SOCK_UNIX_DGRAM)
    {
        int sock = swSocket_listen(type, ls->host, port, serv->backlog);
        if (sock < 0)
        {
            return SW_ERR;
        }

        int bufsize = SwooleG.socket_buffer_size;
        setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
        setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));

        ls->sock = sock;
        ls->type = type;
        serv->have_udp_sock = 1;

        if (type == SW_SOCK_UDP)
        {
            serv->udp_socket_ipv4 = sock;
        }
        else if (type == SW_SOCK_UDP6)
        {
            serv->udp_socket_ipv6 = sock;
        }
    }
    else
    {
        if (type & SW_SOCK_SSL)
        {
            type = type & (~SW_SOCK_SSL);
            ls->type = type;
            ls->ssl = 1;
        }
        if (type != SW_SOCK_UNIX_STREAM && port <= 0)
        {
            swError("listen port must greater than 0.");
            return SW_ERR;
        }
        serv->have_tcp_sock = 1;
    }
    serv->listen_port_num++;
    return SW_OK;
}

/**
 * listen the TCP server socket
 * UDP ignore
 */
int swServer_listen(swServer *serv, swListenPort *ls)
{
    int sock = -1, sockopt;
    //UDP
    if (ls->type == SW_SOCK_UDP || ls->type == SW_SOCK_UDP6 || ls->type == SW_SOCK_UNIX_DGRAM)
    {
        return SW_OK;
    }

#ifdef SW_USE_OPENSSL
    if (ls->ssl)
    {
        if (!serv->ssl_cert_file)
        {
            swWarn("need to configure [server->ssl_cert_file].");
            return SW_ERR;
        }
        if (!serv->ssl_key_file)
        {
            swWarn("need to configure [server->ssl_key_file].");
            return SW_ERR;
        }
    }
#endif

    //TCP
    sock = swSocket_listen(ls->type, ls->host, ls->port, serv->backlog);
    if (sock < 0)
    {
        LL_DELETE(serv->listen_list, ls);
        return SW_ERR;
    }

#ifdef TCP_DEFER_ACCEPT
    if (serv->tcp_defer_accept)
    {
        if (setsockopt(sock, IPPROTO_TCP, TCP_DEFER_ACCEPT, (const void*) &serv->tcp_defer_accept, sizeof(int)) < 0)
        {
            swSysError("setsockopt(TCP_DEFER_ACCEPT) failed.");
        }
    }
#endif

#ifdef TCP_FASTOPEN
    if (serv->tcp_fastopen)
    {
        if (setsockopt(sock, IPPROTO_TCP, TCP_FASTOPEN, (const void*) &serv->tcp_fastopen, sizeof(int)) < 0)
        {
            swSysError("setsockopt(TCP_FASTOPEN) failed.");
        }
    }
#endif

#ifdef SO_KEEPALIVE
    if (serv->open_tcp_keepalive == 1)
    {
        sockopt = 1;
        if (setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (void *) &sockopt, sizeof(int)) < 0)
        {
            swSysError("setsockopt(SO_KEEPALIVE) failed.");
        }
#ifdef TCP_KEEPIDLE
        setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE, (void*) &serv->tcp_keepidle, sizeof(int));
        setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, (void *) &serv->tcp_keepinterval, sizeof(int));
        setsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT, (void *) &serv->tcp_keepcount, sizeof(int));
#endif
    }
#endif

    ls->sock = sock;
    //save server socket to connection_list
    serv->connection_list[sock].fd = sock;

    //IPv4
    if (ls->type == SW_SOCK_TCP)
    {
        serv->connection_list[sock].info.addr.inet_v4.sin_port = htons(ls->port);
    }
    //IPv6
    else
    {
        serv->connection_list[sock].info.addr.inet_v6.sin6_port = htons(ls->port);
    }
    //socket type
    serv->connection_list[sock].socket_type = ls->type;
    //save listen_host object
    serv->connection_list[sock].object = ls;

    if (sock >= 0)
    {
        swServer_set_minfd(serv, sock);
        swServer_set_maxfd(serv, sock);
    }
    return SW_OK;
}

int swServer_get_manager_pid(swServer *serv)
{
    if (SW_MODE_PROCESS != serv->factory_mode)
    {
        return SW_ERR;
    }
    return SwooleGS->manager_pid;
}

static void swServer_signal_hanlder(int sig)
{
    int status;
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
        break;
    case SIGALRM:
        swTimer_signal_handler(SIGALRM);
        break;
    case SIGCHLD:
        if (waitpid(SwooleGS->manager_pid, &status, WNOHANG) >= 0 && SwooleG.running > 0)
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
        break;
    }
}

void swHeartbeatThread_start(swServer *serv)
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
    swDataHead notify_ev;
    swFactory *factory = &serv->factory;
    swConnection *conn;
    swReactor *reactor;

    int fd;
    int serv_max_fd;
    int serv_min_fd;
    int checktime;

    SwooleTG.type = SW_THREAD_HEARTBEAT;

    bzero(&notify_ev, sizeof(notify_ev));
    notify_ev.type = SW_EVENT_CLOSE;

    while (SwooleG.running)
    {
        serv_max_fd = swServer_get_maxfd(serv);
        serv_min_fd = swServer_get_minfd(serv);

        checktime = (int) time(NULL) - serv->heartbeat_idle_time;

        //遍历到最大fd
        for (fd = serv_min_fd; fd <= serv_max_fd; fd++)
        {
            swTrace("check fd=%d", fd);
            conn = swServer_connection_get(serv, fd);

            if (conn != NULL && 1 == conn->active && conn->last_time < checktime)
            {
                notify_ev.fd = fd;
                notify_ev.from_id = conn->from_id;
                conn->close_force = 1;

                if (serv->factory_mode != SW_MODE_PROCESS)
                {
                    conn->close_notify = 1;
                    if (serv->factory_mode == SW_MODE_SINGLE)
                    {
                        reactor = SwooleG.main_reactor;
                    }
                    else
                    {
                        reactor = &serv->reactor_threads[conn->from_id].reactor;
                    }
                    reactor->set(reactor, fd, SW_FD_TCP | SW_EVENT_WRITE);
                }
                else if (serv->disable_notify)
                {
                    conn->close_wait = 1;
                    reactor = &serv->reactor_threads[conn->from_id].reactor;
                    reactor->set(reactor, fd, SW_FD_TCP | SW_EVENT_WRITE);
                }
                else
                {
                    factory->notify(&serv->factory, &notify_ev);
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
static swConnection* swServer_connection_new(swServer *serv, int fd, int from_fd, int reactor_id)
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
    if (serv->open_tcp_nodelay)
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
    if (serv->open_tcp_nopush)
    {
        connection->tcp_nopush = 1;
    }
#endif

    connection->fd = fd;
    connection->from_id = serv->factory_mode == SW_MODE_SINGLE ? SwooleWG.id : reactor_id;
    connection->from_fd = from_fd;
    connection->connect_time = SwooleGS->now;
    connection->last_time = SwooleGS->now;
    connection->active = 1;

#ifdef SW_REACTOR_SYNC_SEND
    if (serv->factory_mode != SW_MODE_THREAD)
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

