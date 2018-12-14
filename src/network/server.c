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
#include "http.h"
#include "connection.h"

static int swServer_start_check(swServer *serv);
static void swServer_signal_handler(int sig);
static void swServer_disable_accept(swReactor *reactor);
static void swServer_master_update_time(swServer *serv);

static swConnection* swServer_connection_new(swServer *serv, swListenPort *ls, int fd, int from_fd, int reactor_id);

swServerG SwooleG;
swWorkerG SwooleWG;
__thread swThreadG SwooleTG;

int16_t sw_errno;
char sw_error[SW_ERROR_MSG_SIZE];

static void swServer_disable_accept(swReactor *reactor)
{
    swListenPort *ls;
    swServer *serv = reactor->ptr;

    LL_FOREACH(serv->listen_list, ls)
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
    swServer *serv = reactor->ptr;

    LL_FOREACH(serv->listen_list, ls)
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
    swListenPort *listen_host = serv->connection_list[event->fd].object;

    int new_fd = 0, reactor_id = 0, i;

    //SW_ACCEPT_AGAIN
    for (i = 0; i < SW_ACCEPT_MAX_COUNT; i++)
    {
        new_fd = swSocket_accept(event->fd, &client_addr);
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

        swTrace("[Master] Accept new connection. maxfd=%d|reactor_id=%d|conn=%d", swServer_get_maxfd(serv), reactor->id, new_fd);

        //too many connection
        if (new_fd >= serv->max_connection)
        {
            swoole_error_log(SW_LOG_WARNING, SW_ERROR_SERVER_TOO_MANY_SOCKET, "Too many connections [now: %d].", new_fd);
            close(new_fd);
            return SW_OK;
        }

        if (serv->factory_mode == SW_MODE_BASE)
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
        conn->connect_notify = 1;
        if (sub_reactor->add(sub_reactor, new_fd, SW_FD_TCP | SW_EVENT_WRITE) < 0)
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
    //stream
    if (serv->have_stream_sock && serv->onReceive == NULL)
    {
        swWarn("onReceive event callback must be set.");
        return SW_ERR;
    }
    //dgram
    if (serv->have_dgram_sock && serv->onPacket == NULL)
    {
        swWarn("onPacket event callback must be set.");
        return SW_ERR;
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
    if (serv->task_worker_num > 0)
    {
        if (serv->onTask == NULL)
        {
            swWarn("onTask event callback must be set.");
            return SW_ERR;
        }
        if (serv->task_worker_num > SW_CPU_NUM * SW_MAX_WORKER_NCPU)
        {
            swWarn("serv->task_worker_num > %d, Too many processes, the system will be slow", SW_CPU_NUM * SW_MAX_WORKER_NCPU);
            serv->task_worker_num = SW_CPU_NUM * SW_MAX_WORKER_NCPU;
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
    // max connections
    uint32_t minimum_connection = (serv->worker_num + serv->task_worker_num) * 2 + 32;
    if (serv->max_connection < minimum_connection)
    {
        serv->max_connection = SwooleG.max_sockets;
        swWarn("serv->max_connection must be bigger than %u, it's reset to %u", minimum_connection, SwooleG.max_sockets);
    }
    else if (SwooleG.max_sockets > 0 && serv->max_connection > SwooleG.max_sockets)
    {
        serv->max_connection = SwooleG.max_sockets;
        swWarn("serv->max_connection is exceed the maximum value, it's reset to %u.", SwooleG.max_sockets);
    }
    else if (serv->max_connection > SW_SESSION_LIST_SIZE)
    {
        serv->max_connection = SW_SESSION_LIST_SIZE;
        swWarn("serv->max_connection is exceed the SW_SESSION_LIST_SIZE, it's reset to %u.", SW_SESSION_LIST_SIZE);
    }
    // package max length
    swListenPort *ls;
    LL_FOREACH(serv->listen_list, ls)
    {
        if (ls->protocol.package_max_length < SW_BUFFER_MIN_SIZE)
        {
            ls->protocol.package_max_length = SW_BUFFER_MIN_SIZE;
        }
    }

#ifdef SW_USE_OPENSSL
    /**
     * OpenSSL thread-safe
     */
    if (serv->factory_mode != SW_MODE_BASE)
    {
        swSSL_init_thread_safety();
    }
#endif

    return SW_OK;
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
                serv->udp_socket_ipv6 = sockfd;
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
    int buffer_num;

    if (serv->factory_mode == SW_MODE_BASE)
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
        buffers[i] = swString_new(SW_BUFFER_SIZE_BIG);
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
    int ipc_mode;

    if (serv->task_ipc_mode == SW_TASK_IPC_MSGQUEUE || serv->task_ipc_mode == SW_TASK_IPC_PREEMPTIVE)
    {
        key = serv->message_queue_key;
        ipc_mode = SW_IPC_MSGQUEUE;
    }
    else if (serv->task_ipc_mode == SW_TASK_IPC_STREAM)
    {
        ipc_mode = SW_IPC_SOCKET;
    }
    else
    {
        ipc_mode = SW_IPC_UNIXSOCK;
    }

    if (swProcessPool_create(&serv->gs->task_workers, serv->task_worker_num, serv->task_max_request, key, ipc_mode) < 0)
    {
        swWarn("[Master] create task_workers failed.");
        return SW_ERR;
    }
    if (ipc_mode == SW_IPC_SOCKET)
    {
        char sockfile[sizeof(struct sockaddr_un)];
        snprintf(sockfile, sizeof(sockfile), "/tmp/swoole.task.%d.sock", serv->gs->master_pid);
        if (swProcessPool_create_unix_socket(&serv->gs->task_workers, sockfile, 2048) < 0)
        {
            return SW_ERR;
        }
    }
    return SW_OK;
}

/**
 * [Master]
 */
int swServer_worker_create(swServer *serv, swWorker *worker)
{
    /**
     * Create shared memory storage
     */
    worker->send_shm = sw_shm_malloc(serv->buffer_output_size);
    if (worker->send_shm == NULL)
    {
        swWarn("malloc for worker->store failed.");
        return SW_ERR;
    }
    swMutex_create(&worker->lock, 1);

    return SW_OK;
}

/**
 * [Worker]
 */
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
#ifdef __FreeBSD__
        if (cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_PID, -1,
                                sizeof(cpu_set), &cpu_set) < 0)
#else
        if (sched_setaffinity(getpid(), sizeof(cpu_set), &cpu_set) < 0)
#endif
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
            int n = swoole_system_random(1, SwooleWG.max_request / 2);
            if (n > 0)
            {
                SwooleWG.max_request += n;
            }
        }
    }

    worker->start_time = serv->gs->now;
    worker->request_time = 0;
    worker->request_count = 0;

    return SW_OK;
}

void swServer_worker_start(swServer *serv, swWorker *worker)
{
    void *hook_args[2];
    hook_args[0] = serv;
    hook_args[1] = (void *) (uintptr_t) worker->id;

    if (SwooleG.hooks[SW_GLOBAL_HOOK_BEFORE_WORKER_START])
    {
        swoole_call_hook(SW_GLOBAL_HOOK_BEFORE_WORKER_START, hook_args);
    }
    if (serv->hooks[SW_SERVER_HOOK_WORKER_START])
    {
        swServer_call_hook(serv, SW_SERVER_HOOK_WORKER_START, hook_args);
    }
    if (serv->onWorkerStart)
    {
        serv->onWorkerStart(serv, worker->id);
    }
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
    if (SwooleG.hooks[SW_GLOBAL_HOOK_BEFORE_SERVER_START])
    {
        swoole_call_hook(SW_GLOBAL_HOOK_BEFORE_SERVER_START, serv);
    }
    //cann't start 2 servers at the same time, please use process->exec.
    if (!sw_atomic_cmp_set(&serv->gs->start, 0, 1))
    {
        swoole_error_log(SW_LOG_ERROR, SW_ERROR_SERVER_ONLY_START_ONE, "must only start one server.");
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
    serv->gs->master_pid = getpid();
    serv->gs->now = serv->stats->start_time = time(NULL);

    if (serv->dispatch_mode == SW_DISPATCH_STREAM)
    {
        serv->stream_socket = swoole_string_format(64, "/tmp/swoole.%d.sock", serv->gs->master_pid);
        if (serv->stream_socket == NULL)
        {
            return SW_ERR;
        }
        int _reuse_port = SwooleG.reuse_port;
        SwooleG.reuse_port = 0;
        serv->stream_fd = swSocket_create_server(SW_SOCK_UNIX_STREAM, serv->stream_socket, 0, 2048);
        if (serv->stream_fd < 0)
        {
            return SW_ERR;
        }
        swoole_fcntl_set_option(serv->stream_fd, 1, 1);
        SwooleG.reuse_port = _reuse_port;
    }

    serv->send = swServer_tcp_send;
    serv->sendwait = swServer_tcp_sendwait;
    serv->sendfile = swServer_tcp_sendfile;
    serv->close = swServer_tcp_close;

    serv->workers = SwooleG.memory_pool->alloc(SwooleG.memory_pool, serv->worker_num * sizeof(swWorker));
    if (serv->workers == NULL)
    {
        swoole_error_log(SW_LOG_ERROR, SW_ERROR_SYSTEM_CALL_FAIL, "gmalloc[server->workers] failed.");
        return SW_ERR;
    }

    /**
     * store to swProcessPool object
     */
    serv->gs->event_workers.ptr = serv;
    serv->gs->event_workers.workers = serv->workers;
    serv->gs->event_workers.worker_num = serv->worker_num;
    serv->gs->event_workers.use_msgqueue = 0;

    int i;
    for (i = 0; i < serv->worker_num; i++)
    {
        serv->gs->event_workers.workers[i].pool = &serv->gs->event_workers;
        serv->gs->event_workers.workers[i].id = i;
        serv->gs->event_workers.workers[i].type = SW_PROCESS_WORKER;
    }

    /*
     * For swoole_server->taskwait, create notify pipe and result shared memory.
     */
    if (serv->task_worker_num > 0 && serv->worker_num > 0)
    {
        serv->task_result = sw_shm_calloc(serv->worker_num, sizeof(swEventData));
        serv->task_notify = sw_calloc(serv->worker_num, sizeof(swPipe));
        for (i = 0; i < serv->worker_num; i++)
        {
            if (swPipeNotify_auto(&serv->task_notify[i], 1, 0))
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
            user_worker->worker->id = serv->worker_num + serv->task_worker_num + i;
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
        ret = snprintf(SwooleTG.buffer_stack->str, SwooleTG.buffer_stack->size, "%d", getpid());
        swoole_file_put_contents(serv->pid_file, SwooleTG.buffer_stack->str, ret);
    }
    if (serv->factory_mode == SW_MODE_BASE)
    {
        ret = swReactorProcess_start(serv);
    }
    else
    {
        ret = swReactorThread_start(serv);
    }
    swServer_free(serv);
    serv->gs->start = 0;
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

    serv->worker_num = SW_CPU_NUM;
    serv->max_connection = MIN(SW_MAX_CONNECTION, SwooleG.max_sockets);

    serv->max_request = 0;
    serv->max_wait_time = SW_WORKER_MAX_WAIT_TIME;

    //http server
    serv->http_parse_post = 1;
    serv->http_compression = 1;
    serv->http_compression_level = 1; // Z_BEST_SPEED
    serv->upload_tmp_dir = sw_strdup("/tmp");

    //heartbeat check
    serv->heartbeat_idle_time = SW_HEARTBEAT_IDLE;
    serv->heartbeat_check_interval = SW_HEARTBEAT_CHECK;

    serv->buffer_input_size = SW_BUFFER_INPUT_SIZE;
    serv->buffer_output_size = SW_BUFFER_OUTPUT_SIZE;

    serv->task_ipc_mode = SW_TASK_IPC_UNIXSOCK;

    /**
     * alloc shared memory
     */
    serv->stats = SwooleG.memory_pool->alloc(SwooleG.memory_pool, sizeof(swServerStats));
    if (serv->stats == NULL)
    {
        swError("[Master] Fatal Error: failed to allocate memory for swServer->stats.");
    }
    serv->gs = SwooleG.memory_pool->alloc(SwooleG.memory_pool, sizeof(swServerGS));
    if (serv->gs == NULL)
    {
        swError("[Master] Fatal Error: failed to allocate memory for swServer->gs.");
    }

    SwooleG.serv = serv;
}

int swServer_create(swServer *serv)
{
    if (SwooleG.main_reactor)
    {
        swoole_error_log(SW_LOG_ERROR, SW_ERROR_SERVER_MUST_CREATED_BEFORE_CLIENT, "The swoole_server must create before client");
        return SW_ERR;
    }

    serv->factory.ptr = serv;
    /**
     * init current time
     */
    swServer_master_update_time(serv);

    serv->session_list = sw_shm_calloc(SW_SESSION_LIST_SIZE, sizeof(swSession));
    if (serv->session_list == NULL)
    {
        swError("sw_shm_calloc(%ld) for session_list failed", SW_SESSION_LIST_SIZE * sizeof(swSession));
        return SW_ERR;
    }

    if (serv->factory_mode == SW_MODE_BASE)
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
    swTraceLog(SW_TRACE_SERVER, "release service.");

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
    if (serv->heartbeat_pidt)
    {
        swTraceLog(SW_TRACE_SERVER, "terminate heartbeat thread.");
        if (pthread_cancel(serv->heartbeat_pidt) < 0)
        {
            swSysError("pthread_cancel(%ld) failed.", (ulong_t )serv->heartbeat_pidt);
        }
        //wait thread
        if (pthread_join(serv->heartbeat_pidt, NULL) < 0)
        {
            swSysError("pthread_join(%ld) failed.", (ulong_t )serv->heartbeat_pidt);
        }
    }
    if (serv->factory_mode == SW_MODE_BASE)
    {
        swTraceLog(SW_TRACE_SERVER, "terminate task workers.");
        if (serv->task_worker_num > 0)
        {
            swProcessPool_shutdown(&serv->gs->task_workers);
        }
    }
    else
    {
        swTraceLog(SW_TRACE_SERVER, "terminate reactor threads.");
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
    if (serv->stream_socket)
    {
        unlink(serv->stream_socket);
        sw_free(serv->stream_socket);
    }
    if (serv->gs->start > 0 && serv->onShutdown != NULL)
    {
        serv->onShutdown(serv);
    }
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

/**
 * worker to master process
 */
int swServer_tcp_feedback(swServer *serv, int fd, int event)
{
    swConnection *conn = swServer_connection_verify(serv, fd);
    if (!conn)
    {
        return SW_ERR;
    }

    if (event == SW_EVENT_CONFIRM && !conn->listen_wait)
    {
        return SW_ERR;
    }

    swSendData _send;
    bzero(&_send, sizeof(_send));
    _send.info.type = event;
    _send.info.fd = fd;
    _send.info.from_id = conn->from_id;

    if (serv->factory_mode == SW_MODE_PROCESS)
    {
        return swWorker_send2reactor(serv, (swEventData *) &_send.info, sizeof(_send.info), fd);
    }
    else
    {
        return swServer_master_send(serv, &_send);
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

swPipe * swServer_get_pipe_object(swServer *serv, int pipe_fd)
{
    return (swPipe *) serv->connection_list[pipe_fd].object;
}

/**
 * [Worker]
 */
int swServer_tcp_send(swServer *serv, int fd, void *data, uint32_t length)
{
    swSendData _send;
    swFactory *factory = &(serv->factory);

    if (unlikely(swIsMaster()))
    {
        swoole_error_log(SW_LOG_ERROR, SW_ERROR_SERVER_SEND_IN_MASTER,
                "can't send data to the connections in master process.");
        return SW_ERR;
    }

    /**
     * More than the output buffer
     */
    if (length > serv->buffer_output_size)
    {
        swoole_error_log(SW_LOG_WARNING, SW_ERROR_DATA_LENGTH_TOO_LARGE, "More than the output buffer size[%d], please use the sendfile.", serv->buffer_output_size);
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
        return factory->finish(factory, &_send) < 0 ? SW_ERR : SW_OK;
    }
}

/**
 * [Master] send to client or append to out_buffer
 */
int swServer_master_send(swServer *serv, swSendData *_send)
{
    uint32_t session_id = _send->info.fd;
    void *_send_data = _send->data;
    uint32_t _send_length = _send->length;

    swConnection *conn;
    if (_send->info.type != SW_EVENT_CLOSE)
    {
        conn = swServer_connection_verify(serv, session_id);
    }
    else
    {
        conn = swServer_connection_verify_no_ssl(serv, session_id);
    }
    if (!conn)
    {
        if (_send->info.type == SW_EVENT_TCP)
        {
            swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SESSION_NOT_EXIST, "send %d byte failed, session#%d does not exist.", _send_length, session_id);
        }
        else
        {
            swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SESSION_NOT_EXIST, "send event$[%d] failed, session#%d does not exist.", _send->info.type, session_id);
        }
        return SW_ERR;
    }

    int fd = conn->fd;
    swReactor *reactor;

    if (serv->factory_mode == SW_MODE_BASE)
    {
        reactor = &(serv->reactor_threads[0].reactor);
        if (conn->overflow)
        {
            if (serv->send_yield)
            {
                SwooleG.error = SW_ERROR_OUTPUT_BUFFER_OVERFLOW;
            }
            else
            {
                swoole_error_log(SW_LOG_WARNING, SW_ERROR_OUTPUT_BUFFER_OVERFLOW, "connection#%d output buffer overflow.", fd);
            }
            return SW_ERR;
        }
    }
    else
    {
        reactor = &(serv->reactor_threads[conn->from_id].reactor);
        assert(fd % serv->reactor_num == reactor->id);
        assert(fd % serv->reactor_num == SwooleTG.id);
    }

    /**
     * Reset send buffer, Immediately close the connection.
     */
    if (_send->info.type == SW_EVENT_CLOSE && (conn->close_reset || conn->removed))
    {
        goto close_fd;
    }
    else if (_send->info.type == SW_EVENT_CONFIRM)
    {
        reactor->add(reactor, conn->fd, conn->fdtype | SW_EVENT_READ);
        conn->listen_wait = 0;
        return SW_OK;
    }
    /**
     * pause recv data
     */
    else if (_send->info.type == SW_EVENT_PAUSE_RECV)
    {
        if (conn->events & SW_EVENT_WRITE)
        {
            return reactor->set(reactor, conn->fd, conn->fdtype | SW_EVENT_WRITE);
        }
        else
        {
            return reactor->del(reactor, conn->fd);
        }
    }
    /**
     * resume recv data
     */
    else if (_send->info.type == SW_EVENT_RESUME_RECV)
    {
        if (conn->events & SW_EVENT_WRITE)
        {
            return reactor->set(reactor, conn->fd, conn->fdtype | SW_EVENT_READ | SW_EVENT_WRITE);
        }
        else
        {
            return reactor->add(reactor, conn->fd, conn->fdtype | SW_EVENT_READ);
        }
    }

    if (swBuffer_empty(conn->out_buffer))
    {
        /**
         * close connection.
         */
        if (_send->info.type == SW_EVENT_CLOSE)
        {
            close_fd:
            reactor->close(reactor, fd);
            return SW_OK;
        }
#ifdef SW_REACTOR_SYNC_SEND
        //Direct send
        if (_send->info.type != SW_EVENT_SENDFILE)
        {
            if (!conn->direct_send)
            {
                goto buffer_send;
            }

            int n;

            direct_send:
            n = swConnection_send(conn, _send_data, _send_length, 0);
            if (n == _send_length)
            {
                return SW_OK;
            }
            else if (n > 0)
            {
                _send_data += n;
                _send_length -= n;
                goto buffer_send;
            }
            else if (errno == EINTR)
            {
                goto direct_send;
            }
            else
            {
                goto buffer_send;
            }
        }
#endif
        //buffer send
        else
        {
#ifdef SW_REACTOR_SYNC_SEND
            buffer_send:
#endif
            if (!conn->out_buffer)
            {
                conn->out_buffer = swBuffer_new(SW_BUFFER_SIZE);
                if (conn->out_buffer == NULL)
                {
                    return SW_ERR;
                }
            }
        }
    }

    swBuffer_chunk *chunk;
    //close connection
    if (_send->info.type == SW_EVENT_CLOSE)
    {
        chunk = swBuffer_new_chunk(conn->out_buffer, SW_CHUNK_CLOSE, 0);
        chunk->store.data.val1 = _send->info.type;
        conn->close_queued = 1;
    }
    //sendfile to client
    else if (_send->info.type == SW_EVENT_SENDFILE)
    {
        swSendFile_request *req = (swSendFile_request *) _send_data;
        swConnection_sendfile(conn, req->filename, req->offset, req->length);
    }
    //send data
    else
    {
        //connection is closed
        if (conn->removed)
        {
            swWarn("connection#%d is closed by client.", fd);
            return SW_ERR;
        }
        //connection output buffer overflow
        if (conn->out_buffer->length >= conn->buffer_size)
        {
            if (serv->send_yield)
            {
                SwooleG.error = SW_ERROR_OUTPUT_BUFFER_OVERFLOW;
            }
            else
            {
                swoole_error_log(SW_LOG_WARNING, SW_ERROR_OUTPUT_BUFFER_OVERFLOW, "connection#%d output buffer overflow.", fd);
            }
            conn->overflow = 1;
            if (serv->onBufferEmpty && serv->onBufferFull == NULL)
            {
                conn->high_watermark = 1;
            }
        }

        int _length = _send_length;
        void* _pos = _send_data;
        int _n;

        //buffer enQueue
        while (_length > 0)
        {
            _n = _length >= SW_BUFFER_SIZE_BIG ? SW_BUFFER_SIZE_BIG : _length;
            swBuffer_append(conn->out_buffer, _pos, _n);
            _pos += _n;
            _length -= _n;
        }

        swListenPort *port = swServer_get_port(serv, fd);
        if (serv->onBufferFull && conn->high_watermark == 0 && conn->out_buffer->length >= port->buffer_high_watermark)
        {
            swServer_tcp_notify(serv, conn, SW_EVENT_BUFFER_FULL);
            conn->high_watermark = 1;
        }
    }

    //listen EPOLLOUT event
    if (reactor->set(reactor, fd, SW_EVENT_TCP | SW_EVENT_WRITE | SW_EVENT_READ) < 0
            && (errno == EBADF || errno == ENOENT))
    {
        goto close_fd;
    }

    return SW_OK;
}

/**
 * use in master process
 */
int swServer_tcp_notify(swServer *serv, swConnection *conn, int event)
{
    swDataHead notify_event;
    notify_event.type = event;
    notify_event.from_id = conn->from_id;
    notify_event.fd = conn->fd;
    notify_event.from_fd = conn->from_fd;
    notify_event.len = 0;
    return serv->factory.notify(&serv->factory, &notify_event);
}

int swServer_tcp_sendfile(swServer *serv, int session_id, char *filename, uint32_t filename_length, off_t offset, size_t length)
{
    if (session_id <= 0 || session_id > SW_MAX_SESSION_ID)
    {
        swoole_error_log(SW_LOG_WARNING, SW_ERROR_SESSION_INVALID_ID, "invalid fd[%d].", session_id);
        return SW_ERR;
    }

    if (unlikely(swIsMaster()))
    {
        swoole_error_log(SW_LOG_ERROR, SW_ERROR_SERVER_SEND_IN_MASTER,
                "can't send data to the connections in master process.");
        return SW_ERR;
    }

    struct stat file_stat;
    if (stat(filename, &file_stat) < 0)
    {
        swoole_error_log(SW_LOG_WARNING, SW_ERROR_SYSTEM_CALL_FAIL, "stat(%s) failed.", filename);
        return SW_ERR;
    }
    if (file_stat.st_size <= offset)
    {
        swoole_error_log(SW_LOG_WARNING, SW_ERROR_SYSTEM_CALL_FAIL, "file[offset=%ld] is empty.", (long)offset);
        return SW_ERR;
    }

    swSendData send_data;
    char _buffer[SW_BUFFER_SIZE];
    swSendFile_request *req = (swSendFile_request*) _buffer;

    //file name size
    if (filename_length > SW_BUFFER_SIZE - sizeof(swSendFile_request) - 1)
    {
        swoole_error_log(SW_LOG_WARNING, SW_ERROR_NAME_TOO_LONG, "sendfile name too long. [MAX_LENGTH=%d]",
                (int) (SW_BUFFER_SIZE - sizeof(swSendFile_request) - 1));
        return SW_ERR;
    }

    req->offset = offset;
    req->length = length;
    strncpy(req->filename, filename, filename_length);
    req->filename[filename_length] = 0;

    send_data.info.fd = session_id;
    send_data.info.type = SW_EVENT_SENDFILE;
    send_data.info.len = sizeof(swSendFile_request) + filename_length + 1;
    send_data.length = 0;
    send_data.data = _buffer;

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

SW_API void swServer_call_hook(swServer *serv, enum swServer_hook_type type, void *arg)
{
    swLinkedList *hooks = serv->hooks[type];
    swLinkedList_node *node = hooks->head;
    swCallback func = NULL;

    while (node)
    {
        func = node->data;
        func(arg);
        node = node->next;
    }
}

int swServer_tcp_close(swServer *serv, int fd, int reset)
{
    if (unlikely(swIsMaster()))
    {
        swoole_error_log(SW_LOG_ERROR, SW_ERROR_SERVER_SEND_IN_MASTER,
                "can't close the connections in master process.");
        return SW_ERR;
    }
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
    //server is initiative to close the connection
    conn->close_actively = 1;
    swTraceLog(SW_TRACE_CLOSE, "session_id=%d, fd=%d.", fd, conn->fd);

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
    if (serv->factory_mode == SW_MODE_PROCESS)
    {
        swSignal_add(SIGCHLD, swServer_signal_handler);
    }
    swSignal_add(SIGUSR1, swServer_signal_handler);
    swSignal_add(SIGUSR2, swServer_signal_handler);
    swSignal_add(SIGTERM, swServer_signal_handler);
#ifdef SIGRTMIN
    swSignal_add(SIGRTMIN, swServer_signal_handler);
#endif
    swSignal_add(SIGALRM, swSystemTimer_signal_handler);
    //for test
    swSignal_add(SIGVTALRM, swServer_signal_handler);
    swServer_set_minfd(SwooleG.serv, SwooleG.signal_fd);
}

void swServer_master_onTimer(swTimer *timer, swTimer_node *tnode)
{
    swServer *serv = (swServer *) tnode->data;
    swServer_master_update_time(serv);
    if (serv->scheduler_warning && serv->warning_time < serv->gs->now)
    {
        serv->scheduler_warning = 0;
        serv->warning_time = serv->gs->now;
        swoole_error_log(SW_LOG_WARNING, SW_ERROR_SERVER_NO_IDLE_WORKER, "No idle worker is available.");
    }

    if (serv->hooks[SW_SERVER_HOOK_MASTER_TIMER])
    {
        swServer_call_hook(serv, SW_SERVER_HOOK_MASTER_TIMER, serv);
    }
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

static void swServer_master_update_time(swServer *serv)
{
    time_t now = time(NULL);
    if (now < 0)
    {
        swWarn("get time failed. Error: %s[%d]", strerror(errno), errno);
    }
    else
    {
        serv->gs->now = now;
    }
}

SW_API int swServer_add_hook(swServer *serv, enum swServer_hook_type type, swCallback func, int push_back)
{
    if (serv->hooks[type] == NULL)
    {
        serv->hooks[type] = swLinkedList_new(0, NULL);
        if (serv->hooks[type] == NULL)
        {
            return SW_ERR;
        }
    }
    if (push_back)
    {
        return swLinkedList_append(serv->hooks[type], func);
    }
    else
    {
        return swLinkedList_prepend(serv->hooks[type], func);
    }
}

/**
 * Return the number of ports successfully
 */
int swserver_add_systemd_socket(swServer *serv)
{
    char *e = getenv("LISTEN_PID");
    if (!e)
    {
        return 0;
    }

    int pid = atoi(e);
    if (getpid() != pid)
    {
        swWarn("invalid LISTEN_PID.");
        return 0;
    }

    e = getenv("LISTEN_FDS");
    if (!e)
    {
        return 0;
    }
    int n = atoi(e);
    if (n < 1)
    {
        swWarn("invalid LISTEN_FDS.");
        return 0;
    }
    else if (n >= SW_MAX_LISTEN_PORT)
    {
        swoole_error_log(SW_LOG_ERROR, SW_ERROR_SERVER_TOO_MANY_LISTEN_PORT, "LISTEN_FDS is too big.");
        return 0;
    }

    int count = 0;
    int sock, val;
    socklen_t optlen;
    swSocketAddress address;
    int sock_type, sock_family;
    char tmp[INET6_ADDRSTRLEN];

    for (sock = SW_SYSTEMD_FDS_START; sock < SW_SYSTEMD_FDS_START + n; sock++)
    {
        swListenPort *ls = SwooleG.memory_pool->alloc(SwooleG.memory_pool, sizeof(swListenPort));
        if (ls == NULL)
        {
            swWarn("alloc failed.");
            return count;
        }
        //get socket type
        optlen = sizeof(val);
        if (getsockopt(sock, SOL_SOCKET, SO_TYPE, &val, &optlen) < 0)
        {
            swWarn("getsockopt(%d, SOL_SOCKET, SO_TYPE) failed.", sock);
            return count;
        }
        sock_type = val;
        //get socket family
#ifndef SO_DOMAIN
        swWarn("no getsockopt(SO_DOMAIN) supports.");
        return count;
#else
        optlen = sizeof(val);
        if (getsockopt(sock, SOL_SOCKET, SO_DOMAIN, &val, &optlen) < 0)
        {
            swWarn("getsockopt(%d, SOL_SOCKET, SO_DOMAIN) failed.", sock);
            return count;
        }
#endif
        sock_family = val;
        //get address info
        address.len = sizeof(address.addr);
        if (getsockname(sock, (struct sockaddr*) &address.addr, &address.len) < 0)
        {
            swWarn("getsockname(%d) failed.", sock);
            return count;
        }

        swPort_init(ls);
        bzero(ls->host, SW_HOST_MAXSIZE);

        switch (sock_family)
        {
        case AF_INET:
            if (sock_type == SOCK_STREAM)
            {
                ls->type = SW_SOCK_TCP;
                ls->port = ntohs(address.addr.inet_v4.sin_port);
                strncpy(ls->host, inet_ntoa(address.addr.inet_v4.sin_addr), SW_HOST_MAXSIZE - 1);
            }
            else
            {
                ls->type = SW_SOCK_UDP;
                ls->port = ntohs(address.addr.inet_v4.sin_port);
                strncpy(ls->host, inet_ntoa(address.addr.inet_v4.sin_addr), SW_HOST_MAXSIZE - 1);
            }
            break;
        case AF_INET6:
            if (sock_type == SOCK_STREAM)
            {
                ls->port = ntohs(address.addr.inet_v6.sin6_port);
                ls->type = SW_SOCK_TCP6;
                inet_ntop(AF_INET6, &address.addr.inet_v6.sin6_addr, tmp, sizeof(tmp));
                strncpy(ls->host, tmp, SW_HOST_MAXSIZE - 1);
            }
            else
            {
                ls->port = ntohs(address.addr.inet_v6.sin6_port);
                ls->type = SW_SOCK_UDP6;
                inet_ntop(AF_INET6, &address.addr.inet_v6.sin6_addr, tmp, sizeof(tmp));
                strncpy(ls->host, tmp, SW_HOST_MAXSIZE - 1);
            }
            break;
        case AF_UNIX:
            ls->type = sock_type == SOCK_STREAM ? SW_SOCK_UNIX_STREAM : SW_SOCK_UNIX_DGRAM;
            ls->port = 0;
            strncpy(ls->host, address.addr.un.sun_path, SW_HOST_MAXSIZE - 1);
            break;
        default:
            swWarn("Unknown socket type[%d].", sock_type);
            break;
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
            serv->have_dgram_sock = 1;
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
            serv->have_stream_sock = 1;
        }

        LL_APPEND(serv->listen_list, ls);
        serv->listen_port_num++;
        count++;
    }
    return count;
}

swListenPort* swServer_add_port(swServer *serv, int type, const char *host, int port)
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
    if (strlen(host) + 1  > SW_HOST_MAXSIZE)
    {
        swoole_error_log(SW_LOG_ERROR, SW_ERROR_NAME_TOO_LONG, "address '%s' exceeds %d characters limit", host, SW_HOST_MAXSIZE - 1);
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
    strncpy(ls->host, host, strlen(host) + 1);

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
            ls->ssl_config.ciphers = sw_strdup(SW_SSL_CIPHER_LIST);
            ls->ssl_config.ecdh_curve = sw_strdup(SW_SSL_ECDH_CURVE);
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
        serv->have_dgram_sock = 1;
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
        serv->have_stream_sock = 1;
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
    return serv->gs->manager_pid;
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

static void swServer_signal_handler(int sig)
{
    swTraceLog(SW_TRACE_SERVER, "signal[%d] triggered.", sig);

    swServer *serv = SwooleG.serv;
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
        if (SwooleG.serv->factory_mode == SW_MODE_BASE)
        {
            break;
        }
        pid = waitpid(-1, &status, WNOHANG);
        if (pid > 0 && pid == serv->gs->manager_pid)
        {
            swWarn("Fatal Error: manager process exit. status=%d, signal=[%s].", WEXITSTATUS(status), swSignal_str(WTERMSIG(status)));
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
        if (SwooleG.serv->factory_mode == SW_MODE_BASE)
        {
            if (serv->gs->event_workers.reloading)
            {
                break;
            }
            serv->gs->event_workers.reloading = 1;
            serv->gs->event_workers.reload_init = 0;
        }
        else
        {
            kill(serv->gs->manager_pid, sig);
        }
        break;
    default:
#ifdef SIGRTMIN
        if (sig == SIGRTMIN)
        {
            int i;
            swWorker *worker;
            for (i = 0; i < SwooleG.serv->worker_num + serv->task_worker_num + SwooleG.serv->user_worker_num; i++)
            {
                worker = swServer_get_worker(SwooleG.serv, i);
                kill(worker->pid, SIGRTMIN);
            }
            if (SwooleG.serv->factory_mode == SW_MODE_PROCESS)
            {
                kill(serv->gs->manager_pid, SIGRTMIN);
            }
            swServer_reopen_log_file(SwooleG.serv);
        }
#endif
        break;
    }
}

/**
 * new connection
 */
static swConnection* swServer_connection_new(swServer *serv, swListenPort *ls, int fd, int from_fd, int reactor_id)
{
    swConnection* connection = NULL;

    serv->stats->accept_count++;
    sw_atomic_fetch_add(&serv->stats->connection_num, 1);
    sw_atomic_fetch_add(&ls->connection_num, 1);

    if (fd > swServer_get_maxfd(serv))
    {
        swServer_set_maxfd(serv, fd);
    }

    connection = &(serv->connection_list[fd]);
    bzero(connection, sizeof(swConnection));

    //TCP Nodelay
    if (ls->open_tcp_nodelay && ls->type != SW_SOCK_UNIX_STREAM)
    {
        int sockopt = 1;
        if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &sockopt, sizeof(sockopt)) < 0)
        {
            swSysError("setsockopt(TCP_NODELAY) failed.");
        }
        connection->tcp_nodelay = 1;
    }

    //socket recv buffer size
    if (ls->kernel_socket_recv_buffer_size > 0)
    {
        if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &ls->kernel_socket_recv_buffer_size, sizeof(int)))
        {
            swSysError("setsockopt(SO_RCVBUF, %d) failed.", ls->kernel_socket_recv_buffer_size);
        }
    }

    //socket send buffer size
    if (ls->kernel_socket_send_buffer_size > 0)
    {
        if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &ls->kernel_socket_send_buffer_size, sizeof(int)) < 0)
        {
            swSysError("setsockopt(SO_SNDBUF, %d) failed.", ls->kernel_socket_send_buffer_size);
        }
    }

    connection->fd = fd;
    connection->from_id = serv->factory_mode == SW_MODE_BASE ? SwooleWG.id : reactor_id;
    connection->from_fd = (sw_atomic_t) from_fd;
    connection->connect_time = serv->gs->now;
    connection->last_time = serv->gs->now;
    connection->active = 1;
    connection->buffer_size = ls->socket_buffer_size;

#ifdef SW_REACTOR_SYNC_SEND
    if (!ls->ssl)
    {
        connection->direct_send = 1;
    }
#endif

    swSession *session;
    sw_spinlock(&serv->gs->spinlock);
    int i;
    uint32_t session_id = serv->gs->session_round;
    //get session id
    for (i = 0; i < serv->max_connection; i++)
    {
        session_id++;
        //SwooleGS->session_round just has 24 bits size;
        if (unlikely(session_id == 1 << 24))
        {
            session_id = 1;
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
    serv->gs->session_round = session_id;
    sw_spinlock_release(&serv->gs->spinlock);
    connection->session_id = session_id;

    return connection;
}


