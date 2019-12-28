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
#include <sys/time.h>
#include <time.h>

static int swServer_destory(swServer *serv);
static int swServer_start_check(swServer *serv);
static void swServer_signal_handler(int sig);
static void swServer_enable_accept(swTimer *timer, swTimer_node *tnode);
static void swServer_disable_accept(swServer *serv);
static void swServer_master_update_time(swServer *serv);

static int swServer_tcp_send(swServer *serv, int session_id, void *data, uint32_t length);
static int swServer_tcp_sendwait(swServer *serv, int session_id, void *data, uint32_t length);
static int swServer_tcp_close(swServer *serv, int session_id, int reset);
static int swServer_tcp_sendfile(swServer *serv, int session_id, const char *file, uint32_t l_file, off_t offset, size_t length);
static int swServer_tcp_notify(swServer *serv, swConnection *conn, int event);
static int swServer_tcp_feedback(swServer *serv, int session_id, int event);

static swConnection* swServer_connection_new(swServer *serv, swListenPort *ls, int fd, int server_fd);

static void swServer_disable_accept(swServer *serv)
{
    swListenPort *ls;

    serv->enable_accept_timer = swoole_timer_add(SW_ACCEPT_RETRY_TIME * 1000, 0, swServer_enable_accept, serv);
    if (serv->enable_accept_timer == nullptr)
    {
        return;
    }

    LL_FOREACH(serv->listen_list, ls)
    {
        //UDP
        if (ls->type == SW_SOCK_UDP || ls->type == SW_SOCK_UDP6 || ls->type == SW_SOCK_UNIX_DGRAM)
        {
            continue;
        }
        swoole_event_del(ls->socket);
    }
}

static void swServer_enable_accept(swTimer *timer, swTimer_node *tnode)
{
    swListenPort *ls;
    swServer *serv = (swServer *) tnode->data;

    LL_FOREACH(serv->listen_list, ls)
    {
        if (swSocket_is_dgram(ls->type))
        {
            continue;
        }
        swoole_event_add(ls->socket, SW_EVENT_READ);
    }

    serv->enable_accept_timer = nullptr;
}

void swServer_close_port(swServer *serv, enum swBool_type only_stream_port)
{
    swListenPort *ls;
    LL_FOREACH(serv->listen_list, ls)
    {
        if (only_stream_port && swSocket_is_dgram(ls->type))
        {
            continue;
        }
        swSocket_free(ls->socket);
    }
}

int swServer_master_onAccept(swReactor *reactor, swEvent *event)
{
    swServer *serv = (swServer *) reactor->ptr;
    swListenPort *listen_host = (swListenPort *) serv->connection_list[event->fd].object;

    int new_fd = 0, i;

    for (i = 0; i < SW_ACCEPT_MAX_COUNT; i++)
    {
        new_fd = swSocket_accept(event->fd, &event->socket->info);
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
                    swServer_disable_accept(serv);
                }
                swSysWarn("accept() failed");
                return SW_OK;
            }
        }

        swTrace("[Master] Accept new connection. maxfd=%d|minfd=%d|reactor_id=%d|conn=%d", swServer_get_maxfd(serv), swServer_get_minfd(serv), reactor->id, new_fd);

        //too many connection
        if (new_fd >= (int) serv->max_connection)
        {
            swoole_error_log(SW_LOG_WARNING, SW_ERROR_SERVER_TOO_MANY_SOCKET, "Too many connections [now: %d]", new_fd);
            close(new_fd);
            return SW_OK;
        }

        //add to connection_list
        swConnection *conn = swServer_connection_new(serv, listen_host, new_fd, event->fd);
        if (conn == nullptr)
        {
            close(new_fd);
            return SW_OK;
        }
        memcpy(&conn->info.addr, &event->socket->info, sizeof(event->socket->info));
        conn->socket_type = listen_host->type;
        swSocket *_socket = conn->socket;

#ifdef SW_USE_OPENSSL
        if (listen_host->ssl)
        {
            if (swSSL_create(_socket, listen_host->ssl_context, 0) < 0)
            {
                reactor->close(reactor, _socket);
                return SW_OK;
            }
            else
            {
                conn->ssl = 1;
            }
        }
        else
        {
            _socket->ssl = NULL;
        }
#endif
        if (serv->single_thread)
        {
            if (swServer_connection_incoming(serv, reactor, conn) < 0)
            {
                reactor->close(reactor, _socket);
                return SW_OK;
            }
        }
        else
        {
            swDataHead ev = {0};
            ev.type = SW_SERVER_EVENT_INCOMING;
            ev.fd = new_fd;
            swSocket *_pipe_sock = swServer_get_send_pipe(serv, conn->session_id, conn->reactor_id);
            if (reactor->write(reactor, _pipe_sock, &ev, sizeof(ev)) < 0)
            {
                reactor->close(reactor, _socket);
                return SW_OK;
            }
        }
    }
    return SW_OK;
}

static int swServer_start_check(swServer *serv)
{
    //stream
    if (serv->have_stream_sock && serv->onReceive == NULL)
    {
        swWarn("onReceive event callback must be set");
        return SW_ERR;
    }
    //dgram
    if (serv->have_dgram_sock && serv->onPacket == NULL)
    {
        swWarn("onPacket event callback must be set");
        return SW_ERR;
    }
    //disable notice when use SW_DISPATCH_ROUND and SW_DISPATCH_QUEUE
    if (serv->factory_mode == SW_MODE_PROCESS)
    {
        if (!swServer_support_unsafe_events(serv))
        {
            if (serv->onConnect)
            {
                swWarn("cannot set 'onConnect' event when using dispatch_mode=1/3/7");
                serv->onConnect = nullptr;
            }
            if (serv->onClose)
            {
                swWarn("cannot set 'onClose' event when using dispatch_mode=1/3/7");
                serv->onClose = nullptr;
            }
            if (serv->onBufferFull)
            {
                swWarn("cannot set 'onBufferFull' event when using dispatch_mode=1/3/7");
                serv->onBufferFull = nullptr;
            }
            if (serv->onBufferEmpty)
            {
                swWarn("cannot set 'onBufferEmpty' event when using dispatch_mode=1/3/7");
                serv->onBufferEmpty = nullptr;
            }
            serv->disable_notify = 1;
        }
        if (!swServer_support_send_yield(serv))
        {
            serv->send_yield = 0;
        }
    }
    //AsyncTask
    if (serv->task_worker_num > 0)
    {
        if (serv->onTask == NULL)
        {
            swWarn("onTask event callback must be set");
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
    else if (serv->reactor_num == 0)
    {
        serv->reactor_num = SW_CPU_NUM;
    }
    if (serv->single_thread)
    {
        serv->reactor_num = 1;
    }
    //check worker num
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
        swWarn("serv->max_connection is exceed the maximum value, it's reset to %u", SwooleG.max_sockets);
    }
    else if (serv->max_connection > SW_SESSION_LIST_SIZE)
    {
        serv->max_connection = SW_SESSION_LIST_SIZE;
        swWarn("serv->max_connection is exceed the SW_SESSION_LIST_SIZE, it's reset to %u", SW_SESSION_LIST_SIZE);
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
        sockfd = ls->socket->fd;
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

    swString **buffers = (swString **) sw_malloc(sizeof(swString*) * buffer_num);
    if (buffers == NULL)
    {
        swError("malloc for worker buffer_input failed");
        return NULL;
    }

    for (i = 0; i < buffer_num; i++)
    {
        buffers[i] = swString_new(SW_BUFFER_SIZE_BIG);
        if (buffers[i] == NULL)
        {
            swError("worker buffer_input init failed");
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

    swProcessPool *pool = &serv->gs->task_workers;
    if (swProcessPool_create(pool, serv->task_worker_num, key, ipc_mode) < 0)
    {
        swWarn("[Master] create task_workers failed");
        return SW_ERR;
    }

    swProcessPool_set_max_request(pool, serv->task_max_request, serv->task_max_request_grace);
    swProcessPool_set_start_id(pool, serv->worker_num);
    swProcessPool_set_type(pool, SW_PROCESS_TASKWORKER);

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
    return swMutex_create(&worker->lock, 1);
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
            swSysWarn("sched_setaffinity() failed");
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
        if (serv->max_request_grace > 0)
        {
            SwooleWG.max_request += swoole_system_random(1, serv->max_request_grace);
        }
    }

    worker->start_time = serv->gs->now;
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
    //cannot start 2 servers at the same time, please use process->exec.
    if (!sw_atomic_cmp_set(&serv->gs->start, 0, 1))
    {
        swoole_error_log(SW_LOG_ERROR, SW_ERROR_SERVER_ONLY_START_ONE, "must only start one server");
        return SW_ERR;
    }
    //init logger
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
                swSysWarn("open(/dev/null) failed");
            }
        }

        if (swoole_daemon(0, 1) < 0)
        {
            return SW_ERR;
        }
    }

    //master pid
    serv->gs->master_pid = getpid();
    serv->gs->now = serv->stats->start_time = time(NULL);

    /**
     * init method
     */
    serv->send = swServer_tcp_send;
    serv->sendwait = swServer_tcp_sendwait;
    serv->sendfile = swServer_tcp_sendfile;
    serv->close = swServer_tcp_close;
    serv->notify = swServer_tcp_notify;
    serv->feedback = swServer_tcp_feedback;

    serv->workers = (swWorker *) SwooleG.memory_pool->alloc(SwooleG.memory_pool, serv->worker_num * sizeof(swWorker));
    if (serv->workers == NULL)
    {
        swSysWarn("gmalloc[server->workers] failed");
        return SW_ERR;
    }

    if (swMutex_create(&serv->lock, 0) < 0)
    {
        return SW_ERR;
    }

    /**
     * store to swProcessPool object
     */
    serv->gs->event_workers.ptr = serv;
    serv->gs->event_workers.workers = serv->workers;
    serv->gs->event_workers.worker_num = serv->worker_num;
    serv->gs->event_workers.use_msgqueue = 0;

    uint32_t i;
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
        serv->task_result = (swEventData *) sw_shm_calloc(serv->worker_num, sizeof(swEventData));
        if (!serv->task_result)
        {
            swWarn("malloc[serv->task_result] failed");
            return SW_ERR;
        }
        serv->task_notify = (swPipe *) sw_calloc(serv->worker_num, sizeof(swPipe));
        if (!serv->task_notify)
        {
            swWarn("malloc[serv->task_notify] failed");
            sw_shm_free(serv->task_result);
            return SW_ERR;
        }
        for (i = 0; i < serv->worker_num; i++)
        {
            if (swPipeNotify_auto(&serv->task_notify[i], 1, 0))
            {
                sw_shm_free(serv->task_result);
                sw_free(serv->task_notify);
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
    serv->running = 1;
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
        ret = sw_snprintf(SwooleTG.buffer_stack->str, SwooleTG.buffer_stack->size, "%d", getpid());
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
    //failed to start
    if (ret < 0)
    {
        return SW_ERR;
    }
    swServer_destory(serv);
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
    serv->max_connection = SW_MIN(SW_MAX_CONNECTION, SwooleG.max_sockets);

    serv->max_wait_time = SW_WORKER_MAX_WAIT_TIME;

    //http server
    serv->http_parse_cookie = 1;
    serv->http_parse_post = 1;
#ifdef SW_HAVE_COMPRESSION
    serv->http_compression = 1;
#endif
    serv->http_compression_level = SW_Z_BEST_SPEED;
    serv->upload_tmp_dir = sw_strdup("/tmp");

    serv->buffer_input_size = SW_BUFFER_INPUT_SIZE;
    serv->buffer_output_size = SW_BUFFER_OUTPUT_SIZE;

    serv->task_ipc_mode = SW_TASK_IPC_UNIXSOCK;

    serv->enable_coroutine = 1;
    serv->reload_async = 1;
    serv->send_yield = 1;

#ifdef __linux__
    serv->timezone = timezone;
#else
    struct timezone tz;
    struct timeval tv;
    gettimeofday(&tv, &tz);
    serv->timezone = tz.tz_minuteswest * 60;
#endif

    /**
     * alloc shared memory
     */
    serv->stats = (swServerStats *) SwooleG.memory_pool->alloc(SwooleG.memory_pool, sizeof(swServerStats));
    if (serv->stats == NULL)
    {
        swError("[Master] Fatal Error: failed to allocate memory for swServer->stats");
    }
    serv->gs = (swServerGS *) SwooleG.memory_pool->alloc(SwooleG.memory_pool, sizeof(swServerGS));
    if (serv->gs == NULL)
    {
        swError("[Master] Fatal Error: failed to allocate memory for swServer->gs");
    }

    SwooleG.serv = serv;
}

int swServer_create(swServer *serv)
{
    serv->factory.ptr = serv;
    /**
     * init current time
     */
    swServer_master_update_time(serv);

    serv->session_list = (swSession *) sw_shm_calloc(SW_SESSION_LIST_SIZE, sizeof(swSession));
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

void swServer_clear_timer(swServer *serv)
{
    if (serv->master_timer)
    {
        swoole_timer_del(serv->master_timer);
        serv->master_timer = nullptr;
    }
    if (serv->heartbeat_timer)
    {
        swoole_timer_del(serv->heartbeat_timer);
        serv->heartbeat_timer = nullptr;
    }
    if (serv->enable_accept_timer)
    {
        swoole_timer_del(serv->enable_accept_timer);
        serv->enable_accept_timer = nullptr;
    }
}

int swServer_shutdown(swServer *serv)
{
    serv->running = 0;
    //stop all thread
    if (SwooleTG.reactor)
    {
        swReactor *reactor = SwooleTG.reactor;
        reactor->wait_exit = 1;
        swListenPort *port;
        LL_FOREACH(serv->listen_list, port)
        {
            if (swSocket_is_stream(port->type))
            {
                reactor->del(reactor, port->socket);
            }
        }
        swServer_clear_timer(serv);
    }
    else
    {
        SwooleG.running = 0;
    }
    swInfo("Server is shutdown now");
    return SW_OK;
}

static int swServer_destory(swServer *serv)
{
    swTraceLog(SW_TRACE_SERVER, "release service");
    /**
     * shutdown workers
     */
    if (serv->factory.shutdown)
    {
        serv->factory.shutdown(&(serv->factory));
    }
    if (serv->factory_mode == SW_MODE_BASE)
    {
        swTraceLog(SW_TRACE_SERVER, "terminate task workers");
        if (serv->task_worker_num > 0)
        {
            swProcessPool_shutdown(&serv->gs->task_workers);
        }
    }
    else
    {
        swTraceLog(SW_TRACE_SERVER, "terminate reactor threads");
        /**
         * Wait until all the end of the thread
         */
        swReactorThread_join(serv);
    }

    swListenPort *port;
    LL_FOREACH(serv->listen_list, port)
    {
        swPort_free(port);
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
    swSignal_clear();
    /**
     * shutdown status
     */
    serv->gs->start = 0;
    serv->gs->shutdown = 1;
    /**
     * callback
     */
    if (serv->onShutdown)
    {
        serv->onShutdown(serv);
    }
    if (serv->factory_mode == SW_MODE_BASE)
    {
        swReactorProcess_free(serv);
    }
    else
    {
        swReactorThread_free(serv);
    }
    serv->lock.free(&serv->lock);
    SwooleG.serv = nullptr;
    return SW_OK;
}

/**
 * worker to master process
 */
static int swServer_tcp_feedback(swServer *serv, int session_id, int event)
{
    swConnection *conn = swServer_connection_verify(serv, session_id);
    if (!conn)
    {
        return SW_ERR;
    }

    if (event == SW_SERVER_EVENT_CONFIRM && !conn->socket->listen_wait)
    {
        return SW_ERR;
    }

    swSendData _send;
    bzero(&_send, sizeof(_send));
    _send.info.type = event;
    _send.info.fd = session_id;
    _send.info.reactor_id = conn->reactor_id;

    if (serv->factory_mode == SW_MODE_PROCESS)
    {
        return swWorker_send2reactor(serv, (swEventData *) &_send.info, sizeof(_send.info), session_id);
    }
    else
    {
        return swServer_master_send(serv, &_send);
    }
}

void swServer_store_pipe_fd(swServer *serv, swPipe *p)
{
    swSocket* master_socket = p->getSocket(p, SW_PIPE_MASTER);
    swSocket* worker_socket = p->getSocket(p, SW_PIPE_WORKER);

    if (master_socket->fd > swServer_get_maxfd(serv))
    {
        swServer_set_maxfd(serv, master_socket->fd);
    }
    if (worker_socket->fd > swServer_get_maxfd(serv))
    {
        swServer_set_maxfd(serv, worker_socket->fd);
    }
}

swPipe * swServer_get_pipe_object(swServer *serv, int pipe_fd)
{
    return (swPipe *) serv->connection_list[pipe_fd].object;
}

/**
 * @process Worker
 * @return SW_OK or SW_ERR
 */
static int swServer_tcp_send(swServer *serv, int session_id, void *data, uint32_t length)
{
    swSendData _send;
    bzero(&_send.info, sizeof(_send.info));
    swFactory *factory = &(serv->factory);

    if (sw_unlikely(swIsMaster()))
    {
        swoole_error_log(SW_LOG_ERROR, SW_ERROR_SERVER_SEND_IN_MASTER, "can't send data to the connections in master process");
        return SW_ERR;
    }

    _send.info.fd = session_id;
    _send.info.type = SW_SERVER_EVENT_SEND_DATA;
    _send.data = (char*) data;
    _send.info.len = length;
    return factory->finish(factory, &_send) < 0 ? SW_ERR : SW_OK;
}

/**
 * [Master] send to client or append to out_buffer
 */
int swServer_master_send(swServer *serv, swSendData *_send)
{
    uint32_t session_id = _send->info.fd;
    char *_send_data = _send->data;
    uint32_t _send_length = _send->info.len;

    swConnection *conn;
    if (_send->info.type != SW_SERVER_EVENT_CLOSE)
    {
        conn = swServer_connection_verify(serv, session_id);
    }
    else
    {
        conn = swServer_connection_verify_no_ssl(serv, session_id);
    }
    if (!conn)
    {
        if (_send->info.type == SW_SERVER_EVENT_SEND_DATA)
        {
            swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SESSION_NOT_EXIST, "send %d byte failed, session#%d does not exist", _send_length, session_id);
        }
        else
        {
            swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SESSION_NOT_EXIST, "send event$[%d] failed, session#%d does not exist", _send->info.type, session_id);
        }
        return SW_ERR;
    }

    int fd = conn->fd;
    swReactor *reactor = SwooleTG.reactor;

    if (!serv->single_thread)
    {
        assert(fd % serv->reactor_num == reactor->id);
        assert(fd % serv->reactor_num == SwooleTG.id);
    }

    if (serv->factory_mode == SW_MODE_BASE && conn->overflow)
    {
        if (serv->send_yield)
        {
            SwooleG.error = SW_ERROR_OUTPUT_BUFFER_OVERFLOW;
        }
        else
        {
            swoole_error_log(SW_LOG_WARNING, SW_ERROR_OUTPUT_BUFFER_OVERFLOW, "connection#%d output buffer overflow", fd);
        }
        return SW_ERR;
    }

    swSocket *_socket = conn->socket;

    /**
     * Reset send buffer, Immediately close the connection.
     */
    if (_send->info.type == SW_SERVER_EVENT_CLOSE && (conn->close_reset || conn->peer_closed))
    {
        goto _close_fd;
    }
    else if (_send->info.type == SW_SERVER_EVENT_CONFIRM)
    {
        reactor->add(reactor, conn->socket, SW_EVENT_READ);
        conn->socket->listen_wait = 0;
        return SW_OK;
    }
    /**
     * pause recv data
     */
    else if (_send->info.type == SW_SERVER_EVENT_PAUSE_RECV)
    {
        if (_socket->events & SW_EVENT_WRITE)
        {
            return reactor->set(reactor, conn->socket, SW_EVENT_WRITE);
        }
        else
        {
            return reactor->del(reactor, conn->socket);
        }
    }
    /**
     * resume recv data
     */
    else if (_send->info.type == SW_SERVER_EVENT_RESUME_RECV)
    {
        if (_socket->events & SW_EVENT_WRITE)
        {
            return reactor->set(reactor, _socket, SW_EVENT_READ | SW_EVENT_WRITE);
        }
        else
        {
            return reactor->add(reactor, _socket, SW_EVENT_READ);
        }
    }

    if (swBuffer_empty(_socket->out_buffer))
    {
        /**
         * close connection.
         */
        if (_send->info.type == SW_SERVER_EVENT_CLOSE)
        {
            _close_fd:
            reactor->close(reactor, _socket);
            return SW_OK;
        }
        //Direct send
        if (_send->info.type != SW_SERVER_EVENT_SEND_FILE)
        {
            if (!_socket->direct_send)
            {
                goto _buffer_send;
            }

            ssize_t n;

            _direct_send:
            n = swSocket_send(_socket, _send_data, _send_length, 0);
            if (n == _send_length)
            {
                return SW_OK;
            }
            else if (n > 0)
            {
                _send_data += n;
                _send_length -= n;
                goto _buffer_send;
            }
            else if (errno == EINTR)
            {
                goto _direct_send;
            }
            else
            {
                goto _buffer_send;
            }
        }
        //buffer send
        else
        {
            _buffer_send:
            if (!_socket->out_buffer)
            {
                _socket->out_buffer = swBuffer_new(SW_SEND_BUFFER_SIZE);
                if (_socket->out_buffer == NULL)
                {
                    return SW_ERR;
                }
            }
        }
    }

    swBuffer_chunk *chunk;
    //close connection
    if (_send->info.type == SW_SERVER_EVENT_CLOSE)
    {
        chunk = swBuffer_new_chunk(_socket->out_buffer, SW_CHUNK_CLOSE, 0);
        chunk->store.data.val1 = _send->info.type;
        conn->close_queued = 1;
    }
    //sendfile to client
    else if (_send->info.type == SW_SERVER_EVENT_SEND_FILE)
    {
        swSendFile_request *req = (swSendFile_request *) _send_data;
        swSocket_sendfile(conn->socket, req->filename, req->offset, req->length);
    }
    //send data
    else
    {
        //connection is closed
        if (conn->peer_closed)
        {
            swWarn("connection#%d is closed by client", fd);
            return SW_ERR;
        }
        //connection output buffer overflow
        if (_socket->out_buffer->length >= _socket->buffer_size)
        {
            if (serv->send_yield)
            {
                SwooleG.error = SW_ERROR_OUTPUT_BUFFER_OVERFLOW;
            }
            else
            {
                swoole_error_log(SW_LOG_WARNING, SW_ERROR_OUTPUT_BUFFER_OVERFLOW, "connection#%d output buffer overflow", fd);
            }
            conn->overflow = 1;
            if (serv->onBufferEmpty && serv->onBufferFull == NULL)
            {
                conn->high_watermark = 1;
            }
        }

        if (swBuffer_append(_socket->out_buffer, _send_data, _send_length) < 0)
        {
            swWarn("append to pipe_buffer failed");
            return SW_ERR;
        }

        swListenPort *port = swServer_get_port(serv, fd);
        if (serv->onBufferFull && conn->high_watermark == 0 && _socket->out_buffer->length >= port->buffer_high_watermark)
        {
            serv->notify(serv, conn, SW_SERVER_EVENT_BUFFER_FULL);
            conn->high_watermark = 1;
        }
    }

    //listen EPOLLOUT event
    if (reactor->set(reactor, _socket, SW_EVENT_WRITE | SW_EVENT_READ) < 0 && (errno == EBADF || errno == ENOENT))
    {
        goto _close_fd;
    }

    return SW_OK;
}

/**
 * use in master process
 */
static int swServer_tcp_notify(swServer *serv, swConnection *conn, int event)
{
    swDataHead notify_event = {0};
    notify_event.type = event;
    notify_event.reactor_id = conn->reactor_id;
    notify_event.fd = conn->fd;
    notify_event.server_fd = conn->server_fd;
    return serv->factory.notify(&serv->factory, &notify_event);
}

/**
 * @process Worker
 * @return SW_OK or SW_ERR
 */
static int swServer_tcp_sendfile(swServer *serv, int session_id, const char *file, uint32_t l_file, off_t offset, size_t length)
{
    if (sw_unlikely(session_id <= 0 || session_id > SW_MAX_SESSION_ID))
    {
        swoole_error_log(SW_LOG_WARNING, SW_ERROR_SESSION_INVALID_ID, "invalid fd[%d]", session_id);
        return SW_ERR;
    }

    if (sw_unlikely(swIsMaster()))
    {
        swoole_error_log(SW_LOG_ERROR, SW_ERROR_SERVER_SEND_IN_MASTER, "can't send data to the connections in master process");
        return SW_ERR;
    }

    char _buffer[SW_IPC_BUFFER_SIZE];
    swSendFile_request *req = (swSendFile_request*) _buffer;

    // file name size
    if (sw_unlikely(l_file > SW_IPC_BUFFER_SIZE - sizeof(swSendFile_request) - 1))
    {
        swoole_error_log(
            SW_LOG_WARNING, SW_ERROR_NAME_TOO_LONG, "sendfile name[%.8s...] length %u is exceed the max name len %u",
            file, l_file, (uint32_t) (SW_IPC_BUFFER_SIZE - sizeof(swSendFile_request) - 1)
        );
        return SW_ERR;
    }
    // string must be zero termination (for `state` system call)
    char *_file = strncpy((char *) req->filename, file, l_file);
    _file[l_file] = '\0';

    // check state
    struct stat file_stat;
    if (stat(_file, &file_stat) < 0)
    {
        swoole_error_log(SW_LOG_WARNING, SW_ERROR_SYSTEM_CALL_FAIL, "stat(%s) failed", _file);
        return SW_ERR;
    }
    if (file_stat.st_size <= offset)
    {
        swoole_error_log(SW_LOG_WARNING, SW_ERROR_SYSTEM_CALL_FAIL, "file[offset=%ld] is empty", (long) offset);
        return SW_ERR;
    }
    req->offset = offset;
    req->length = length;

    // construct send data
    swSendData send_data = {{0}};
    send_data.info.fd = session_id;
    send_data.info.type = SW_SERVER_EVENT_SEND_FILE;
    send_data.info.len = sizeof(swSendFile_request) + l_file + 1;
    send_data.data = _buffer;

    return serv->factory.finish(&serv->factory, &send_data) < 0 ? SW_ERR : SW_OK;
}

/**
 * [Worker] Returns the number of bytes sent
 */
static int swServer_tcp_sendwait(swServer *serv, int session_id, void *data, uint32_t length)
{
    swConnection *conn = swServer_connection_verify(serv, session_id);
    if (!conn)
    {
        swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SESSION_CLOSED, "send %d byte failed, because session#%d is closed", length, session_id);
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
        func = (swCallback) node->data;
        func(arg);
        node = node->next;
    }
}

/**
 * [Worker]
 */
static int swServer_tcp_close(swServer *serv, int session_id, int reset)
{
    if (sw_unlikely(swIsMaster()))
    {
        swoole_error_log(SW_LOG_ERROR, SW_ERROR_SERVER_SEND_IN_MASTER, "can't close the connections in master process");
        return SW_ERR;
    }
    swConnection *conn = swServer_connection_verify_no_ssl(serv, session_id);
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
    swTraceLog(SW_TRACE_CLOSE, "session_id=%d, fd=%d", session_id, conn->session_id);

    int retval;
    swWorker *worker;
    swDataHead ev = { 0 };

    if (swServer_dispatch_mode_is_mod(serv))
    {
        int worker_id = swServer_worker_schedule(serv, conn->fd, nullptr);
        if (worker_id != (int) SwooleWG.id)
        {
            worker = swServer_get_worker(serv, worker_id);
            goto _notify;
        }
        else
        {
            goto _close;
        }
    }
    else if (!swIsWorker())
    {
        worker = swServer_get_worker(serv, conn->fd % serv->worker_num);
        _notify:
        ev.type = SW_SERVER_EVENT_CLOSE;
        ev.fd = session_id;
        ev.reactor_id = conn->reactor_id;
        retval = swWorker_send2worker(worker, &ev, sizeof(ev), SW_PIPE_MASTER);
    }
    else
    {
        _close:
        retval = serv->factory.end(&serv->factory, session_id);
    }
    return retval;
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
        swoole_error_log(SW_LOG_WARNING, SW_ERROR_SERVER_NO_IDLE_WORKER, "No idle worker is available");
    }

    if (serv->hooks[SW_SERVER_HOOK_MASTER_TIMER])
    {
        swServer_call_hook(serv, SW_SERVER_HOOK_MASTER_TIMER, serv);
    }
}

int swServer_add_worker(swServer *serv, swWorker *worker)
{
    swUserWorker_node *user_worker = (swUserWorker_node *) sw_malloc(sizeof(swUserWorker_node));
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
        swSysWarn("get time failed");
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
        return swLinkedList_append(serv->hooks[type], (void*) func);
    }
    else
    {
        return swLinkedList_prepend(serv->hooks[type], (void*) func);
    }
}

/**
 * Return the number of ports successfully
 */
int swServer_add_systemd_socket(swServer *serv)
{
    char *e = getenv("LISTEN_PID");
    if (!e)
    {
        return 0;
    }

    int pid = atoi(e);
    if (getpid() != pid)
    {
        swWarn("invalid LISTEN_PID");
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
        swWarn("invalid LISTEN_FDS");
        return 0;
    }
    else if (n >= SW_MAX_LISTEN_PORT)
    {
        swoole_error_log(SW_LOG_ERROR, SW_ERROR_SERVER_TOO_MANY_LISTEN_PORT, "LISTEN_FDS is too big");
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
        swListenPort *ls = (swListenPort *) SwooleG.memory_pool->alloc(SwooleG.memory_pool, sizeof(swListenPort));
        if (ls == NULL)
        {
            swWarn("alloc failed");
            return count;
        }
        //get socket type
        optlen = sizeof(val);
        if (getsockopt(sock, SOL_SOCKET, SO_TYPE, &val, &optlen) < 0)
        {
            swWarn("getsockopt(%d, SOL_SOCKET, SO_TYPE) failed", sock);
            return count;
        }
        sock_type = val;
        //get socket family
#ifndef SO_DOMAIN
        swWarn("no getsockopt(SO_DOMAIN) supports");
        return count;
#else
        optlen = sizeof(val);
        if (getsockopt(sock, SOL_SOCKET, SO_DOMAIN, &val, &optlen) < 0)
        {
            swWarn("getsockopt(%d, SOL_SOCKET, SO_DOMAIN) failed", sock);
            return count;
        }
#endif
        sock_family = val;
        //get address info
        address.len = sizeof(address.addr);
        if (getsockname(sock, (struct sockaddr*) &address.addr, &address.len) < 0)
        {
            swWarn("getsockname(%d) failed", sock);
            return count;
        }

        swPort_init(ls);

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
            strncpy(ls->host, address.addr.un.sun_path, SW_HOST_MAXSIZE);
            break;
        default:
            swWarn("Unknown socket type[%d]", sock_type);
            break;
        }

        ls->host[SW_HOST_MAXSIZE - 1] = 0;

        //dgram socket, setting socket buffer size
        if (swSocket_is_dgram(ls->type))
        {
            swSocket_set_buffer_size(sock, ls->socket_buffer_size);
        }
        //O_NONBLOCK & O_CLOEXEC
        swoole_fcntl_set_option(sock, 1, 1);
        ls->socket = swSocket_new(sock, swSocket_is_dgram(ls->type) ? SW_FD_DGRAM_SERVER : SW_FD_STREAM_SERVER);
        if (ls->socket == nullptr)
        {
            close(sock);
            return count;
        }

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

swListenPort* swServer_add_port(swServer *serv, enum swSocket_type type, const char *host, int port)
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
        swoole_error_log(SW_LOG_ERROR, SW_ERROR_NAME_TOO_LONG, "address '%s' exceeds %ld characters limit", host, SW_HOST_MAXSIZE - 1);
        return NULL;
    }

    swListenPort *ls = (swListenPort *) SwooleG.memory_pool->alloc(SwooleG.memory_pool, sizeof(swListenPort));
    if (ls == NULL)
    {
        swError("alloc failed");
        return NULL;
    }

    swPort_init(ls);
    ls->type = type;
    ls->port = port;
    strncpy(ls->host, host, SW_HOST_MAXSIZE - 1);
    ls->host[SW_HOST_MAXSIZE - 1] = 0;

    if (type & SW_SOCK_SSL)
    {
        type = (enum swSocket_type) (type & (~SW_SOCK_SSL));
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
        swSysWarn("create socket failed");
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
        swSocket_set_buffer_size(sock, ls->socket_buffer_size);
    }
    //O_NONBLOCK & O_CLOEXEC
    swoole_fcntl_set_option(sock, 1, 1);
    ls->socket = swSocket_new(sock, swSocket_is_dgram(ls->type) ? SW_FD_DGRAM_SERVER : SW_FD_STREAM_SERVER);
    if (ls->socket == nullptr)
    {
        close(sock);
        return nullptr;
    }

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

int swServer_get_socket(swServer *serv, int port)
{
    swListenPort *ls;
    LL_FOREACH(serv->listen_list, ls)
    {
        if (ls->port == port || port == 0)
        {
            return ls->socket->fd;
        }
    }
    return SW_ERR;
}

static void swServer_signal_handler(int sig)
{
    swTraceLog(SW_TRACE_SERVER, "signal[%d] %s triggered in %d", sig, swSignal_str(sig), getpid());

    swServer *serv = SwooleG.serv;
    int status;
    pid_t pid;
    switch (sig)
    {
    case SIGTERM:
        swServer_shutdown(serv);
        break;
    case SIGALRM:
        swSystemTimer_signal_handler(SIGALRM);
        break;
    case SIGCHLD:
        if (!serv->running)
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
            swWarn("Fatal Error: manager process exit. status=%d, signal=[%s]", WEXITSTATUS(status), swSignal_str(WTERMSIG(status)));
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
            swoole_kill(serv->gs->manager_pid, sig);
        }
        break;
    default:
#ifdef SIGRTMIN
        if (sig == SIGRTMIN)
        {
            uint32_t i;
            swWorker *worker;
            for (i = 0; i < SwooleG.serv->worker_num + serv->task_worker_num + SwooleG.serv->user_worker_num; i++)
            {
                worker = swServer_get_worker(SwooleG.serv, i);
                swoole_kill(worker->pid, SIGRTMIN);
            }
            if (SwooleG.serv->factory_mode == SW_MODE_PROCESS)
            {
                swoole_kill(serv->gs->manager_pid, SIGRTMIN);
            }
            swLog_reopen(SwooleG.serv->daemonize ? SW_TRUE : SW_FALSE);
        }
#endif
        break;
    }
}

void swServer_connection_each(swServer *serv, void (*callback)(swConnection *conn))
{
    swConnection *conn;

    int fd;
    int serv_max_fd = swServer_get_maxfd(serv);
    int serv_min_fd = swServer_get_minfd(serv);

    for (fd = serv_min_fd; fd <= serv_max_fd; fd++)
    {
        conn = swServer_connection_get(serv, fd);
        if (conn && conn->socket && conn->active == 1 && conn->closed == 0 && conn->socket->fdtype == SW_FD_SESSION)
        {
            callback(conn);
        }
    }
}

/**
 * new connection
 */
static swConnection* swServer_connection_new(swServer *serv, swListenPort *ls, int fd, int server_fd)
{
    swSocket *_socket = swSocket_new(fd, SW_FD_SESSION);
    if (_socket == nullptr)
    {
        return nullptr;
    }

    serv->stats->accept_count++;
    sw_atomic_fetch_add(&serv->stats->connection_num, 1);
    sw_atomic_fetch_add(&ls->connection_num, 1);

    if (fd > swServer_get_maxfd(serv))
    {
        swServer_set_maxfd(serv, fd);
    }
    else if (fd < swServer_get_minfd(serv))
    {
        swServer_set_minfd(serv, fd);
    }

    swConnection *connection = &(serv->connection_list[fd]);
    bzero(connection, sizeof(*connection));
    _socket->object = connection;
    _socket->buffer_size = ls->socket_buffer_size;

    //TCP Nodelay
    if (ls->open_tcp_nodelay && ls->type != SW_SOCK_UNIX_STREAM)
    {
        int sockopt = 1;
        if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &sockopt, sizeof(sockopt)) != 0)
        {
            swSysWarn("setsockopt(TCP_NODELAY) failed");
        }
        _socket->tcp_nodelay = 1;
    }

    //socket recv buffer size
    if (ls->kernel_socket_recv_buffer_size > 0)
    {
        if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &ls->kernel_socket_recv_buffer_size, sizeof(int)) != 0)
        {
            swSysWarn("setsockopt(SO_RCVBUF, %d) failed", ls->kernel_socket_recv_buffer_size);
        }
    }

    //socket send buffer size
    if (ls->kernel_socket_send_buffer_size > 0)
    {
        if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &ls->kernel_socket_send_buffer_size, sizeof(int)) != 0)
        {
            swSysWarn("setsockopt(SO_SNDBUF, %d) failed", ls->kernel_socket_send_buffer_size);
        }
    }

    connection->fd = fd;
    connection->reactor_id = serv->factory_mode == SW_MODE_BASE ? SwooleWG.id : fd % serv->reactor_num;
    connection->server_fd = (sw_atomic_t) server_fd;
    connection->connect_time = serv->gs->now;
    connection->last_time = serv->gs->now;
    connection->active = 1;
    connection->socket = _socket;

    if (!ls->ssl)
    {
        _socket->direct_send = 1;
    }

    swSession *session;
    sw_spinlock(&serv->gs->spinlock);
    uint32_t i;
    uint32_t session_id = serv->gs->session_round;
    //get session id
    for (i = 0; i < serv->max_connection; i++)
    {
        session_id++;
        //SwooleGS->session_round just has 24 bits size;
        if (sw_unlikely(session_id == 1 << 24))
        {
            session_id = 1;
        }
        session = swServer_get_session(serv, session_id);
        //vacancy
        if (session->fd == 0)
        {
            session->fd = fd;
            session->id = session_id;
            session->reactor_id = connection->reactor_id;
            break;
        }
    }
    serv->gs->session_round = session_id;
    sw_spinlock_release(&serv->gs->spinlock);
    connection->session_id = session_id;

    return connection;
}
