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
#include "swoole_cxx.h"
#include "http.h"
#include <sys/time.h>
#include <time.h>

using namespace swoole;

static int swServer_destory(swServer *serv);
static int swServer_start_check(swServer *serv);
static void swServer_signal_handler(int sig);
static void swServer_enable_accept(swTimer *timer, swTimer_node *tnode);
static void swServer_disable_accept(swServer *serv);

static int swServer_tcp_send(swServer *serv, int session_id, void *data, uint32_t length);
static int swServer_tcp_sendwait(swServer *serv, int session_id, void *data, uint32_t length);
static int swServer_tcp_close(swServer *serv, int session_id, int reset);
static int swServer_tcp_sendfile(swServer *serv, int session_id, const char *file, uint32_t l_file, off_t offset, size_t length);
static int swServer_tcp_notify(swServer *serv, swConnection *conn, int event);
static int swServer_tcp_feedback(swServer *serv, int session_id, int event);

static void** swServer_worker_create_buffers(swServer *serv, uint buffer_num);
static void* swServer_worker_get_buffer(swServer *serv, swDataHead *info);
static size_t swServer_worker_get_buffer_len(swServer *serv, swDataHead *info);
static void swServer_worker_add_buffer_len(swServer *serv, swDataHead *info, size_t len);
static void swServer_worker_move_buffer(swServer *serv, swPipeBuffer *buffer);

static size_t swServer_worker_get_packet(swServer *serv, swEventData *req, char **data_ptr);

static swConnection* swServer_connection_new(swServer *serv, swListenPort *ls, swSocket *_socket, int server_fd);

static void swServer_check_port_type(swServer *serv, swListenPort *ls);

static void swServer_disable_accept(swServer *serv)
{
    serv->enable_accept_timer = swoole_timer_add(SW_ACCEPT_RETRY_TIME * 1000, 0, swServer_enable_accept, serv);
    if (serv->enable_accept_timer == nullptr)
    {
        return;
    }

    for (auto ls : *serv->listen_list)
    {
        //UDP
        if (swSocket_is_dgram(ls->type))
        {
            continue;
        }
        swoole_event_del(ls->socket);
    }
}

static void swServer_enable_accept(swTimer *timer, swTimer_node *tnode)
{
    swServer *serv = (swServer *) tnode->data;

    for (auto ls : *serv->listen_list)
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
    for (auto ls : *serv->listen_list)
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
    swSocketAddress client_addr;

    for (int i = 0; i < SW_ACCEPT_MAX_COUNT; i++)
    {
        swSocket *sock = swSocket_accept(event->socket, &client_addr);
        if (sock == nullptr)
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

        swTrace("[Master] Accept new connection. maxfd=%d|minfd=%d|reactor_id=%d|conn=%d", swServer_get_maxfd(serv), swServer_get_minfd(serv), reactor->id, sock->fd);

        //too many connection
        if (sock->fd >= (int) serv->max_connection)
        {
            swoole_error_log(SW_LOG_WARNING, SW_ERROR_SERVER_TOO_MANY_SOCKET, "Too many connections [now: %d]", sock->fd);
            swSocket_free(sock);
            swServer_disable_accept(serv);
            return SW_OK;
        }

        //add to connection_list
        swConnection *conn = swServer_connection_new(serv, listen_host, sock, event->fd);
        if (conn == nullptr)
        {
            swSocket_free(sock);
            return SW_OK;
        }
        sock->chunk_size = SW_SEND_BUFFER_SIZE;

#ifdef SW_USE_OPENSSL
        if (listen_host->ssl)
        {
            if (swSSL_create(sock, listen_host->ssl_context, SW_SSL_SERVER) < 0)
            {
                reactor->close(reactor, sock);
                return SW_OK;
            }
            else
            {
                conn->ssl = 1;
            }
        }
        else
        {
            sock->ssl = nullptr;
        }
#endif
        if (serv->single_thread)
        {
            if (swServer_connection_incoming(serv, reactor, conn) < 0)
            {
                reactor->close(reactor, sock);
                return SW_OK;
            }
        }
        else
        {
            swDataHead ev = {};
            ev.type = SW_SERVER_EVENT_INCOMING;
            ev.fd = sock->fd;
            swSocket *_pipe_sock = swServer_get_send_pipe(serv, conn->session_id, conn->reactor_id);
            if (reactor->write(reactor, _pipe_sock, &ev, sizeof(ev)) < 0)
            {
                reactor->close(reactor, sock);
                return SW_OK;
            }
        }
    }

    return SW_OK;
}

#ifdef SW_SUPPORT_DTLS
dtls::Session* swServer_dtls_accept(swServer *serv, swListenPort *port, swSocketAddress *sa)
{
    swSocket *sock = nullptr;
    dtls::Session *session = nullptr;
    swConnection *conn = nullptr;

    int fd = swSocket_create(port->type, 1, 1);
    if (fd < 0)
    {
        return nullptr;
    }

    int on = 1, off = 0;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void*) &on, (socklen_t) sizeof(on));
#ifdef HAVE_KQUEUE
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, (const void*) &on, (socklen_t) sizeof(on));
#endif

    switch (port->type)
    {
    case SW_SOCK_UDP:
    {
        if (inet_pton(AF_INET, port->host, &port->socket->info.addr.inet_v4.sin_addr) < 0)
        {
            swSysWarn("inet_pton(AF_INET, %s) failed", port->host);
            goto _cleanup;
        }
        port->socket->info.addr.inet_v4.sin_port = htons(port->port);
        port->socket->info.addr.inet_v4.sin_family = AF_INET;

        if (bind(fd, (const struct sockaddr *) &port->socket->info.addr, sizeof(struct sockaddr_in)))
        {
            swSysWarn("bind() failed");
            goto _cleanup;
        }
        if (connect(fd, (struct sockaddr *) &sa->addr, sizeof(struct sockaddr_in)))
        {
            swSysWarn("connect() failed");
            goto _cleanup;
        }
        break;
    }
    case SW_SOCK_UDP6:
    {
        if (inet_pton(AF_INET6, port->host, &port->socket->info.addr.inet_v6.sin6_addr) < 0)
        {
            swSysWarn("inet_pton(AF_INET6, %s) failed", port->host);
            goto _cleanup;
        }
        port->socket->info.addr.inet_v6.sin6_port = htons(port->port);
        port->socket->info.addr.inet_v6.sin6_family = AF_INET6;

        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (char *) &off, sizeof(off));
        if (bind(fd, (const struct sockaddr *) &port->socket->info.addr, sizeof(struct sockaddr_in6)))
        {
            swSysWarn("bind() failed");
            goto _cleanup;
        }
        if (connect(fd, (struct sockaddr *) &sa->addr, sizeof(struct sockaddr_in6)))
        {
            swSysWarn("connect() failed");
            goto _cleanup;
        }
        break;
    }
    default:
        OPENSSL_assert(0);
        break;
    }

    sock = swSocket_new(fd, SW_FD_SESSION);
    if (!sock)
    {
        goto _cleanup;
    }

    memcpy(&sock->info, sa, sizeof(*sa));
    sock->socket_type = port->type;
    sock->nonblock = 1;
    sock->cloexec = 1;
    sock->chunk_size = SW_BUFFER_SIZE_STD;

    conn = swServer_connection_new(serv, port, sock, port->socket->fd);
    if (conn == nullptr)
    {
        goto _cleanup;
    }

    session = new dtls::Session(sock, port->ssl_context);
    port->dtls_sessions->emplace(fd, session);

    if (!session->init())
    {
        goto _cleanup;
    }

    return session;

    _cleanup:
    if (sock)
    {
        sw_free(sock);
    }
    if (conn)
    {
        sw_memset_zero(conn, sizeof(*conn));
    }
    if (session)
    {
        delete session;
    }
    close(fd);

    return nullptr;
}
#endif

static int swServer_start_check(swServer *serv)
{
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
    else
    {
        serv->max_queued_bytes = 0;
    }
    //AsyncTask
    if (serv->task_worker_num > 0)
    {
        if (serv->onTask == nullptr)
        {
            swWarn("onTask event callback must be set");
            return SW_ERR;
        }
        if (serv->task_worker_num > SW_CPU_NUM * SW_MAX_WORKER_NCPU)
        {
            swWarn("serv->task_worker_num == %d, Too many processes, reset to max value %d", serv->task_worker_num, SW_CPU_NUM * SW_MAX_WORKER_NCPU);
            serv->task_worker_num = SW_CPU_NUM * SW_MAX_WORKER_NCPU;
        }
    }
    //check thread num
    if (serv->reactor_num > SW_CPU_NUM * SW_MAX_THREAD_NCPU)
    {
        swWarn("serv->reactor_num == %d, Too many threads, reset to max value %d", serv->reactor_num, SW_CPU_NUM * SW_MAX_THREAD_NCPU);
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
        swWarn("serv->worker_num == %d, Too many processes, reset to max value %d", serv->worker_num, SW_CPU_NUM * SW_MAX_WORKER_NCPU);
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
    for (auto ls : *serv->listen_list)
    {
        if (ls->protocol.package_max_length < SW_BUFFER_MIN_SIZE)
        {
            ls->protocol.package_max_length = SW_BUFFER_MIN_SIZE;
        }
        if (swServer_if_require_receive_callback(serv, ls, serv->onReceive))
        {
            swWarn("require onReceive callback");
            return SW_ERR;
        }
        if (swServer_if_require_packet_callback(serv, ls, serv->onPacket))
        {
            swWarn("require onPacket callback");
            return SW_ERR;
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
    int sockfd;

    for (auto ls : *serv->listen_list)
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

uint sw_inline swServer_worker_buffer_num(swServer *serv)
{
    uint buffer_num;

    if (serv->factory_mode == SW_MODE_BASE)
    {
        buffer_num = 1;
    }
    else
    {
        buffer_num = serv->reactor_num + serv->dgram_port_num;
    }
    return buffer_num;
}

void** swServer_worker_create_buffers(swServer *serv, uint buffer_num)
{
    swString **buffers = (swString **) sw_malloc(sizeof(swString *) * buffer_num);
    if (buffers == nullptr)
    {
        swError("malloc for worker input_buffers failed");
    }

    for (uint i = 0; i < buffer_num; i++)
    {
        buffers[i] = swString_new(SW_BUFFER_SIZE_BIG);
        if (buffers[i] == nullptr)
        {
            swError("worker input_buffers init failed");
        }
    }

    return (void **) buffers;
}

/**
 * only the memory of the swWorker structure is allocated, no process is fork
 */
int swServer_create_task_workers(swServer *serv)
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
 * @description: 
 *  only the memory of the swWorker structure is allocated, no process is fork.
 *  called when the manager process start.
 * @param swServer
 * @return: SW_OK|SW_ERR
 */
int swServer_create_user_workers(swServer *serv)
{
    /**
     * if Swoole\Server::addProcess is called first, 
     * swServer::user_worker_list is initialized in the swServer_add_worker function
     */
    if (serv->user_worker_list == nullptr)
    {
        serv->user_worker_list = new std::vector<swWorker *>;
    }

    serv->user_workers = (swWorker *) SwooleG.memory_pool->alloc(SwooleG.memory_pool, serv->user_worker_num * sizeof(swWorker));
    if (serv->user_workers == nullptr)
    {
        swSysWarn("gmalloc[server->user_workers] failed");
        return SW_ERR;
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

    SwooleWG.input_buffers = serv->create_buffers(serv, swServer_worker_buffer_num(serv));
    if (!SwooleWG.input_buffers)
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

    worker->start_time = time(nullptr);
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
    //run as daemon
    if (serv->daemonize > 0)
    {
        /**
         * redirect STDOUT to log file
         */
        if (swLog_is_opened())
        {
            swLog_set_redirect_stdout(1);
        }
        /**
         * redirect STDOUT_FILENO/STDERR_FILENO to /dev/null
         */
        else
        {
            serv->null_fd = open("/dev/null", O_WRONLY);
            if (serv->null_fd > 0)
            {
                swoole_redirect_stdout(serv->null_fd);
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
    serv->stats->start_time = time(nullptr);

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
    if (serv->workers == nullptr)
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
        i = 0;
        for (auto worker : *serv->user_worker_list)
        {
            worker->id = serv->worker_num + serv->task_worker_num + i;
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
    sw_memset_zero(serv, sizeof(swServer));

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
    serv->http_compression_level = SW_Z_BEST_SPEED;
#endif
    serv->upload_tmp_dir = sw_strdup("/tmp");

    serv->input_buffer_size = SW_INPUT_BUFFER_SIZE;
    serv->output_buffer_size = SW_OUTPUT_BUFFER_SIZE;

    serv->task_ipc_mode = SW_TASK_IPC_UNIXSOCK;

    serv->enable_coroutine = 1;
    serv->reload_async = 1;
    serv->send_yield = 1;

    serv->null_fd = -1;

    serv->recv_buffer_size = SW_BUFFER_SIZE_BIG;
    serv->buffer_allocator = &SwooleG.std_allocator;

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
    if (serv->stats == nullptr)
    {
        swError("[Master] Fatal Error: failed to allocate memory for swServer->stats");
    }
    serv->gs = (swServerGS *) SwooleG.memory_pool->alloc(SwooleG.memory_pool, sizeof(swServerGS));
    if (serv->gs == nullptr)
    {
        swError("[Master] Fatal Error: failed to allocate memory for swServer->gs");
    }

    /**
     * init method
     */
    serv->create_buffers = swServer_worker_create_buffers;
    serv->get_buffer = swServer_worker_get_buffer;
    serv->get_buffer_len = swServer_worker_get_buffer_len;
    serv->add_buffer_len = swServer_worker_add_buffer_len;
    serv->move_buffer = swServer_worker_move_buffer;
    serv->get_packet = swServer_worker_get_packet;

    SwooleG.serv = serv;
}

int swServer_create(swServer *serv)
{
    serv->factory.ptr = serv;

    serv->session_list = (swSession *) sw_shm_calloc(SW_SESSION_LIST_SIZE, sizeof(swSession));
    if (serv->session_list == nullptr)
    {
        swError("sw_shm_calloc(%ld) for session_list failed", SW_SESSION_LIST_SIZE * sizeof(swSession));
        return SW_ERR;
    }

    if (serv->enable_static_handler && serv->locations == nullptr)
    {
        serv->locations = new std::unordered_set<std::string>;
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
        swReactor_wait_exit(reactor, 1);
        for (auto ls : *serv->listen_list)
        {
            if (swSocket_is_stream(ls->type))
            {
                reactor->del(reactor, ls->socket);
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

    for (auto ls : *serv->listen_list)
    {
        swPort_free(ls);
    }
    delete serv->listen_list;
    serv->listen_list = nullptr;

    /**
     * because the swWorker in user_worker_list is the memory allocated by emalloc, 
     * the efree function will be called when the user process is destructed, 
     * so there's no need to call the efree here.
     */
    delete serv->user_worker_list;
    serv->user_worker_list = nullptr;

    if (serv->null_fd > 0)
    {
        close(serv->null_fd);
        serv->null_fd = -1;
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
    if (serv->locations)
    {
        delete serv->locations;
    }
    if (serv->http_index_files)
    {
        delete serv->http_index_files;
    }
    if (serv->chroot)
    {
        sw_free(serv->chroot);
        serv->chroot = nullptr;
    }
    if (serv->user)
    {
        sw_free(serv->user);
        serv->user = nullptr;
    }
    if (serv->group)
    {
        sw_free(serv->group);
        serv->group = nullptr;
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

    swSendData _send;
    sw_memset_zero(&_send, sizeof(_send));
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

    serv->connection_list[master_socket->fd].object = p;
    serv->connection_list[worker_socket->fd].object = p;

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
    sw_memset_zero(&_send.info, sizeof(_send.info));
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
    return factory->finish(factory, &_send);
}

/**
 * [Master] send to client or append to out_buffer
 */
int swServer_master_send(swServer *serv, swSendData *_send)
{
    uint32_t session_id = _send->info.fd;
    const char *_send_data = _send->data;
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
            swoole_set_last_error(SW_ERROR_OUTPUT_SEND_YIELD);
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
    /**
     * pause recv data
     */
    else if (_send->info.type == SW_SERVER_EVENT_PAUSE_RECV)
    {
        if (_socket->removed || !(_socket->events & SW_EVENT_READ))
        {
            return SW_OK;
        }
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
        if (!_socket->removed || (_socket->events & SW_EVENT_READ))
        {
            return SW_OK;
        }
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
                if (_socket->out_buffer == nullptr)
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
        if (chunk == nullptr)
        {
            return SW_ERR;
        }
        chunk->store.data.val1 = _send->info.type;
        conn->close_queued = 1;
    }
    //sendfile to client
    else if (_send->info.type == SW_SERVER_EVENT_SEND_FILE)
    {
        swSendFile_request *req = (swSendFile_request *) _send_data;
        if (swSocket_sendfile(conn->socket, req->filename, req->offset, req->length) < 0)
        {
            return SW_ERR;
        }
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
                swoole_set_last_error(SW_ERROR_OUTPUT_SEND_YIELD);
            }
            else
            {
                swoole_error_log(SW_LOG_WARNING, SW_ERROR_OUTPUT_BUFFER_OVERFLOW, "connection#%d output buffer overflow", fd);
            }
            conn->overflow = 1;
            if (serv->onBufferEmpty && serv->onBufferFull == nullptr)
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
    swDataHead notify_event = {};
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
    swSendData send_data = {};
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
    return swSocket_write_blocking(conn->socket, data, length);
}

static sw_inline swString *swServer_worker_get_input_buffer(swServer *serv, int reactor_id)
{
    swString **buffers = (swString **) SwooleWG.input_buffers;
    if (serv->factory_mode == SW_MODE_BASE)
    {
        return buffers[0];
    }
    else
    {
        return buffers[reactor_id];
    }
}

static sw_inline void swServer_server_worker_set_buffer(swServer *serv, swDataHead *info, swString *addr)
{
    swString **buffers = (swString **) SwooleWG.input_buffers;
    buffers[info->reactor_id] = addr;
}

static void* swServer_worker_get_buffer(swServer *serv, swDataHead *info)
{
    swString *worker_buffer = swServer_worker_get_input_buffer(serv, info->reactor_id);
    
    if (worker_buffer == nullptr)
    {
        worker_buffer = swString_new(info->len);
        swServer_server_worker_set_buffer(serv, info, worker_buffer);
    }

    return worker_buffer->str + worker_buffer->length;
}

static size_t swServer_worker_get_buffer_len(swServer *serv, swDataHead *info)
{
    swString *worker_buffer = swServer_worker_get_input_buffer(serv, info->reactor_id);

    return worker_buffer == nullptr ? 0 : worker_buffer->length;
}

static void swServer_worker_add_buffer_len(swServer *serv, swDataHead *info, size_t len)
{
    swString *worker_buffer = swServer_worker_get_input_buffer(serv, info->reactor_id);
    worker_buffer->length += len;
}

static void swServer_worker_move_buffer(swServer *serv, swPipeBuffer *buffer)
{
    swString *worker_buffer = swServer_worker_get_input_buffer(serv, buffer->info.reactor_id);
    memcpy(buffer->data, &worker_buffer, sizeof(worker_buffer));
    swServer_server_worker_set_buffer(serv, &buffer->info, nullptr);
}

static size_t swServer_worker_get_packet(swServer *serv, swEventData *req, char **data_ptr)
{
    size_t length;
    if (req->info.flags & SW_EVENT_DATA_PTR)
    {
        swPacket_ptr *task = (swPacket_ptr *) req;
        *data_ptr = task->data.str;
        length = task->data.length;
    }
    else if (req->info.flags & SW_EVENT_DATA_OBJ_PTR)
    {
        swString *worker_buffer;
        memcpy(&worker_buffer, req->data, sizeof(worker_buffer));
        *data_ptr = worker_buffer->str;
        length = worker_buffer->length;
    }
    else
    {
        *data_ptr = req->data;
        length = req->info.len;
    }

    return length;
}

SW_API void swServer_call_hook(swServer *serv, enum swServer_hook_type type, void *arg)
{
    swoole::hook_call(serv->hooks, type, arg);
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
    swDataHead ev = {};

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
    swSignal_add(SIGPIPE, nullptr);
    swSignal_add(SIGHUP, nullptr);
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
    swServer_set_minfd(sw_server(), SwooleG.signal_fd);
}

void swServer_master_onTimer(swTimer *timer, swTimer_node *tnode)
{
    swServer *serv = (swServer *) tnode->data;
    time_t now = time(nullptr);
    if (serv->scheduler_warning && serv->warning_time < now)
    {
        serv->scheduler_warning = 0;
        serv->warning_time = now;
        swoole_error_log(SW_LOG_WARNING, SW_ERROR_SERVER_NO_IDLE_WORKER, "No idle worker is available");
    }

    if (serv->gs->task_workers.scheduler_warning && serv->gs->task_workers.warning_time < now)
    {
        serv->gs->task_workers.scheduler_warning = 0;
        serv->gs->task_workers.warning_time = now;
        swoole_error_log(SW_LOG_WARNING, SW_ERROR_SERVER_NO_IDLE_WORKER, "No idle task worker is available");
    }

    if (serv->hooks[SW_SERVER_HOOK_MASTER_TIMER])
    {
        swServer_call_hook(serv, SW_SERVER_HOOK_MASTER_TIMER, serv);
    }
}

int swServer_add_worker(swServer *serv, swWorker *worker)
{
    if (serv->user_worker_list == nullptr)
    {
        serv->user_worker_list = new std::vector<swWorker *>;
    }
    serv->user_worker_num++;
    serv->user_worker_list->push_back(worker);

    if (!serv->user_worker_map)
    {
        serv->user_worker_map = swHashMap_new(SW_HASHMAP_INIT_BUCKET_N, nullptr);
    }

    return worker->id;
}

SW_API int swServer_add_hook(swServer *serv, enum swServer_hook_type type, swCallback func, int push_back)
{
    return swoole::hook_add(serv->hooks, (int) type, func, push_back);
}

static void swServer_check_port_type(swServer *serv, swListenPort *ls)
{
    if (swSocket_is_dgram(ls->type))
    {
        //dgram socket, setting socket buffer size
        swSocket_set_buffer_size(ls->socket, ls->socket_buffer_size);
        serv->have_dgram_sock = 1;
        serv->dgram_port_num++;
        if (ls->type == SW_SOCK_UDP)
        {
            serv->udp_socket_ipv4 = ls->socket->fd;
        }
        else if (ls->type == SW_SOCK_UDP6)
        {
            serv->udp_socket_ipv6 = ls->socket->fd;
        }
    }
    else
    {
        serv->have_stream_sock = 1;
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

    int n = swoole_get_systemd_listen_fds();
    if (n == 0)
    {
        return 0;
    }

    int count = 0;
    int sock;

    for (sock = SW_SYSTEMD_FDS_START; sock < SW_SYSTEMD_FDS_START + n; sock++)
    {
        swListenPort *ls = (swListenPort *) SwooleG.memory_pool->alloc(SwooleG.memory_pool, sizeof(swListenPort));
        if (ls == nullptr)
        {
            swWarn("alloc failed");
            return count;
        }

        if (swPort_set_address(ls, sock) < 0)
        {
            return count;
        }
        ls->host[SW_HOST_MAXSIZE - 1] = 0;

        //O_NONBLOCK & O_CLOEXEC
        swoole_fcntl_set_option(sock, 1, 1);
        ls->socket = swSocket_new(sock, swSocket_is_dgram(ls->type) ? SW_FD_DGRAM_SERVER : SW_FD_STREAM_SERVER);
        if (ls->socket == nullptr)
        {
            close(sock);
            return count;
        }
        swServer_check_port_type(serv, ls);

        serv->listen_list->push_back(ls);
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
        return nullptr;
    }
    if (!(type == SW_SOCK_UNIX_DGRAM || type == SW_SOCK_UNIX_STREAM) && (port < 0 || port > 65535))
    {
        swoole_error_log(SW_LOG_ERROR, SW_ERROR_SERVER_INVALID_LISTEN_PORT, "invalid port [%d]", port);
        return nullptr;
    }
    if (strlen(host) + 1  > SW_HOST_MAXSIZE)
    {
        swoole_error_log(SW_LOG_ERROR, SW_ERROR_NAME_TOO_LONG, "address '%s' exceeds %ld characters limit", host, SW_HOST_MAXSIZE - 1);
        return nullptr;
    }

    swListenPort *ls = (swListenPort *) SwooleG.memory_pool->alloc(SwooleG.memory_pool, sizeof(swListenPort));
    if (ls == nullptr)
    {
        swError("alloc failed");
        return nullptr;
    }

    swPort_init(ls);
    ls->type = type;
    ls->port = port;
    strncpy(ls->host, host, SW_HOST_MAXSIZE - 1);
    ls->host[SW_HOST_MAXSIZE - 1] = 0;

#ifdef SW_USE_OPENSSL
    if (type & SW_SOCK_SSL)
    {
        type = (enum swSocket_type) (type & (~SW_SOCK_SSL));
        ls->type = type;
        ls->ssl = 1;
        ls->ssl_config.prefer_server_ciphers = 1;
        ls->ssl_config.session_tickets = 0;
        ls->ssl_config.stapling = 1;
        ls->ssl_config.stapling_verify = 1;
        ls->ssl_config.ciphers = sw_strdup(SW_SSL_CIPHER_LIST);
        ls->ssl_config.ecdh_curve = sw_strdup(SW_SSL_ECDH_CURVE);

        if (swSocket_is_dgram(type))
        {
#ifdef SW_SUPPORT_DTLS
            ls->ssl_option.method = SW_DTLS_SERVER_METHOD;
            ls->ssl_option.dtls = 1;
            ls->dtls_sessions = new std::unordered_map<int, swoole::dtls::Session*>;

#else
            swWarn("DTLS support require openssl-1.1 or later");
            return nullptr;
#endif
        }
    }
#endif

    //create server socket
    int sock = swSocket_create(ls->type, 1, 1);
    if (sock < 0)
    {
        swSysWarn("create socket failed");
        return nullptr;
    }
#if defined(SW_SUPPORT_DTLS) && defined(HAVE_KQUEUE)
    if (ls->ssl_option.dtls)
    {
        int on = 1;
        setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &on, (socklen_t) sizeof(on));
    }
#endif
    ls->socket = swSocket_new(sock, swSocket_is_dgram(ls->type) ? SW_FD_DGRAM_SERVER : SW_FD_STREAM_SERVER);
    if (ls->socket == nullptr)
    {
        close(sock);
        return nullptr;
    }
    ls->socket->nonblock = 1;
    ls->socket->cloexec = 1;
    ls->socket->socket_type = ls->type;
    if (swSocket_bind(ls->socket, ls->host, &ls->port) < 0)
    {
        swSocket_free(ls->socket);
        return nullptr;
    }
    swServer_check_port_type(serv, ls);
    ls->socket_fd = ls->socket->fd;
    if (serv->listen_list == nullptr)
    {
        serv->listen_list = new std::vector<swListenPort *>;
    }
    serv->listen_list->push_back(ls);
    serv->listen_port_num++;
    return ls;
}

int swServer_get_socket(swServer *serv, int port)
{
    for (auto ls : *serv->listen_list)
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

    swServer *serv = sw_server();
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
        if (sw_server()->factory_mode == SW_MODE_BASE)
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
        if (sw_server()->factory_mode == SW_MODE_BASE)
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
            for (i = 0; i < sw_server()->worker_num + serv->task_worker_num + sw_server()->user_worker_num; i++)
            {
                worker = swServer_get_worker(sw_server(), i);
                swoole_kill(worker->pid, SIGRTMIN);
            }
            if (sw_server()->factory_mode == SW_MODE_PROCESS)
            {
                swoole_kill(serv->gs->manager_pid, SIGRTMIN);
            }
            swLog_reopen();
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
static swConnection* swServer_connection_new(swServer *serv, swListenPort *ls, swSocket *_socket, int server_fd)
{
    serv->stats->accept_count++;
    sw_atomic_fetch_add(&serv->stats->connection_num, 1);
    sw_atomic_fetch_add(&ls->connection_num, 1);
    time_t now;

    int fd = _socket->fd;
    if (fd > swServer_get_maxfd(serv))
    {
        swServer_set_maxfd(serv, fd);
    }
    else if (fd < swServer_get_minfd(serv))
    {
        swServer_set_minfd(serv, fd);
    }

    swConnection *connection = &(serv->connection_list[fd]);
    sw_memset_zero(connection, sizeof(*connection));
    _socket->object = connection;
    _socket->removed = 1;
    _socket->buffer_size = ls->socket_buffer_size;

    //TCP Nodelay
    if (ls->open_tcp_nodelay && (ls->type == SW_SOCK_TCP || ls->type == SW_SOCK_TCP6))
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

    now = time(nullptr);

    connection->fd = fd;
    connection->reactor_id = serv->factory_mode == SW_MODE_BASE ? SwooleWG.id : fd % serv->reactor_num;
    connection->server_fd = (sw_atomic_t) server_fd;
    connection->connect_time = now;
    connection->last_time = now;
    connection->active = 1;
    connection->socket_type = ls->type;
    connection->socket = _socket;

    memcpy(&connection->info.addr, &_socket->info.addr, _socket->info.len);
    connection->info.len = _socket->info.len;

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

void swServer_set_ipc_max_size(swServer *serv)
{
#ifdef HAVE_KQUEUE
    serv->ipc_max_size = SW_IPC_MAX_SIZE;
#else
    int bufsize;
    socklen_t _len = sizeof(bufsize);
    /**
     * Get the maximum ipc[unix socket with dgram] transmission length
     */
    if (getsockopt(serv->workers[0].pipe_master->fd, SOL_SOCKET, SO_SNDBUF, &bufsize, &_len) != 0)
    {
        bufsize = SW_IPC_MAX_SIZE;
    }
    serv->ipc_max_size = bufsize - SW_DGRAM_HEADER_SIZE;
#endif
}

/**
 * allocate memory for swServer::pipe_buffers
 */
int swServer_create_pipe_buffers(swServer *serv)
{
    serv->pipe_buffers = (swPipeBuffer **) sw_calloc(serv->reactor_num, sizeof(swPipeBuffer *));
    if (serv->pipe_buffers == nullptr)
    {
        swSysError("malloc[buffers] failed");
        return SW_ERR;
    }
    for (uint32_t i = 0; i < serv->reactor_num; i++)
    {
        serv->pipe_buffers[i] = (swPipeBuffer *) sw_malloc(serv->ipc_max_size);
        if (serv->pipe_buffers[i] == nullptr)
        {
            swSysError("malloc[sndbuf][%d] failed", i);
            return SW_ERR;
        }
        sw_memset_zero(serv->pipe_buffers[i], sizeof(swDataHead));
    }

    return SW_OK;
}

int swServer_worker_idle_num(swServer *serv)
{
    uint32_t i;
    uint32_t worker_num = serv->worker_num;
    uint32_t idle_worker_num = 0;

    for (i = 0; i < worker_num; i++)
    {
        swWorker *worker = swServer_get_worker(serv, i);
        if (worker->status == SW_WORKER_IDLE)
        {
            idle_worker_num++;
        }
    }

    return idle_worker_num;
}

int swServer_task_worker_idle_num(swServer *serv)
{
    uint32_t i;
    uint32_t worker_num = serv->worker_num;
    uint32_t task_worker_num = serv->task_worker_num;
    uint32_t idle_worker_num = 0;

    for (i = worker_num; i < (worker_num + task_worker_num); i++)
    {
        swWorker *worker = swServer_get_worker(serv, i);
        if (worker->status == SW_WORKER_IDLE)
        {
            idle_worker_num++;
        }
    }

    return idle_worker_num;
}
