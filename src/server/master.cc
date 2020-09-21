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

#include "swoole_server.h"
#include "swoole_memory.h"
#include "swoole_log.h"
#include "swoole_http.h"
#include "swoole_lock.h"

#include <assert.h>

using namespace swoole;
using swoole::network::Address;
using swoole::network::Socket;
using swoole::network::SendfileTask;

Server *g_server_instance = nullptr;

static void Server_signal_handler(int sig);

static void **Server_worker_create_buffers(Server *serv, uint32_t buffer_num);
static void Server_worker_free_buffers(Server *serv, uint32_t buffer_num, void **buffers);
static void *Server_worker_get_buffer(Server *serv, DataHead *info);
static size_t Server_worker_get_buffer_len(Server *serv, DataHead *info);
static void Server_worker_add_buffer_len(Server *serv, DataHead *info, size_t len);
static void Server_worker_move_buffer(Server *serv, PipeBuffer *buffer);
static size_t Server_worker_get_packet(Server *serv, EventData *req, char **data_ptr);

void Server::disable_accept() {
    enable_accept_timer = swoole_timer_add(
        SW_ACCEPT_RETRY_TIME * 1000,
        false,
        [](Timer *timer, TimerNode *tnode) {
            Server *serv = (Server *) tnode->data;
            for (auto port : serv->ports) {
                if (port->is_dgram()) {
                    continue;
                }
                swoole_event_add(port->socket, SW_EVENT_READ);
            }
            serv->enable_accept_timer = nullptr;
        },
        this);

    if (enable_accept_timer == nullptr) {
        return;
    }

    for (auto port : ports) {
        if (port->is_dgram()) {
            continue;
        }
        swoole_event_del(port->socket);
    }
}

void Server::close_port(bool only_stream_port) {
    for (auto port : ports) {
        if (only_stream_port && port->is_dgram()) {
            continue;
        }
        if (port->socket) {
            port->socket->free();
            port->socket = nullptr;
        }
    }
}

int Server::accept_connection(Reactor *reactor, Event *event) {
    Server *serv = (Server *) reactor->ptr;
    ListenPort *listen_host = serv->get_port_by_server_fd(event->fd);

    for (int i = 0; i < SW_ACCEPT_MAX_COUNT; i++) {
        Socket *sock = event->socket->accept();
        if (sock == nullptr) {
            switch (errno) {
            case EAGAIN:
                return SW_OK;
            case EINTR:
                continue;
            default:
                if (errno == EMFILE || errno == ENFILE) {
                    serv->disable_accept();
                }
                swSysWarn("accept() failed");
                return SW_OK;
            }
        }

        swTrace("[Master] Accept new connection. maxfd=%d|minfd=%d|reactor_id=%d|conn=%d",
                serv->get_maxfd(),
                serv->get_minfd(),
                reactor->id,
                sock->fd);

        // too many connection
        if (sock->fd >= (int) serv->max_connection) {
            swoole_error_log(
                SW_LOG_WARNING, SW_ERROR_SERVER_TOO_MANY_SOCKET, "Too many connections [now: %d]", sock->fd);
            sock->free();
            serv->disable_accept();
            return SW_OK;
        }

        // add to connection_list
        Connection *conn = serv->add_connection(listen_host, sock, event->fd);
        if (conn == nullptr) {
            sock->free();
            return SW_OK;
        }
        sock->chunk_size = SW_SEND_BUFFER_SIZE;

#ifdef SW_USE_OPENSSL
        if (listen_host->ssl) {
            if (swSSL_create(sock, listen_host->ssl_context, SW_SSL_SERVER) < 0) {
                reactor->close(reactor, sock);
                return SW_OK;
            } else {
                conn->ssl = 1;
            }
        } else {
            sock->ssl = nullptr;
        }
#endif
        if (serv->single_thread) {
            if (serv->connection_incoming(reactor, conn) < 0) {
                reactor->close(reactor, sock);
                return SW_OK;
            }
        } else {
            DataHead ev = {};
            ev.type = SW_SERVER_EVENT_INCOMING;
            ev.fd = sock->fd;
            Socket *_pipe_sock = serv->get_reactor_thread_pipe(conn->session_id, conn->reactor_id);
            if (reactor->write(reactor, _pipe_sock, &ev, sizeof(ev)) < 0) {
                reactor->close(reactor, sock);
                return SW_OK;
            }
        }
    }

    return SW_OK;
}

int Server::connection_incoming(Reactor *reactor, Connection *conn) {
    if (heartbeat_idle_time > 0) {
        add_heartbeat_check_timer(reactor, conn);
    }
#ifdef SW_USE_OPENSSL
    if (conn->socket->ssl) {
        return reactor->add(reactor, conn->socket, SW_EVENT_READ);
    }
#endif
    // delay receive, wait resume command
    if (!enable_delay_receive) {
        if (reactor->add(reactor, conn->socket, SW_EVENT_READ) < 0) {
            return SW_ERR;
        }
    }
    // notify worker process
    if (onConnect) {
        if (!notify(conn, SW_SERVER_EVENT_CONNECT)) {
            return SW_ERR;
        }
    }
    return SW_OK;
}

void Server::add_heartbeat_check_timer(Reactor *reactor, Connection *conn) {
    if (conn->protect) {
        return;
    }
    if (conn->socket->recv_timer) {
        swoole_timer_delay(conn->socket->recv_timer, heartbeat_idle_time * 1000);
        return;
    }
    conn->socket->recv_timer = swoole_timer_add(heartbeat_idle_time * 1000, false, [this, conn, reactor](Timer *, TimerNode *) {
        if (disable_notify || conn->close_force) {
            Server::close_connection(reactor, conn->socket);
            return;
        }

        conn->close_force = 1;
        Event _ev = {};
        _ev.fd = conn->fd;
        _ev.socket = conn->socket;
        reactor->trigger_close_event(&_ev);
    });
}

#ifdef SW_SUPPORT_DTLS
dtls::Session *Server::accept_dtls_connection(swListenPort *port, Address *sa) {
    dtls::Session *session = nullptr;
    Connection *conn = nullptr;

    Socket *sock = swoole::make_socket(port->type, SW_FD_SESSION, SW_SOCK_CLOEXEC | SW_SOCK_NONBLOCK);
    if (!sock) {
        return nullptr;
    }

    int fd = sock->fd;
    int on = 1, off = 0;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void *) &on, (socklen_t) sizeof(on));
#ifdef HAVE_KQUEUE
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, (const void *) &on, (socklen_t) sizeof(on));
#endif

    switch (port->type) {
    case SW_SOCK_UDP: {
        if (inet_pton(AF_INET, port->host, &port->socket->info.addr.inet_v4.sin_addr) < 0) {
            swSysWarn("inet_pton(AF_INET, %s) failed", port->host);
            goto _cleanup;
        }
        port->socket->info.addr.inet_v4.sin_port = htons(port->port);
        port->socket->info.addr.inet_v4.sin_family = AF_INET;

        if (bind(fd, (const struct sockaddr *) &port->socket->info.addr, sizeof(struct sockaddr_in))) {
            swSysWarn("bind() failed");
            goto _cleanup;
        }
        if (connect(fd, (struct sockaddr *) &sa->addr, sizeof(struct sockaddr_in))) {
            swSysWarn("connect() failed");
            goto _cleanup;
        }
        break;
    }
    case SW_SOCK_UDP6: {
        if (inet_pton(AF_INET6, port->host, &port->socket->info.addr.inet_v6.sin6_addr) < 0) {
            swSysWarn("inet_pton(AF_INET6, %s) failed", port->host);
            goto _cleanup;
        }
        port->socket->info.addr.inet_v6.sin6_port = htons(port->port);
        port->socket->info.addr.inet_v6.sin6_family = AF_INET6;

        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (char *) &off, sizeof(off));
        if (bind(fd, (const struct sockaddr *) &port->socket->info.addr, sizeof(struct sockaddr_in6))) {
            swSysWarn("bind() failed");
            goto _cleanup;
        }
        if (connect(fd, (struct sockaddr *) &sa->addr, sizeof(struct sockaddr_in6))) {
            swSysWarn("connect() failed");
            goto _cleanup;
        }
        break;
    }
    default:
        OPENSSL_assert(0);
        break;
    }

    memcpy(&sock->info, sa, sizeof(*sa));
    sock->chunk_size = SW_BUFFER_SIZE_STD;

    conn = add_connection(port, sock, port->socket->fd);
    if (conn == nullptr) {
        goto _cleanup;
    }

    session = new dtls::Session(sock, port->ssl_context);
    port->dtls_sessions->emplace(fd, session);

    if (!session->init()) {
        goto _cleanup;
    }

    return session;

_cleanup:
    if (conn) {
        sw_memset_zero(conn, sizeof(*conn));
    }
    if (session) {
        delete session;
    }
    sock->free();
    return nullptr;
}
#endif

void Server::set_max_connection(uint32_t _max_connection) {
    if (connection_list != nullptr) {
        swWarn("max_connection must be set before server create");
        return;
    }
    max_connection = _max_connection;
    if (max_connection == 0) {
        max_connection = SW_MIN(SW_MAX_CONNECTION, SwooleG.max_sockets);
    } else if (max_connection > SW_SESSION_LIST_SIZE) {
        max_connection = SW_SESSION_LIST_SIZE;
        swWarn("max_connection is exceed the SW_SESSION_LIST_SIZE, it's reset to %u", SW_SESSION_LIST_SIZE);
    }
    if (SwooleG.max_sockets > 0 && max_connection > SwooleG.max_sockets) {
        max_connection = SwooleG.max_sockets;
        swWarn("max_connection is exceed the maximum value, it's reset to %u", SwooleG.max_sockets);
    }
}

int Server::start_check() {
    // disable notice when use SW_DISPATCH_ROUND and SW_DISPATCH_QUEUE
    if (is_process_mode()) {
        if (!is_support_unsafe_events()) {
            if (onConnect) {
                swWarn("cannot set 'onConnect' event when using dispatch_mode=1/3/7");
                onConnect = nullptr;
            }
            if (onClose) {
                swWarn("cannot set 'onClose' event when using dispatch_mode=1/3/7");
                onClose = nullptr;
            }
            if (onBufferFull) {
                swWarn("cannot set 'onBufferFull' event when using dispatch_mode=1/3/7");
                onBufferFull = nullptr;
            }
            if (onBufferEmpty) {
                swWarn("cannot set 'onBufferEmpty' event when using dispatch_mode=1/3/7");
                onBufferEmpty = nullptr;
            }
            disable_notify = 1;
        }
        if (!is_support_send_yield()) {
            send_yield = 0;
        }
    } else {
        max_queued_bytes = 0;
    }
    if (task_worker_num > 0) {
        if (onTask == nullptr) {
            swWarn("onTask event callback must be set");
            return SW_ERR;
        }
    }
    for (auto ls : ports) {
        if (ls->protocol.package_max_length < SW_BUFFER_MIN_SIZE) {
            ls->protocol.package_max_length = SW_BUFFER_MIN_SIZE;
        }
        if (if_require_receive_callback(ls, onReceive != nullptr)) {
            swWarn("require onReceive callback");
            return SW_ERR;
        }
        if (if_require_packet_callback(ls, onPacket != nullptr)) {
            swWarn("require onPacket callback");
            return SW_ERR;
        }
    }
#ifdef SW_USE_OPENSSL
    /**
     * OpenSSL thread-safe
     */
    if (is_base_mode()) {
        swSSL_init_thread_safety();
    }
#endif

    return SW_OK;
}

void Server::store_listen_socket() {
    for (auto ls : ports) {
        int sockfd = ls->socket->fd;
        // save server socket to connection_list
        connection_list[sockfd].fd = sockfd;
        connection_list[sockfd].socket = ls->socket;
        connection_list[sockfd].socket_type = ls->type;
        connection_list[sockfd].object = ls;
        connection_list[sockfd].info.assign(ls->type, ls->host, ls->port);
        if (sockfd >= 0) {
            set_minfd(sockfd);
            set_maxfd(sockfd);
        }
    }
}

static void **Server_worker_create_buffers(Server *serv, uint32_t buffer_num) {
    swString **buffers = (swString **) sw_malloc(sizeof(swString *) * buffer_num);
    if (buffers == nullptr) {
        swError("malloc for worker input_buffers failed");
    }

    for (uint i = 0; i < buffer_num; i++) {
        buffers[i] = swString_new(SW_BUFFER_SIZE_BIG);
        if (buffers[i] == nullptr) {
            swError("worker input_buffers init failed");
        }
    }

    return (void **) buffers;
}

static void Server_worker_free_buffers(Server *serv, uint32_t buffer_num, void **buffers) {
    for (uint i = 0; i < buffer_num; i++) {
        swString_free((swString *) buffers[i]);
    }
    sw_free(buffers);
}

/**
 * only the memory of the Worker structure is allocated, no process is fork
 */
int Server::create_task_workers() {
    key_t key = 0;
    int ipc_mode;

    if (task_ipc_mode == SW_TASK_IPC_MSGQUEUE || task_ipc_mode == SW_TASK_IPC_PREEMPTIVE) {
        key = message_queue_key;
        ipc_mode = SW_IPC_MSGQUEUE;
    } else if (task_ipc_mode == SW_TASK_IPC_STREAM) {
        ipc_mode = SW_IPC_SOCKET;
    } else {
        ipc_mode = SW_IPC_UNIXSOCK;
    }

    ProcessPool *pool = &gs->task_workers;
    if (ProcessPool::create(pool, task_worker_num, key, ipc_mode) < 0) {
        swWarn("[Master] create task_workers failed");
        return SW_ERR;
    }

    pool->set_max_request(task_max_request, task_max_request_grace);
    pool->set_start_id(worker_num);
    pool->set_type(SW_PROCESS_TASKWORKER);

    if (ipc_mode == SW_IPC_SOCKET) {
        char sockfile[sizeof(struct sockaddr_un)];
        snprintf(sockfile, sizeof(sockfile), "/tmp/swoole.task.%d.sock", gs->master_pid);
        if (gs->task_workers.create_unix_socket(sockfile, 2048) < 0) {
            return SW_ERR;
        }
    }

    init_task_workers();

    return SW_OK;
}

/**
 * @description:
 *  only the memory of the Worker structure is allocated, no process is fork.
 *  called when the manager process start.
 * @param Server
 * @return: SW_OK|SW_ERR
 */
int Server::create_user_workers() {
    /**
     * if Swoole\Server::addProcess is called first,
     * Server::user_worker_list is initialized in the Server_add_worker function
     */
    if (user_worker_list == nullptr) {
        user_worker_list = new std::vector<Worker *>;
    }

    user_workers = (Worker *) sw_shm_calloc(user_worker_num, sizeof(Worker));
    if (user_workers == nullptr) {
        swSysWarn("gmalloc[server->user_workers] failed");
        return SW_ERR;
    }

    return SW_OK;
}

/**
 * [Master]
 */
int Server::create_worker(Worker *worker) {
    return swMutex_create(&worker->lock, SW_MUTEX_PROCESS_SHARED);
}

/**
 * [Worker]
 */
void Server::init_worker(Worker *worker) {
#ifdef HAVE_CPU_AFFINITY
    if (open_cpu_affinity) {
        cpu_set_t cpu_set;
        CPU_ZERO(&cpu_set);
        if (cpu_affinity_available_num) {
            CPU_SET(cpu_affinity_available[SwooleG.process_id % cpu_affinity_available_num], &cpu_set);
        } else {
            CPU_SET(SwooleG.process_id % SW_CPU_NUM, &cpu_set);
        }
        if (swoole_set_cpu_affinity(&cpu_set) < 0) {
            swSysWarn("swoole_set_cpu_affinity() failed");
        }
    }
#endif
    // signal init
    worker_signal_init();

    worker_input_buffers = (void **) create_buffers(this, get_worker_buffer_num());
    if (!worker_input_buffers) {
        swError("failed to create worker buffers");
    }

    if (max_request < 1) {
        SwooleWG.run_always = true;
    } else {
        SwooleWG.max_request = max_request;
        if (max_request_grace > 0) {
            SwooleWG.max_request += swoole_system_random(1, max_request_grace);
        }
    }

    worker->start_time = ::time(nullptr);
    worker->request_count = 0;
}

void Server::call_worker_start_callback(Worker *worker) {
    void *hook_args[2];
    hook_args[0] = this;
    hook_args[1] = (void *) (uintptr_t) worker->id;

    if (SwooleG.hooks[SW_GLOBAL_HOOK_BEFORE_WORKER_START]) {
        swoole_call_hook(SW_GLOBAL_HOOK_BEFORE_WORKER_START, hook_args);
    }
    if (hooks[Server::HOOK_WORKER_START]) {
        call_hook(Server::HOOK_WORKER_START, hook_args);
    }
    if (onWorkerStart) {
        onWorkerStart(this, worker->id);
    }
}

int Server::start() {
    if (start_check() < 0) {
        return SW_ERR;
    }
    if (SwooleG.hooks[SW_GLOBAL_HOOK_BEFORE_SERVER_START]) {
        swoole_call_hook(SW_GLOBAL_HOOK_BEFORE_SERVER_START, this);
    }
    // cannot start 2 servers at the same time, please use process->exec.
    if (!sw_atomic_cmp_set(&gs->start, 0, 1)) {
        swoole_error_log(SW_LOG_ERROR, SW_ERROR_SERVER_ONLY_START_ONE, "must only start one server");
        return SW_ERR;
    }
    // run as daemon
    if (daemonize > 0) {
        /**
         * redirect STDOUT to log file
         */
        if (sw_logger()->is_opened()) {
            sw_logger()->redirect_stdout_and_stderr(1);
        }
        /**
         * redirect STDOUT_FILENO/STDERR_FILENO to /dev/null
         */
        else {
            null_fd = open("/dev/null", O_WRONLY);
            if (null_fd > 0) {
                swoole_redirect_stdout(null_fd);
            } else {
                swSysWarn("open(/dev/null) failed");
            }
        }

        if (swoole_daemon(0, 1) < 0) {
            return SW_ERR;
        }
    }

    // master pid
    gs->master_pid = getpid();
    gs->start_time = ::time(nullptr);

    /**
     * store to swProcessPool object
     */
    gs->event_workers.ptr = this;
    gs->event_workers.workers = workers;
    gs->event_workers.worker_num = worker_num;
    gs->event_workers.use_msgqueue = 0;

    uint32_t i;
    for (i = 0; i < worker_num; i++) {
        gs->event_workers.workers[i].pool = &gs->event_workers;
        gs->event_workers.workers[i].id = i;
        gs->event_workers.workers[i].type = SW_PROCESS_WORKER;
    }

    /*
     * For swoole_server->taskwait, create notify pipe and result shared memory.
     */
    if (task_worker_num > 0 && worker_num > 0) {
        task_result = (EventData *) sw_shm_calloc(worker_num, sizeof(EventData));
        if (!task_result) {
            swWarn("malloc[task_result] failed");
            return SW_ERR;
        }
        task_notify = (swPipe *) sw_calloc(worker_num, sizeof(swPipe));
        if (!task_notify) {
            swWarn("malloc[task_notify] failed");
            sw_shm_free(task_result);
            return SW_ERR;
        }
        for (i = 0; i < worker_num; i++) {
            if (swPipeNotify_auto(&task_notify[i], 1, 0)) {
                sw_shm_free(task_result);
                sw_free(task_notify);
                return SW_ERR;
            }
        }
    }

    /**
     * user worker process
     */
    if (user_worker_list) {
        i = 0;
        for (auto worker : *user_worker_list) {
            worker->id = worker_num + task_worker_num + i;
            i++;
        }
    }
    running = true;
    // factory start
    if (factory.start(&factory) < 0) {
        return SW_ERR;
    }
    init_signal_handler();

    // write PID file
    if (!pid_file.empty()) {
        size_t n = sw_snprintf(SwooleTG.buffer_stack->str, SwooleTG.buffer_stack->size, "%d", getpid());
        swoole_file_put_contents(pid_file.c_str(), SwooleTG.buffer_stack->str, n);
    }
    int ret;
    if (is_base_mode()) {
        ret = start_reactor_processes();
    } else {
        ret = start_reactor_threads();
    }
    // failed to start
    if (ret < 0) {
        return SW_ERR;
    }
    destroy();
    // remove PID file
    if (!pid_file.empty()) {
        unlink(pid_file.c_str());
    }
    return SW_OK;
}

/**
 * initializing server config, set default
 */
Server::Server(enum Mode _mode) {
    swoole_init();

    reactor_num = SW_REACTOR_NUM > SW_REACTOR_MAX_THREAD ? SW_REACTOR_MAX_THREAD : SW_REACTOR_NUM;

    worker_num = SW_CPU_NUM;
    max_connection = SW_MIN(SW_MAX_CONNECTION, SwooleG.max_sockets);
    mode_ = _mode;

    // http server
#ifdef SW_HAVE_COMPRESSION
    http_compression = 1;
    http_compression_level = SW_Z_BEST_SPEED;
#endif

#ifdef __linux__
    timezone_ = timezone;
#else
    struct timezone tz;
    struct timeval tv;
    gettimeofday(&tv, &tz);
    timezone_ = tz.tz_minuteswest * 60;
#endif

    /**
     * alloc shared memory
     */
    gs = (ServerGS *) sw_shm_malloc(sizeof(ServerGS));
    if (gs == nullptr) {
        swError("[Master] Fatal Error: failed to allocate memory for Server->gs");
    }
    /**
     * init method
     */
    create_buffers = Server_worker_create_buffers;
    free_buffers = Server_worker_free_buffers;
    get_buffer = Server_worker_get_buffer;
    get_buffer_len = Server_worker_get_buffer_len;
    add_buffer_len = Server_worker_add_buffer_len;
    move_buffer = Server_worker_move_buffer;
    get_packet = Server_worker_get_packet;

    g_server_instance = this;
}

Server::~Server() {
    if (!is_shutdown() && getpid() == gs->master_pid) {
        destroy();
    }
    for (auto port : ports) {
        delete port;
    }
    sw_shm_free(gs);
}

int Server::create() {
    factory.ptr = this;

    session_list = (Session *) sw_shm_calloc(SW_SESSION_LIST_SIZE, sizeof(Session));
    if (session_list == nullptr) {
        swError("sw_shm_calloc(%ld) for session_list failed", SW_SESSION_LIST_SIZE * sizeof(Session));
        return SW_ERR;
    }

    port_connnection_num_list = (uint32_t *) sw_shm_calloc(ports.size(), sizeof(sw_atomic_t));
    if (port_connnection_num_list == nullptr) {
        swError("sw_shm_calloc() for port_connnection_num_array failed");
        return SW_ERR;
    }

    int index = 0;
    for (auto port : ports) {
        port->connection_num = &port_connnection_num_list[index++];
    }

    if (enable_static_handler and locations == nullptr) {
        locations = new std::unordered_set<std::string>;
    }

    // Max Connections
    uint32_t minimum_connection = (worker_num + task_worker_num) * 2 + 32;
    if (ports.size() > 0) {
        minimum_connection += ports.back()->socket_fd;
    }
    if (max_connection < minimum_connection) {
        max_connection = SwooleG.max_sockets;
        swWarn("max_connection must be bigger than %u, it's reset to %u", minimum_connection, SwooleG.max_sockets);
    }
    // Reactor Thread Num
    if (reactor_num > SW_CPU_NUM * SW_MAX_THREAD_NCPU) {
        swWarn("serv->reactor_num == %d, Too many threads, reset to max value %d", reactor_num,
               SW_CPU_NUM * SW_MAX_THREAD_NCPU);
        reactor_num = SW_CPU_NUM * SW_MAX_THREAD_NCPU;
    } else if (reactor_num == 0) {
        reactor_num = SW_CPU_NUM;
    }
    if (single_thread) {
        reactor_num = 1;
    }
    // Worker Process Num
    if (worker_num > SW_CPU_NUM * SW_MAX_WORKER_NCPU) {
        swWarn("worker_num == %d, Too many processes, reset to max value %d", worker_num,
               SW_CPU_NUM * SW_MAX_WORKER_NCPU);
        worker_num = SW_CPU_NUM * SW_MAX_WORKER_NCPU;
    }
    if (worker_num < reactor_num) {
        reactor_num = worker_num;
    }
    // TaskWorker Process Num
    if (task_worker_num > 0) {
        if (task_worker_num > SW_CPU_NUM * SW_MAX_WORKER_NCPU) {
            swWarn("serv->task_worker_num == %d, Too many processes, reset to max value %d", task_worker_num,
                   SW_CPU_NUM * SW_MAX_WORKER_NCPU);
            task_worker_num = SW_CPU_NUM * SW_MAX_WORKER_NCPU;
        }
    }
    workers = (Worker *) sw_shm_calloc(worker_num, sizeof(Worker));
    if (workers == nullptr) {
        swSysWarn("gmalloc[server->workers] failed");
        return SW_ERR;
    }

    if (is_base_mode()) {
        return create_reactor_processes();
    } else {
        return create_reactor_threads();
    }
}

void Server::clear_timer() {
    if (master_timer) {
        swoole_timer_del(master_timer);
        master_timer = nullptr;
    }
    if (heartbeat_timer) {
        swoole_timer_del(heartbeat_timer);
        heartbeat_timer = nullptr;
    }
    if (enable_accept_timer) {
        swoole_timer_del(enable_accept_timer);
        enable_accept_timer = nullptr;
    }
}

void Server::shutdown() {
    if (getpid() != gs->master_pid) {
        kill(gs->master_pid, SIGTERM);
        return;
    }
    running = false;
    // stop all thread
    if (SwooleTG.reactor) {
        swReactor *reactor = SwooleTG.reactor;
        reactor->set_wait_exit(true);
        for (auto port : ports) {
            if (port->is_dgram() and is_process_mode()) {
                continue;
            }
            reactor->del(reactor, port->socket);
        }
        clear_timer();
    }

    if (is_base_mode()) {
        gs->event_workers.running = 0;
    }

    swInfo("Server is shutdown now");
}

void Server::destroy() {
    swTraceLog(SW_TRACE_SERVER, "release service");
    if (SwooleG.hooks[SW_GLOBAL_HOOK_BEFORE_SERVER_SHUTDOWN]) {
        swoole_call_hook(SW_GLOBAL_HOOK_BEFORE_SERVER_SHUTDOWN, this);
    }
    /**
     * shutdown workers
     */
    if (factory.shutdown) {
        factory.shutdown(&(factory));
    }
    if (is_base_mode()) {
        swTraceLog(SW_TRACE_SERVER, "terminate task workers");
        if (task_worker_num > 0) {
            gs->task_workers.shutdown();
            gs->task_workers.destroy();
        }
    } else {
        swTraceLog(SW_TRACE_SERVER, "terminate reactor threads");
        /**
         * Wait until all the end of the thread
         */
        join_reactor_thread();
    }

    for (auto port : ports) {
        port->close();
    }

    /**
     * because the Worker in user_worker_list is the memory allocated by emalloc,
     * the efree function will be called when the user process is destructed,
     * so there's no need to call the efree here.
     */
    if (user_worker_list) {
        delete user_worker_list;
        user_worker_list = nullptr;
    }
    if (user_workers) {
        sw_shm_free(user_workers);
        user_workers = nullptr;
    }
    if (null_fd > 0) {
        ::close(null_fd);
        null_fd = -1;
    }
    swSignal_clear();
    /**
     * shutdown status
     */
    gs->start = 0;
    gs->shutdown = 1;
    /**
     * callback
     */
    if (onShutdown) {
        onShutdown(this);
    }
    if (is_base_mode()) {
        destroy_reactor_processes();
    } else {
        destroy_reactor_threads();
    }
    if (locations) {
        delete locations;
    }
    if (http_index_files) {
        delete http_index_files;
    }
    for (auto i = 0; i < SW_MAX_HOOK_TYPE; i++) {
        if (hooks[i]) {
            std::list<swCallback> *l = reinterpret_cast<std::list<swCallback> *>(hooks[i]);
            hooks[i] = nullptr;
            delete l;
        }
    }

    sw_shm_free(session_list);
    sw_shm_free(port_connnection_num_list);
    sw_shm_free(workers);

    session_list = nullptr;
    port_connnection_num_list = nullptr;
    workers = nullptr;

    g_server_instance = nullptr;
}

/**
 * worker to master process
 */
bool Server::feedback(int session_id, int event) {
    Connection *conn = get_connection_verify(session_id);
    if (!conn) {
        return false;
    }

    SendData _send;
    sw_memset_zero(&_send, sizeof(_send));
    _send.info.type = event;
    _send.info.fd = session_id;
    _send.info.reactor_id = conn->reactor_id;

    if (is_process_mode()) {
        return send_to_reactor_thread((EventData *) &_send.info, sizeof(_send.info), session_id) > 0;
    } else {
        return send_to_connection(&_send) == SW_OK;
    }
}

void Server::store_pipe_fd(swPipe *p) {
    Socket *master_socket = p->getSocket(p, SW_PIPE_MASTER);
    Socket *worker_socket = p->getSocket(p, SW_PIPE_WORKER);

    connection_list[master_socket->fd].object = p;
    connection_list[worker_socket->fd].object = p;

    if (master_socket->fd > get_maxfd()) {
        set_maxfd(master_socket->fd);
    }
    if (worker_socket->fd > get_maxfd()) {
        set_maxfd(worker_socket->fd);
    }
}

/**
 * @process Worker
 * @return SW_OK or SW_ERR
 */
bool Server::send(int session_id, const void *data, uint32_t length) {
    SendData _send;
    sw_memset_zero(&_send.info, sizeof(_send.info));

    if (sw_unlikely(swIsMaster())) {
        swoole_error_log(
            SW_LOG_ERROR, SW_ERROR_SERVER_SEND_IN_MASTER, "can't send data to the connections in master process");
        return false;
    }

    _send.info.fd = session_id;
    _send.info.type = SW_SERVER_EVENT_RECV_DATA;
    _send.data = (char *) data;
    _send.info.len = length;
    return factory.finish(&factory, &_send);
}

/**
 * [Master] send to client or append to out_buffer
 * @return SW_OK or SW_ERR
 */
int Server::send_to_connection(SendData *_send) {
    uint32_t session_id = _send->info.fd;
    const char *_send_data = _send->data;
    uint32_t _send_length = _send->info.len;

    Connection *conn;
    if (_send->info.type != SW_SERVER_EVENT_CLOSE) {
        conn = get_connection_verify(session_id);
    } else {
        conn = get_connection_verify_no_ssl(session_id);
    }
    if (!conn) {
        if (_send->info.type == SW_SERVER_EVENT_RECV_DATA) {
            swoole_error_log(SW_LOG_NOTICE,
                             SW_ERROR_SESSION_NOT_EXIST,
                             "send %d byte failed, session#%d does not exist",
                             _send_length,
                             session_id);
        } else {
            swoole_error_log(SW_LOG_NOTICE,
                             SW_ERROR_SESSION_NOT_EXIST,
                             "send event$[%d] failed, session#%d does not exist",
                             _send->info.type,
                             session_id);
        }
        return SW_ERR;
    }

    int fd = conn->fd;
    swReactor *reactor = SwooleTG.reactor;

    if (!single_thread) {
        assert(fd % reactor_num == reactor->id);
        assert(fd % reactor_num == SwooleTG.id);
    }

    if (is_base_mode() && conn->overflow) {
        if (send_yield) {
            swoole_set_last_error(SW_ERROR_OUTPUT_SEND_YIELD);
        } else {
            swoole_error_log(
                SW_LOG_WARNING, SW_ERROR_OUTPUT_BUFFER_OVERFLOW, "connection#%d output buffer overflow", fd);
        }
        return SW_ERR;
    }

    Socket *_socket = conn->socket;

    /**
     * Reset send buffer, Immediately close the connection.
     */
    if (_send->info.type == SW_SERVER_EVENT_CLOSE && (conn->close_reset || conn->peer_closed)) {
        goto _close_fd;
    }
    /**
     * pause recv data
     */
    else if (_send->info.type == SW_SERVER_EVENT_PAUSE_RECV) {
        if (_socket->removed || !(_socket->events & SW_EVENT_READ)) {
            return SW_OK;
        }
        if (_socket->events & SW_EVENT_WRITE) {
            return reactor->set(reactor, conn->socket, SW_EVENT_WRITE);
        } else {
            return reactor->del(reactor, conn->socket);
        }
    }
    /**
     * resume recv data
     */
    else if (_send->info.type == SW_SERVER_EVENT_RESUME_RECV) {
        if (!_socket->removed || (_socket->events & SW_EVENT_READ)) {
            return SW_OK;
        }
        if (_socket->events & SW_EVENT_WRITE) {
            return reactor->set(reactor, _socket, SW_EVENT_READ | SW_EVENT_WRITE);
        } else {
            return reactor->add(reactor, _socket, SW_EVENT_READ);
        }
    }

    if (Buffer::empty(_socket->out_buffer)) {
        /**
         * close connection.
         */
        if (_send->info.type == SW_SERVER_EVENT_CLOSE) {
        _close_fd:
            reactor->close(reactor, _socket);
            return SW_OK;
        }
        // Direct send
        if (_send->info.type != SW_SERVER_EVENT_SEND_FILE) {
            if (!_socket->direct_send) {
                goto _buffer_send;
            }

            ssize_t n;

        _direct_send:
            n = _socket->send(_send_data, _send_length, 0);
            if (n == _send_length) {
                return SW_OK;
            } else if (n > 0) {
                _send_data += n;
                _send_length -= n;
                goto _buffer_send;
            } else if (errno == EINTR) {
                goto _direct_send;
            } else {
                goto _buffer_send;
            }
        }
        // buffer send
        else {
        _buffer_send:
            if (!_socket->out_buffer) {
                _socket->out_buffer = new Buffer(SW_SEND_BUFFER_SIZE);
            }
        }
    }

    BufferChunk *chunk;
    // close connection
    if (_send->info.type == SW_SERVER_EVENT_CLOSE) {
        chunk = _socket->out_buffer->alloc(BufferChunk::TYPE_CLOSE, 0);
        chunk->value.data.val1 = _send->info.type;
        conn->close_queued = 1;
    }
    // sendfile to client
    else if (_send->info.type == SW_SERVER_EVENT_SEND_FILE) {
        SendfileTask *task = (SendfileTask *) _send_data;
        if (conn->socket->sendfile(task->filename, task->offset, task->length) < 0) {
            return false;
        }
    }
    // send data
    else {
        // connection is closed
        if (conn->peer_closed) {
            swWarn("connection#%d is closed by client", fd);
            return false;
        }
        // connection output buffer overflow
        if (_socket->out_buffer->length() >= _socket->buffer_size) {
            if (send_yield) {
                swoole_set_last_error(SW_ERROR_OUTPUT_SEND_YIELD);
            } else {
                swoole_error_log(
                    SW_LOG_WARNING, SW_ERROR_OUTPUT_BUFFER_OVERFLOW, "connection#%d output buffer overflow", fd);
            }
            conn->overflow = 1;
            if (onBufferEmpty && onBufferFull == nullptr) {
                conn->high_watermark = 1;
            }
        }

        _socket->out_buffer->append(_send_data, _send_length);

        ListenPort *port = get_port_by_fd(fd);
        if (onBufferFull && conn->high_watermark == 0 && _socket->out_buffer->length() >= port->buffer_high_watermark) {
            notify(conn, SW_SERVER_EVENT_BUFFER_FULL);
            conn->high_watermark = 1;
        }
    }

    // listen EPOLLOUT event
    if (reactor->set(reactor, _socket, SW_EVENT_WRITE | SW_EVENT_READ) < 0 && (errno == EBADF || errno == ENOENT)) {
        goto _close_fd;
    }

    return SW_OK;
}

/**
 * use in master process
 */
bool Server::notify(Connection *conn, int event) {
    DataHead notify_event = {};
    notify_event.type = event;
    notify_event.reactor_id = conn->reactor_id;
    notify_event.fd = conn->fd;
    notify_event.server_fd = conn->server_fd;
    return factory.notify(&factory, &notify_event);
}

/**
 * @process Worker
 * @return SW_OK or SW_ERR
 */
bool Server::sendfile(int session_id, const char *file, uint32_t l_file, off_t offset, size_t length) {
    if (sw_unlikely(session_id <= 0 || session_id > SW_MAX_SESSION_ID)) {
        swoole_error_log(SW_LOG_WARNING, SW_ERROR_SESSION_INVALID_ID, "invalid fd[%d]", session_id);
        return false;
    }

    if (sw_unlikely(swIsMaster())) {
        swoole_error_log(
            SW_LOG_ERROR, SW_ERROR_SERVER_SEND_IN_MASTER, "can't send data to the connections in master process");
        return false;
    }

    char _buffer[SW_IPC_BUFFER_SIZE];
    SendfileTask *req = reinterpret_cast<SendfileTask *>(_buffer);

    // file name size
    if (sw_unlikely(l_file > SW_IPC_BUFFER_SIZE - sizeof(SendfileTask) - 1)) {
        swoole_error_log(SW_LOG_WARNING,
                         SW_ERROR_NAME_TOO_LONG,
                         "sendfile name[%.8s...] length %u is exceed the max name len %u",
                         file,
                         l_file,
                         (uint32_t)(SW_IPC_BUFFER_SIZE - sizeof(SendfileTask) - 1));
        return false;
    }
    // string must be zero termination (for `state` system call)
    char *_file = strncpy((char *) req->filename, file, l_file);
    _file[l_file] = '\0';

    // check state
    struct stat file_stat;
    if (stat(_file, &file_stat) < 0) {
        swoole_error_log(SW_LOG_WARNING, SW_ERROR_SYSTEM_CALL_FAIL, "stat(%s) failed", _file);
        return false;
    }
    if (file_stat.st_size <= offset) {
        swoole_error_log(SW_LOG_WARNING, SW_ERROR_SYSTEM_CALL_FAIL, "file[offset=%ld] is empty", (long) offset);
        return false;
    }
    req->offset = offset;
    req->length = length;

    // construct send data
    SendData send_data{};
    send_data.info.fd = session_id;
    send_data.info.type = SW_SERVER_EVENT_SEND_FILE;
    send_data.info.len = sizeof(SendfileTask) + l_file + 1;
    send_data.data = _buffer;

    return factory.finish(&factory, &send_data);
}

/**
 * [Worker] Returns the number of bytes sent
 */
bool Server::sendwait(int session_id, const void *data, uint32_t length) {
    Connection *conn = get_connection_verify(session_id);
    if (!conn) {
        swoole_error_log(SW_LOG_NOTICE,
                         SW_ERROR_SESSION_CLOSED,
                         "send %d byte failed, because session#%d is closed",
                         length,
                         session_id);
        return false;
    }
    return conn->socket->send_blocking(data, length) == length;
}

static sw_inline void Server_worker_set_buffer(Server *serv, DataHead *info, swString *addr) {
    swString **buffers = (swString **) serv->worker_input_buffers;
    buffers[info->reactor_id] = addr;
}

static void *Server_worker_get_buffer(Server *serv, DataHead *info) {
    swString *worker_buffer = serv->get_worker_input_buffer(info->reactor_id);

    if (worker_buffer == nullptr) {
        worker_buffer = swString_new(info->len);
        Server_worker_set_buffer(serv, info, worker_buffer);
    }

    return worker_buffer->str + worker_buffer->length;
}

static size_t Server_worker_get_buffer_len(Server *serv, DataHead *info) {
    swString *worker_buffer = serv->get_worker_input_buffer(info->reactor_id);

    return worker_buffer == nullptr ? 0 : worker_buffer->length;
}

static void Server_worker_add_buffer_len(Server *serv, DataHead *info, size_t len) {
    swString *worker_buffer = serv->get_worker_input_buffer(info->reactor_id);
    worker_buffer->length += len;
}

static void Server_worker_move_buffer(Server *serv, PipeBuffer *buffer) {
    swString *worker_buffer = serv->get_worker_input_buffer(buffer->info.reactor_id);
    memcpy(buffer->data, &worker_buffer, sizeof(worker_buffer));
    Server_worker_set_buffer(serv, &buffer->info, nullptr);
}

static size_t Server_worker_get_packet(Server *serv, EventData *req, char **data_ptr) {
    size_t length;
    if (req->info.flags & SW_EVENT_DATA_PTR) {
        PacketPtr *task = (PacketPtr *) req;
        *data_ptr = task->data.str;
        length = task->data.length;
    } else if (req->info.flags & SW_EVENT_DATA_OBJ_PTR) {
        String *worker_buffer;
        memcpy(&worker_buffer, req->data, sizeof(worker_buffer));
        *data_ptr = worker_buffer->str;
        length = worker_buffer->length;
    } else {
        *data_ptr = req->data;
        length = req->info.len;
    }

    return length;
}

void Server::call_hook(HookType type, void *arg) {
    swoole::hook_call(hooks, type, arg);
}

/**
 * [Worker]
 */
bool Server::close(int session_id, bool reset) {
    if (sw_unlikely(swIsMaster())) {
        swoole_error_log(SW_LOG_ERROR, SW_ERROR_SERVER_SEND_IN_MASTER, "can't close the connections in master process");
        return false;
    }
    Connection *conn = get_connection_verify_no_ssl(session_id);
    if (!conn) {
        return false;
    }
    // Reset send buffer, Immediately close the connection.
    if (reset) {
        conn->close_reset = 1;
    }
    // server is initiative to close the connection
    conn->close_actively = 1;
    swTraceLog(SW_TRACE_CLOSE, "session_id=%d, fd=%d", session_id, conn->session_id);

    Worker *worker;
    DataHead ev = {};

    if (is_hash_dispatch_mode()) {
        int worker_id = schedule_worker(conn->fd, nullptr);
        if (worker_id != (int) SwooleG.process_id) {
            worker = get_worker(worker_id);
            goto _notify;
        } else {
            goto _close;
        }
    } else if (!swIsWorker()) {
        worker = get_worker(conn->fd % worker_num);
    _notify:
        ev.type = SW_SERVER_EVENT_CLOSE;
        ev.fd = session_id;
        ev.reactor_id = conn->reactor_id;
        return send_to_worker_from_worker(worker, &ev, sizeof(ev), SW_PIPE_MASTER) > 0;
    } else {
    _close:
        return factory.end(&factory, session_id);
    }
}

void Server::init_signal_handler() {
    swSignal_set(SIGPIPE, nullptr);
    swSignal_set(SIGHUP, nullptr);
    if (is_process_mode()) {
        swSignal_set(SIGCHLD, Server_signal_handler);
    } else {
        swSignal_set(SIGIO, Server_signal_handler);
    }
    swSignal_set(SIGUSR1, Server_signal_handler);
    swSignal_set(SIGUSR2, Server_signal_handler);
    swSignal_set(SIGTERM, Server_signal_handler);
#ifdef SIGRTMIN
    swSignal_set(SIGRTMIN, Server_signal_handler);
#endif
    // for test
    swSignal_set(SIGVTALRM, Server_signal_handler);

    set_minfd(SwooleG.signal_fd);
}

void Server::timer_callback(Timer *timer, TimerNode *tnode) {
    Server *serv = (Server *) tnode->data;
    time_t now = ::time(nullptr);
    if (serv->scheduler_warning && serv->warning_time < now) {
        serv->scheduler_warning = false;
        serv->warning_time = now;
        swoole_error_log(SW_LOG_WARNING, SW_ERROR_SERVER_NO_IDLE_WORKER, "No idle worker is available");
    }

    if (serv->gs->task_workers.scheduler_warning && serv->gs->task_workers.warning_time < now) {
        serv->gs->task_workers.scheduler_warning = 0;
        serv->gs->task_workers.warning_time = now;
        swoole_error_log(SW_LOG_WARNING, SW_ERROR_SERVER_NO_IDLE_WORKER, "No idle task worker is available");
    }

    if (serv->hooks[Server::HOOK_MASTER_TIMER]) {
        serv->call_hook(Server::HOOK_MASTER_TIMER, serv);
    }
}

int Server::add_worker(Worker *worker) {
    if (user_worker_list == nullptr) {
        user_worker_list = new std::vector<Worker *>();
    }
    user_worker_num++;
    user_worker_list->push_back(worker);

    if (!user_worker_map) {
        user_worker_map = new std::unordered_map<pid_t, Worker *>();
    }

    return worker->id;
}

int Server::add_hook(Server::HookType type, const swCallback &func, int push_back) {
    return swoole::hook_add(hooks, (int) type, func, push_back);
}

void Server::check_port_type(swListenPort *ls) {
    if (ls->is_dgram()) {
        // dgram socket, setting socket buffer size
        ls->socket->set_buffer_size(ls->socket_buffer_size);
        have_dgram_sock = 1;
        dgram_port_num++;
        if (ls->type == SW_SOCK_UDP) {
            udp_socket_ipv4 = ls->socket;
        } else if (ls->type == SW_SOCK_UDP6) {
            udp_socket_ipv6 = ls->socket;
        } else if (ls->type == SW_SOCK_UNIX_DGRAM) {
            dgram_socket = ls->socket;
        }
    } else {
        have_stream_sock = 1;
    }
}

/**
 * Return the number of ports successfully
 */
int Server::add_systemd_socket() {
    char *e = getenv("LISTEN_PID");
    if (!e) {
        return 0;
    }

    int pid = atoi(e);
    if (getpid() != pid) {
        swWarn("invalid LISTEN_PID");
        return 0;
    }

    int n = swoole_get_systemd_listen_fds();
    if (n == 0) {
        return 0;
    }

    int count = 0;
    int sock;

    for (sock = SW_SYSTEMD_FDS_START; sock < SW_SYSTEMD_FDS_START + n; sock++) {
        std::unique_ptr<ListenPort> ptr(new ListenPort());
        ListenPort *ls = ptr.get();

        if (ls->set_address(sock) < 0) {
            return count;
        }
        ls->host[SW_HOST_MAXSIZE - 1] = 0;

        // O_NONBLOCK & O_CLOEXEC
        swoole_fcntl_set_option(sock, 1, 1);
        ls->socket = swoole::make_socket(sock, ls->is_dgram() ? SW_FD_DGRAM_SERVER : SW_FD_STREAM_SERVER);
        if (ls->socket == nullptr) {
            ::close(sock);
            return count;
        }
        ptr.release();
        check_port_type(ls);
        ports.push_back(ls);
        count++;
    }

    return count;
}

swListenPort *Server::add_port(enum swSocket_type type, const char *host, int port) {
    if (session_list) {
        swoole_error_log(SW_LOG_ERROR, SW_ERROR_WRONG_OPERATION, "must add port before server is created");
        return nullptr;
    }
    if (ports.size() >= SW_MAX_LISTEN_PORT) {
        swoole_error_log(
            SW_LOG_ERROR, SW_ERROR_SERVER_TOO_MANY_LISTEN_PORT, "allows up to %d ports to listen", SW_MAX_LISTEN_PORT);
        return nullptr;
    }
    if (!(type == SW_SOCK_UNIX_DGRAM || type == SW_SOCK_UNIX_STREAM) && (port < 0 || port > 65535)) {
        swoole_error_log(SW_LOG_ERROR, SW_ERROR_SERVER_INVALID_LISTEN_PORT, "invalid port [%d]", port);
        return nullptr;
    }
    if (strlen(host) + 1 > SW_HOST_MAXSIZE) {
        swoole_error_log(SW_LOG_ERROR,
                         SW_ERROR_NAME_TOO_LONG,
                         "address '%s' exceeds %ld characters limit",
                         host,
                         SW_HOST_MAXSIZE - 1);
        return nullptr;
    }

    std::unique_ptr<swListenPort> ptr(new swListenPort);
    swListenPort *ls = ptr.get();

    ls->type = type;
    ls->port = port;
    strncpy(ls->host, host, SW_HOST_MAXSIZE - 1);
    ls->host[SW_HOST_MAXSIZE - 1] = 0;

#ifdef SW_USE_OPENSSL
    if (type & SW_SOCK_SSL) {
        type = (enum swSocket_type)(type & (~SW_SOCK_SSL));
        ls->type = type;
        ls->ssl = 1;
        ls->ssl_config.prefer_server_ciphers = 1;
        ls->ssl_config.session_tickets = 0;
        ls->ssl_config.stapling = 1;
        ls->ssl_config.stapling_verify = 1;
        ls->ssl_config.ciphers = sw_strdup(SW_SSL_CIPHER_LIST);
        ls->ssl_config.ecdh_curve = sw_strdup(SW_SSL_ECDH_CURVE);

        if (ls->is_dgram()) {
#ifdef SW_SUPPORT_DTLS
            ls->ssl_option.create_flag = SW_SSL_SERVER;
            ls->ssl_option.protocols = SW_SSL_DTLS;
            ls->dtls_sessions = new std::unordered_map<int, swoole::dtls::Session *>;

#else
            swWarn("DTLS support require openssl-1.1 or later");
            return nullptr;
#endif
        }
    }
#endif

    ls->socket = swoole::make_socket(
        ls->type, ls->is_dgram() ? SW_FD_DGRAM_SERVER : SW_FD_STREAM_SERVER, SW_SOCK_CLOEXEC | SW_SOCK_NONBLOCK);
    if (ls->socket == nullptr) {
        return nullptr;
    }
#if defined(SW_SUPPORT_DTLS) && defined(HAVE_KQUEUE)
    if (ls->ssl_option.protocols & SW_SSL_DTLS) {
        int on = 1;
        setsockopt(ls->socket->fd, SOL_SOCKET, SO_REUSEPORT, &on, (socklen_t) sizeof(on));
    }
#endif

    ls->socket->socket_type = ls->type;
    if (ls->socket->bind(ls->host, &ls->port) < 0) {
        ls->socket->free();
        return nullptr;
    }
    check_port_type(ls);
    ptr.release();
    ls->socket_fd = ls->socket->fd;
    ports.push_back(ls);
    return ls;
}

static void Server_signal_handler(int sig) {
    swTraceLog(SW_TRACE_SERVER, "signal[%d] %s triggered in %d", sig, swSignal_str(sig), getpid());

    Server *serv = sw_server();
    if (!SwooleG.running or !serv) {
        return;
    }

    int status;
    pid_t pid;
    switch (sig) {
    case SIGTERM:
        serv->shutdown();
        break;
    case SIGCHLD:
        if (!serv->running) {
            break;
        }
        if (sw_server()->is_base_mode()) {
            break;
        }
        pid = waitpid(-1, &status, WNOHANG);
        if (pid > 0 && pid == serv->gs->manager_pid) {
            swWarn("Fatal Error: manager process exit. status=%d, signal=[%s]",
                   WEXITSTATUS(status),
                   swSignal_str(WTERMSIG(status)));
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
        if (serv->is_base_mode()) {
            if (serv->gs->event_workers.reloading) {
                break;
            }
            serv->gs->event_workers.reloading = true;
            serv->gs->event_workers.reload_init = false;
        } else {
            swoole_kill(serv->gs->manager_pid, sig);
        }
        sw_logger()->reopen();
        break;
    default:

#ifdef SIGRTMIN
        if (sig == SIGRTMIN) {
            uint32_t i;
            Worker *worker;
            for (i = 0; i < serv->worker_num + serv->task_worker_num + serv->user_worker_num; i++) {
                worker = serv->get_worker(i);
                swoole_kill(worker->pid, SIGRTMIN);
            }
            if (serv->is_process_mode()) {
                swoole_kill(serv->gs->manager_pid, SIGRTMIN);
            }
            sw_logger()->reopen();
        }
#endif
        break;
    }
}

void Server::foreach_connection(const std::function<void(Connection *)> &callback) {
    for (int fd = get_minfd(); fd <= get_maxfd(); fd++) {
        Connection *conn = get_connection(fd);
        if (is_valid_connection(conn)) {
            callback(conn);
        }
    }
}

/**
 * new connection
 */
Connection *Server::add_connection(ListenPort *ls, Socket *_socket, int server_fd) {
    gs->accept_count++;
    sw_atomic_fetch_add(&gs->connection_num, 1);
    sw_atomic_fetch_add(ls->connection_num, 1);
    time_t now;

    int fd = _socket->fd;

    lock();
    if (fd > get_maxfd()) {
        set_maxfd(fd);
    } else if (fd < get_minfd()) {
        set_minfd(fd);
    }
    unlock();

    Connection *connection = &(connection_list[fd]);
    sw_memset_zero(connection, sizeof(*connection));
    _socket->object = connection;
    _socket->removed = 1;
    _socket->buffer_size = ls->socket_buffer_size;

    // TCP Nodelay
    if (ls->open_tcp_nodelay && (ls->type == SW_SOCK_TCP || ls->type == SW_SOCK_TCP6)) {
        int sockopt = 1;
        if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &sockopt, sizeof(sockopt)) != 0) {
            swSysWarn("setsockopt(TCP_NODELAY) failed");
        }
        _socket->tcp_nodelay = 1;
    }

    // socket recv buffer size
    if (ls->kernel_socket_recv_buffer_size > 0) {
        if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &ls->kernel_socket_recv_buffer_size, sizeof(int)) != 0) {
            swSysWarn("setsockopt(SO_RCVBUF, %d) failed", ls->kernel_socket_recv_buffer_size);
        }
    }

    // socket send buffer size
    if (ls->kernel_socket_send_buffer_size > 0) {
        if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &ls->kernel_socket_send_buffer_size, sizeof(int)) != 0) {
            swSysWarn("setsockopt(SO_SNDBUF, %d) failed", ls->kernel_socket_send_buffer_size);
        }
    }

    now = ::time(nullptr);

    connection->fd = fd;
    connection->reactor_id = is_base_mode() ? SwooleG.process_id : fd % reactor_num;
    connection->server_fd = (sw_atomic_t) server_fd;
    connection->connect_time = now;
    connection->last_time = now;
    connection->active = 1;
    connection->socket_type = ls->type;
    connection->socket = _socket;

    memcpy(&connection->info.addr, &_socket->info.addr, _socket->info.len);
    connection->info.len = _socket->info.len;
    connection->info.type = connection->socket_type;

    if (!ls->ssl) {
        _socket->direct_send = 1;
    }

    Session *session;
    sw_spinlock(&gs->spinlock);
    uint32_t i;
    uint32_t session_id = gs->session_round;
    // get session id
    for (i = 0; i < max_connection; i++) {
        session_id++;
        // SwooleGS->session_round just has 24 bits size;
        if (sw_unlikely(session_id == 1 << 24)) {
            session_id = 1;
        }
        session = get_session(session_id);
        // vacancy
        if (session->fd == 0) {
            session->fd = fd;
            session->id = session_id;
            session->reactor_id = connection->reactor_id;
            break;
        }
    }
    gs->session_round = session_id;
    sw_spinlock_release(&gs->spinlock);
    connection->session_id = session_id;

    return connection;
}

void Server::set_ipc_max_size() {
#ifdef HAVE_KQUEUE
    ipc_max_size = SW_IPC_MAX_SIZE;
#else
    int bufsize;
    socklen_t _len = sizeof(bufsize);
    /**
     * Get the maximum ipc[unix socket with dgram] transmission length
     */
    if (getsockopt(workers[0].pipe_master->fd, SOL_SOCKET, SO_SNDBUF, &bufsize, &_len) != 0) {
        bufsize = SW_IPC_MAX_SIZE;
    }
    ipc_max_size = bufsize - SW_DGRAM_HEADER_SIZE;
#endif
}

/**
 * allocate memory for Server::pipe_buffers
 */
int Server::create_pipe_buffers() {
    pipe_buffers = (PipeBuffer **) sw_calloc(reactor_num, sizeof(PipeBuffer *));
    if (pipe_buffers == nullptr) {
        swSysError("malloc[buffers] failed");
        return SW_ERR;
    }
    for (uint32_t i = 0; i < reactor_num; i++) {
        pipe_buffers[i] = (PipeBuffer *) sw_malloc(ipc_max_size);
        if (pipe_buffers[i] == nullptr) {
            swSysError("malloc[sndbuf][%d] failed", i);
            return SW_ERR;
        }
        sw_memset_zero(pipe_buffers[i], sizeof(DataHead));
    }

    return SW_OK;
}

int Server::get_idle_worker_num() {
    uint32_t i;
    uint32_t idle_worker_num = 0;

    for (i = 0; i < worker_num; i++) {
        Worker *worker = get_worker(i);
        if (worker->status == SW_WORKER_IDLE) {
            idle_worker_num++;
        }
    }

    return idle_worker_num;
}

int Server::get_idle_task_worker_num() {
    uint32_t i;
    uint32_t idle_worker_num = 0;

    for (i = worker_num; i < (worker_num + task_worker_num); i++) {
        Worker *worker = get_worker(i);
        if (worker->status == SW_WORKER_IDLE) {
            idle_worker_num++;
        }
    }

    return idle_worker_num;
}
