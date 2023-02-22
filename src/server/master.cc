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
  | Author: Tianfeng Han  <rango@swoole.com>                             |
  +----------------------------------------------------------------------+
*/

#include "swoole_server.h"
#include "swoole_memory.h"
#include "swoole_lock.h"
#include "swoole_util.h"

#include <assert.h>

using swoole::network::Address;
using swoole::network::SendfileTask;
using swoole::network::Socket;

swoole::Server *g_server_instance = nullptr;

namespace swoole {

static void Server_signal_handler(int sig);

TimerCallback Server::get_timeout_callback(ListenPort *port, Reactor *reactor, Connection *conn) {
    return [this, port, conn, reactor](Timer *, TimerNode *) {
        if (conn->protect) {
            return;
        }
        long ms = time<std::chrono::milliseconds>(true);
        if (ms - conn->socket->last_received_time < port->max_idle_time &&
            ms - conn->socket->last_sent_time < port->max_idle_time) {
            return;
        }
        if (disable_notify || conn->closed || conn->close_force) {
            close_connection(reactor, conn->socket);
            return;
        }
        conn->close_force = 1;
        Event _ev{};
        _ev.fd = conn->fd;
        _ev.socket = conn->socket;
        reactor->trigger_close_event(&_ev);
    };
}

void Server::disable_accept() {
    enable_accept_timer = swoole_timer_add((long) (SW_ACCEPT_RETRY_TIME * 1000),
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

void Server::call_command_callback(int64_t request_id, const std::string &result) {
    auto iter = command_callbacks.find(request_id);
    if (iter == command_callbacks.end()) {
        swoole_error_log(
            SW_LOG_ERROR, SW_ERROR_SERVER_INVALID_COMMAND, "Invalid command result[request_id=%ld]", request_id);
        return;
    }
    iter->second(this, result);
}

ResultCode Server::call_command_handler(MessageBus &mb, uint16_t worker_id, Socket *sock) {
    PipeBuffer *buffer = mb.get_buffer();
    int command_id = buffer->info.server_fd;
    auto iter = command_handlers.find(command_id);
    if (iter == command_handlers.end()) {
        swoole_error_log(SW_LOG_ERROR, SW_ERROR_SERVER_INVALID_COMMAND, "Unknown command[command_id=%d]", command_id);
        return SW_OK;
    }

    Server::Command::Handler handler = iter->second;
    auto packet = mb.get_packet();
    auto result = handler(this, std::string(packet.data, packet.length));

    SendData task{};
    task.info.fd = buffer->info.fd;
    task.info.reactor_id = worker_id;
    task.info.server_fd = -1;
    task.info.type = SW_SERVER_EVENT_COMMAND_RESPONSE;
    task.info.len = result.length();
    task.data = result.c_str();

    return mb.write(sock, &task) ? SW_OK : SW_ERR;
}

std::string Server::call_command_handler_in_master(int command_id, const std::string &msg) {
    auto iter = command_handlers.find(command_id);
    if (iter == command_handlers.end()) {
        swoole_error_log(SW_LOG_ERROR, SW_ERROR_SERVER_INVALID_COMMAND, "Unknown command[%d]", command_id);
        return "";
    }

    Server::Command::Handler handler = iter->second;
    return handler(this, msg);
}

int Server::accept_command_result(Reactor *reactor, Event *event) {
    Server *serv = (Server *) reactor->ptr;

    if (serv->message_bus.read(event->socket) <= 0) {
        return SW_OK;
    }

    auto packet = serv->message_bus.get_packet();
    std::string result(packet.data, packet.length);

    auto buffer = serv->message_bus.get_buffer();
    serv->call_command_callback(buffer->info.fd, result);
    serv->message_bus.pop();

    return SW_OK;
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
                swoole_sys_warning("accept() failed");
                return SW_OK;
            }
        }

        swoole_trace("[Master] Accept new connection. maxfd=%d|minfd=%d|reactor_id=%d|conn=%d",
                     serv->get_maxfd(),
                     serv->get_minfd(),
                     reactor->id,
                     sock->fd);

        // too many connection
        if (sock->fd >= (int) serv->max_connection) {
            swoole_error_log(
                SW_LOG_WARNING, SW_ERROR_SERVER_TOO_MANY_SOCKET, "Too many connections [now: %d]", sock->fd);
            serv->abort_connection(reactor, listen_host, sock);
            serv->disable_accept();
            return SW_OK;
        }

        // add to connection_list
        Connection *conn = serv->add_connection(listen_host, sock, event->fd);
        if (conn == nullptr) {
            serv->abort_connection(reactor, listen_host, sock);
            return SW_OK;
        }
        sock->chunk_size = SW_SEND_BUFFER_SIZE;

#ifdef SW_USE_OPENSSL
        if (listen_host->ssl) {
            if (!listen_host->ssl_create(conn, sock)) {
                serv->abort_connection(reactor, listen_host, sock);
                return SW_OK;
            }
        } else {
            sock->ssl = nullptr;
        }
#endif
        if (serv->single_thread) {
            if (serv->connection_incoming(reactor, conn) < 0) {
                serv->abort_connection(reactor, listen_host, sock);
                return SW_OK;
            }
        } else {
            DataHead ev{};
            ev.type = SW_SERVER_EVENT_INCOMING;
            ev.fd = conn->session_id;
            ev.reactor_id = conn->reactor_id;
            ev.server_fd = event->fd;
            if (serv->send_to_reactor_thread((EventData *) &ev, sizeof(ev), conn->session_id) < 0) {
                serv->abort_connection(reactor, listen_host, sock);
                return SW_OK;
            }
        }
    }

    return SW_OK;
}

int Server::connection_incoming(Reactor *reactor, Connection *conn) {
    ListenPort *port = get_port_by_server_fd(conn->server_fd);
    if (port->max_idle_time > 0) {
        auto timeout_callback = get_timeout_callback(port, reactor, conn);
        conn->socket->recv_timeout_ = port->max_idle_time;
        conn->socket->recv_timer = swoole_timer_add((long) (port->max_idle_time * 1000), true, timeout_callback);
    }
#ifdef SW_USE_OPENSSL
    if (conn->socket->ssl) {
        return reactor->add(conn->socket, SW_EVENT_READ);
    }
#endif
    // delay receive, wait resume command
    if (!enable_delay_receive) {
        if (reactor->add(conn->socket, SW_EVENT_READ) < 0) {
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

#ifdef SW_SUPPORT_DTLS
dtls::Session *Server::accept_dtls_connection(ListenPort *port, Address *sa) {
    dtls::Session *session = nullptr;
    Connection *conn = nullptr;

    Socket *sock = make_socket(port->type, SW_FD_SESSION, SW_SOCK_CLOEXEC | SW_SOCK_NONBLOCK);
    if (!sock) {
        return nullptr;
    }

    int fd = sock->fd;
    sock->set_reuse_addr();
#ifdef HAVE_KQUEUE
    sock->set_reuse_port();
#endif

    switch (port->type) {
    case SW_SOCK_UDP:
    case SW_SOCK_UDP6:
        break;
    default:
        OPENSSL_assert(0);
        break;
    }

    if (sock->bind(port->socket->info) < 0) {
        swoole_sys_warning("bind() failed");
        goto _cleanup;
    }
    if (sock->is_inet6()) {
        sock->set_option(IPPROTO_IPV6, IPV6_V6ONLY, 0);
    }
    if (sock->connect(sa) < 0) {
        swoole_sys_warning("connect(%s:%d) failed", sa->get_addr(), sa->get_port());
        goto _cleanup;
    }

    memcpy(&sock->info, sa, sizeof(*sa));
    sock->chunk_size = SW_SSL_BUFFER_SIZE;

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
        *conn = {};
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
        swoole_warning("max_connection must be set before server create");
        return;
    }
    max_connection = _max_connection;
    if (max_connection == 0) {
        max_connection = SW_MIN(SW_MAX_CONNECTION, SwooleG.max_sockets);
    } else if (max_connection > SW_SESSION_LIST_SIZE) {
        max_connection = SW_SESSION_LIST_SIZE;
        swoole_warning("max_connection is exceed the SW_SESSION_LIST_SIZE, it's reset to %u", SW_SESSION_LIST_SIZE);
    }
    if (SwooleG.max_sockets > 0 && max_connection > SwooleG.max_sockets) {
        max_connection = SwooleG.max_sockets;
        swoole_warning("max_connection is exceed the maximum value, it's reset to %u", SwooleG.max_sockets);
    }
}

int Server::start_check() {
    // disable notice when use SW_DISPATCH_ROUND and SW_DISPATCH_QUEUE
    if (is_process_mode()) {
        if (!is_support_unsafe_events()) {
            if (onConnect) {
                swoole_warning("cannot set 'onConnect' event when using dispatch_mode=1/3/7");
                onConnect = nullptr;
            }
            if (onClose) {
                swoole_warning("cannot set 'onClose' event when using dispatch_mode=1/3/7");
                onClose = nullptr;
            }
            if (onBufferFull) {
                swoole_warning("cannot set 'onBufferFull' event when using dispatch_mode=1/3/7");
                onBufferFull = nullptr;
            }
            if (onBufferEmpty) {
                swoole_warning("cannot set 'onBufferEmpty' event when using dispatch_mode=1/3/7");
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
            swoole_warning("onTask event callback must be set");
            return SW_ERR;
        }
    }
    if (send_timeout > 0 && send_timeout < SW_TIMER_MIN_SEC) {
        send_timeout = SW_TIMER_MIN_SEC;
    }
    if (heartbeat_check_interval > 0) {
        for (auto ls : ports) {
            if (ls->heartbeat_idle_time == 0) {
                ls->heartbeat_idle_time = heartbeat_check_interval * 2;
            }
        }
    }
    for (auto ls : ports) {
        if (ls->protocol.package_max_length < SW_BUFFER_MIN_SIZE) {
            ls->protocol.package_max_length = SW_BUFFER_MIN_SIZE;
        }
        if (if_require_receive_callback(ls, onReceive != nullptr)) {
            swoole_warning("require onReceive callback");
            return SW_ERR;
        }
        if (if_require_packet_callback(ls, onPacket != nullptr)) {
            swoole_warning("require onPacket callback");
            return SW_ERR;
        }
        if (ls->heartbeat_idle_time > 0) {
            int expect_heartbeat_check_interval = ls->heartbeat_idle_time > 2 ? ls->heartbeat_idle_time / 2 : 1;
            if (heartbeat_check_interval == 0 || heartbeat_check_interval > expect_heartbeat_check_interval) {
                heartbeat_check_interval = expect_heartbeat_check_interval;
            }
        }
    }
#ifdef SW_USE_OPENSSL
    /**
     * OpenSSL thread-safe
     */
    if (is_process_mode() && !single_thread) {
        swoole_ssl_init_thread_safety();
    }
#endif

    return SW_OK;
}

int Server::start_master_thread() {
    SwooleTG.type = THREAD_MASTER;
    SwooleTG.id = single_thread ? 0 : reactor_num;

    Reactor *reactor = sw_reactor();

    if (SwooleTG.timer && SwooleTG.timer->get_reactor() == nullptr) {
        SwooleTG.timer->reinit(reactor);
    }

    SwooleG.pid = getpid();
    SwooleG.process_type = SW_PROCESS_MASTER;

    reactor->ptr = this;
    reactor->set_handler(SW_FD_STREAM_SERVER, Server::accept_connection);

    if (pipe_command) {
        if (!single_thread) {
            reactor->set_handler(SW_FD_PIPE, Server::accept_command_result);
        }
        reactor->add(pipe_command->get_socket(true), SW_EVENT_READ);
    }

    if ((master_timer = swoole_timer_add(1000L, true, Server::timer_callback, this)) == nullptr) {
        swoole_event_free();
        return SW_ERR;
    }

#ifdef HAVE_PTHREAD_BARRIER
    if (!single_thread) {
        pthread_barrier_wait(&reactor_thread_barrier);
    }
#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    SW_START_SLEEP;
#else
    pthread_barrier_wait(&gs->manager_barrier);
#endif
#else
    SW_START_SLEEP;
#endif

    if (isset_hook(HOOK_MASTER_START)) {
        call_hook(HOOK_MASTER_START, this);
    }

    if (onStart) {
        onStart(this);
    }

    return swoole_event_wait();
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

/**
 * only the memory of the Worker structure is allocated, no process is fork
 */
int Server::create_task_workers() {
    key_t key = 0;
    swIPCMode ipc_mode;

    if (task_ipc_mode == TASK_IPC_MSGQUEUE || task_ipc_mode == TASK_IPC_PREEMPTIVE) {
        key = message_queue_key;
        ipc_mode = SW_IPC_MSGQUEUE;
    } else if (task_ipc_mode == TASK_IPC_STREAM) {
        ipc_mode = SW_IPC_SOCKET;
    } else {
        ipc_mode = SW_IPC_UNIXSOCK;
    }

    ProcessPool *pool = &gs->task_workers;
    *pool = {};
    if (pool->create(task_worker_num, key, ipc_mode) < 0) {
        swoole_warning("[Master] create task_workers failed");
        return SW_ERR;
    }

    pool->set_max_request(task_max_request, task_max_request_grace);
    pool->set_start_id(worker_num);
    pool->set_type(SW_PROCESS_TASKWORKER);

    if (ipc_mode == SW_IPC_SOCKET) {
        char sockfile[sizeof(struct sockaddr_un)];
        snprintf(sockfile, sizeof(sockfile), "/tmp/swoole.task.%d.sock", gs->master_pid);
        if (gs->task_workers.listen(sockfile, 2048) < 0) {
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
    user_workers = (Worker *) sw_shm_calloc(get_user_worker_num(), sizeof(Worker));
    if (user_workers == nullptr) {
        swoole_sys_warning("gmalloc[server->user_workers] failed");
        return SW_ERR;
    }
    return SW_OK;
}

/**
 * [Master]
 */
void Server::create_worker(Worker *worker) {
    worker->lock = new Mutex(Mutex::PROCESS_SHARED);
}

void Server::destroy_worker(Worker *worker) {
    delete worker->lock;
    worker->lock = nullptr;
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
            swoole_sys_warning("swoole_set_cpu_affinity() failed");
        }
    }
#endif
    // signal init
    worker_signal_init();

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

    if (swoole_isset_hook(SW_GLOBAL_HOOK_BEFORE_WORKER_START)) {
        swoole_call_hook(SW_GLOBAL_HOOK_BEFORE_WORKER_START, hook_args);
    }
    if (isset_hook(HOOK_WORKER_START)) {
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
    if (swoole_isset_hook(SW_GLOBAL_HOOK_BEFORE_SERVER_START)) {
        swoole_call_hook(SW_GLOBAL_HOOK_BEFORE_SERVER_START, this);
    }
    // cannot start 2 servers at the same time, please use process->exec.
    if (!sw_atomic_cmp_set(&gs->start, 0, 1)) {
        swoole_error_log(SW_LOG_ERROR, SW_ERROR_SERVER_ONLY_START_ONE, "can only start one server");
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
                swoole_sys_warning("open(/dev/null) failed");
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
     * store to ProcessPool object
     */
    gs->event_workers.ptr = this;
    gs->event_workers.workers = workers;
    gs->event_workers.worker_num = worker_num;
    gs->event_workers.use_msgqueue = 0;

    SW_LOOP_N(worker_num) {
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
            swoole_warning("malloc[task_result] failed");
            return SW_ERR;
        }
        SW_LOOP_N(worker_num) {
            auto _pipe = new Pipe(true);
            if (!_pipe->ready()) {
                sw_shm_free(task_result);
                delete _pipe;
                return SW_ERR;
            }
            task_notify_pipes.emplace_back(_pipe);
        }
    }

    if (!user_worker_list.empty()) {
        uint32_t i = 0;
        for (auto worker : user_worker_list) {
            worker->id = worker_num + task_worker_num + i;
            i++;
        }
    }

    running = true;
    // factory start
    if (!factory->start()) {
        return SW_ERR;
    }
    init_signal_handler();

    // write PID file
    if (!pid_file.empty()) {
        size_t n = sw_snprintf(sw_tg_buffer()->str, sw_tg_buffer()->size, "%d", getpid());
        file_put_contents(pid_file, sw_tg_buffer()->str, n);
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

    reactor_num = SW_CPU_NUM > SW_REACTOR_MAX_THREAD ? SW_REACTOR_MAX_THREAD : SW_CPU_NUM;
    worker_num = SW_CPU_NUM;
    max_connection = SW_MIN(SW_MAX_CONNECTION, SwooleG.max_sockets);
    mode_ = _mode;

    // http server
#ifdef SW_HAVE_COMPRESSION
    http_compression = 1;
    http_compression_level = SW_Z_BEST_SPEED;
    compression_min_length = SW_COMPRESSION_MIN_LENGTH_DEFAULT;
#endif

    timezone_ = get_timezone();

    gs = (ServerGS *) sw_shm_malloc(sizeof(ServerGS));
    if (gs == nullptr) {
        swoole_error("[Master] Fatal Error: failed to allocate memory for Server->gs");
    }

    gs->pipe_packet_msg_id = 1;
    message_bus.set_id_generator([this]() { return sw_atomic_fetch_add(&gs->pipe_packet_msg_id, 1); });

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
    if (is_created()) {
        return SW_ERR;
    }

    if (swoole_isset_hook(SW_GLOBAL_HOOK_BEFORE_SERVER_CREATE)) {
        swoole_call_hook(SW_GLOBAL_HOOK_BEFORE_SERVER_CREATE, this);
    }

    session_list = (Session *) sw_shm_calloc(SW_SESSION_LIST_SIZE, sizeof(Session));
    if (session_list == nullptr) {
        swoole_error("sw_shm_calloc(%ld) for session_list failed", SW_SESSION_LIST_SIZE * sizeof(Session));
        return SW_ERR;
    }

    port_gs_list = (ServerPortGS *) sw_shm_calloc(ports.size(), sizeof(ServerPortGS));
    if (port_gs_list == nullptr) {
        swoole_error("sw_shm_calloc() for port_connnection_num_array failed");
        return SW_ERR;
    }

    int index = 0;
    for (auto port : ports) {
        port->gs = &port_gs_list[index++];
    }

    if (enable_static_handler and locations == nullptr) {
        locations = std::make_shared<std::unordered_set<std::string>>();
    }

    // Max Connections
    uint32_t minimum_connection = (worker_num + task_worker_num) * 2 + 32;
    if (ports.size() > 0) {
        minimum_connection += ports.back()->get_fd();
    }
    if (max_connection < minimum_connection) {
        max_connection = SwooleG.max_sockets;
        swoole_warning(
            "max_connection must be bigger than %u, it's reset to %u", minimum_connection, SwooleG.max_sockets);
    }
    // Reactor Thread Num
    if (reactor_num > SW_CPU_NUM * SW_MAX_THREAD_NCPU) {
        swoole_warning("serv->reactor_num == %d, Too many threads, reset to max value %d",
                       reactor_num,
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
        swoole_warning(
            "worker_num == %d, Too many processes, reset to max value %d", worker_num, SW_CPU_NUM * SW_MAX_WORKER_NCPU);
        worker_num = SW_CPU_NUM * SW_MAX_WORKER_NCPU;
    }
    if (worker_num < reactor_num) {
        reactor_num = worker_num;
    }
    // TaskWorker Process Num
    if (task_worker_num > 0) {
        if (task_worker_num > SW_CPU_NUM * SW_MAX_WORKER_NCPU) {
            swoole_warning("serv->task_worker_num == %d, Too many processes, reset to max value %d",
                           task_worker_num,
                           SW_CPU_NUM * SW_MAX_WORKER_NCPU);
            task_worker_num = SW_CPU_NUM * SW_MAX_WORKER_NCPU;
        }
    }
    workers = (Worker *) sw_shm_calloc(worker_num, sizeof(Worker));
    if (workers == nullptr) {
        swoole_sys_warning("gmalloc[server->workers] failed");
        return SW_ERR;
    }

    int retval;
    if (is_base_mode()) {
        factory = new BaseFactory(this);
        retval = create_reactor_processes();
    } else {
        factory = new ProcessFactory(this);
        retval = create_reactor_threads();
    }

#ifdef HAVE_PTHREAD_BARRIER
    if (is_process_mode()) {
        pthread_barrier_init(&reactor_thread_barrier, nullptr, reactor_num + 1);
#if !(defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__))
        pthread_barrierattr_setpshared(&gs->manager_barrier_attr, PTHREAD_PROCESS_SHARED);
        pthread_barrier_init(&gs->manager_barrier, &gs->manager_barrier_attr, 2);
#endif
    }
#endif

    if (swoole_isset_hook(SW_GLOBAL_HOOK_AFTER_SERVER_CREATE)) {
        swoole_call_hook(SW_GLOBAL_HOOK_AFTER_SERVER_CREATE, this);
    }

    return retval;
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
    swoole_trace_log(SW_TRACE_SERVER, "shutdown service");
    if (getpid() != gs->master_pid) {
        kill(gs->master_pid, SIGTERM);
        return;
    }
    if (is_process_mode()) {
        if (swoole_isset_hook(SW_GLOBAL_HOOK_BEFORE_SERVER_SHUTDOWN)) {
            swoole_call_hook(SW_GLOBAL_HOOK_BEFORE_SERVER_SHUTDOWN, this);
        }
        if (onBeforeShutdown) {
            onBeforeShutdown(this);
        }
    }
    running = false;
    // stop all thread
    if (SwooleTG.reactor) {
        Reactor *reactor = SwooleTG.reactor;
        reactor->set_wait_exit(true);
        for (auto port : ports) {
            if (port->is_dgram() and is_process_mode()) {
                continue;
            }
            reactor->del(port->socket);
        }
        if (pipe_command) {
            reactor->del(pipe_command->get_socket(true));
        }
        clear_timer();
    }

    if (is_base_mode()) {
        gs->event_workers.running = 0;
    }

    swoole_info("Server is shutdown now");
}

void Server::destroy() {
    swoole_trace_log(SW_TRACE_SERVER, "release service");
    if (swoole_isset_hook(SW_GLOBAL_HOOK_AFTER_SERVER_SHUTDOWN)) {
        swoole_call_hook(SW_GLOBAL_HOOK_AFTER_SERVER_SHUTDOWN, this);
    }
    /**
     * shutdown workers
     */
    factory->shutdown();
    if (is_base_mode()) {
        swoole_trace_log(SW_TRACE_SERVER, "terminate task workers");
        if (task_worker_num > 0) {
            gs->task_workers.shutdown();
            gs->task_workers.destroy();
        }
    } else {
        swoole_trace_log(SW_TRACE_SERVER, "terminate reactor threads");
        /**
         * Wait until all the end of the thread
         */
        join_reactor_thread();
    }

    for (auto port : ports) {
        port->close();
    }

    if (user_workers) {
        sw_shm_free(user_workers);
        user_workers = nullptr;
    }
    if (null_fd > 0) {
        ::close(null_fd);
        null_fd = -1;
    }
    swoole_signal_clear();
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
    SW_LOOP_N(SW_MAX_HOOK_TYPE) {
        if (hooks[i]) {
            std::list<Callback> *l = reinterpret_cast<std::list<Callback> *>(hooks[i]);
            hooks[i] = nullptr;
            delete l;
        }
    }
#ifdef HAVE_PTHREAD_BARRIER
    if (is_process_mode()) {
        pthread_barrier_destroy(&reactor_thread_barrier);
#if !(defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__))
        pthread_barrier_destroy(&gs->manager_barrier);
        pthread_barrierattr_destroy(&gs->manager_barrier_attr);
#endif
    }
#endif
    sw_shm_free(session_list);
    sw_shm_free(port_gs_list);
    sw_shm_free(workers);

    session_list = nullptr;
    port_gs_list = nullptr;
    workers = nullptr;

    delete factory;
    factory = nullptr;

    g_server_instance = nullptr;
}

/**
 * worker to master process
 */
bool Server::feedback(Connection *conn, enum ServerEventType event) {
    SendData _send{};
    _send.info.type = event;
    _send.info.fd = conn->session_id;
    _send.info.reactor_id = conn->reactor_id;

    if (is_process_mode()) {
        return send_to_reactor_thread((EventData *) &_send.info, sizeof(_send.info), conn->session_id) > 0;
    } else {
        return send_to_connection(&_send) == SW_OK;
    }
}

bool Server::command(WorkerId process_id,
                     Command::ProcessType process_type,
                     const std::string &name,
                     const std::string &msg,
                     const Command::Callback &fn) {
    if (!is_started()) {
        return false;
    }
    auto iter = commands.find(name);
    if (iter == commands.end()) {
        swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SERVER_INVALID_COMMAND, "Unknown command[%s]", name.c_str());
        return false;
    }

    if (is_process_mode() && !is_master()) {
        swoole_error_log(SW_LOG_NOTICE, SW_ERROR_INVALID_PARAMS, "command() can only be used in master process");
        return false;
    } else if (is_base_mode() && SwooleWG.worker->id != 0) {
        swoole_error_log(SW_LOG_NOTICE, SW_ERROR_INVALID_PARAMS, "command() can only be used in worker process 0");
        return false;
    }

    if (is_base_mode() && process_type == Command::EVENT_WORKER && process_id == 0) {
        process_type = Command::MASTER;
    }

    if (is_process_mode() && process_type == Command::REACTOR_THREAD && process_id == reactor_num) {
        process_type = Command::MASTER;
        process_id = 0;
    }

    int command_id = iter->second.id;
    int64_t requset_id = command_current_request_id++;
    Socket *pipe_sock;

    SendData task{};
    task.info.fd = requset_id;
    task.info.reactor_id = process_id;
    task.info.server_fd = command_id;
    task.info.type = SW_SERVER_EVENT_COMMAND_REQUEST;
    task.info.len = msg.length();
    task.data = msg.c_str();

    if (!(process_type & iter->second.accepted_process_types)) {
        swoole_error_log(SW_LOG_NOTICE, SW_ERROR_OPERATION_NOT_SUPPORT, "unsupported [process_type]");
        return false;
    }

    if (process_type == Command::REACTOR_THREAD) {
        if (!is_process_mode()) {
            swoole_error_log(SW_LOG_NOTICE, SW_ERROR_OPERATION_NOT_SUPPORT, "unsupported [server_mode]");
            return false;
        }
        if (process_id >= reactor_num) {
            swoole_error_log(SW_LOG_NOTICE, SW_ERROR_INVALID_PARAMS, "invalid thread_id[%d]", process_id);
            return false;
        }
        pipe_sock = get_worker(process_id)->pipe_worker;
    } else if (process_type == Command::EVENT_WORKER) {
        if (process_id >= worker_num) {
            swoole_error_log(SW_LOG_NOTICE, SW_ERROR_INVALID_PARAMS, "invalid worker_id[%d]", process_id);
            return false;
        }
        pipe_sock = get_worker(process_id)->pipe_master;
    } else if (process_type == Command::TASK_WORKER) {
        if (process_id >= task_worker_num) {
            swoole_error_log(SW_LOG_NOTICE, SW_ERROR_INVALID_PARAMS, "invalid task_worker_id[%d]", process_id);
            return false;
        }
        EventData buf;
        memset(&buf.info, 0, sizeof(buf.info));
        if (!task_pack(&buf, msg.c_str(), msg.length())) {
            return false;
        }
        buf.info.type = SW_SERVER_EVENT_COMMAND_REQUEST;
        buf.info.fd = requset_id;
        buf.info.server_fd = command_id;
        int _dst_worker_id = process_id;
        if (gs->task_workers.dispatch(&buf, &_dst_worker_id) <= 0) {
            return false;
        }
        command_callbacks[requset_id] = fn;
        return true;
    } else if (process_type == Command::MANAGER) {
        EventData buf;
        if (msg.length() >= sizeof(buf.data)) {
            swoole_error_log(SW_LOG_NOTICE,
                             SW_ERROR_DATA_LENGTH_TOO_LARGE,
                             "message is too large, maximum length is %lu, the given length is %lu",
                             sizeof(buf.data),
                             msg.length());
            return false;
        }
        memset(&buf.info, 0, sizeof(buf.info));
        buf.info.type = SW_SERVER_EVENT_COMMAND_REQUEST;
        buf.info.fd = requset_id;
        buf.info.server_fd = command_id;
        buf.info.len = msg.length();
        memcpy(buf.data, msg.c_str(), msg.length());
        if (gs->event_workers.push_message(&buf) < 0) {
            return false;
        }
        command_callbacks[requset_id] = fn;
        return true;
    } else if (process_type == Command::MASTER) {
        auto result = call_command_handler_in_master(command_id, msg);
        fn(this, result);
        return true;
    } else {
        swoole_error_log(SW_LOG_NOTICE, SW_ERROR_OPERATION_NOT_SUPPORT, "unsupported [process_type]");
        return false;
    }
    if (!message_bus.write(pipe_sock, &task)) {
        return false;
    }
    command_callbacks[requset_id] = fn;
    return true;
}

void Server::store_pipe_fd(UnixSocket *p) {
    Socket *master_socket = p->get_socket(true);
    Socket *worker_socket = p->get_socket(false);

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
 */
bool Server::send(SessionId session_id, const void *data, uint32_t length) {
    SendData _send{};
    _send.info.fd = session_id;
    _send.info.type = SW_SERVER_EVENT_SEND_DATA;
    _send.data = (char *) data;
    _send.info.len = length;
    if (factory->finish(&_send)) {
        sw_atomic_fetch_add(&gs->response_count, 1);
        sw_atomic_fetch_add(&gs->total_send_bytes, length);
        ListenPort *port = get_port_by_session_id(session_id);
        if (port) {
            sw_atomic_fetch_add(&port->gs->response_count, 1);
            sw_atomic_fetch_add(&port->gs->total_send_bytes, length);
        }
        if (SwooleWG.worker) {
            SwooleWG.worker->response_count++;
        }
        return true;
    }
    return false;
}

int Server::schedule_worker(int fd, SendData *data) {
    uint32_t key = 0;

    if (dispatch_func) {
        int id = dispatch_func(this, get_connection(fd), data);
        if (id != DISPATCH_RESULT_USERFUNC_FALLBACK) {
            return id;
        }
    }

    // polling mode
    if (dispatch_mode == DISPATCH_ROUND) {
        key = sw_atomic_fetch_add(&worker_round_id, 1);
    }
    // Using the FD touch access to hash
    else if (dispatch_mode == DISPATCH_FDMOD) {
        key = fd;
    }
    // Using the IP touch access to hash
    else if (dispatch_mode == DISPATCH_IPMOD) {
        Connection *conn = get_connection(fd);
        // UDP
        if (conn == nullptr) {
            key = fd;
        }
        // IPv4
        else if (conn->socket_type == SW_SOCK_TCP) {
            key = conn->info.addr.inet_v4.sin_addr.s_addr;
        }
        // IPv6
        else {
#ifdef HAVE_KQUEUE
            key = *(((uint32_t *) &conn->info.addr.inet_v6.sin6_addr) + 3);
#elif defined(_WIN32)
            key = conn->info.addr.inet_v6.sin6_addr.u.Word[3];
#else
            key = conn->info.addr.inet_v6.sin6_addr.s6_addr32[3];
#endif
        }
    } else if (dispatch_mode == DISPATCH_UIDMOD) {
        Connection *conn = get_connection(fd);
        if (conn == nullptr || conn->uid == 0) {
            key = fd;
        } else {
            key = conn->uid;
        }
    } else if (dispatch_mode == DISPATCH_CO_CONN_LB) {
        Connection *conn = get_connection(fd);
        if (conn == nullptr) {
            return key % worker_num;
        }
        if (conn->worker_id < 0) {
            conn->worker_id = get_lowest_load_worker_id();
        }
        return conn->worker_id;
    } else if (dispatch_mode == DISPATCH_CO_REQ_LB) {
        return get_lowest_load_worker_id();
    }
    // deliver tasks to idle worker processes
    else {
        return get_idle_worker_id();
    }

    return key % worker_num;
}

/**
 * [Master] send to client or append to out_buffer
 * @return SW_OK or SW_ERR
 */
int Server::send_to_connection(SendData *_send) {
    SessionId session_id = _send->info.fd;
    const char *_send_data = _send->data;
    uint32_t _send_length = _send->info.len;

    Connection *conn;
    if (_send->info.type != SW_SERVER_EVENT_CLOSE) {
        conn = get_connection_verify(session_id);
    } else {
        conn = get_connection_verify_no_ssl(session_id);
    }
    if (!conn) {
        if (_send->info.type == SW_SERVER_EVENT_SEND_DATA) {
            swoole_error_log(SW_LOG_NOTICE,
                             SW_ERROR_SESSION_NOT_EXIST,
                             "send %d byte failed, session#%ld does not exist",
                             _send_length,
                             session_id);
        } else {
            swoole_error_log(SW_LOG_NOTICE,
                             SW_ERROR_SESSION_NOT_EXIST,
                             "send event[%d] failed, session#%ld does not exist",
                             _send->info.type,
                             session_id);
        }
        return SW_ERR;
    }

    int fd = conn->fd;
    Reactor *reactor = SwooleTG.reactor;
    ListenPort *port = get_port_by_server_fd(conn->server_fd);

    if (!single_thread) {
        assert(fd % reactor_num == reactor->id);
        assert(fd % reactor_num == SwooleTG.id);
    }

    if (is_base_mode() && conn->overflow) {
        if (send_yield) {
            swoole_set_last_error(SW_ERROR_OUTPUT_SEND_YIELD);
        } else {
            swoole_error_log(SW_LOG_WARNING, SW_ERROR_OUTPUT_BUFFER_OVERFLOW, "socket#%d output buffer overflow", fd);
        }
        return SW_ERR;
    }

    Socket *_socket = conn->socket;

    /**
     * Reset send buffer, Immediately close the connection.
     */
    if (_send->info.type == SW_SERVER_EVENT_CLOSE && (conn->close_reset || conn->close_force || conn->peer_closed)) {
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
            return reactor->set(conn->socket, SW_EVENT_WRITE);
        } else {
            return reactor->del(conn->socket);
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
            return reactor->set(_socket, SW_EVENT_READ | SW_EVENT_WRITE);
        } else {
            return reactor->add(_socket, SW_EVENT_READ);
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
                conn->last_send_time = microtime();
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
            swoole_error_log(
                SW_LOG_NOTICE, SW_ERROR_SESSION_CLOSED_BY_CLIENT, "Server::send(): socket#%d is closed by client", fd);
            return false;
        }
        // connection output buffer overflow
        if (_socket->out_buffer->length() >= _socket->buffer_size) {
            if (send_yield) {
                swoole_set_last_error(SW_ERROR_OUTPUT_SEND_YIELD);
            } else {
                swoole_error_log(SW_LOG_WARNING,
                                 SW_ERROR_OUTPUT_BUFFER_OVERFLOW,
                                 "Server::send(): connection#%d output buffer overflow",
                                 fd);
            }
            conn->overflow = 1;
            if (onBufferEmpty && onBufferFull == nullptr) {
                conn->high_watermark = 1;
            }
        }

        _socket->out_buffer->append(_send_data, _send_length);
        conn->send_queued_bytes = _socket->out_buffer->length();

        ListenPort *port = get_port_by_fd(fd);
        if (onBufferFull && conn->high_watermark == 0 && _socket->out_buffer->length() >= port->buffer_high_watermark) {
            notify(conn, SW_SERVER_EVENT_BUFFER_FULL);
            conn->high_watermark = 1;
        }
    }

    if (port->max_idle_time > 0 && _socket->send_timer == nullptr) {
        auto timeout_callback = get_timeout_callback(port, reactor, conn);
        _socket->send_timeout_ = port->max_idle_time;
        _socket->last_sent_time = time<std::chrono::milliseconds>(true);
        _socket->send_timer = swoole_timer_add((long) (port->max_idle_time * 1000), true, timeout_callback);
    }

    if (!_socket->isset_writable_event()) {
        reactor->add_write_event(_socket);
    }

    return SW_OK;
}

/**
 * use in master process
 */
bool Server::notify(Connection *conn, enum ServerEventType event) {
    DataHead notify_event{};
    notify_event.type = event;
    notify_event.reactor_id = conn->reactor_id;
    notify_event.fd = conn->fd;
    notify_event.server_fd = conn->server_fd;
    return factory->notify(&notify_event);
}

/**
 * @process Worker
 */
bool Server::sendfile(SessionId session_id, const char *file, uint32_t l_file, off_t offset, size_t length) {
    if (sw_unlikely(session_id <= 0)) {
        swoole_error_log(SW_LOG_WARNING, SW_ERROR_SESSION_INVALID_ID, "invalid fd[%ld]", session_id);
        return false;
    }

    if (sw_unlikely(is_master())) {
        swoole_error_log(
            SW_LOG_ERROR, SW_ERROR_SERVER_SEND_IN_MASTER, "can't send data to the connections in master process");
        return false;
    }

    char _buffer[SW_IPC_BUFFER_SIZE];
    SendfileTask *req = reinterpret_cast<SendfileTask *>(_buffer);

    // file name size
    if (sw_unlikely(l_file > sizeof(_buffer) - sizeof(*req) - 1)) {
        swoole_error_log(SW_LOG_WARNING,
                         SW_ERROR_NAME_TOO_LONG,
                         "sendfile name[%.8s...] length %u is exceed the max name len %u",
                         file,
                         l_file,
                         (uint32_t) (SW_IPC_BUFFER_SIZE - sizeof(SendfileTask) - 1));
        return false;
    }
    // string must be zero termination (for `state` system call)
    swoole_strlcpy((char *) req->filename, file, sizeof(_buffer) - sizeof(*req));

    // check state
    struct stat file_stat;
    if (stat(req->filename, &file_stat) < 0) {
        swoole_error_log(SW_LOG_WARNING, SW_ERROR_SYSTEM_CALL_FAIL, "stat(%s) failed", req->filename);
        return false;
    }
    if (!S_ISREG(file_stat.st_mode)) {
        swoole_error_log(SW_LOG_WARNING,
                         SW_ERROR_SERVER_IS_NOT_REGULAR_FILE,
                         "the path[%s] given is not a regular file",
                         req->filename);
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

    return factory->finish(&send_data);
}

/**
 * [Worker] Returns the number of bytes sent
 */
bool Server::sendwait(SessionId session_id, const void *data, uint32_t length) {
    Connection *conn = get_connection_verify(session_id);
    if (!conn) {
        swoole_error_log(SW_LOG_NOTICE,
                         SW_ERROR_SESSION_CLOSED,
                         "send %d byte failed, because session#%ld is closed",
                         length,
                         session_id);
        return false;
    }
    return conn->socket->send_blocking(data, length) == length;
}

void Server::call_hook(HookType type, void *arg) {
    assert(type <= HOOK_END);
    swoole::hook_call(hooks, type, arg);
}

/**
 * [Worker]
 */
bool Server::close(SessionId session_id, bool reset) {
    return factory->end(session_id, reset ? (CLOSE_ACTIVELY | CLOSE_RESET) : CLOSE_ACTIVELY);
}

void Server::init_signal_handler() {
    swoole_signal_set(SIGPIPE, nullptr);
    swoole_signal_set(SIGHUP, nullptr);
    if (is_process_mode()) {
        swoole_signal_set(SIGCHLD, Server_signal_handler);
    } else {
        swoole_signal_set(SIGIO, Server_signal_handler);
    }
    swoole_signal_set(SIGUSR1, Server_signal_handler);
    swoole_signal_set(SIGUSR2, Server_signal_handler);
    swoole_signal_set(SIGTERM, Server_signal_handler);
#ifdef SIGRTMIN
    swoole_signal_set(SIGRTMIN, Server_signal_handler);
#endif
    // for test
    swoole_signal_set(SIGVTALRM, Server_signal_handler);

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
    user_worker_list.push_back(worker);
    return worker->id;
}

int Server::add_hook(Server::HookType type, const Callback &func, int push_back) {
    return swoole::hook_add(hooks, (int) type, func, push_back);
}

bool Server::add_command(const std::string &name, int accepted_process_types, const Command::Handler &func) {
    if (is_started()) {
        return false;
    }
    if (commands.find(name) != commands.end()) {
        return false;
    }
    if (is_process_mode() && pipe_command == nullptr) {
        auto _pipe = new UnixSocket(false, SOCK_DGRAM);
        if (!_pipe->ready()) {
            delete _pipe;
            return false;
        }
        pipe_command = _pipe;
    }
    int command_id = command_current_id++;
    Command command{
        command_id,
        accepted_process_types,
        name,
    };
    commands.emplace(name, command);
    command_handlers[command_id] = func;
    return true;
}

void Server::check_port_type(ListenPort *ls) {
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

bool Server::is_healthy_connection(double now, Connection *conn) {
    if (conn->protect || conn->last_recv_time == 0) {
        return true;
    }
    auto lp = get_port_by_session_id(conn->session_id);
    if (!lp) {
        return true;
    }
    if (lp->heartbeat_idle_time == 0) {
        return true;
    }
    if (conn->last_recv_time > now - lp->heartbeat_idle_time) {
        return true;
    }
    return false;
}

/**
 * Return the number of ports successfully
 */
int Server::add_systemd_socket() {
    int pid;
    if (!swoole_get_env("LISTEN_PID", &pid) && getpid() != pid) {
        swoole_warning("invalid LISTEN_PID");
        return 0;
    }

    int n = swoole_get_systemd_listen_fds();
    if (n <= 0) {
        return 0;
    }

    int count = 0;
    int sock;

    int start_fd;
    if (!swoole_get_env("LISTEN_FDS_START", &start_fd)) {
        start_fd = SW_SYSTEMD_FDS_START;
    } else if (start_fd < 0) {
        swoole_warning("invalid LISTEN_FDS_START");
        return 0;
    }

    for (sock = start_fd; sock < start_fd + n; sock++) {
        std::unique_ptr<ListenPort> ptr(new ListenPort());
        ListenPort *ls = ptr.get();

        if (!ls->import(sock)) {
            continue;
        }

        // O_NONBLOCK & O_CLOEXEC
        ls->socket->set_fd_option(1, 1);

        ptr.release();
        check_port_type(ls);
        ports.push_back(ls);
        count++;
    }

    return count;
}

ListenPort *Server::add_port(SocketType type, const char *host, int port) {
    if (session_list) {
        swoole_error_log(SW_LOG_ERROR, SW_ERROR_WRONG_OPERATION, "must add port before server is created");
        return nullptr;
    }
    if (ports.size() >= SW_MAX_LISTEN_PORT) {
        swoole_error_log(SW_LOG_ERROR,
                         SW_ERROR_SERVER_TOO_MANY_LISTEN_PORT,
                         "up to %d listening ports are allowed",
                         SW_MAX_LISTEN_PORT);
        return nullptr;
    }
    if (!(type == SW_SOCK_UNIX_DGRAM || type == SW_SOCK_UNIX_STREAM) && (port < 0 || port > 65535)) {
        swoole_error_log(SW_LOG_ERROR, SW_ERROR_SERVER_INVALID_LISTEN_PORT, "invalid port [%d]", port);
        return nullptr;
    }
    if (strlen(host) + 1 > SW_HOST_MAXSIZE) {
        swoole_error_log(SW_LOG_ERROR,
                         SW_ERROR_NAME_TOO_LONG,
                         "address '%s' exceeds the limit of %ld characters",
                         host,
                         SW_HOST_MAXSIZE - 1);
        return nullptr;
    }

    std::unique_ptr<ListenPort> ptr(new ListenPort);
    ListenPort *ls = ptr.get();

    ls->type = type;
    ls->port = port;
    ls->host = host;

#ifdef SW_USE_OPENSSL
    if (type & SW_SOCK_SSL) {
        type = (SocketType) (type & (~SW_SOCK_SSL));
        ls->type = type;
        ls->ssl = 1;
        ls->ssl_context = new SSLContext();
        ls->ssl_context->prefer_server_ciphers = 1;
        ls->ssl_context->session_tickets = 0;
        ls->ssl_context->stapling = 1;
        ls->ssl_context->stapling_verify = 1;
        ls->ssl_context->ciphers = sw_strdup(SW_SSL_CIPHER_LIST);
        ls->ssl_context->ecdh_curve = sw_strdup(SW_SSL_ECDH_CURVE);

        if (ls->is_dgram()) {
#ifdef SW_SUPPORT_DTLS
            ls->ssl_context->protocols = SW_SSL_DTLS;
            ls->dtls_sessions = new std::unordered_map<int, dtls::Session *>;

#else
            swoole_warning("DTLS support require openssl-1.1 or later");
            return nullptr;
#endif
        }
    }
#endif

    ls->socket = make_socket(
        ls->type, ls->is_dgram() ? SW_FD_DGRAM_SERVER : SW_FD_STREAM_SERVER, SW_SOCK_CLOEXEC | SW_SOCK_NONBLOCK);
    if (ls->socket == nullptr) {
        return nullptr;
    }
#if defined(SW_SUPPORT_DTLS) && defined(HAVE_KQUEUE)
    if (ls->is_dtls()) {
        ls->socket->set_reuse_port();
    }
#endif

    if (ls->socket->bind(ls->host, &ls->port) < 0) {
        ls->socket->free();
        return nullptr;
    }
    ls->socket->info.assign(ls->type, ls->host, ls->port);
    check_port_type(ls);
    ptr.release();
    ports.push_back(ls);
    return ls;
}

static void Server_signal_handler(int sig) {
    swoole_trace_log(SW_TRACE_SERVER, "signal[%d] %s triggered in %d", sig, swoole_signal_to_str(sig), getpid());

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
            swoole_warning("Fatal Error: manager process exit. status=%d, signal=[%s]",
                           WEXITSTATUS(status),
                           swoole_signal_to_str(WTERMSIG(status)));
        }
        break;
    case SIGVTALRM:
        swoole_warning("SIGVTALRM coming");
        break;
    case SIGUSR1:
    case SIGUSR2:
        if (serv->is_base_mode()) {
            if (!serv->gs->event_workers.reload()) {
                break;
            }
            serv->gs->event_workers.reload_init = false;
        } else {
            swoole_kill(serv->gs->manager_pid, sig);
        }
        sw_logger()->reopen();
        break;
    case SIGIO:
        serv->gs->event_workers.read_message = true;
        break;
    default:

#ifdef SIGRTMIN
        if (sig == SIGRTMIN) {
            uint32_t i;
            Worker *worker;
            for (i = 0; i < serv->worker_num + serv->task_worker_num + serv->get_user_worker_num(); i++) {
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

void Server::abort_connection(Reactor *reactor, ListenPort *ls, Socket *_socket) {
    sw_atomic_fetch_add(&gs->abort_count, 1);
    sw_atomic_fetch_add(&ls->gs->abort_count, 1);
    if (_socket->object) {
        reactor->close(reactor, _socket);
    } else {
        _socket->free();
    }
}

/**
 * new connection
 */
Connection *Server::add_connection(ListenPort *ls, Socket *_socket, int server_fd) {
    int fd = _socket->fd;

    Connection *connection = &(connection_list[fd]);
    ReactorId reactor_id = is_base_mode() ? SwooleG.process_id : fd % reactor_num;
    *connection = {};

    sw_spinlock(&gs->spinlock);
    SessionId session_id = gs->session_round;
    // get session id
    SW_LOOP_N(max_connection) {
        Session *session = get_session(++session_id);
        // available slot
        if (session->fd == 0) {
            session->fd = fd;
            session->id = session_id;
            session->reactor_id = reactor_id;
            goto _find_available_slot;
        }
    }
    sw_spinlock_release(&gs->spinlock);
    swoole_error_log(SW_LOG_WARNING, SW_ERROR_SERVER_TOO_MANY_SOCKET, "no available session slot, fd=%d", fd);
    return nullptr;

_find_available_slot:
    sw_spinlock_release(&gs->spinlock);
    gs->session_round = session_id;
    connection->session_id = session_id;

    _socket->object = connection;
    _socket->removed = 1;
    _socket->buffer_size = ls->socket_buffer_size;
    _socket->send_timeout_ = _socket->recv_timeout_ = 0;

    // TCP Nodelay
    if (ls->open_tcp_nodelay && (ls->type == SW_SOCK_TCP || ls->type == SW_SOCK_TCP6)) {
        if (ls->socket->set_tcp_nodelay() != 0) {
            swoole_sys_warning("setsockopt(TCP_NODELAY) failed");
        }
        _socket->enable_tcp_nodelay = true;
    }

    // socket recv buffer size
    if (ls->kernel_socket_recv_buffer_size > 0) {
        if (ls->socket->set_option(SOL_SOCKET, SO_RCVBUF, ls->kernel_socket_recv_buffer_size) != 0) {
            swoole_sys_warning("setsockopt(SO_RCVBUF, %d) failed", ls->kernel_socket_recv_buffer_size);
        }
    }

    // socket send buffer size
    if (ls->kernel_socket_send_buffer_size > 0) {
        if (ls->socket->set_option(SOL_SOCKET, SO_SNDBUF, ls->kernel_socket_send_buffer_size) != 0) {
            swoole_sys_warning("setsockopt(SO_SNDBUF, %d) failed", ls->kernel_socket_send_buffer_size);
        }
    }

    connection->fd = fd;
    connection->reactor_id = reactor_id;
    connection->server_fd = (sw_atomic_t) server_fd;
    connection->last_recv_time = connection->connect_time = microtime();
    connection->active = 1;
    connection->worker_id = -1;
    connection->socket_type = ls->type;
    connection->socket = _socket;

    memcpy(&connection->info.addr, &_socket->info.addr, _socket->info.len);
    connection->info.len = _socket->info.len;
    connection->info.type = connection->socket_type;

    if (!ls->ssl) {
        _socket->direct_send = 1;
    }

    lock();
    if (fd > get_maxfd()) {
        set_maxfd(fd);
    } else if (fd < get_minfd()) {
        set_minfd(fd);
    }
    unlock();

    gs->accept_count++;
    ls->gs->accept_count++;
    sw_atomic_fetch_add(&gs->connection_num, 1);
    sw_atomic_fetch_add(&ls->gs->connection_num, 1);

    return connection;
}

void Server::init_ipc_max_size() {
#ifndef __linux__
    ipc_max_size = SW_IPC_MAX_SIZE;
#else
    int bufsize;
    /**
     * Get the maximum ipc[unix socket with dgram] transmission length
     */
    if (workers[0].pipe_master->get_option(SOL_SOCKET, SO_SNDBUF, &bufsize) != 0) {
        bufsize = SW_IPC_MAX_SIZE;
    }
    ipc_max_size = SW_MIN(bufsize, SW_IPC_BUFFER_MAX_SIZE) - SW_DGRAM_HEADER_SIZE;
#endif
}

/**
 * allocate memory for Server::pipe_buffers
 */
int Server::create_pipe_buffers() {
    message_bus.set_buffer_size(ipc_max_size);
    return message_bus.alloc_buffer() ? SW_OK : SW_ERR;
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
    uint32_t idle_worker_num = 0;

    for (uint32_t i = worker_num; i < (worker_num + task_worker_num); i++) {
        Worker *worker = get_worker(i);
        if (worker->status == SW_WORKER_IDLE) {
            idle_worker_num++;
        }
    }

    return idle_worker_num;
}

int Server::get_task_count() {
    // TODO Why need to reset ?
    int tasking_num = gs->tasking_num;
    if (tasking_num < 0) {
        tasking_num = gs->tasking_num = 0;
    }
    return tasking_num;
}

}  // namespace swoole
