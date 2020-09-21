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

#pragma once

#include "swoole_api.h"
#include "swoole_string.h"
#include "swoole_socket.h"
#include "swoole_timer.h"
#include "swoole_reactor.h"
#include "swoole_signal.h"
#include "swoole_protocol.h"
#include "swoole_log.h"
#include "swoole_process_pool.h"
#include "swoole_pipe.h"
#include "swoole_channel.h"
#include "swoole_ssl.h"

#ifdef SW_USE_OPENSSL
#include "swoole_dtls.h"
#endif

#ifdef __MACH__
#include <sys/syslimits.h>
#endif

#include <string>
#include <queue>
#include <thread>
#include <mutex>
#include <unordered_map>
#include <unordered_set>

#define SW_REACTOR_NUM SW_CPU_NUM
#define SW_WORKER_NUM (SW_CPU_NUM * 2)

enum swTask_ipc_mode {
    SW_TASK_IPC_UNIXSOCK = 1,
    SW_TASK_IPC_MSGQUEUE = 2,
    SW_TASK_IPC_PREEMPTIVE = 3,
    SW_TASK_IPC_STREAM = 4,
};

enum swFactory_dispatch_mode {
    SW_DISPATCH_ROUND = 1,
    SW_DISPATCH_FDMOD = 2,
    SW_DISPATCH_QUEUE = 3,
    SW_DISPATCH_IPMOD = 4,
    SW_DISPATCH_UIDMOD = 5,
    SW_DISPATCH_USERFUNC = 6,
    SW_DISPATCH_STREAM = 7,
};

enum swFactory_dispatch_result {
    SW_DISPATCH_RESULT_DISCARD_PACKET = -1,
    SW_DISPATCH_RESULT_CLOSE_CONNECTION = -2,
    SW_DISPATCH_RESULT_USERFUNC_FALLBACK = -3,
};

//------------------------------------Server-------------------------------------------
namespace swoole {

namespace http_server {
struct Request;
}

struct Session {
    uint32_t id;
    uint32_t fd : 24;
    uint32_t reactor_id : 8;
};

struct Connection {
    /**
     * file descript
     */
    int fd;
    /**
     * session id
     */
    uint32_t session_id;
    /**
     * socket type, SW_SOCK_TCP or SW_SOCK_UDP
     */
    enum swSocket_type socket_type;
    //--------------------------------------------------------------
    /**
     * is active
     * system fd must be 0. en: signalfd, listen socket
     */
    uint8_t active;
#ifdef SW_USE_OPENSSL
    uint8_t ssl;
    uint8_t ssl_ready;
#endif
    //--------------------------------------------------------------
    uint8_t overflow;
    uint8_t high_watermark;
    //--------------------------------------------------------------
    uint8_t http_upgrade;
#ifdef SW_USE_HTTP2
    uint8_t http2_stream;
#endif
#ifdef SW_HAVE_ZLIB
    uint8_t websocket_compression;
#endif
    //--------------------------------------------------------------
    /**
     * server is actively close the connection
     */
    uint8_t close_actively;
    uint8_t closed;
    uint8_t close_queued;
    uint8_t closing;
    uint8_t close_reset;
    uint8_t peer_closed;
    /**
     * protected connection, cannot be closed by heartbeat thread.
     */
    uint8_t protect;
    //--------------------------------------------------------------
    uint8_t close_notify;
    uint8_t close_force;
    //--------------------------------------------------------------
    /**
     * ReactorThread id
     */
    uint16_t reactor_id;
    /**
     * close error code
     */
    uint16_t close_errno;
    /**
     * from which socket fd
     */
    sw_atomic_t server_fd;
    sw_atomic_t queued_bytes;
    uint16_t waiting_time;
    TimerNode *timer;
    /**
     * socket address
     */
    network::Address info;
    /**
     * link any thing, for kernel, do not use with application.
     */
    void *object;
    /**
     * socket info
     */
    network::Socket *socket;
    /**
     * connect time(seconds)
     */
    time_t connect_time;

    /**
     * received time with last data
     */
    time_t last_time;

#ifdef SW_BUFFER_RECV_TIME
    /**
     * received time(microseconds) with last data
     */
    double last_time_usec;
#endif
    /**
     * bind uid
     */
    uint32_t uid;
    /**
     * upgarde websocket
     */
    uint8_t websocket_status;
    /**
     * unfinished data frame
     */
    String *websocket_buffer;

#ifdef SW_USE_OPENSSL
    String *ssl_client_cert;
    uint16_t ssl_client_cert_pid;
#endif
    sw_atomic_t lock;
};

struct ReactorThread {
    std::thread thread;
    network::Socket *notify_pipe = nullptr;
    uint32_t pipe_num = 0;
    network::Socket *pipe_sockets = nullptr;
    std::unordered_map<int, String *> send_buffers;
};

struct WorkerStopMessage {
    pid_t pid;
    uint16_t worker_id;
};

struct SendData {
    DataHead info;
    const char *data;
};

struct RecvData {
    DataHead info;
    const char *data;
};

struct PipeBuffer {
    DataHead info;
    char data[0];
};

struct DgramPacket {
    int socket_type;
    network::Address socket_addr;
    uint32_t length;
    char data[0];
};

//------------------------------------Packet-------------------------------------------
struct PacketTask {
    size_t length;
    char tmpfile[SW_TASK_TMPDIR_SIZE + sizeof(SW_TASK_TMP_FILE)];
};

struct PacketPtr {
    DataHead info;
    String data;
};

struct ListenPort {
    /**
     * tcp socket listen backlog
     */
    uint16_t backlog = SW_BACKLOG;
    /**
     * open tcp_defer_accept option
     */
    int tcp_defer_accept = 0;
    /**
     * TCP_FASTOPEN
     */
    int tcp_fastopen = 0;
    /**
     * TCP KeepAlive
     */
    int tcp_keepidle = SW_TCP_KEEPIDLE;
    int tcp_keepinterval = SW_TCP_KEEPINTERVAL;
    int tcp_keepcount = SW_TCP_KEEPCOUNT;

    int tcp_user_timeout = 0;

    int socket_buffer_size = network::Socket::default_buffer_size;
    uint32_t buffer_high_watermark = 0;
    uint32_t buffer_low_watermark = 0;

    enum swSocket_type type = SW_SOCK_TCP;
    uint8_t ssl = 0;
    int port = 0;
    int socket_fd = 0;
    network::Socket *socket = nullptr;
    pthread_t thread_id = 0;
    char host[SW_HOST_MAXSIZE] = {};

    /**
     * check data eof
     */
    bool open_eof_check = false;
    /**
     * built-in http protocol
     */
    bool open_http_protocol = false;
    /**
     * built-in http2.0 protocol
     */
    bool open_http2_protocol = false;
    /**
     * built-in websocket protocol
     */
    bool open_websocket_protocol = false;
    /**
     * open websocket close frame
     */
    bool open_websocket_close_frame = false;
    /**
     * open websocket ping frame
     */
    bool open_websocket_ping_frame = false;
    /**
     * open websocket pong frame
     */
    bool open_websocket_pong_frame = false;
    /**
     *  one package: length check
     */
    bool open_length_check = false;
    /**
     * for mqtt protocol
     */
    bool open_mqtt_protocol = false;
    /**
     *  redis protocol
     */
    bool open_redis_protocol = false;
    /**
     * open tcp nodelay option
     */
    bool open_tcp_nodelay = false;
    /**
     * open tcp nopush option(for sendfile)
     */
    bool open_tcp_nopush = true;
    /**
     * open tcp keepalive
     */
    bool open_tcp_keepalive = false;
    /**
     * open tcp keepalive
     */
    bool open_ssl_encrypt = false;
    /**
     * Sec-WebSocket-Protocol
     */
    std::string websocket_subprotocol;
    /**
     * set socket option
     */
    int kernel_socket_recv_buffer_size = 0;
    int kernel_socket_send_buffer_size = 0;

#ifdef SW_USE_OPENSSL
    SSL_CTX *ssl_context = nullptr;
    swSSL_config ssl_config = {};
    swSSL_option ssl_option = {};
#ifdef SW_SUPPORT_DTLS
    std::unordered_map<int, dtls::Session *> *dtls_sessions = nullptr;
#endif
#endif

    sw_atomic_t *connection_num = nullptr;

    Protocol protocol = {};
    void *ptr = nullptr;

    int (*onRead)(Reactor *reactor, ListenPort *port, swEvent *event) = nullptr;

    inline bool is_dgram() {
        return network::Socket::is_dgram(type);
    }

    inline bool is_stream() {
        return network::Socket::is_stream(type);
    }

    inline void set_eof_protocol(const std::string &eof, bool find_from_right = false) {
        open_eof_check = true;
        protocol.split_by_eof = !find_from_right;
        protocol.package_eof_len = std::min(eof.length(), sizeof(protocol.package_eof));
        memcpy(protocol.package_eof, eof.c_str(), protocol.package_eof_len);
    }

    inline void set_length_protocol(uint32_t length_offset, char length_type, uint32_t body_offset) {
        open_length_check = true;
        protocol.package_length_type = length_type;
        protocol.package_length_size = swoole_type_size(length_type);
        protocol.package_body_offset = length_offset;
        protocol.package_body_offset = body_offset;
    }

    ListenPort();
    ~ListenPort() = default;
    int listen();
    void close();
    int set_address(int sock);
#ifdef SW_USE_OPENSSL
    int enable_ssl_encrypt();
#endif
    void clear_protocol();
    inline network::Socket *get_socket() {
        return socket;
    }
};

struct ServerGS {
    pid_t master_pid;
    pid_t manager_pid;

    uint32_t session_round : 24;
    sw_atomic_t start;
    sw_atomic_t shutdown;

    int max_fd;
    int min_fd;

    time_t start_time;
    sw_atomic_t connection_num;
    sw_atomic_t tasking_num;
    sw_atomic_long_t accept_count;
    sw_atomic_long_t close_count;
    sw_atomic_long_t request_count;

    sw_atomic_t spinlock;

    ProcessPool task_workers;
    ProcessPool event_workers;
};

struct Factory {
    void *object;
    void *ptr;  // server object

    int (*start)(Factory *);
    int (*shutdown)(Factory *);
    bool (*dispatch)(Factory *, SendData *);
    bool (*finish)(Factory *, SendData *);
    bool (*notify)(Factory *, DataHead *);  // send a event notify
    bool (*end)(Factory *, int fd);
    void (*free)(Factory *);
};

enum ServerEventType {
    // recv data payload
    SW_SERVER_EVENT_RECV_DATA,
    SW_SERVER_EVENT_RECV_DGRAM,
    // send data
    SW_SERVER_EVENT_SEND_FILE,
    // connection event
    SW_SERVER_EVENT_CLOSE,
    SW_SERVER_EVENT_CONNECT,
    SW_SERVER_EVENT_CLOSE_FORCE,
    // task
    SW_SERVER_EVENT_TASK,
    SW_SERVER_EVENT_FINISH,
    // pipe
    SW_SERVER_EVENT_PIPE_MESSAGE,
    // proxy
    SW_SERVER_EVENT_PROXY_START,
    SW_SERVER_EVENT_PROXY_END,
    // event operate
    SW_SERVER_EVENT_PAUSE_RECV,
    SW_SERVER_EVENT_RESUME_RECV,
    // buffer event
    SW_SERVER_EVENT_BUFFER_FULL,
    SW_SERVER_EVENT_BUFFER_EMPTY,
    // process message
    SW_SERVER_EVENT_INCOMING,
    SW_SERVER_EVENT_SHUTDOWN,
};

class Server {
  public:
    typedef int (*DispatchFunction)(Server *, Connection *, SendData *);

    enum Mode {
        MODE_BASE = 1,
        MODE_PROCESS = 2,
    };

    enum HookType {
        HOOK_MASTER_START,
        HOOK_MASTER_TIMER,
        HOOK_REACTOR_START,
        HOOK_WORKER_START,
        HOOK_TASK_WORKER_START,
        HOOK_MASTER_CONNECT,
        HOOK_REACTOR_CONNECT,
        HOOK_WORKER_CONNECT,
        HOOK_REACTOR_RECEIVE,
        HOOK_WORKER_RECEIVE,
        HOOK_REACTOR_CLOSE,
        HOOK_WORKER_CLOSE,
        HOOK_MANAGER_START,
        HOOK_MANAGER_TIMER,
        HOOK_PROCESS_TIMER,
    };

    /**
     * reactor thread/process num
     */
    uint16_t reactor_num = 0;
    /**
     * worker process num
     */
    uint32_t worker_num = 0;

    uint8_t dgram_port_num = 0;

    /**
     * package dispatch mode
     */
    uint8_t dispatch_mode = SW_DISPATCH_FDMOD;

    /**
     * No idle work process is available.
     */
    bool scheduler_warning = false;

    int worker_uid = 0;
    int worker_groupid = 0;
    void **worker_input_buffers = nullptr;

    /**
     * worker process max request
     */
    uint32_t max_request = 0;
    uint32_t max_request_grace = 0;

    network::Socket *udp_socket_ipv4 = nullptr;
    network::Socket *udp_socket_ipv6 = nullptr;
    network::Socket *dgram_socket = nullptr;
    int null_fd = -1;

    uint32_t max_wait_time = SW_WORKER_MAX_WAIT_TIME;

    /*----------------------------Reactor schedule--------------------------------*/
    sw_atomic_t worker_round_id = 0;

    /**
     * worker(worker and task_worker) process chroot / user / group
     */
    std::string chroot;
    std::string user;
    std::string group;

    /**
     * run as a daemon process
     */
    bool daemonize = false;
    /**
     * have dgram socket
     */
    bool have_dgram_sock = false;
    /**
     * have stream socket
     */
    bool have_stream_sock = false;
    /**
     * open cpu affinity setting
     */
    bool open_cpu_affinity = false;
    /**
     * disable notice when use SW_DISPATCH_ROUND and SW_DISPATCH_QUEUE
     */
    bool disable_notify = false;
    /**
     * discard the timeout request
     */
    bool discard_timeout_request = false;
    /**
     * parse cookie header
     */
    bool http_parse_cookie = true;
    /**
     * parse x-www-form-urlencoded data
     */
    bool http_parse_post = true;
    /**
     * parse multipart/form-data files to match $_FILES
     */
    bool http_parse_files = false;
    /**
     * http content compression
     */
    bool http_compression = false;
    /**
     * RFC-7692
     */
    bool websocket_compression = false;
    /**
     * handle static files
     */
    bool enable_static_handler = false;
    /**
     * show file list in the current directory
     */
    bool http_autoindex = false;
    /**
     * enable onConnect/onClose event when use dispatch_mode=1/3
     */
    bool enable_unsafe_event = false;
    /**
     * waiting for worker onConnect callback function to return
     */
    bool enable_delay_receive = false;
    /**
     * reuse port
     */
    bool enable_reuse_port = false;
    /**
     * asynchronous reloading
     */
    bool reload_async = true;
    /**
     * use task object
     */
    bool task_use_object = false;
    /**
     * enable coroutine in task worker
     */
    bool task_enable_coroutine = false;
    /**
     * yield coroutine when the output buffer is full
     */
    bool send_yield = true;
    /**
     * enable coroutine
     */
    bool enable_coroutine = true;
    /**
     * disable multi-threads
     */
    bool single_thread = false;
    /**
     * server status
     */
    bool running = true;

    /**
     *  heartbeat check time
     */
    uint16_t heartbeat_idle_time = 0;

    int *cpu_affinity_available = 0;
    int cpu_affinity_available_num = 0;

    PipeBuffer **pipe_buffers = nullptr;
    double send_timeout = 0;

    time_t reload_time = 0;
    time_t warning_time = 0;
    long timezone_ = 0;
    TimerNode *master_timer = nullptr;

    /* buffer output/input setting*/
    uint32_t output_buffer_size = SW_OUTPUT_BUFFER_SIZE;
    uint32_t input_buffer_size = SW_INPUT_BUFFER_SIZE;
    uint32_t max_queued_bytes = 0;

    /**
     * the master process and worker process communicate using unix socket dgram.
     * ipc_max_size represents the maximum size of each datagram,
     * which is obtained from the kernel send buffer of unix socket in swServer_set_ipc_max_size function.
     */
    uint32_t ipc_max_size = SW_IPC_MAX_SIZE;

    void *ptr2 = nullptr;
    void *private_data_3 = nullptr;

    Factory factory;
    std::vector<ListenPort *> ports;

    inline ListenPort *get_primary_port() {
        return ports.front();
    }

    inline ListenPort *get_port(int _port) {
        for (auto port : ports) {
            if (port->port == _port || _port == 0) {
                return port;
            }
        }
        return nullptr;
    }

    inline ListenPort *get_port_by_server_fd(int server_fd) {
        return (ListenPort *) connection_list[server_fd].object;
    }

    inline ListenPort *get_port_by_fd(int fd) {
        return get_port_by_server_fd(connection_list[fd].server_fd);
    }

    inline ListenPort *get_port_by_session_id(int session_id) {
        Connection *conn = get_connection_by_session_id(session_id);
        if (!conn) {
            return nullptr;
        }
        return get_port_by_fd(conn->fd);
    }

    inline network::Socket *get_server_socket(int fd) {
        return connection_list[fd].socket;
    }

    /**
     *  task process
     */
    uint32_t task_worker_num = 0;
    uint8_t task_ipc_mode = SW_TASK_IPC_UNIXSOCK;
    uint32_t task_max_request = 0;
    uint32_t task_max_request_grace = 0;
    Pipe *task_notify = nullptr;
    EventData *task_result = nullptr;

    /**
     * user process
     */
    uint32_t user_worker_num = 0;
    std::vector<Worker *> *user_worker_list = nullptr;
    std::unordered_map<pid_t, Worker *> *user_worker_map = nullptr;
    Worker *user_workers = nullptr;

    Worker *workers = nullptr;
    Channel *message_box = nullptr;
    ServerGS *gs = nullptr;

    std::unordered_set<std::string> *types = nullptr;
    std::unordered_set<std::string> *locations = nullptr;
    std::vector<std::string> *http_index_files = nullptr;

#ifdef HAVE_PTHREAD_BARRIER
    pthread_barrier_t barrier = {};
#endif

    /**
     * temporary directory for HTTP uploaded file.
     */
    std::string upload_tmp_dir = "/tmp";
    /**
     * http compression level for gzip/br
     */
#ifdef SW_HAVE_COMPRESSION
    uint8_t http_compression_level = 0;
#endif
    /**
     * master process pid
     */
    std::string pid_file;
    /**
     * stream
     */
    char *stream_socket_file = nullptr;
    network::Socket *stream_socket = nullptr;
    Protocol stream_protocol = {};
    network::Socket *last_stream_socket = nullptr;
    EventData *last_task = nullptr;
    std::queue<String *> *buffer_pool = nullptr;

    swAllocator *buffer_allocator = &SwooleG.std_allocator;
    size_t recv_buffer_size = SW_BUFFER_SIZE_BIG;

#ifdef SW_BUFFER_RECV_TIME
    double last_receive_usec = 0;
#endif

    int manager_alarm = 0;

    /**
     * message queue key
     */
    uint64_t message_queue_key = 0;

    void *hooks[SW_MAX_HOOK_TYPE] = {};

    /**
     * Master Process
     */
    std::function<void(Server *)> onStart;
    std::function<void(Server *)> onShutdown;
    /**
     * Manager Process
     */
    std::function<void(Server *)> onManagerStart;
    std::function<void(Server *)> onManagerStop;
    std::function<void(Server *, int, pid_t, int, int)> onWorkerError;
    std::function<void(Server *)> onBeforeReload;
    std::function<void(Server *)> onAfterReload;
    /**
     * Worker Process
     */
    std::function<void(Server *, EventData *)> onPipeMessage;
    std::function<void(Server *, uint32_t)> onWorkerStart;
    std::function<void(Server *, uint32_t)> onWorkerStop;
    std::function<void(Server *, uint32_t)> onWorkerExit;
    std::function<void(Server *, Worker *)> onUserWorkerStart;
    /**
     * Connection
     */
    std::function<int(Server *, RecvData *)> onReceive;
    std::function<int(Server *, RecvData *)> onPacket;
    std::function<void(Server *, DataHead *)> onClose;
    std::function<void(Server *, DataHead *)> onConnect;
    std::function<void(Server *, DataHead *)> onBufferFull;
    std::function<void(Server *, DataHead *)> onBufferEmpty;
    /**
     * Task Worker
     */
    std::function<int(Server *, EventData *)> onTask;
    std::function<int(Server *, EventData *)> onFinish;
    /**
     * Chunk control
     */
    void **(*create_buffers)(Server *serv, uint32_t buffer_num) = nullptr;
    void (*free_buffers)(Server *serv, uint32_t buffer_num, void **buffers) = nullptr;
    void *(*get_buffer)(Server *serv, DataHead *info) = nullptr;
    size_t (*get_buffer_len)(Server *serv, DataHead *info) = nullptr;
    void (*add_buffer_len)(Server *serv, DataHead *info, size_t len) = nullptr;
    void (*move_buffer)(Server *serv, PipeBuffer *buffer) = nullptr;
    size_t (*get_packet)(Server *serv, EventData *req, char **data_ptr) = nullptr;
    /**
     * Hook
     */
    int (*dispatch_func)(Server *, Connection *, SendData *) = nullptr;

  public:
    Server(enum Mode _mode = MODE_BASE);
    ~Server();

    bool set_document_root(const std::string &path) {
        if (path.length() > PATH_MAX) {
            swWarn("The length of document_root must be less than %d", PATH_MAX);
            return false;
        }

        char _realpath[PATH_MAX];
        if (!realpath(path.c_str(), _realpath)) {
            swWarn("document_root[%s] does not exist", path.c_str());
            return false;
        }

        document_root = std::string(_realpath);
        return true;
    }

    void add_static_handler_location(const std::string &);
    void add_static_handler_index_files(const std::string &);
    bool select_static_handler(http_server::Request *request, Connection *conn);

    int create();
    int start();
    void shutdown();

    int add_worker(Worker *worker);
    ListenPort *add_port(enum swSocket_type type, const char *host, int port);
    int add_systemd_socket();
    int add_hook(enum HookType type, const Callback &func, int push_back);
    Connection *add_connection(ListenPort *ls, network::Socket *_socket, int server_fd);
    void add_heartbeat_check_timer(Reactor *reactor, Connection *conn);
    int connection_incoming(Reactor *reactor, Connection *conn);

    int get_idle_worker_num();
    int get_idle_task_worker_num();

    inline int get_minfd() {
        return gs->min_fd;
    }

    inline int get_maxfd() {
        return gs->max_fd;
    }

    inline void set_maxfd(int maxfd) {
        gs->max_fd = maxfd;
    }

    inline void set_minfd(int minfd) {
        gs->min_fd = minfd;
    }

    void store_listen_socket();
    void store_pipe_fd(Pipe *p);

    inline const std::string &get_document_root() {
        return document_root;
    }

    inline String *get_recv_buffer(swSocket *_socket) {
        String *buffer = _socket->recv_buffer;
        if (buffer == nullptr) {
            buffer = swoole::make_string(SW_BUFFER_SIZE_BIG, buffer_allocator);
            if (!buffer) {
                return nullptr;
            }
            _socket->recv_buffer = buffer;
        }

        return buffer;
    }

    inline uint32_t get_worker_buffer_num() {
        return is_base_mode() ? 1 : reactor_num + dgram_port_num;
    }

    /**
     * reactor_id: The fd in which the reactor.
     */
    inline swSocket *get_reactor_thread_pipe(int session_id, int reactor_id) {
        int pipe_index = session_id % reactor_pipe_num;
        /**
         * pipe_worker_id: The pipe in which worker.
         */
        int pipe_worker_id = reactor_id + (pipe_index * reactor_num);
        Worker *worker = get_worker(pipe_worker_id);
        return worker->pipe_worker;
    }

    inline bool is_support_unsafe_events() {
        if (dispatch_mode != SW_DISPATCH_ROUND && dispatch_mode != SW_DISPATCH_QUEUE &&
            dispatch_mode != SW_DISPATCH_STREAM) {
            return true;
        } else {
            return enable_unsafe_event;
        }
    }

    inline bool is_process_mode() {
        return mode_ == MODE_PROCESS;
    }

    inline bool is_base_mode() {
        return mode_ == MODE_BASE;
    }

    inline bool is_hash_dispatch_mode() {
        return dispatch_mode == SW_DISPATCH_FDMOD || dispatch_mode == SW_DISPATCH_IPMOD;
    }

    inline bool is_support_send_yield() {
        return is_hash_dispatch_mode();
    }

    inline bool if_require_packet_callback(ListenPort *port, bool isset) {
#ifdef SW_USE_OPENSSL
        return (port->is_dgram() && !port->ssl && !isset);
#else
        return (port->is_dgram() && !isset);
#endif
    }

    inline bool if_require_receive_callback(ListenPort *port, bool isset) {
#ifdef SW_USE_OPENSSL
        return (((port->is_dgram() && port->ssl) || port->is_stream()) && !isset);
#else
        return (port->is_stream() && !isset);
#endif
    }

    inline Worker *get_worker(uint16_t worker_id) {
        // Event Worker
        if (worker_id < worker_num) {
            return &(gs->event_workers.workers[worker_id]);
        }

        // Task Worker
        uint32_t task_worker_max = task_worker_num + worker_num;
        if (worker_id < task_worker_max) {
            return &(gs->task_workers.workers[worker_id - worker_num]);
        }

        // User Worker
        uint32_t user_worker_max = task_worker_max + user_worker_num;
        if (worker_id < user_worker_max) {
            return &(user_workers[worker_id - task_worker_max]);
        }

        return nullptr;
    }

    void stop_async_worker(Worker *worker);

    inline Pipe *get_pipe_object(int pipe_fd) {
        return (Pipe *) connection_list[pipe_fd].object;
    }

    inline String *get_worker_input_buffer(int reactor_id) {
        if (is_base_mode()) {
            return (String *) worker_input_buffers[0];
        } else {
            return (String *) worker_input_buffers[reactor_id];
        }
    }

    inline ReactorThread *get_thread(int reactor_id) {
        return &reactor_threads[reactor_id];
    }

    inline bool is_started() {
        return gs->start;
    }

    inline bool is_shutdown() {
        return gs->shutdown;
    }

    inline bool is_valid_connection(Connection *conn) {
        return (conn && conn->socket && conn->active && conn->socket->fdtype == SW_FD_SESSION);
    }

    static int is_dgram_event(uint8_t type) {
        switch (type) {
        case SW_SERVER_EVENT_RECV_DGRAM:
            return true;
        default:
            return false;
        }
    }

    static int is_stream_event(uint8_t type) {
        switch (type) {
        case SW_SERVER_EVENT_RECV_DATA:
        case SW_SERVER_EVENT_CONNECT:
        case SW_SERVER_EVENT_CLOSE:
        case SW_SERVER_EVENT_PAUSE_RECV:
        case SW_SERVER_EVENT_RESUME_RECV:
        case SW_SERVER_EVENT_BUFFER_FULL:
        case SW_SERVER_EVENT_BUFFER_EMPTY:
            return true;
        default:
            return false;
        }
    }

    inline int get_connection_fd(uint32_t session_id) {
        return session_list[session_id % SW_SESSION_LIST_SIZE].fd;
    }

    inline Connection *get_connection_verify_no_ssl(uint32_t session_id) {
        Session *session = get_session(session_id);
        int fd = session->fd;
        Connection *conn = get_connection(fd);
        if (!conn || conn->active == 0) {
            return nullptr;
        }
        if (session->id != session_id || conn->session_id != session_id) {
            return nullptr;
        }
        return conn;
    }

    inline Connection *get_connection_verify(uint32_t session_id) {
        Connection *conn = get_connection_verify_no_ssl(session_id);
#ifdef SW_USE_OPENSSL
        if (conn && conn->ssl && !conn->ssl_ready) {
            swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SSL_NOT_READY, "SSL not ready");
            return nullptr;
        }
#endif
        return conn;
    }

    inline Connection *get_connection(int fd) {
        if ((uint32_t) fd > max_connection) {
            return nullptr;
        }
        return &connection_list[fd];
    }

    inline Connection *get_connection_by_session_id(int session_id) {
        return get_connection(get_connection_fd(session_id));
    }

    inline Session *get_session(uint32_t session_id) {
        return &session_list[session_id % SW_SESSION_LIST_SIZE];
    }

    inline void lock() {
        lock_.lock();
    }

    inline void unlock() {
        lock_.unlock();
    }

    void close_port(bool only_stream_port);
    void clear_timer();
    static void timer_callback(Timer *timer, TimerNode *tnode);

    int create_task_workers();
    int create_user_workers();
    int start_manager_process();

    void call_hook(enum HookType type, void *arg);
    void call_worker_start_callback(Worker *worker);

    void foreach_connection(const std::function<void(Connection *)> &callback);

    int accept_task(EventData *task);
    static int accept_connection(Reactor *reactor, Event *event);
#ifdef SW_SUPPORT_DTLS
    dtls::Session *accept_dtls_connection(ListenPort *ls, network::Address *sa);
#endif
    static int close_connection(Reactor *reactor, network::Socket *_socket);
    static int dispatch_task(Protocol *proto, network::Socket *_socket, const char *data, uint32_t length);

    int send_to_connection(SendData *);
    ssize_t send_to_worker_from_master(Worker *worker, const void *data, size_t len);
    ssize_t send_to_worker_from_worker(Worker *dst_worker, const void *buf, size_t len, int flags);
    ssize_t send_to_reactor_thread(EventData *ev_data, size_t sendn, int session_id);
    int reply_task_result(const char *data, size_t data_len, int flags, EventData *current_task);

    bool send(int session_id, const void *data, uint32_t length);
    bool sendfile(int session_id, const char *file, uint32_t l_file, off_t offset, size_t length);
    bool sendwait(int session_id, const void *data, uint32_t length);
    bool close(int session_id, bool reset);
    bool notify(Connection *conn, int event);
    bool feedback(int session_id, int event);

    void init_reactor(Reactor *reactor);
    void init_worker(Worker *worker);
    void init_task_workers();
    void init_port_protocol(ListenPort *port);
    void init_signal_handler();

    void set_ipc_max_size();
    void set_max_connection(uint32_t _max_connection);

    inline uint32_t get_max_connection() {
        return max_connection;
    }

    int create_pipe_buffers();
    int create_worker(Worker *worker);
    void disable_accept();

    void destroy_http_request(Connection *conn);



    inline int schedule_worker(int fd, SendData *data) {
        uint32_t key = 0;

        if (dispatch_func) {
            int id = dispatch_func(this, get_connection(fd), data);
            if (id != SW_DISPATCH_RESULT_USERFUNC_FALLBACK) {
                return id;
            }
        }

        // polling mode
        if (dispatch_mode == SW_DISPATCH_ROUND) {
            key = sw_atomic_fetch_add(&worker_round_id, 1);
        }
        // Using the FD touch access to hash
        else if (dispatch_mode == SW_DISPATCH_FDMOD) {
            key = fd;
        }
        // Using the IP touch access to hash
        else if (dispatch_mode == SW_DISPATCH_IPMOD) {
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
        } else if (dispatch_mode == SW_DISPATCH_UIDMOD) {
            Connection *conn = get_connection(fd);
            if (conn == nullptr || conn->uid == 0) {
                key = fd;
            } else {
                key = conn->uid;
            }
        }
        // Preemptive distribution
        else {
            uint32_t i;
            bool found = false;
            for (i = 0; i < worker_num + 1; i++) {
                key = sw_atomic_fetch_add(&worker_round_id, 1) % worker_num;
                if (workers[key].status == SW_WORKER_IDLE) {
                    found = true;
                    break;
                }
            }
            if (sw_unlikely(!found)) {
                scheduler_warning = true;
            }
            swTraceLog(SW_TRACE_SERVER, "schedule=%d, round=%d", key, worker_round_id);
            return key;
        }
        return key % worker_num;
    }

    /**
     * [Manager]
     */
    pid_t spawn_event_worker(Worker *worker);
    pid_t spawn_user_worker(Worker *worker);
    pid_t spawn_task_worker(Worker *worker);

    void kill_user_workers();
    void kill_event_workers();
    void kill_task_workers();

    static int wait_other_worker(ProcessPool *pool, pid_t pid, int status);

    void drain_worker_pipe();

    void check_worker_exit_status(int worker_id, pid_t pid, int status);

    /**
     * [Worker]
     */
    void worker_start_callback();
    void worker_stop_callback();
    static void worker_signal_handler(int signo);
    static void worker_signal_init(void);

  private:
    enum Mode mode_;
    Connection *connection_list = nullptr;
    Session *session_list = nullptr;
    uint32_t *port_connnection_num_list = nullptr;
    /**
     * http static file directory
     */
    std::string document_root;
    std::mutex lock_;
    uint32_t max_connection = 0;
    TimerNode *enable_accept_timer = nullptr;
    /**
     * The number of pipe per reactor maintenance
     */
    uint16_t reactor_pipe_num = 0;
    ReactorThread *reactor_threads = nullptr;

    int start_check();
    void check_port_type(ListenPort *ls);
    void destroy();
    void destroy_reactor_threads();
    void destroy_reactor_processes();
    int create_reactor_processes();
    int create_reactor_threads();
    int start_reactor_threads();
    int start_reactor_processes();
    int start_event_worker(Worker *worker);
    void join_reactor_thread();
};

}  // namespace swoole

typedef swoole::Server swServer;
typedef swoole::ListenPort swListenPort;
typedef swoole::Connection swConnection;
typedef swoole::Factory swFactory;
typedef swoole::RecvData swRecvData;
typedef swoole::DgramPacket swDgramPacket;

#define SW_MAX_SESSION_ID 0x1000000

extern swoole::Server *g_server_instance;

static inline swoole::Server *sw_server() {
    return g_server_instance;
}

bool swFactory_finish(swoole::Factory *factory, swoole::SendData *_send);
