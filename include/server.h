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
#include "swoole_cxx.h"
#include "ssl.h"
#include "http.h"

#ifdef SW_USE_OPENSSL
#include "dtls.h"
#endif

#include <string>
#include <queue>
#include <thread>
#include <unordered_map>
#include <unordered_set>

#define SW_REACTOR_NUM             SW_CPU_NUM
#define SW_WORKER_NUM              (SW_CPU_NUM*2)

enum swServer_event_type
{
    //data payload
    SW_SERVER_EVENT_SEND_DATA,
    SW_SERVER_EVENT_SEND_FILE,
    SW_SERVER_EVENT_SNED_DGRAM,
    //connection event
    SW_SERVER_EVENT_CLOSE,
    SW_SERVER_EVENT_CONNECT,
    SW_SERVER_EVENT_CLOSE_FORCE,
    //task
    SW_SERVER_EVENT_TASK,
    SW_SERVER_EVENT_FINISH,
    //pipe
    SW_SERVER_EVENT_PIPE_MESSAGE,
    //proxy
    SW_SERVER_EVENT_PROXY_START,
    SW_SERVER_EVENT_PROXY_END,
    //event operate
    SW_SERVER_EVENT_PAUSE_RECV,
    SW_SERVER_EVENT_RESUME_RECV,
    //buffer event
    SW_SERVER_EVENT_BUFFER_FULL,
    SW_SERVER_EVENT_BUFFER_EMPTY,
    //process message
    SW_SERVER_EVENT_INCOMING,
    SW_SERVER_EVENT_SHUTDOWN,
};

enum swTask_ipc_mode
{
    SW_TASK_IPC_UNIXSOCK    = 1,
    SW_TASK_IPC_MSGQUEUE    = 2,
    SW_TASK_IPC_PREEMPTIVE  = 3,
    SW_TASK_IPC_STREAM      = 4,
};

enum swFactory_dispatch_mode
{
    SW_DISPATCH_ROUND    = 1,
    SW_DISPATCH_FDMOD    = 2,
    SW_DISPATCH_QUEUE    = 3,
    SW_DISPATCH_IPMOD    = 4,
    SW_DISPATCH_UIDMOD   = 5,
    SW_DISPATCH_USERFUNC = 6,
    SW_DISPATCH_STREAM   = 7,
};

enum swFactory_dispatch_result
{
    SW_DISPATCH_RESULT_DISCARD_PACKET    = -1,
    SW_DISPATCH_RESULT_CLOSE_CONNECTION  = -2,
    SW_DISPATCH_RESULT_USERFUNC_FALLBACK = -3,
};

#define SW_SERVER_MAX_FD_INDEX          0 //max connection socket
#define SW_SERVER_MIN_FD_INDEX          1 //min listen socket

struct swListenPort
{
    /**
     * tcp socket listen backlog
     */
    uint16_t backlog;
    /**
     * open tcp_defer_accept option
     */
    int tcp_defer_accept;
    /**
     * TCP_FASTOPEN
     */
    int tcp_fastopen;
    /**
     * TCP KeepAlive
     */
    int tcp_keepidle;
    int tcp_keepinterval;
    int tcp_keepcount;

    int tcp_user_timeout;

    int socket_buffer_size;
    uint32_t buffer_high_watermark;
    uint32_t buffer_low_watermark;

    enum swSocket_type type;
    uint8_t ssl;
    int port;
    int socket_fd;
    swSocket *socket;
    pthread_t thread_id;
    char host[SW_HOST_MAXSIZE];

    /**
     * check data eof
     */
    uchar open_eof_check :1;
    /**
     * built-in http protocol
     */
    uchar open_http_protocol :1;
    /**
     * built-in http2.0 protocol
     */
    uchar open_http2_protocol :1;
    /**
     * built-in websocket protocol
     */
    uchar open_websocket_protocol :1;
    /**
     * open websocket close frame
     */
    uchar open_websocket_close_frame :1;
    /**
     *  one package: length check
     */
    uchar open_length_check :1;
    /**
     * for mqtt protocol
     */
    uchar open_mqtt_protocol :1;
    /**
     *  redis protocol
     */
    uchar open_redis_protocol :1;
    /**
     * open tcp nodelay option
     */
    uchar open_tcp_nodelay :1;
    /**
     * open tcp nopush option(for sendfile)
     */
    uchar open_tcp_nopush :1;
    /**
     * open tcp keepalive
     */
    uchar open_tcp_keepalive :1;
    /**
     * open tcp keepalive
     */
    uchar open_ssl_encrypt :1;
    /**
     * Sec-WebSocket-Protocol
     */
    char *websocket_subprotocol;
    uint16_t websocket_subprotocol_length;
    /**
     * set socket option
     */
    int kernel_socket_recv_buffer_size;
    int kernel_socket_send_buffer_size;

#ifdef SW_USE_OPENSSL
    SSL_CTX *ssl_context;
    swSSL_config ssl_config;
    swSSL_option ssl_option;
#ifdef SW_SUPPORT_DTLS
    std::unordered_map<int, swoole::dtls::Session*> *dtls_sessions;
#endif
#endif

    sw_atomic_t *connection_num;

    swProtocol protocol;
    void *ptr;
    int (*onRead)(swReactor *reactor, swListenPort *port, swEvent *event);
};

struct swWorkerStopMessage
{
    pid_t pid;
    uint16_t worker_id;
};

//------------------------------------Packet-------------------------------------------
struct swPacket_task
{
    size_t length;
    char tmpfile[SW_TASK_TMPDIR_SIZE + sizeof(SW_TASK_TMP_FILE)];
};

struct swPacket_response
{
    int length;
    int worker_id;
};

struct swPacket_ptr
{
    swDataHead info;
    swString data;
};

//-----------------------------------Factory--------------------------------------------
struct swFactory
{
    void *object;
    void *ptr; //server object

    int (*start)(swFactory *);
    int (*shutdown)(swFactory *);
    int (*dispatch)(swFactory *, swSendData *);
    /**
     * success returns SW_OK, failure returns SW_ERR.
     */
    int (*finish)(swFactory *, swSendData *);
    int (*notify)(swFactory *, swDataHead *);    //send a event notify
    int (*end)(swFactory *, int fd);
    void (*free)(swFactory *);
};

int swFactory_create(swFactory *factory);
int swFactory_finish(swFactory *factory, swSendData *_send);

int swFactoryProcess_create(swFactory *factory, uint32_t worker_num);

//------------------------------------Server-------------------------------------------
enum swServer_hook_type
{
    SW_SERVER_HOOK_MASTER_START,
    SW_SERVER_HOOK_MASTER_TIMER,
    SW_SERVER_HOOK_REACTOR_START,
    SW_SERVER_HOOK_WORKER_START,
    SW_SERVER_HOOK_TASK_WORKER_START,
    SW_SERVER_HOOK_MASTER_CONNECT,
    SW_SERVER_HOOK_REACTOR_CONNECT,
    SW_SERVER_HOOK_WORKER_CONNECT,
    SW_SERVER_HOOK_REACTOR_RECEIVE,
    SW_SERVER_HOOK_WORKER_RECEIVE,
    SW_SERVER_HOOK_REACTOR_CLOSE,
    SW_SERVER_HOOK_WORKER_CLOSE,
    SW_SERVER_HOOK_MANAGER_START,
    SW_SERVER_HOOK_MANAGER_TIMER,
    SW_SERVER_HOOK_PROCESS_TIMER,
};

namespace swoole {

struct ReactorThread
{
    std::thread thread;
    swReactor reactor = {};
    swSocket *notify_pipe = nullptr;
    uint32_t pipe_num = 0;
    swSocket *pipe_sockets = nullptr;
    std::unordered_map<int, swString *> send_buffers;
};

struct ServerGS
{
    pid_t master_pid;
    pid_t manager_pid;

    uint32_t session_round :24;
    sw_atomic_t start;
    sw_atomic_t shutdown;

    time_t start_time;
    sw_atomic_t connection_num;
    sw_atomic_t tasking_num;
    sw_atomic_long_t accept_count;
    sw_atomic_long_t close_count;
    sw_atomic_long_t request_count;

    sw_atomic_t spinlock;

    swProcessPool task_workers;
    swProcessPool event_workers;
};

class Server
{
 public:
    /**
     * reactor thread/process num
     */
    uint16_t reactor_num = 0;
    /**
     * worker process num
     */
    uint32_t worker_num = 0;
    /**
     * The number of pipe per reactor maintenance
     */
    uint16_t reactor_pipe_num = 0;

    enum swServer_mode factory_mode;

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
     * max connection num
     */
    uint32_t max_connection = 0;

    /**
     * worker process max request
     */
    uint32_t max_request = 0;
    uint32_t max_request_grace = 0;

    int udp_socket_ipv4 = 0;
    int udp_socket_ipv6 = 0;
    int null_fd = -1;

    uint32_t max_wait_time = SW_WORKER_MAX_WAIT_TIME;

    /*----------------------------Reactor schedule--------------------------------*/
    uint16_t reactor_round_i = 0;
    uint16_t reactor_next_i = 0;
    uint16_t reactor_schedule_count = 0;

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
    uint16_t heartbeat_check_interval = 0;

    int *cpu_affinity_available = 0;
    int cpu_affinity_available_num = 0;

    swPipeBuffer **pipe_buffers = nullptr;
    double send_timeout = 0;

    time_t reload_time = 0;
    time_t warning_time = 0;
    long timezone_ = 0;
    swTimer_node *master_timer = nullptr;
    swTimer_node *heartbeat_timer = nullptr;
    swTimer_node *enable_accept_timer = nullptr;

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

    swFactory factory;
    std::vector<swListenPort*> ports;

    inline swListenPort *get_primary_port()
    {
        return ports.front();
    }

    swListenPort *get_port(int _port)
    {
        for (auto port : ports)
        {
            if (port->port == _port || _port == 0)
            {
                return port;
            }
        }

        return nullptr;
    }

    std::thread heartbeat_thread;

    /**
     *  task process
     */
    uint32_t task_worker_num = 0;
    uint8_t task_ipc_mode = SW_TASK_IPC_UNIXSOCK;
    uint32_t task_max_request = 0;
    uint32_t task_max_request_grace = 0;
    swPipe *task_notify = nullptr;
    swEventData *task_result = nullptr;

    /**
     * user process
     */
    uint32_t user_worker_num = 0;
    std::vector<swWorker*> *user_worker_list = nullptr;
    swHashMap *user_worker_map = nullptr;
    swWorker *user_workers = nullptr;

    ReactorThread *reactor_threads = nullptr;
    swWorker *workers = nullptr;

    swLock lock;
    swChannel *message_box = nullptr;

    ServerGS *gs = nullptr;

    std::unordered_set<std::string> *types = nullptr;
    std::unordered_set<std::string> *locations = nullptr;
    std::vector<std::string> *http_index_files = nullptr;

#ifdef HAVE_PTHREAD_BARRIER
    pthread_barrier_t barrier = {};
#endif

    swConnection *connection_list = nullptr;
    swSession *session_list = nullptr;
    uint32_t *port_connnection_num_list = nullptr;

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
    swSocket *stream_socket = nullptr;
    swProtocol stream_protocol = {};
    swSocket *last_stream_socket = nullptr;
    std::queue<swString*> *buffer_pool = nullptr;

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
    std::function<void(Server *, swEventData *)> onPipeMessage;
    std::function<void(Server *, uint32_t)> onWorkerStart;
    std::function<void(Server *, uint32_t)> onWorkerStop;
    std::function<void(Server *, uint32_t)> onWorkerExit;
    std::function<void(Server *, swWorker *)> onUserWorkerStart;
    /**
     * Connection
     */
    std::function<int(Server *, swEventData *)> onReceive;
    std::function<int(Server *, swEventData *)> onPacket;
    std::function<void(Server *, swDataHead *)> onClose;
    std::function<void(Server *, swDataHead *)> onConnect;
    std::function<void(Server *, swDataHead *)> onBufferFull;
    std::function<void(Server *, swDataHead *)> onBufferEmpty;
    /**
     * Task Worker
     */
    std::function<int(Server *, swEventData *)> onTask;
    std::function<int(Server *, swEventData *)> onFinish;
    /**
     * Server method
     */
    int (*send)(Server *serv, int session_id, const void *data, uint32_t length) = nullptr;
    int (*sendfile)(Server *serv, int session_id, const char *file, uint32_t l_file, off_t offset, size_t length) = nullptr;
    int (*sendwait)(Server *serv, int session_id, const void *data, uint32_t length) = nullptr;
    int (*close)(Server *serv, int session_id, int reset) = nullptr;
    int (*notify)(Server *serv, swConnection *conn, int event) = nullptr;
    int (*feedback)(Server *serv, int session_id, int event) = nullptr;
    /**
     * Chunk control
     */
    void** (*create_buffers)(Server *serv, uint buffer_num) = nullptr;
    void* (*get_buffer)(Server *serv, swDataHead *info) = nullptr;
    size_t (*get_buffer_len)(Server *serv, swDataHead *info) = nullptr;
    void (*add_buffer_len)(Server *serv, swDataHead *info, size_t len) = nullptr;
    void (*move_buffer)(Server *serv, swPipeBuffer *buffer) = nullptr;
    size_t (*get_packet)(Server *serv, swEventData *req, char **data_ptr) = nullptr;
    /**
     * Hook
     */
    int (*dispatch_func)(Server *, swConnection *, swSendData *) = nullptr;

 public:
    Server(enum swServer_mode mode = SW_MODE_BASE);

    ~Server()
    {
        if (gs != nullptr && getpid() == gs->master_pid)
        {
            destory();
        }
        SwooleG.serv = nullptr;
    }

    bool set_document_root(const std::string &path)
    {
        if (path.length() > PATH_MAX)
        {
            swWarn("The length of document_root must be less than %d", PATH_MAX);
            return false;
        }

        char _realpath[PATH_MAX];
        if (!realpath(path.c_str(), _realpath))
        {
            swWarn("document_root[%s] does not exist", path.c_str());
            return false;
        }

        document_root = std::string(_realpath);
        return true;
    }

    void add_static_handler_location(const std::string &);
    void add_static_handler_index_files(const std::string &);

    int create();
    int start();
    void shutdown();

    int add_worker(swWorker *worker);
    swListenPort *add_port(enum swSocket_type type, const char *host, int port);
    int add_systemd_socket();
    int add_hook(enum swServer_hook_type type, swCallback func, int push_back);
    swConnection *add_connection(swListenPort *ls, swSocket *_socket, int server_fd);

    int get_idle_worker_num();
    int get_idle_task_worker_num();

    inline int get_minfd()
    {
        return connection_list[SW_SERVER_MIN_FD_INDEX].fd;
    }

    inline int get_maxfd()
    {
        return connection_list[SW_SERVER_MAX_FD_INDEX].fd;
    }
    /**
     *  connection_list[0] => the largest fd
     */
    inline void set_maxfd(int maxfd)
    {
        connection_list[SW_SERVER_MAX_FD_INDEX].fd = maxfd;
    }
    /**
     * connection_list[1] => the smallest fd
     */
    inline void set_minfd(int minfd)
    {
        connection_list[SW_SERVER_MIN_FD_INDEX].fd = minfd;
    }

    inline const std::string& get_document_root()
    {
        return document_root;
    }

    inline swString *get_recv_buffer(swSocket *_socket)
    {
        swString *buffer = _socket->recv_buffer;
        if (buffer == nullptr)
        {
            buffer = swoole::make_string(SW_BUFFER_SIZE_BIG, buffer_allocator);
            if (!buffer)
            {
                return nullptr;
            }
            _socket->recv_buffer = buffer;
        }

        return buffer;
    }

    inline bool is_support_unsafe_events()
    {
        if (dispatch_mode != SW_DISPATCH_ROUND && dispatch_mode != SW_DISPATCH_QUEUE
                && dispatch_mode != SW_DISPATCH_STREAM)
        {
            return true;
        }
        else
        {
            return enable_unsafe_event;
        }
    }

    inline bool if_require_packet_callback(swListenPort *port, bool isset)
    {
#ifdef SW_USE_OPENSSL
        return (swSocket_is_dgram(port->type) && !port->ssl && !isset);
#else
        return (swSocket_is_dgram(port->type) && !isset);
#endif
    }

    inline bool if_require_receive_callback(swListenPort *port, bool isset)
    {
#ifdef SW_USE_OPENSSL
        return (((swSocket_is_dgram(port->type) && port->ssl) || swSocket_is_stream(port->type)) && !isset);
#else
        return (swSocket_is_stream(port->type) && !isset);
#endif
    }

    inline swWorker *get_worker(uint16_t worker_id)
    {
        //Event Worker
        if (worker_id < worker_num)
        {
            return &(gs->event_workers.workers[worker_id]);
        }

        //Task Worker
        uint32_t task_worker_max = task_worker_num + worker_num;
        if (worker_id < task_worker_max)
        {
            return &(gs->task_workers.workers[worker_id - worker_num]);
        }

        //User Worker
        uint32_t user_worker_max = task_worker_max + user_worker_num;
        if (worker_id < user_worker_max)
        {
            return &(user_workers[worker_id - task_worker_max]);
        }

        return nullptr;
    }

    inline swString *get_worker_input_buffer(int reactor_id)
    {
        if (factory_mode == SW_MODE_BASE)
        {
            return (swString *) worker_input_buffers[0];
        }
        else
        {
            return (swString *) worker_input_buffers[reactor_id];
        }
    }

    inline ReactorThread *get_thread(int reactor_id)
    {
        return &reactor_threads[reactor_id];
    }

    inline swConnection *get_connection(int fd)
    {
        if ((uint32_t) fd > max_connection)
        {
            return nullptr;
        }
        return &connection_list[fd];
    }

    inline swSession *get_session(uint32_t session_id)
    {
        return &session_list[session_id % SW_SESSION_LIST_SIZE];
    }

    int create_task_workers();
    int create_user_workers();
    int start_manager_process();

    void call_hook(enum swServer_hook_type type, void *arg);
    void call_worker_start_callback(swWorker *worker);

    int accept_task(swEventData *task);
    static int accept_connection(swReactor *reactor, swEvent *event);
    static int close_connection(swReactor *reactor, swSocket *_socket);
    static int dispatch_task(swProtocol *proto, swSocket *_socket, const char *data, uint32_t length);

    int send_to_connection(swSendData *);

 private:
    /**
     * http static file directory
     */
    std::string document_root;
    int start_check();
    void check_port_type(swListenPort *ls);
    void destory();
    int create_reactor_processes();
    int create_reactor_threads();
    int start_reactor_threads();
    int start_reactor_processes();
    void start_heartbeat_thread();
};

}

typedef swoole::Server swServer;
typedef swoole::ReactorThread swReactorThread;

typedef int (*swServer_dispatch_function)(swServer *, swConnection *, swSendData *);

void swServer_master_onTimer(swTimer *timer, swTimer_node *tnode);

void swServer_signal_init(swServer *serv);
void swServer_close_port(swServer *serv, enum swBool_type only_stream_port);
void swServer_clear_timer(swServer *serv);

#ifdef SW_SUPPORT_DTLS
swoole::dtls::Session* swServer_dtls_accept(swServer *serv, swListenPort *ls, swSocketAddress *sa);
#endif

void swServer_set_ipc_max_size(swServer *serv);
int swServer_create_pipe_buffers(swServer *serv);

static sw_inline swListenPort* swServer_get_port(swServer *serv, int fd)
{
    sw_atomic_t server_fd = serv->connection_list[fd].server_fd;
    return (swListenPort*) serv->connection_list[server_fd].object;
}

static sw_inline void swServer_lock(swServer *serv)
{
    if (serv->single_thread)
    {
        return;
    }
    serv->lock.lock(&serv->lock);
}

static sw_inline void swServer_unlock(swServer *serv)
{
    if (serv->single_thread)
    {
        return;
    }
    serv->lock.unlock(&serv->lock);
}

#define SW_MAX_SESSION_ID             0x1000000

static sw_inline int swEventData_is_dgram(uint8_t type)
{
    switch (type)
    {
    case SW_SERVER_EVENT_SNED_DGRAM:
        return SW_TRUE;
    default:
        return SW_FALSE;
    }
}

static sw_inline int swEventData_is_stream(uint8_t type)
{
    switch (type)
    {
    case SW_SERVER_EVENT_SEND_DATA:
    case SW_SERVER_EVENT_CONNECT:
    case SW_SERVER_EVENT_CLOSE:
    case SW_SERVER_EVENT_PAUSE_RECV:
    case SW_SERVER_EVENT_RESUME_RECV:
    case SW_SERVER_EVENT_BUFFER_FULL:
    case SW_SERVER_EVENT_BUFFER_EMPTY:
        return SW_TRUE;
    default:
        return SW_FALSE;
    }
}

swPipe * swServer_get_pipe_object(swServer *serv, int pipe_fd);
void swServer_store_pipe_fd(swServer *serv, swPipe *p);
void swServer_store_listen_socket(swServer *serv);

int swServer_worker_create(swServer *serv, swWorker *worker);
int swServer_worker_init(swServer *serv, swWorker *worker);

void swTaskWorker_init(swServer *serv);
int swTaskWorker_onTask(swProcessPool *pool, swEventData *task);
int swTaskWorker_onFinish(swReactor *reactor, swEvent *event);
void swTaskWorker_onStart(swProcessPool *pool, int worker_id);
void swTaskWorker_onStop(swProcessPool *pool, int worker_id);
int swTaskWorker_large_pack(swEventData *task, const void *data, size_t data_len);
int swTaskWorker_finish(swServer *serv, const char *data, size_t data_len, int flags, swEventData *current_task);

static sw_inline swString *swTaskWorker_large_unpack(swEventData *task_result)
{
    swPacket_task _pkg;
    memcpy(&_pkg, task_result->data, sizeof(_pkg));

    int tmp_file_fd = open(_pkg.tmpfile, O_RDONLY);
    if (tmp_file_fd < 0)
    {
        swSysWarn("open(%s) failed", _pkg.tmpfile);
        return nullptr;
    }
    if (SwooleTG.buffer_stack->size < _pkg.length && swString_extend_align(SwooleTG.buffer_stack, _pkg.length) < 0)
    {
        close(tmp_file_fd);
        return nullptr;
    }
    if (swoole_sync_readfile(tmp_file_fd, SwooleTG.buffer_stack->str, _pkg.length) != _pkg.length)
    {
        close(tmp_file_fd);
        return nullptr;
    }
    close(tmp_file_fd);
    if (!(swTask_type(task_result) & SW_TASK_PEEK))
    {
        unlink(_pkg.tmpfile);
    }
    SwooleTG.buffer_stack->length = _pkg.length;
    return SwooleTG.buffer_stack;
}

static sw_inline int swServer_connection_valid(swServer *serv, swConnection *conn)
{
    return (conn && conn->socket && conn->active == 1 && conn->closed == 0 
        && conn->socket->fdtype == SW_FD_SESSION);
}

static sw_inline int swServer_get_fd(swServer *serv, uint32_t session_id)
{
    return serv->session_list[session_id % SW_SESSION_LIST_SIZE].fd;
}

static sw_inline int swServer_worker_schedule(swServer *serv, int fd, swSendData *data)
{
    uint32_t key = 0;

    if (serv->dispatch_func)
    {
        int id = serv->dispatch_func(serv, serv->get_connection(fd), data);
        if (id != SW_DISPATCH_RESULT_USERFUNC_FALLBACK)
        {
            return id;
        }
    }

    //polling mode
    if (serv->dispatch_mode == SW_DISPATCH_ROUND)
    {
        key = sw_atomic_fetch_add(&serv->worker_round_id, 1);
    }
    //Using the FD touch access to hash
    else if (serv->dispatch_mode == SW_DISPATCH_FDMOD)
    {
        key = fd;
    }
    //Using the IP touch access to hash
    else if (serv->dispatch_mode == SW_DISPATCH_IPMOD)
    {
        swConnection *conn = serv->get_connection(fd);
        //UDP
        if (conn == nullptr)
        {
            key = fd;
        }
        //IPv4
        else if (conn->socket_type == SW_SOCK_TCP)
        {
            key = conn->info.addr.inet_v4.sin_addr.s_addr;
        }
        //IPv6
        else
        {
#ifdef HAVE_KQUEUE
            key = *(((uint32_t *) &conn->info.addr.inet_v6.sin6_addr) + 3);
#elif defined(_WIN32)
            key = conn->info.addr.inet_v6.sin6_addr.u.Word[3];
#else
            key = conn->info.addr.inet_v6.sin6_addr.s6_addr32[3];
#endif
        }
    }
    else if (serv->dispatch_mode == SW_DISPATCH_UIDMOD)
    {
        swConnection *conn = serv->get_connection(fd);
        if (conn == nullptr || conn->uid == 0)
        {
            key = fd;
        }
        else
        {
            key = conn->uid;
        }
    }
    //Preemptive distribution
    else
    {
        uint32_t i;
        bool found = false;
        for (i = 0; i < serv->worker_num + 1; i++)
        {
            key = sw_atomic_fetch_add(&serv->worker_round_id, 1) % serv->worker_num;
            if (serv->workers[key].status == SW_WORKER_IDLE)
            {
                found = true;
                break;
            }
        }
        if (sw_unlikely(!found))
        {
            serv->scheduler_warning = true;
        }
        swTraceLog(SW_TRACE_SERVER, "schedule=%d, round=%d", key, serv->worker_round_id);
        return key;
    }
    return key % serv->worker_num;
}

void swServer_worker_onStart(swServer *serv);
void swServer_worker_onStop(swServer *serv);

int swServer_http_static_handler_hit(swServer *serv, swHttpRequest *request, swConnection *conn);

void swWorker_stop(swWorker *worker);

static sw_inline swConnection *swWorker_get_connection(swServer *serv, int session_id)
{
    return serv->get_connection(swServer_get_fd(serv, session_id));
}

static sw_inline swConnection *swServer_connection_verify_no_ssl(swServer *serv, uint32_t session_id)
{
    swSession *session = serv->get_session(session_id);
    int fd = session->fd;
    swConnection *conn = serv->get_connection(fd);
    if (!conn || conn->active == 0)
    {
        return nullptr;
    }
    if (session->id != session_id || conn->session_id != session_id)
    {
        return nullptr;
    }
    return conn;
}

static sw_inline swConnection *swServer_connection_verify(swServer *serv, int session_id)
{
    swConnection *conn = swServer_connection_verify_no_ssl(serv, session_id);
#ifdef SW_USE_OPENSSL
    if (conn && conn->ssl && !conn->ssl_ready)
    {
        swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SSL_NOT_READY, "SSL not ready");
        return nullptr;
    }
#endif
    return conn;
}

static sw_inline int swServer_connection_incoming(swServer *serv, swReactor *reactor, swConnection *conn)
{
#ifdef SW_USE_OPENSSL
    if (conn->socket->ssl)
    {
        return reactor->add(reactor, conn->socket, SW_EVENT_READ);
    }
#endif
    //delay receive, wait resume command
    if (!serv->enable_delay_receive)
    {
        if (reactor->add(reactor, conn->socket, SW_EVENT_READ) < 0)
        {
            return SW_ERR;
        }
    }
    //notify worker process
    if (serv->onConnect)
    {
        if (serv->notify(serv, conn, SW_SERVER_EVENT_CONNECT) < 0)
        {
            return SW_ERR;
        }
    }

    return SW_OK;
}

void swServer_connection_each(swServer *serv, void (*callback)(swConnection *conn));

/**
 * reactor_id: The fd in which the reactor.
 */
static sw_inline swSocket *swServer_get_send_pipe(swServer *serv, int session_id, int reactor_id)
{
    int pipe_index = session_id % serv->reactor_pipe_num;
    /**
     * pipe_worker_id: The pipe in which worker.
     */
    int pipe_worker_id = reactor_id + (pipe_index * serv->reactor_num);
    swWorker *worker = serv->get_worker(pipe_worker_id);
    return worker->pipe_worker;
}

static sw_inline uint8_t swServer_dispatch_mode_is_mod(swServer *serv)
{
    return serv->dispatch_mode == SW_DISPATCH_FDMOD || serv->dispatch_mode == SW_DISPATCH_IPMOD;
}

static sw_inline swServer *sw_server()
{
    return (swServer *) SwooleG.serv;
}

#define swServer_support_send_yield swServer_dispatch_mode_is_mod

//------------------------------------Listen Port-------------------------------------------
void swPort_init(swListenPort *port);
void swPort_free(swListenPort *port);
int swPort_listen(swListenPort *ls);
void swPort_set_protocol(swServer *serv, swListenPort *ls);
int swPort_set_address(swListenPort *ls, int sock);
#ifdef SW_USE_OPENSSL
int swPort_enable_ssl_encrypt(swListenPort *ls);
#endif
void swPort_clear_protocol(swListenPort *ls);
//------------------------------------Worker Process-------------------------------------------
void swWorker_onStart(swServer *serv);
void swWorker_onStop(swServer *serv);
int swWorker_loop(swServer *serv, swWorker *worker);
void swWorker_clean_pipe_buffer(swServer *serv);
int swWorker_send2reactor(swServer *serv, swEventData *ev_data, size_t sendn, int session_id);
int swWorker_send2worker(swWorker *dst_worker, const void *buf, int n, int flag);
void swWorker_signal_handler(int signo);
void swWorker_signal_init(void);

int swReactorThread_create(swServer *serv);
int swReactorThread_start(swServer *serv);
void swReactorThread_set_protocol(swServer *serv, swReactor *reactor);
void swReactorThread_join(swServer *serv);
void swReactorThread_free(swServer *serv);

int swReactorThread_send2worker(swServer *serv, swWorker *worker, const void *data, size_t len);

void swReactorProcess_free(swServer *serv);

pid_t swManager_spawn_worker(swServer *serv, swWorker *worker);
pid_t swManager_spawn_user_worker(swServer *serv, swWorker* worker);
pid_t swManager_spawn_task_worker(swServer *serv, swWorker* worker);
pid_t swManager_spawn_worker_by_type(swServer *serv, swWorker *worker, int worker_type);
int swManager_wait_other_worker(swProcessPool *pool, pid_t pid, int status);
void swManager_kill_workers(swServer *serv);
void swManager_kill_task_workers(swServer *serv);
void swManager_kill_user_workers(swServer *serv);
