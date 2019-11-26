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

#ifndef SW_SERVER_H_
#define SW_SERVER_H_

#include "swoole_api.h"
#include "buffer.h"
#include "connection.h"

SW_EXTERN_C_BEGIN

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
    //task
    SW_SERVER_EVENT_TASK,
    SW_SERVER_EVENT_FINISH,
    //pipe
    SW_SERVER_EVENT_PIPE_MESSAGE,
    //proxy
    SW_SERVER_EVENT_PROXY_START,
    SW_SERVER_EVENT_PROXY_END,
    //event operate
    SW_SERVER_EVENT_CONFIRM,
    SW_SERVER_EVENT_PAUSE_RECV,
    SW_SERVER_EVENT_RESUME_RECV,
    //buffer event
    SW_SERVER_EVENT_BUFFER_FULL,
    SW_SERVER_EVENT_BUFFER_EMPTY,
    //process message
    SW_SERVER_EVENT_INCOMING,
    SW_SERVER_EVENT_SHUTDOWN,
};

enum swIPC_type
{
    SW_IPC_NONE     = 0,
    SW_IPC_UNIXSOCK = 1,
    SW_IPC_MSGQUEUE = 2,
    SW_IPC_SOCKET   = 3,
};

enum swTask_ipc_mode
{
    SW_TASK_IPC_UNIXSOCK    = 1,
    SW_TASK_IPC_MSGQUEUE    = 2,
    SW_TASK_IPC_PREEMPTIVE  = 3,
    SW_TASK_IPC_STREAM      = 4,
};

enum swWorker_pipe_type
{
    SW_PIPE_WORKER     = 0,
    SW_PIPE_MASTER     = 1,
    SW_PIPE_NONBLOCK   = 2,
};

/**
 * use swDataHead->from_fd, 1 byte 8 bit
 */
enum swTask_type
{
    SW_TASK_TMPFILE    = 1,  //tmp file
    SW_TASK_SERIALIZE  = 2,  //php serialize
    SW_TASK_NONBLOCK   = 4,  //task
    SW_TASK_CALLBACK   = 8,  //callback
    SW_TASK_WAITALL    = 16, //for taskWaitAll
    SW_TASK_COROUTINE  = 32, //coroutine
    SW_TASK_PEEK       = 64, //peek
    SW_TASK_NOREPLY    = 128, //don't reply
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

typedef struct _swReactorThread
{
    pthread_t thread_id;
    swReactor reactor;
    int notify_pipe;
    uint32_t pipe_num;
    void *send_buffers;
} swReactorThread;

typedef struct _swListenPort
{
    struct _swListenPort *next, *prev;

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

    int socket_buffer_size;
    uint32_t buffer_high_watermark;
    uint32_t buffer_low_watermark;

    enum swSocket_type type;
    uint8_t ssl;
    int port;
    int sock;
    pthread_t thread_id;
    char host[SW_HOST_MAXSIZE];

    /**
     * check data eof
     */
    uint32_t open_eof_check :1;
    /**
     * built-in http protocol
     */
    uint32_t open_http_protocol :1;
    /**
     * built-in http2.0 protocol
     */
    uint32_t open_http2_protocol :1;
    /**
     * built-in websocket protocol
     */
    uint32_t open_websocket_protocol :1;
    /**
     * open websocket close frame
     */
    uint32_t open_websocket_close_frame :1;
    /**
     *  one package: length check
     */
    uint32_t open_length_check :1;
    /**
     * for mqtt protocol
     */
    uint32_t open_mqtt_protocol :1;
    /**
     *  redis protocol
     */
    uint32_t open_redis_protocol :1;
    /**
     * open tcp nodelay option
     */
    uint32_t open_tcp_nodelay :1;
    /**
     * open tcp nopush option(for sendfile)
     */
    uint32_t open_tcp_nopush :1;
    /**
     * open tcp keepalive
     */
    uint32_t open_tcp_keepalive :1;
    /**
     * open tcp keepalive
     */
    uint32_t open_ssl_encrypt :1;
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
#endif

    sw_atomic_t connection_num;

    swProtocol protocol;
    void *ptr;
    int (*onRead)(swReactor *reactor, struct _swListenPort *port, swEvent *event);
} swListenPort;

typedef struct _swUserWorker_node
{
    struct _swUserWorker_node *next, *prev;
    swWorker *worker;
} swUserWorker_node;

typedef struct _swTask_sendfile
{
    char *filename;
    uint16_t name_len;
    int fd;
    size_t length;
    off_t offset;
} swTask_sendfile;

typedef struct _swWorkerStopMessage
{
    pid_t pid;
    uint16_t worker_id;
} swWorkerStopMessage;

//------------------------------------Packet-------------------------------------------
typedef struct _swPacket_task
{
    size_t length;
    char tmpfile[SW_TASK_TMPDIR_SIZE + sizeof(SW_TASK_TMP_FILE)];
} swPacket_task;

typedef struct _swPacket_response
{
    int length;
    int worker_id;
} swPacket_response;

typedef struct _swPacket_ptr
{
    swDataHead info;
    swString data;
} swPacket_ptr;
//-----------------------------------Factory--------------------------------------------
struct _swFactory
{
    void *object;
    void *ptr; //server object

    int (*start)(struct _swFactory *);
    int (*shutdown)(struct _swFactory *);
    int (*dispatch)(struct _swFactory *, swSendData *);
    /**
     * Returns the number of bytes sent
     */
    int (*finish)(struct _swFactory *, swSendData *);
    int (*notify)(struct _swFactory *, swDataHead *);    //send a event notify
    int (*end)(struct _swFactory *, int fd);
    void (*free)(struct _swFactory *);
};

typedef int (*swServer_dispatch_function)(swServer *, swConnection *, swSendData *);

int swFactory_create(swFactory *factory);
int swFactory_finish(swFactory *factory, swSendData *_send);
int swFactory_check_callback(swFactory *factory);

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

typedef struct _swServerStats
{
    time_t start_time;
    sw_atomic_t connection_num;
    sw_atomic_t tasking_num;
    sw_atomic_long_t accept_count;
    sw_atomic_long_t close_count;
    sw_atomic_long_t request_count;
} swServerStats;

typedef struct _swServerGS
{
    pid_t master_pid;
    pid_t manager_pid;

    uint32_t session_round :24;
    sw_atomic_t start;
    sw_atomic_t shutdown;

    time_t now;

    sw_atomic_t spinlock;

    swProcessPool task_workers;
    swProcessPool event_workers;

} swServerGS;

struct _swServer
{
    /**
     * reactor thread/process num
     */
    uint16_t reactor_num;
    /**
     * worker process num
     */
    uint32_t worker_num;
    /**
     * The number of pipe per reactor maintenance
     */
    uint16_t reactor_pipe_num;

    uint8_t factory_mode;

    uint8_t dgram_port_num;

    /**
     * package dispatch mode
     */
    uint8_t dispatch_mode;

    /**
     * No idle work process is available.
     */
    uint8_t scheduler_warning;

    int worker_uid;
    int worker_groupid;

    /**
     * max connection num
     */
    uint32_t max_connection;

    /**
     * worker process max request
     */
    uint32_t max_request;
    uint32_t max_request_grace;

    int udp_socket_ipv4;
    int udp_socket_ipv6;

    uint32_t max_wait_time;

    /*----------------------------Reactor schedule--------------------------------*/
    uint16_t reactor_round_i;
    uint16_t reactor_next_i;
    uint16_t reactor_schedule_count;

    sw_atomic_t worker_round_id;

    /**
     * run as a daemon process
     */
    uint32_t daemonize :1;
    /**
     * have dgram socket
     */
    uint32_t have_dgram_sock :1;
    /**
     * have stream socket
     */
    uint32_t have_stream_sock :1;
    /**
     * open cpu affinity setting
     */
    uint32_t open_cpu_affinity :1;
    /**
     * disable notice when use SW_DISPATCH_ROUND and SW_DISPATCH_QUEUE
     */
    uint32_t disable_notify :1;
    /**
     * discard the timeout request
     */
    uint32_t discard_timeout_request :1;
    /**
     * parse cookie header
     */
    uint32_t http_parse_cookie :1;
    /**
     * parse x-www-form-urlencoded data
     */
    uint32_t http_parse_post :1;
    /**
     * parse multipart/form-data files to match $_FILES
     */
    uint32_t http_parse_files :1;
    /**
     * http content compression
     */
    uint32_t http_compression :1;
    /**
     * RFC-7692
     */
    uint32_t websocket_compression :1;
    /**
     * handle static files
     */
    uint32_t enable_static_handler :1;
    /**
     * enable onConnect/onClose event when use dispatch_mode=1/3
     */
    uint32_t enable_unsafe_event :1;
    /**
     * waiting for worker onConnect callback function to return
     */
    uint32_t enable_delay_receive :1;
    /**
     * asynchronous reloading
     */
    uint32_t reload_async :1;
    /**
     * use task object
     */
    uint32_t task_use_object :1;
    /**
     * enable coroutine in task worker
     */
    uint32_t task_enable_coroutine :1;
    /**
     * yield coroutine when the output buffer is full
     */
    uint32_t send_yield :1;
    /**
     * enable coroutine
     */
    uint32_t enable_coroutine :1;
    /**
     * disable multi-threads
     */
    uint32_t single_thread :1;
    /**
     * server status
     */
    uint32_t running :1;

    /**
     *  heartbeat check time
     */
    uint16_t heartbeat_idle_time;
    uint16_t heartbeat_check_interval;

    int *cpu_affinity_available;
    int cpu_affinity_available_num;

    swPipeBuffer **pipe_buffers;
    double send_timeout;

    uint16_t listen_port_num;
    time_t reload_time;
    time_t warning_time;
    long timezone;
    swTimer_node *master_timer;
    swTimer_node *heartbeat_timer;

    /* buffer output/input setting*/
    uint32_t buffer_output_size;
    uint32_t buffer_input_size;

    uint32_t ipc_max_size;

    void *ptr2;
    void *private_data_3;

    swFactory factory;
    swListenPort *listen_list;
    pthread_t heartbeat_pidt;

    /**
     *  task process
     */
    uint32_t task_worker_num;
    uint8_t task_ipc_mode;
    uint32_t task_max_request;
    uint32_t task_max_request_grace;
    swPipe *task_notify;
    swEventData *task_result;

    /**
     * user process
     */
    uint32_t user_worker_num;
    swUserWorker_node *user_worker_list;
    swHashMap *user_worker_map;
    swWorker *user_workers;

    swReactorThread *reactor_threads;
    swWorker *workers;

    swLock lock;
    swChannel *message_box;

    swServerStats *stats;
    swServerGS *gs;

#ifdef HAVE_PTHREAD_BARRIER
    pthread_barrier_t barrier;
#endif

    swConnection *connection_list;
    swSession *session_list;

    /**
     * temporary directory for HTTP uploaded file.
     */
    char *upload_tmp_dir;
    /**
     * http compression level for gzip/br
     */
    uint8_t http_compression_level;
    /**
     * http static file directory
     */
    char *document_root;
    uint16_t document_root_len;
    /**
     * master process pid
     */
    char *pid_file;
    /**
     * stream
     */
    char *stream_socket;
    int stream_fd;
    swProtocol stream_protocol;
    int last_stream_fd;
    swLinkedList *buffer_pool;

#ifdef SW_BUFFER_RECV_TIME
    double last_receive_usec;
#endif

    int manager_alarm;

    /**
     * message queue key
     */
    uint64_t message_queue_key;

    swLinkedList *hooks[SW_MAX_HOOK_TYPE];

    void (*onStart)(swServer *serv);
    void (*onManagerStart)(swServer *serv);
    void (*onManagerStop)(swServer *serv);
    void (*onShutdown)(swServer *serv);
    void (*onPipeMessage)(swServer *, swEventData *);
    void (*onWorkerStart)(swServer *serv, int worker_id);
    void (*onWorkerStop)(swServer *serv, int worker_id);
    void (*onWorkerExit)(swServer *serv, int worker_id);
    void (*onWorkerError)(swServer *serv, int worker_id, pid_t worker_pid, int exit_code, int signo);
    void (*onUserWorkerStart)(swServer *serv, swWorker *worker);
    /**
     * Client
     */
    int (*onReceive)(swServer *, swEventData *);
    int (*onPacket)(swServer *, swEventData *);
    void (*onClose)(swServer *serv, swDataHead *);
    void (*onConnect)(swServer *serv, swDataHead *);
    void (*onBufferFull)(swServer *serv, swDataHead *);
    void (*onBufferEmpty)(swServer *serv, swDataHead *);
    /**
     * Task Worker
     */
    int (*onTask)(swServer *serv, swEventData *data);
    int (*onFinish)(swServer *serv, swEventData *data);
    /**
     * Server method
     */
    int (*send)(swServer *serv, int session_id, void *data, uint32_t length);
    int (*sendfile)(swServer *serv, int session_id, const char *file, uint32_t l_file, off_t offset, size_t length);
    int (*sendwait)(swServer *serv, int session_id, void *data, uint32_t length);
    int (*close)(swServer *serv, int session_id, int reset);
    int (*notify)(swServer *serv, swConnection *conn, int event);
    int (*feedback)(swServer *serv, int session_id, int event);

    int (*dispatch_func)(swServer *, swConnection *, swSendData *);
};

int swServer_master_onAccept(swReactor *reactor, swEvent *event);
void swServer_master_onTimer(swTimer *timer, swTimer_node *tnode);
int swServer_master_send(swServer *serv, swSendData *_send);

int swServer_onFinish(swFactory *factory, swSendData *resp);
int swServer_onFinish2(swFactory *factory, swSendData *resp);

void swServer_init(swServer *serv);
void swServer_signal_init(swServer *serv);
int swServer_start(swServer *serv);
swListenPort* swServer_add_port(swServer *serv, enum swSocket_type type, const char *host, int port);
void swServer_close_port(swServer *serv, enum swBool_type only_stream_port);
int swServer_add_worker(swServer *serv, swWorker *worker);
int swServer_add_systemd_socket(swServer *serv);
int swServer_add_hook(swServer *serv, enum swServer_hook_type type, swCallback func, int push_back);
void swServer_call_hook(swServer *serv, enum swServer_hook_type type, void *arg);

int swServer_create(swServer *serv);
int swServer_shutdown(swServer *serv);

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

int swServer_get_socket(swServer *serv, int port);
int swServer_worker_create(swServer *serv, swWorker *worker);
int swServer_worker_init(swServer *serv, swWorker *worker);
void swServer_worker_start(swServer *serv, swWorker *worker);

swString** swServer_create_worker_buffer(swServer *serv);
int swServer_create_task_worker(swServer *serv);
void swServer_enable_accept(swReactor *reactor);
void swServer_reopen_log_file(swServer *serv);

void swTaskWorker_init(swServer *serv);
int swTaskWorker_onTask(swProcessPool *pool, swEventData *task);
int swTaskWorker_onFinish(swReactor *reactor, swEvent *event);
void swTaskWorker_onStart(swProcessPool *pool, int worker_id);
void swTaskWorker_onStop(swProcessPool *pool, int worker_id);
int swTaskWorker_large_pack(swEventData *task, const void *data, size_t data_len);
int swTaskWorker_finish(swServer *serv, const char *data, size_t data_len, int flags, swEventData *current_task);

#define swTask_type(task)                  ((task)->info.server_fd)

static sw_inline swString* swTaskWorker_large_unpack(swEventData *task_result)
{
    swPacket_task _pkg;
    memcpy(&_pkg, task_result->data, sizeof(_pkg));

    int tmp_file_fd = open(_pkg.tmpfile, O_RDONLY);
    if (tmp_file_fd < 0)
    {
        swSysWarn("open(%s) failed", _pkg.tmpfile);
        return NULL;
    }
    if (SwooleTG.buffer_stack->size < _pkg.length && swString_extend_align(SwooleTG.buffer_stack, _pkg.length) < 0)
    {
        close(tmp_file_fd);
        return NULL;
    }
    if (swoole_sync_readfile(tmp_file_fd, SwooleTG.buffer_stack->str, _pkg.length) != _pkg.length)
    {
        close(tmp_file_fd);
        return NULL;
    }
    close(tmp_file_fd);
    if (!(swTask_type(task_result) & SW_TASK_PEEK))
    {
        unlink(_pkg.tmpfile);
    }
    SwooleTG.buffer_stack->length = _pkg.length;
    return SwooleTG.buffer_stack;
}

#define SW_SERVER_MAX_FD_INDEX          0 //max connection socket
#define SW_SERVER_MIN_FD_INDEX          1 //min listen socket

// connection_list[0] => the largest fd
#define swServer_set_maxfd(serv,maxfd) (serv->connection_list[SW_SERVER_MAX_FD_INDEX].fd=maxfd)
#define swServer_get_maxfd(serv) (serv->connection_list[SW_SERVER_MAX_FD_INDEX].fd)
// connection_list[1] => the smallest fd
#define swServer_set_minfd(serv,maxfd) (serv->connection_list[SW_SERVER_MIN_FD_INDEX].fd=maxfd)
#define swServer_get_minfd(serv) (serv->connection_list[SW_SERVER_MIN_FD_INDEX].fd)

#define swServer_get_thread(serv, reactor_id)    (&(serv->reactor_threads[reactor_id]))

static sw_inline swConnection* swServer_connection_get(swServer *serv, int fd)
{
    if ((uint32_t) fd > serv->max_connection)
    {
        return NULL;
    }
    else
    {
        return &serv->connection_list[fd];
    }
}

static sw_inline swSession* swServer_get_session(swServer *serv, uint32_t session_id)
{
    return &serv->session_list[session_id % SW_SESSION_LIST_SIZE];
}

static sw_inline int swServer_get_fd(swServer *serv, uint32_t session_id)
{
    return serv->session_list[session_id % SW_SESSION_LIST_SIZE].fd;
}

static sw_inline swWorker* swServer_get_worker(swServer *serv, uint16_t worker_id)
{
    //Event Worker
    if (worker_id < serv->worker_num)
    {
        return &(serv->gs->event_workers.workers[worker_id]);
    }

    //Task Worker
    uint32_t task_worker_max = serv->task_worker_num + serv->worker_num;
    if (worker_id < task_worker_max)
    {
        return &(serv->gs->task_workers.workers[worker_id - serv->worker_num]);
    }

    //User Worker
    uint32_t user_worker_max = task_worker_max + serv->user_worker_num;
    if (worker_id < user_worker_max)
    {
        return &(serv->user_workers[worker_id - task_worker_max]);
    }

    return NULL;
}

static sw_inline int swServer_worker_schedule(swServer *serv, int fd, swSendData *data)
{
    uint32_t key = 0;

    if (serv->dispatch_func)
    {
        int id = serv->dispatch_func(serv, swServer_connection_get(serv, fd), data);
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
        swConnection *conn = swServer_connection_get(serv, fd);
        //UDP
        if (conn == NULL)
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
        swConnection *conn = swServer_connection_get(serv, fd);
        if (conn == NULL || conn->uid == 0)
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
        uint8_t found = 0;
        for (i = 0; i < serv->worker_num + 1; i++)
        {
            key = sw_atomic_fetch_add(&serv->worker_round_id, 1) % serv->worker_num;
            if (serv->workers[key].status == SW_WORKER_IDLE)
            {
                found = 1;
                break;
            }
        }
        if (sw_unlikely(found == 0))
        {
            serv->scheduler_warning = 1;
        }
        swTraceLog(SW_TRACE_SERVER, "schedule=%d, round=%d", key, serv->worker_round_id);
        return key;
    }
    return key % serv->worker_num;
}

void swServer_worker_onStart(swServer *serv);
void swServer_worker_onStop(swServer *serv);

int swWorker_onTask(swFactory *factory, swEventData *task);
void swWorker_stop(swWorker *worker);

static sw_inline swConnection *swWorker_get_connection(swServer *serv, int session_id)
{
    int real_fd = swServer_get_fd(serv, session_id);
    swConnection *conn = swServer_connection_get(serv, real_fd);
    return conn;
}

static sw_inline swString *swWorker_get_buffer(swServer *serv, int reactor_id)
{
    if (serv->factory_mode == SW_MODE_BASE)
    {
        return SwooleWG.buffer_input[0];
    }
    else
    {
        return SwooleWG.buffer_input[reactor_id];
    }
}

static sw_inline size_t swWorker_get_data(swServer *serv, swEventData *req, char **data_ptr)
{
    size_t length;
    if (req->info.flags & SW_EVENT_DATA_PTR)
    {
        swPacket_ptr *task = (swPacket_ptr *) req;
        *data_ptr = task->data.str;
        length = task->data.length;
    }
    else if (req->info.flags & SW_EVENT_DATA_END)
    {
        swString *worker_buffer = swWorker_get_buffer(serv, req->info.reactor_id);
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

static sw_inline swConnection *swServer_connection_verify_no_ssl(swServer *serv, uint32_t session_id)
{
    swSession *session = swServer_get_session(serv, session_id);
    int fd = session->fd;
    swConnection *conn = swServer_connection_get(serv, fd);
    if (!conn || conn->active == 0)
    {
        return NULL;
    }
    if (session->id != session_id || conn->session_id != session_id)
    {
        return NULL;
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
        return NULL;
    }
#endif
    return conn;
}

static sw_inline int swServer_connection_incoming(swServer *serv, swReactor *reactor, swConnection *conn)
{
#ifdef SW_USE_OPENSSL
    if (conn->socket->ssl)
    {
        return reactor->add(reactor, conn->fd, SW_FD_SESSION | SW_EVENT_READ);
    }
#endif
    //delay receive, wait resume command.
    if (serv->enable_delay_receive)
    {
        conn->socket->listen_wait = 1;
        return SW_OK;
    }
    if (reactor->add(reactor, conn->fd, SW_FD_SESSION | SW_EVENT_READ) < 0)
    {
        return SW_ERR;
    }
    //notify worker process
    if (serv->onConnect)
    {
        return serv->notify(serv, conn, SW_SERVER_EVENT_CONNECT);
    }
    else
    {
        return SW_OK;
    }
}

void swServer_connection_each(swServer *serv, void (*callback)(swConnection *conn));

/**
 * reactor_id: The fd in which the reactor.
 */
static sw_inline int swServer_get_send_pipe(swServer *serv, int session_id, int reactor_id)
{
    int pipe_index = session_id % serv->reactor_pipe_num;
    /**
     * pipe_worker_id: The pipe in which worker.
     */
    int pipe_worker_id = reactor_id + (pipe_index * serv->reactor_num);
    swWorker *worker = swServer_get_worker(serv, pipe_worker_id);
    return worker->pipe_worker;
}

static sw_inline uint8_t swServer_support_unsafe_events(swServer *serv)
{
    if (serv->dispatch_mode != SW_DISPATCH_ROUND && serv->dispatch_mode != SW_DISPATCH_QUEUE
            && serv->dispatch_mode != SW_DISPATCH_STREAM)
    {
        return 1;
    }
    else
    {
        return serv->enable_unsafe_event;
    }
}

static sw_inline uint8_t swServer_dispatch_mode_is_mod(swServer *serv)
{
    return serv->dispatch_mode == SW_DISPATCH_FDMOD || serv->dispatch_mode == SW_DISPATCH_IPMOD;
}

#define swServer_support_send_yield swServer_dispatch_mode_is_mod

//------------------------------------Listen Port-------------------------------------------
void swPort_init(swListenPort *port);
void swPort_free(swListenPort *port);
int swPort_listen(swListenPort *ls);
void swPort_set_protocol(swServer *serv, swListenPort *ls);
#ifdef SW_USE_OPENSSL
int swPort_enable_ssl_encrypt(swListenPort *ls);
#endif
void swPort_clear_protocol(swListenPort *ls);
//------------------------------------Worker Process-------------------------------------------
void swWorker_onStart(swServer *serv);
void swWorker_onStop(swServer *serv);
int swWorker_loop(swServer *serv, int worker_pti);
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
int swReactorThread_close(swReactor *reactor, int fd);
int swReactorThread_dispatch(swProtocol *proto, swSocket *_socket, char *data, uint32_t length);
int swReactorThread_send2worker(swServer *serv, swWorker *worker, void *data, int len);

int swReactorProcess_create(swServer *serv);
int swReactorProcess_start(swServer *serv);
void swReactorProcess_free(swServer *serv);

int swManager_start(swServer *serv);
pid_t swManager_spawn_user_worker(swServer *serv, swWorker* worker);
pid_t swManager_spawn_task_worker(swServer *serv, swWorker* worker);
int swManager_wait_other_worker(swProcessPool *pool, pid_t pid, int status);
void swManager_kill_user_worker(swServer *serv);

SW_EXTERN_C_END

#endif /* SW_SERVER_H_ */
