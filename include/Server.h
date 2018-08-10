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

#include "swoole.h"
#include "buffer.h"
#include "Connection.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SW_REACTOR_NUM             SW_CPU_NUM
#define SW_WORKER_NUM              (SW_CPU_NUM*2)

#define SW_HEARTBEAT_IDLE          0   //心跳存活最大时间
#define SW_HEARTBEAT_CHECK         0   //心跳定时侦测时间

enum swEventType
{
    //networking socket
    SW_EVENT_TCP             = 0,
    SW_EVENT_UDP             = 1,
    SW_EVENT_TCP6            = 2,
    SW_EVENT_UDP6            = 3,
    //tcp event
    SW_EVENT_CLOSE           = 4,
    SW_EVENT_CONNECT         = 5,
    //timer
    SW_EVENT_TIMER           = 6,
    //task
    SW_EVENT_TASK            = 7,
    SW_EVENT_FINISH          = 8,
    //package
    SW_EVENT_PACKAGE_START   = 9,
    SW_EVENT_PACKAGE_END     = 10,
    SW_EVENT_PACKAGE         = 11,
    SW_EVENT_SENDFILE        = 12,
    SW_EVENT_UNIX_DGRAM      = 13,
    SW_EVENT_UNIX_STREAM     = 14,
    //pipe
    SW_EVENT_PIPE_MESSAGE    = 15,
    //proxy
    SW_EVENT_PROXY_START     = 16,
    SW_EVENT_PROXY_END       = 17,
    SW_EVENT_CONFIRM         = 18,
    //event operate
    SW_EVENT_PAUSE_RECV,
    SW_EVENT_RESUME_RECV,
    //buffer event
    SW_EVENT_BUFFER_FULL,
    SW_EVENT_BUFFER_EMPTY,
};

enum swIPCType
{
    SW_IPC_NONE     = 0,
    SW_IPC_UNIXSOCK = 1,
    SW_IPC_MSGQUEUE = 2,
    SW_IPC_SOCKET   = 3,
};

enum swTaskIPCMode
{
    SW_TASK_IPC_UNIXSOCK    = 1,
    SW_TASK_IPC_MSGQUEUE    = 2,
    SW_TASK_IPC_PREEMPTIVE  = 3,
    SW_TASK_IPC_STREAM      = 4,
};

enum swCloseType
{
    SW_CLOSE_PASSIVE = 32,
    SW_CLOSE_INITIATIVE,
};

enum swResponseType
{
    SW_RESPONSE_SMALL = 0,
    SW_RESPONSE_SHM = 1,
    SW_RESPONSE_TMPFILE,
    SW_RESPONSE_EXIT,
};

enum swWorkerPipeType
{
    SW_PIPE_WORKER     = 0,
    SW_PIPE_MASTER     = 1,
    SW_PIPE_NONBLOCK   = 2,
};

/**
 * use swDataHead->from_fd, 1 byte 8 bit
 */
enum swTaskType
{
    SW_TASK_TMPFILE    = 1,  //tmp file
    SW_TASK_SERIALIZE  = 2,  //php serialize
    SW_TASK_NONBLOCK   = 4,  //task
    SW_TASK_CALLBACK   = 8,  //callback
    SW_TASK_WAITALL    = 16, //for taskWaitAll
    SW_TASK_COROUTINE  = 32, //coroutine
    SW_TASK_PEEK       = 64, //peek
};

typedef struct _swUdpFd
{
    struct sockaddr addr;
    int sock;
} swUdpFd;

typedef struct _swReactorThread
{
    pthread_t thread_id;
    swReactor reactor;
    swUdpFd *udp_addrs;
    swMemoryPool *buffer_input;
#ifdef SW_USE_RINGBUFFER
    int *pipe_read_list;
#endif
    swLock lock;
    int notify_pipe;
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

    uint8_t type;
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

typedef struct {
	char *filename;
	uint16_t name_len;
	int fd;
	size_t length;
	off_t offset;
} swTask_sendfile;

typedef struct
{
    uint16_t num;
} swUserWorker;

typedef struct
{
    pid_t pid;
    uint16_t worker_id;
} swWorkerStopMessage;

//-----------------------------------Factory--------------------------------------------
typedef struct
{
    long target_worker_id;
    swEventData data;
} swDispatchData;

struct _swFactory
{
    void *object;
    void *ptr; //server object
    int last_from_id;

    swReactor *reactor; //reserve for reactor

    int (*start)(struct _swFactory *);
    int (*shutdown)(struct _swFactory *);
    int (*dispatch)(struct _swFactory *, swDispatchData *);
    int (*finish)(struct _swFactory *, swSendData *);
    int (*notify)(struct _swFactory *, swDataHead *);    //send a event notify
    int (*end)(struct _swFactory *, int fd);
};

typedef struct _swFactoryProcess
{
    swPipe *pipes;
} swFactoryProcess;

typedef struct _swRequest
{
    int fd;
    uint8_t type;
    uint8_t status;
    void *object;
} swRequest;

typedef int (*swServer_dispatch_function)(swServer *, swConnection *, swEventData *);

int swFactory_create(swFactory *factory);
int swFactory_start(swFactory *factory);
int swFactory_shutdown(swFactory *factory);
int swFactory_dispatch(swFactory *factory, swDispatchData *req);
int swFactory_finish(swFactory *factory, swSendData *_send);
int swFactory_notify(swFactory *factory, swDataHead *event);
int swFactory_end(swFactory *factory, int fd);
int swFactory_check_callback(swFactory *factory);

int swFactoryProcess_create(swFactory *factory, int worker_num);
int swFactoryThread_create(swFactory *factory, int writer_num);


//------------------------------------Server-------------------------------------------
enum swServer_callback_type
{
    SW_SERVER_CALLBACK_onConnect = 1,
    SW_SERVER_CALLBACK_onReceive,
    SW_SERVER_CALLBACK_onClose,
};

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

typedef struct
{
    time_t start_time;
    sw_atomic_t connection_num;
    sw_atomic_t tasking_num;
    sw_atomic_long_t accept_count;
    sw_atomic_long_t close_count;
    sw_atomic_long_t request_count;
} swServerStats;

typedef struct
{
    pid_t master_pid;
    pid_t manager_pid;

    uint32_t session_round :24;
    sw_atomic_t start;  //after swServer_start will set start=1

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
    uint16_t worker_num;
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

    int signal_fd;
    int event_fd;

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
     * have udp listen socket
     */
    uint32_t have_udp_sock :1;
    /**
     * have tcp listen socket
     */
    uint32_t have_tcp_sock :1;
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
     * parse x-www-form-urlencoded data
     */
    uint32_t http_parse_post :1;
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
     * slowlog
     */
    uint32_t trace_event_worker :1;
    /**
     * yield coroutine when the output buffer is full
     */
    uint32_t send_yield :1;

    /**
     *  heartbeat check time
     */
    uint16_t heartbeat_idle_time;
    uint16_t heartbeat_check_interval;

    int *cpu_affinity_available;
    int cpu_affinity_available_num;
    
    double send_timeout;

    uint16_t listen_port_num;
    time_t reload_time;
    time_t warning_time;

    /* buffer output/input setting*/
    uint32_t buffer_output_size;
    uint32_t buffer_input_size;

    void *ptr2;
    void *private_data_3;

    swReactor reactor;
    swFactory factory;
    swListenPort *listen_list;
    pthread_t heartbeat_pidt;

    /**
     *  task process
     */
    uint16_t task_worker_num;
    uint8_t task_ipc_mode;
    uint16_t task_max_request;
    swPipe *task_notify;
    swEventData *task_result;

    /**
     * user process
     */
    uint16_t user_worker_num;
    swUserWorker_node *user_worker_list;
    swHashMap *user_worker_map;
    swWorker *user_workers;

    swReactorThread *reactor_threads;
    swWorker *workers;

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
    swLinkedList *buffer_pool;
    int last_stream_fd;
    int last_session_id;

#ifdef SW_BUFFER_RECV_TIME
    double last_receive_usec;
#endif

    int manager_alarm;

    /**
     * message queue key
     */
    uint64_t message_queue_key;

    /**
     * slow request log
     */
    uint8_t request_slowlog_timeout;
    FILE *request_slowlog_file;

    swReactor *reactor_ptr; //Main Reactor
    swFactory *factory_ptr; //Factory

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

    int (*send)(swServer *serv, int fd, void *data, uint32_t length);
    int (*sendfile)(swServer *serv, int fd, char *filename, uint32_t filename_length, off_t offset, size_t length);
    int (*sendwait)(swServer *serv, int fd, void *data, uint32_t length);
    int (*close)(swServer *serv, int fd, int reset);
    int (*dispatch_func)(swServer *, swConnection *, swEventData *);
};

typedef struct _swSocketLocal
{
	socklen_t len;
	char file[0];
} swSocketLocal;

typedef struct _swPackage
{
    void *data;
    uint32_t length;
    uint32_t id;
} swPackage;

typedef struct
{
    int length;
    char tmpfile[SW_TASK_TMPDIR_SIZE + sizeof(SW_TASK_TMP_FILE)];
} swPackage_task;

typedef struct
{
	int length;
	int worker_id;
} swPackage_response;

int swServer_master_onAccept(swReactor *reactor, swEvent *event);
void swServer_master_onTimer(swTimer *timer, swTimer_node *tnode);
void swServer_update_time(swServer *serv);

int swServer_onFinish(swFactory *factory, swSendData *resp);
int swServer_onFinish2(swFactory *factory, swSendData *resp);

void swServer_init(swServer *serv);
void swServer_signal_init(swServer *serv);
int swServer_start(swServer *serv);
swListenPort* swServer_add_port(swServer *serv, int type, char *host, int port);
void swServer_close_port(swServer *serv, enum swBool_type only_stream_port);
int swServer_add_worker(swServer *serv, swWorker *worker);
int swserver_add_systemd_socket(swServer *serv);
int swServer_add_hook(swServer *serv, enum swServer_hook_type type, swCallback func, int push_back);
void swServer_call_hook(swServer *serv, enum swServer_hook_type type, void *arg);

int swServer_create(swServer *serv);
int swServer_free(swServer *serv);
int swServer_shutdown(swServer *serv);

static sw_inline swString *swServer_get_buffer(swServer *serv, int fd)
{
    swString *buffer = serv->connection_list[fd].recv_buffer;
    if (buffer == NULL)
    {
        buffer = swString_new(SW_BUFFER_SIZE_STD);
        //alloc memory failed.
        if (!buffer)
        {
            return NULL;
        }
        serv->connection_list[fd].recv_buffer = buffer;
    }
    return buffer;
}

static sw_inline void swServer_free_buffer(swServer *serv, int fd)
{
    swString *buffer = serv->connection_list[fd].recv_buffer;
    if (buffer)
    {
        swString_free(buffer);
        serv->connection_list[fd].recv_buffer = NULL;
    }
}

static sw_inline swListenPort* swServer_get_port(swServer *serv, int fd)
{
    sw_atomic_t server_fd = serv->connection_list[fd].from_fd;
    return (swListenPort*) serv->connection_list[server_fd].object;
}

int swServer_udp_send(swServer *serv, swSendData *resp);
int swServer_tcp_send(swServer *serv, int fd, void *data, uint32_t length);
int swServer_tcp_sendwait(swServer *serv, int fd, void *data, uint32_t length);
int swServer_tcp_close(swServer *serv, int fd, int reset);
int swServer_tcp_sendfile(swServer *serv, int session_id, char *filename, uint32_t filename_length, off_t offset, size_t length);
int swServer_tcp_notify(swServer *serv, swConnection *conn, int event);
int swServer_tcp_feedback(swServer *serv, int fd, int event);

//UDP, UDP必然超过0x1000000
//原因：IPv4的第4字节最小为1,而这里的conn_fd是网络字节序
#define SW_MAX_SOCKET_ID             0x1000000
#define swServer_is_udp(fd)          ((uint32_t) fd > SW_MAX_SOCKET_ID)

static sw_inline int swEventData_is_dgram(uint8_t type)
{
    switch (type)
    {
    case SW_EVENT_UDP:
    case SW_EVENT_UDP6:
    case SW_EVENT_UNIX_DGRAM:
        return SW_TRUE;
    default:
        return SW_FALSE;
    }
}

static sw_inline int swEventData_is_stream(uint8_t type)
{
    switch (type)
    {
    case SW_EVENT_TCP:
    case SW_EVENT_TCP6:
    case SW_EVENT_UNIX_STREAM:
    case SW_EVENT_PACKAGE_START:
    case SW_EVENT_PACKAGE:
    case SW_EVENT_PACKAGE_END:
    case SW_EVENT_CONNECT:
    case SW_EVENT_CLOSE:
    case SW_EVENT_PAUSE_RECV:
    case SW_EVENT_RESUME_RECV:
    case SW_EVENT_BUFFER_FULL:
    case SW_EVENT_BUFFER_EMPTY:
        return SW_TRUE;
    default:
        return SW_FALSE;
    }
}

swPipe * swServer_get_pipe_object(swServer *serv, int pipe_fd);
void swServer_store_pipe_fd(swServer *serv, swPipe *p);
void swServer_store_listen_socket(swServer *serv);

int swServer_get_manager_pid(swServer *serv);
int swServer_get_socket(swServer *serv, int port);
int swServer_worker_init(swServer *serv, swWorker *worker);
swString** swServer_create_worker_buffer(swServer *serv);
int swServer_create_task_worker(swServer *serv);
void swServer_close_listen_port(swServer *serv);
void swServer_enable_accept(swReactor *reactor);
void swServer_reopen_log_file(swServer *serv);

void swTaskWorker_init(swProcessPool *pool);
int swTaskWorker_onTask(swProcessPool *pool, swEventData *task);
int swTaskWorker_onFinish(swReactor *reactor, swEvent *event);
void swTaskWorker_onStart(swProcessPool *pool, int worker_id);
void swTaskWorker_onStop(swProcessPool *pool, int worker_id);
int swTaskWorker_large_pack(swEventData *task, void *data, int data_len);
int swTaskWorker_finish(swServer *serv, char *data, int data_len, int flags);

#define swTask_type(task)                  ((task)->info.from_fd)

static sw_inline swString* swTaskWorker_large_unpack(swEventData *task_result)
{
    swPackage_task _pkg;
    memcpy(&_pkg, task_result->data, sizeof(_pkg));

    int tmp_file_fd = open(_pkg.tmpfile, O_RDONLY);
    if (tmp_file_fd < 0)
    {
        swSysError("open(%s) failed.", _pkg.tmpfile);
        return NULL;
    }
    if (SwooleTG.buffer_stack->size < _pkg.length && swString_extend_align(SwooleTG.buffer_stack, _pkg.length) < 0)
    {
        close(tmp_file_fd);
        return NULL;
    }
    if (swoole_sync_readfile(tmp_file_fd, SwooleTG.buffer_stack->str, _pkg.length) < 0)
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

#define swPackage_data(task) ((task->info.type==SW_EVENT_PACKAGE_END)?SwooleWG.buffer_input[task->info.from_id]->str:task->data)
#define swPackage_length(task) ((task->info.type==SW_EVENT_PACKAGE_END)?SwooleWG.buffer_input[task->info.from_id]->length:task->info.len)

#define SW_SERVER_MAX_FD_INDEX          0 //max connection socket
#define SW_SERVER_MIN_FD_INDEX          1 //min listen socket
#define SW_SERVER_TIMER_FD_INDEX        2 //for timerfd

//使用connection_list[0]表示最大的FD
#define swServer_set_maxfd(serv,maxfd) (serv->connection_list[SW_SERVER_MAX_FD_INDEX].fd=maxfd)
#define swServer_get_maxfd(serv) (serv->connection_list[SW_SERVER_MAX_FD_INDEX].fd)
//使用connection_list[1]表示最小的FD
#define swServer_set_minfd(serv,maxfd) (serv->connection_list[SW_SERVER_MIN_FD_INDEX].fd=maxfd)
#define swServer_get_minfd(serv) (serv->connection_list[SW_SERVER_MIN_FD_INDEX].fd)

#define swServer_get_thread(serv, reactor_id)    (&(serv->reactor_threads[reactor_id]))

static sw_inline swConnection* swServer_connection_get(swServer *serv, int fd)
{
    if (fd > serv->max_connection || fd <= 2)
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
    uint16_t task_worker_max = serv->task_worker_num + serv->worker_num;
    if (worker_id < task_worker_max)
    {
        return &(serv->gs->task_workers.workers[worker_id - serv->worker_num]);
    }

    //User Worker
    uint16_t user_worker_max = task_worker_max + serv->user_worker_num;
    if (worker_id < user_worker_max)
    {
        return &(serv->user_workers[worker_id - task_worker_max]);
    }

    return NULL;
}

static sw_inline int swServer_worker_schedule(swServer *serv, int fd, swEventData *data)
{
    uint32_t key;

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
    //schedule by dispatch function
    else if (serv->dispatch_mode == SW_DISPATCH_USERFUNC)
    {
        return serv->dispatch_func(serv, swServer_connection_get(serv, fd), data);
    }
    //Preemptive distribution
    else
    {
        int i;
        int found = 0;
        for (i = 0; i < serv->worker_num + 1; i++)
        {
            key = sw_atomic_fetch_add(&serv->worker_round_id, 1) % serv->worker_num;
            if (serv->workers[key].status == SW_WORKER_IDLE)
            {
                found = 1;
                break;
            }
        }
        if (unlikely(found == 0))
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

void swServer_set_callback(swServer *serv, int type, void *callback);
void swServer_set_callback_onReceive(swServer *serv, int (*callback)(swServer *, char *, int, int, int));
void swServer_set_callback_onConnect(swServer *serv, void (*callback)(swServer *, int, int));
void swServer_set_callback_onClose(swServer *serv, void (*callback)(swServer *, int, int));

int swWorker_create(swWorker *worker);
int swWorker_onTask(swFactory *factory, swEventData *task);

static sw_inline swConnection *swWorker_get_connection(swServer *serv, int session_id)
{
    int real_fd = swServer_get_fd(serv, session_id);
    swConnection *conn = swServer_connection_get(serv, real_fd);
    return conn;
}

static sw_inline swString *swWorker_get_buffer(swServer *serv, int reactor_id)
{
    if (serv->factory_mode == SW_MODE_SINGLE)
    {
        return SwooleWG.buffer_input[0];
    }
    else if (serv->factory_mode == SW_MODE_THREAD)
    {
        return SwooleTG.buffer_input[reactor_id];
    }
    else
    {
        return SwooleWG.buffer_input[reactor_id];
    }
}

static sw_inline swConnection *swServer_connection_verify_no_ssl(swServer *serv, int session_id)
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
    if (!conn)
    {
        return NULL;
    }
    if (conn->ssl && conn->ssl_state != SW_SSL_STATE_READY)
    {
        swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SSL_NOT_READY, "SSL not ready");
        return NULL;
    }
#endif
    return conn;
}

void swPort_init(swListenPort *port);
void swPort_free(swListenPort *port);
void swPort_set_protocol(swListenPort *ls);
int swPort_listen(swListenPort *ls);
#ifdef SW_USE_OPENSSL
int swPort_enable_ssl_encrypt(swListenPort *ls);
#endif
void swPort_clear_protocol(swListenPort *ls);

void swWorker_free(swWorker *worker);
void swWorker_onStart(swServer *serv);
void swWorker_onStop(swServer *serv);
void swWorker_try_to_exit();
int swWorker_loop(swFactory *factory, int worker_pti);
int swWorker_send2reactor(swEventData *ev_data, size_t sendn, int fd);
int swWorker_send2worker(swWorker *dst_worker, void *buf, int n, int flag);
void swWorker_signal_handler(int signo);
void swWorker_signal_init(void);
void swWorker_clean(void);

/**
 * reactor_id: The fd in which the reactor.
 */
static sw_inline int swWorker_get_send_pipe(swServer *serv, int session_id, int reactor_id)
{
    int pipe_index = session_id % serv->reactor_pipe_num;
    /**
     * pipe_worker_id: The pipe in which worker.
     */
    int pipe_worker_id = reactor_id + (pipe_index * serv->reactor_num);
    swWorker *worker = swServer_get_worker(serv, pipe_worker_id);
    return worker->pipe_worker;
}

int swReactorThread_create(swServer *serv);
int swReactorThread_start(swServer *serv, swReactor *main_reactor_ptr);
void swReactorThread_set_protocol(swServer *serv, swReactor *reactor);
void swReactorThread_free(swServer *serv);
int swReactorThread_close(swReactor *reactor, int fd);
int swReactorThread_onClose(swReactor *reactor, swEvent *event);
int swReactorThread_dispatch(swConnection *conn, char *data, uint32_t length);
int swReactorThread_send(swSendData *_send);
int swReactorThread_send2worker(void *data, int len, uint16_t target_worker_id);

int swReactorProcess_create(swServer *serv);
int swReactorProcess_start(swServer *serv);
int swReactorProcess_onClose(swReactor *reactor, swEvent *event);

int swManager_start(swFactory *factory);
pid_t swManager_spawn_user_worker(swServer *serv, swWorker* worker);
int swManager_wait_user_worker(swProcessPool *pool, pid_t pid, int status);
void swManager_kill_user_worker(swServer *serv);

#ifdef __cplusplus
}
#endif

#endif /* SW_SERVER_H_ */
