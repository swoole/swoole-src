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
};

#define SW_HOST_MAXSIZE            128
#define SW_MAX_TMP_PKG             1000
#define SW_LOG_FILENAME            128

enum swIPCMode
{
	SW_IPC_UNSOCK   = 1,
	SW_IPC_MSGQUEUE = 2,
	SW_IPC_CHANNEL  = 3,
};

enum swTaskIPCMode
{
    SW_TASK_IPC_UNIXSOCK    = 1,
    SW_TASK_IPC_MSGQUEUE    = 2,
    SW_TASK_IPC_PREEMPTIVE  = 3,
};

enum swCloseType
{
	SW_CLOSE_PASSIVE = 32,
	SW_CLOSE_INITIATIVE,
};

enum swResponseType
{
	SW_RESPONSE_SMALL = 0,
	SW_RESPONSE_BIG   = 1,
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
    int c_udp_fd;
} swReactorThread;

typedef struct _swListenPort
{
    struct _swListenPort *next, *prev;
    uint8_t type;
    uint8_t ssl;
    int port;
    int sock;
    pthread_t thread_id;
    char host[SW_HOST_MAXSIZE];
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
	off_t filesize;
	off_t offset;
} swTask_sendfile;

typedef struct
{
    uint16_t num;
} swUserWorker;

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
struct _swServer
{
    /**
     * tcp socket listen backlog
     */
    uint16_t backlog;
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

    /**
     * swoole packet mode
     */
    int packet_mode;

    /**
     * package dispatch mode
     */
    uint8_t dispatch_mode; //分配模式，1平均分配，2按FD取摸固定分配，3,使用抢占式队列(IPC消息队列)分配

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

    int timeout_sec;
    int timeout_usec;

    int sock_client_buffer_size; //client的socket缓存区设置
    int sock_server_buffer_size; //server的socket缓存区设置

    char log_file[SW_LOG_FILENAME]; //日志文件

    int signal_fd;
    int event_fd;

    int udp_socket_ipv4;
    int udp_socket_ipv6;

    int ringbuffer_size;

    /*----------------------------Reactor schedule--------------------------------*/
    uint16_t reactor_round_i; //轮询调度
    uint16_t reactor_next_i; //平均算法调度
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
     * oepn cpu affinity setting
     */
    uint32_t open_cpu_affinity :1;

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
     * check data eof
     */
    uint32_t open_eof_check :1;

    /**
     * built-in http protocol
     */
    uint32_t open_http_protocol :1;

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
     * Use data key as factory->dispatch() param.
     */
    uint32_t open_dispatch_key :1;

    /**
     * Udisable notice when use SW_DISPATCH_ROUND and SW_DISPATCH_QUEUE
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

    uint32_t enable_unsafe_event :1;

    /**
     * open tcp_defer_accept option
     */
    int tcp_defer_accept;
    /**
     * TCP_FASTOPEN
     */
    int tcp_fastopen;

    int tcp_keepidle;
    int tcp_keepinterval;
    int tcp_keepcount;

    /* heartbeat check time*/
    uint16_t heartbeat_idle_time; //心跳存活时间
    uint16_t heartbeat_check_interval; //心跳定时侦测时间, 必需小于heartbeat_idle_time

    int *cpu_affinity_available;
    int cpu_affinity_available_num;
    
    uint8_t listen_port_num;

    /**
     * 来自客户端的心跳侦测包
     */
    char heartbeat_ping[SW_HEARTBEAT_PING_LEN + 1];
    uint8_t heartbeat_ping_length;

    /**
     * 服务器端对心跳包的响应
     */
    char heartbeat_pong[SW_HEARTBEAT_PING_LEN + 1];
    uint8_t heartbeat_pong_length;

    swProtocol protocol;

    uint8_t dispatch_key_size;
    uint16_t dispatch_key_offset;
    uint16_t dispatch_key_type;

    /* buffer output/input setting*/
    uint32_t buffer_output_size;
    uint32_t buffer_input_size;

    uint32_t pipe_buffer_size;

#ifdef SW_USE_OPENSSL
    uint8_t open_ssl;
    char *ssl_cert_file;
    char *ssl_key_file;
#endif

    void *ptr2;

    swReactor reactor;
    swFactory factory;

    swListenPort *listen_list;

    swUserWorker_node *user_worker_list;
    swHashMap *user_worker_map;

    swReactorThread *reactor_threads;
    swWorker *workers;

#ifdef HAVE_PTHREAD_BARRIER
    pthread_barrier_t barrier;
#endif

    swConnection *connection_list;  //连接列表
    swSession *session_list;

    int connection_list_capacity; //超过此容量，会自动扩容

    /**
     * message queue key
     */
    uint64_t message_queue_key;

    swReactor *reactor_ptr; //Main Reactor
    swFactory *factory_ptr; //Factory

    void (*onStart)(swServer *serv);
    void (*onManagerStart)(swServer *serv);
    void (*onManagerStop)(swServer *serv);
    int (*onReceive)(swServer *, swEventData *);
    int (*onPacket)(swServer *, swEventData *); //for datagram
    int (*onRequest)(swServer *serv, swRequest *request);
    void (*onClose)(swServer *serv, int fd, int from_id);
    void (*onConnect)(swServer *serv, int fd, int from_id);
    void (*onShutdown)(swServer *serv);
    void (*onTimer)(swServer *serv, int interval);
    void (*onPipeMessage)(swServer *, swEventData *);
    void (*onWorkerStart)(swServer *serv, int worker_id);
    void (*onWorkerStop)(swServer *serv, int worker_id);
    void (*onWorkerError)(swServer *serv, int worker_id, pid_t worker_pid, int exit_code); //Only process mode
    void (*onUserWorkerStart)(swServer *serv, swWorker *worker);
    int (*onTask)(swServer *serv, swEventData *data);
    int (*onFinish)(swServer *serv, swEventData *data);

    int (*send)(swServer *, swSendData *);
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

int swServer_onFinish(swFactory *factory, swSendData *resp);
int swServer_onFinish2(swFactory *factory, swSendData *resp);

void swServer_init(swServer *serv);
void swServer_signal_init(void);
int swServer_start(swServer *serv);
int swServer_add_listener(swServer *serv, int type, char *host,int port);
int swServer_add_worker(swServer *serv, swWorker *worker);

int swServer_create(swServer *serv);
int swServer_listen(swServer *serv, swListenPort *ls);
int swServer_free(swServer *serv);
int swServer_shutdown(swServer *serv);

int swServer_udp_send(swServer *serv, swSendData *resp);
int swServer_tcp_send(swServer *serv, int fd, void *data, uint32_t length);
int swServer_tcp_sendwait(swServer *serv, int fd, void *data, uint32_t length);

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
        return SW_TRUE;
    default:
        return SW_FALSE;
    }
}

static sw_inline int swServer_package_integrity(swServer *serv)
{
    if (serv->open_eof_check || serv->open_length_check || serv->open_http_protocol || serv->open_mqtt_protocol)
    {
        return SW_TRUE;
    }
    else
    {
        return SW_FALSE;
    }
}

swPipe * swServer_pipe_get(swServer *serv, int pipe_fd);
void swServer_pipe_set(swServer *serv, swPipe *p);

int swServer_get_manager_pid(swServer *serv);
int swServer_worker_init(swServer *serv, swWorker *worker);
void swServer_onTimer(swTimer *timer, swTimer_node *event);
void swServer_enable_accept(swReactor *reactor);

void swTaskWorker_init(swProcessPool *pool);
int swTaskWorker_onTask(swProcessPool *pool, swEventData *task);
int swTaskWorker_onFinish(swReactor *reactor, swEvent *event);
void swTaskWorker_onStart(swProcessPool *pool, int worker_id);
void swTaskWorker_onStop(swProcessPool *pool, int worker_id);
int swTaskWorker_large_pack(swEventData *task, void *data, int data_len);
int swTaskWorker_finish(swServer *serv, char *data, int data_len, int flags);

#define swTask_type(task)                  ((task)->info.from_fd)

#define swTaskWorker_large_unpack(task, __malloc, _buf, _length)   swPackage_task _pkg;\
	memcpy(&_pkg, task->data, sizeof(_pkg));\
	_length = _pkg.length;\
    if (_length > SwooleG.serv->protocol.package_max_length) {\
        swWarn("task package is too big.");\
    }\
    _buf = __malloc(_length + 1);\
    _buf[_length] = 0;\
    int tmp_file_fd = open(_pkg.tmpfile, O_RDONLY);\
    if (tmp_file_fd < 0){\
        swSysError("open(%s) failed.", task->data);\
        _length = -1;\
    } else if (swoole_sync_readfile(tmp_file_fd, _buf, _length) > 0) {\
        close(tmp_file_fd);\
        unlink(_pkg.tmpfile);\
    } else {\
        _length = -1;\
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
    int task_num = SwooleG.task_worker_max > 0 ? SwooleG.task_worker_max : SwooleG.task_worker_num;
    if (worker_id > serv->worker_num + task_num)
    {
        swWarn("worker_id is exceed serv->worker_num + SwooleG.task_worker_num");
        return NULL;
    }
    else if (worker_id >= serv->worker_num)
    {
        return &(SwooleGS->task_workers.workers[worker_id - serv->worker_num]);
    }
    else
    {
        return &(SwooleGS->event_workers.workers[worker_id]);
    }
}

static sw_inline uint32_t swServer_worker_schedule(swServer *serv, uint32_t schedule_key)
{
    uint32_t target_worker_id = 0;

    //polling mode
    if (serv->dispatch_mode == SW_DISPATCH_ROUND)
    {
        target_worker_id = sw_atomic_fetch_add(&serv->worker_round_id, 1) % serv->worker_num;
    }
    //Using the FD touch access to hash
    else if (serv->dispatch_mode == SW_DISPATCH_FDMOD)
    {
        target_worker_id = schedule_key % serv->worker_num;
    }
    //Using the IP touch access to hash
    else if (serv->dispatch_mode == SW_DISPATCH_IPMOD)
    {
        swConnection *conn = swServer_connection_get(serv, schedule_key);
        //UDP
        if (conn == NULL)
        {
            target_worker_id = schedule_key % serv->worker_num;
        }
        //IPv4
        else if (conn->socket_type == SW_SOCK_TCP)
        {
            target_worker_id = conn->info.addr.inet_v4.sin_addr.s_addr % serv->worker_num;
        }
        //IPv6
        else
        {
#ifdef HAVE_KQUEUE
            uint32_t ipv6_last_int = *(((uint32_t *) &conn->info.addr.inet_v6.sin6_addr) + 3);
            target_worker_id = ipv6_last_int % serv->worker_num;
#else
            target_worker_id = conn->info.addr.inet_v6.sin6_addr.s6_addr32[3] % serv->worker_num;
#endif
        }
    }
    else if (serv->dispatch_mode == SW_DISPATCH_UIDMOD)
    {
        swConnection *conn = swServer_connection_get(serv, schedule_key);
        if (conn == NULL)
        {
            target_worker_id = schedule_key % serv->worker_num;
        }
        else if (conn->uid)
        {
            target_worker_id = conn->uid % serv->worker_num;
        }
        else
        {
            target_worker_id = schedule_key % serv->worker_num;
        }
    }
    //Preemptive distribution
    else
    {
        int i;
        for (i = 0; i < serv->worker_num + 1; i++)
        {
            target_worker_id = sw_atomic_fetch_add(&serv->worker_round_id, 1) % serv->worker_num;
            if (serv->workers[target_worker_id].status == SW_WORKER_IDLE)
            {
                break;
            }
        }
        //swWarn("schedule=%d|round=%d\n", target_worker_id, *round);
    }
    return target_worker_id;
}

void swServer_worker_onStart(swServer *serv);
void swServer_worker_onStop(swServer *serv);

int swWorker_create(swWorker *worker);
int swWorker_onTask(swFactory *factory, swEventData *task);

static sw_inline swConnection *swWorker_get_connection(swServer *serv, int session_id)
{
    int real_fd = swServer_get_fd(serv, session_id);
    swConnection *conn = swServer_connection_get(serv, real_fd);
    return conn;
}

static sw_inline swConnection *swServer_connection_verify(swServer *serv, int session_id)
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

void swWorker_free(swWorker *worker);
void swWorker_signal_init(void);
void swWorker_onStart(swServer *serv);
void swWorker_onStop(swServer *serv);
int swWorker_loop(swFactory *factory, int worker_pti);
int swWorker_send2reactor(swEventData *ev_data, size_t sendn, int fd);
int swWorker_send2worker(swWorker *dst_worker, void *buf, int n, int flag);
void swWorker_signal_handler(int signo);
void swWorker_clean(void);

int swServer_master_onAccept(swReactor *reactor, swEvent *event);

int swReactorThread_create(swServer *serv);
int swReactorThread_start(swServer *serv, swReactor *main_reactor_ptr);
void swReactorThread_set_protocol(swServer *serv, swReactor *reactor);
void swReactorThread_free(swServer *serv);
int swReactorThread_close(swReactor *reactor, int fd);
int swReactorThread_send(swSendData *_send);
int swReactorThread_send2worker(void *data, int len, uint16_t target_worker_id);

int swReactorProcess_create(swServer *serv);
int swReactorProcess_start(swServer *serv);
int swReactorProcess_onClose(swReactor *reactor, swEvent *event);

#ifdef __cplusplus
}
#endif

#endif /* SW_SERVER_H_ */
