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
#define SW_WRITER_NUM              SW_CPU_NUM
#define SW_PIPES_NUM               (SW_WORKER_NUM/SW_WRITER_NUM + 1) //每个写线程pipes数组大小
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
};

#define SW_STATUS_EMPTY            0
#define SW_STATUS_ACTIVE           1
#define SW_STATUS_CLOSED           2

#define SW_HOST_MAXSIZE            128
#define SW_MAX_TMP_PKG             1000
#define SW_LOG_FILENAME            128

enum swIPCMode
{
	SW_IPC_UNSOCK   = 1,
	SW_IPC_MSGQUEUE = 2,
	SW_IPC_CHANNEL  = 3,
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
    SW_PIPE_WORKER   = 0,
    SW_PIPE_MASTER   = 1,
};

/**
 * use swDataHead->from_fd, 1 byte 8 bit
 */
enum swTaskType
{
    SW_TASK_TMPFILE    = 1,  //tmp file
    SW_TASK_SERIALIZE  = 2,  //php serialize
    SW_TASK_BLOCKING   = 4,  //taskwait
    SW_TASK_NONBLOCK   = 8,  //task
    SW_TASK_MESSAGE    = 16, //pipe message
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
    swArray *buffer_pipe;
    int c_udp_fd;
} swReactorThread;

typedef struct _swWorkerThread
{
	pthread_t ptid; //线程ID
	int pipe_num; //writer thread's pipe num
	int *pipes; //worker pipes
	int c_pipe; //current pipe
	swReactor reactor;
	swShareMemory shm; //共享内存
	swPipe evfd;       //eventfd
} swWorkerThread;

typedef struct
{
    long pti;
    swEventData _send;
} swEventData_overflow;

typedef struct _swListenList_node
{
	struct _swListenList_node *next, *prev;
	uint8_t type;
	uint8_t ssl;
	int port;
	int sock;
	pthread_t thread_id;
	char host[SW_HOST_MAXSIZE];
} swListenList_node;

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

    int (*onTask)(struct _swFactory *, swEventData *task); //worker function.get a task,goto to work
    int (*onFinish)(struct _swFactory *, swSendData *result); //factory worker finish.callback
};

typedef struct _swFactoryProcess
{
    swPipe *pipes;
    int writer_pti; //current writer id
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

int swFactoryProcess_create(swFactory *factory, int writer_num, int worker_num);
int swFactoryProcess_start(swFactory *factory);
int swFactoryProcess_shutdown(swFactory *factory);
int swFactoryProcess_end(swFactory *factory, int fd);

int swFactoryThread_create(swFactory *factory, int writer_num);
int swFactoryThread_start(swFactory *factory);
int swFactoryThread_shutdown(swFactory *factory);
int swFactoryThread_dispatch(swFactory *factory, swDispatchData *buf);
int swFactoryThread_finish(swFactory *factory, swSendData *data);

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
    uint16_t writer_num;
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
     * package dispatch mode
     */
    uint8_t dispatch_mode; //分配模式，1平均分配，2按FD取摸固定分配，3,使用抢占式队列(IPC消息队列)分配

    /**
     * 1: unix socket, 2: message queue, 3: memory channel
     */
    uint8_t ipc_mode;

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
    /**
     * task worker process max request
     */
    uint32_t task_max_request;

    int timeout_sec;
    int timeout_usec;

    int sock_client_buffer_size; //client的socket缓存区设置
    int sock_server_buffer_size; //server的socket缓存区设置

    char log_file[SW_LOG_FILENAME]; //日志文件

    int signal_fd;
    int event_fd;

    int ringbuffer_size;

    /*----------------------------Reactor schedule--------------------------------*/
    uint16_t reactor_round_i; //轮询调度
    uint16_t reactor_next_i; //平均算法调度
    uint16_t reactor_schedule_count;

    uint16_t worker_round_id;

    int udp_sock_buffer_size; //UDP临时包数量，超过数量未处理将会被丢弃

    /**
     * reactor ringbuffer memory pool size
     */
    size_t reactor_ringbuffer_size;

    /**
     * run as a daemon process
     */
    uint16_t daemonize :1;

    /**
     * have udp listen socket
     */
    uint16_t have_udp_sock :1;

    /**
     * have tcp listen socket
     */
    uint16_t have_tcp_sock :1;

    /**
     * oepn cpu affinity setting
     */
    uint16_t open_cpu_affinity :1;

    /**
     * open tcp nodelay option
     */
    uint16_t open_tcp_nodelay :1;

    /**
     * open tcp nopush option(for sendfile)
     */
    uint16_t open_tcp_nopush :1;

    /**
     * open tcp keepalive
     */
    uint16_t open_tcp_keepalive :1;

    /**
     * check data eof
     */
    uint16_t open_eof_check :1;

    /**
     * built-in http protocol
     */
    uint16_t open_http_protocol :1;

    /**
     *  one package: length check
     */
    uint16_t open_length_check :1;

    /**
     * Use data key as factory->dispatch() param.
     */
    uint16_t open_dispatch_key: 1;

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

    /**
     * 来自客户端的心跳侦测包
     */
    char heartbeat_ping[SW_HEARTBEAT_PING_LEN];
    uint8_t heartbeat_ping_length;

    /**
     * 服务器端对心跳包的响应
     */
    char heartbeat_pong[SW_HEARTBEAT_PING_LEN];
    uint8_t heartbeat_pong_length;

    /* one package: eof check */

    uint8_t package_eof_len; //数据缓存结束符长度
    //int data_buffer_max_num;             //数据缓存最大个数(超过此数值的连接会被当作坏连接，将清除缓存&关闭连接)
    //uint8_t max_trunk_num;               //每个请求最大允许创建的trunk数
    char package_eof[SW_DATA_EOF_MAXLEN]; //数据缓存结束符

    uint32_t http_max_post_size;
    uint32_t http_max_websocket_size;

    char package_length_type; //length field type
    uint8_t package_length_size;
    uint16_t package_length_offset; //第几个字节开始表示长度
    uint16_t package_body_offset; //第几个字节开始计算长度
    uint32_t package_max_length;

    uint8_t dispatch_key_size;
    uint16_t dispatch_key_offset;
    uint16_t dispatch_key_type;

    /* buffer output/input setting*/
    uint32_t buffer_output_size;
    uint32_t buffer_input_size;

#ifdef SW_USE_OPENSSL
    uint8_t open_ssl;
    char *ssl_cert_file;
    char *ssl_key_file;
#endif

    void *ptr2;

    swReactor reactor;
    swFactory factory;

    swListenList_node *listen_list;

    swUserWorker_node *user_worker_list;
    swHashMap *user_worker_map;

    swReactorThread *reactor_threads;
    swWorkerThread *writer_threads;

    swWorker *workers;

    swQueue read_queue;
    swQueue write_queue;

    swConnection *connection_list; //连接列表
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
    int (*onReceive)(swFactory *, swEventData *);
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
} swPackage;

typedef struct
{
	int length;
	char tmpfile[sizeof(SW_TASK_TMP_FILE)];
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
int swServer_addListener(swServer *serv, int type, char *host,int port);
int swServer_add_worker(swServer *serv, swWorker *worker);

int swServer_create(swServer *serv);
int swServer_listen(swServer *serv, swReactor *reactor);
int swServer_free(swServer *serv);
int swServer_shutdown(swServer *serv);

int swServer_udp_send(swServer *serv, swSendData *resp);
int swServer_tcp_send(swServer *serv, int fd, void *data, int length);

//UDP, UDP必然超过0x1000000
//原因：IPv4的第4字节最小为1,而这里的conn_fd是网络字节序
#define swSocket_isUDP(fd)          (fd > 0x1000000)

int swServer_reactor_add(swServer *serv, int fd, int sock_type); //no use
int swServer_reactor_del(swServer *serv, int fd, int reacot_id); //no use

swPipe * swServer_pipe_get(swServer *serv, int pipe_fd);
void swServer_pipe_set(swServer *serv, swPipe *p);

int swServer_get_manager_pid(swServer *serv);
int swServer_worker_init(swServer *serv, swWorker *worker);
void swServer_onTimer(swTimer *timer, int interval);

void swTaskWorker_init(swProcessPool *pool);
int swTaskWorker_onTask(swProcessPool *pool, swEventData *task);
int swTaskWorker_onFinish(swReactor *reactor, swEvent *event);
void swTaskWorker_onStart(swProcessPool *pool, int worker_id);
void swTaskWorker_onStop(swProcessPool *pool, int worker_id);
int swTaskWorker_large_pack(swEventData *task, void *data, int data_len);
int swTaskWorker_finish(swServer *serv, char *data, int data_len, int flags);

#define swTask_type(task)                  (task)->info.from_fd

#define swTaskWorker_large_unpack(task, __malloc, _buf, _length)   swPackage_task _pkg;\
	memcpy(&_pkg, task->data, sizeof(_pkg));\
	_length = _pkg.length;\
	_buf = __malloc(_length + 1);\
	_buf[_length] = 0;\
	int tmp_file_fd = open(_pkg.tmpfile, O_RDONLY);\
	if (tmp_file_fd < 0){\
		swWarn("open(%s) failed. Error: %s[%d]", task->data, strerror(errno), errno);\
		_length = -1;\
	} else if (swoole_sync_readfile(tmp_file_fd, _buf, _length) > 0) {\
		unlink(_pkg.tmpfile);\
	} else {\
		_length = -1;\
	}

#define swPackage_data(task) ((task->info.type==SW_EVENT_PACKAGE_END)?SwooleWG.buffer_input[task->info.from_id]->str:task->data)
#define swPackage_length(task) ((task->info.type==SW_EVENT_PACKAGE_END)?SwooleWG.buffer_input[task->info.from_id]->length:task->info.len)

swConnection* swServer_connection_new(swServer *serv, swDataHead *ev);

#define SW_SERVER_MAX_FD_INDEX          0 //max connection socket
#define SW_SERVER_MIN_FD_INDEX          1 //min listen socket
#define SW_SERVER_TIMER_FD_INDEX        2 //for timerfd

//使用connection_list[0]表示最大的FD
#define swServer_set_maxfd(serv,maxfd) (serv->connection_list[SW_SERVER_MAX_FD_INDEX].fd=maxfd)
#define swServer_get_maxfd(serv) (serv->connection_list[SW_SERVER_MAX_FD_INDEX].fd)
#define swServer_connection_get(serv,fd) ((fd>serv->max_connection || fd<=2)?NULL:&serv->connection_list[fd])
//使用connection_list[1]表示最小的FD
#define swServer_set_minfd(serv,maxfd) (serv->connection_list[SW_SERVER_MIN_FD_INDEX].fd=maxfd)
#define swServer_get_minfd(serv) (serv->connection_list[SW_SERVER_MIN_FD_INDEX].fd)

#define swServer_get_thread(serv, reactor_id)    (&(serv->reactor_threads[reactor_id]))

static sw_inline swWorker* swServer_get_worker(swServer *serv, uint16_t worker_id)
{
    int task_num = SwooleG.task_worker_max>0?SwooleG.task_worker_max:SwooleG.task_worker_num;
    if (worker_id > serv->worker_num + task_num)
    {
        swWarn("worker_id is exceed serv->worker_num + SwooleG.task_worker_num");
        return NULL;
    }
    else if (worker_id >= serv->worker_num)
    {
        return &(SwooleG.task_workers.workers[worker_id - serv->worker_num]);
    }
    else
    {
        return &(serv->workers[worker_id]);
    }
}

static sw_inline int swServer_send2worker_blocking(swServer *serv, void *data, int len, uint16_t target_worker_id)
{
    int ret = -1;
    swWorker *worker = &(serv->workers[target_worker_id]);

    if (serv->ipc_mode == SW_IPC_MSGQUEUE)
    {
        swQueue_data *in_data = (swQueue_data *) ((void *) data - sizeof(long));

        //加1,消息队列的type必须不能为0
        in_data->mtype = target_worker_id + 1;
        ret = serv->read_queue.in(&serv->read_queue, in_data, len);
    }
    else
    {
        sendto_unix_sock:
        ret = write(worker->pipe_master, (void *) data, len);
        if (ret < 0)
        {
            if (errno == EINTR)
            {
                goto sendto_unix_sock;
            }
            else if (errno == EAGAIN)
            {
                swSocket_wait(worker->pipe_master, SW_WORKER_WAIT_TIMEOUT, SW_EVENT_WRITE);
            }
        }
    }
    return ret;
}

static sw_inline uint32_t swServer_worker_schedule(swServer *serv, uint32_t schedule_key)
{
    uint32_t target_worker_id = 0;

    //polling mode
    if (serv->dispatch_mode == SW_DISPATCH_ROUND)
    {
        target_worker_id = (serv->worker_round_id++) % serv->worker_num;
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
        else
        {
            target_worker_id = conn->addr.sin_addr.s_addr % serv->worker_num;
        }
    }
    else if (serv->dispatch_mode == SW_DISPATCH_UIDMOD)
    {
        swConnection *conn = swServer_connection_get(serv, schedule_key);
        if(conn->uid) {
            target_worker_id = conn->uid % serv->worker_num;
        }else{
            target_worker_id = schedule_key % serv->worker_num;
        }
    }
    //Preemptive distribution
    else
    {
        if (serv->ipc_mode == SW_IPC_MSGQUEUE)
        {
            //msgsnd参数必须>0
            //worker进程中正确的mtype应该是pti + 1
            target_worker_id = serv->worker_num;
        }
        else
        {
            int i;
            sw_atomic_t *round = &SwooleTG.worker_round_i;
            for (i = 0; i < serv->worker_num; i++)
            {
                sw_atomic_fetch_add(round, 1);
                target_worker_id = (*round) % serv->worker_num;

                if (serv->workers[target_worker_id].status == SW_WORKER_IDLE)
                {
                    break;
                }
            }
            swTrace("schedule=%d|round=%d\n", target_worker_id, *round);
        }
    }
    return target_worker_id;
}

void swServer_worker_onStart(swServer *serv);
void swServer_worker_onStop(swServer *serv);

int swWorker_create(swWorker *worker);
void swWorker_free(swWorker *worker);
void swWorker_signal_init(void);
void swWorker_onStart(swServer *serv);
void swWorker_onStop(swServer *serv);
int swWorker_loop(swFactory *factory, int worker_pti);
int swWorker_send2reactor(swEventData_overflow *sdata, size_t sendn, int fd);
void swWorker_signal_handler(int signo);

int swServer_master_onAccept(swReactor *reactor, swEvent *event);

int swReactorThread_create(swServer *serv);
int swReactorThread_start(swServer *serv, swReactor *main_reactor_ptr);
void swReactorThread_free(swServer *serv);

int swReactorThread_onReceive_no_buffer(swReactor *reactor, swEvent *event);
int swReactorThread_onReceive_buffer_check_length(swReactor *reactor, swEvent *event);
int swReactorThread_onReceive_buffer_check_eof(swReactor *reactor, swEvent *event);
int swReactorThread_onReceive_http_request(swReactor *reactor, swEvent *event);
int swReactorThread_onPackage(swReactor *reactor, swEvent *event);
int swReactorThread_onPipeReceive(swReactor *reactor, swEvent *ev);
int swReactorThread_onWrite(swReactor *reactor, swEvent *ev);

int swReactorThread_send(swSendData *_send);
int swReactorThread_send2worker(void *data, int len, uint16_t target_worker_id);

int swReactorProcess_create(swServer *serv);
int swReactorProcess_start(swServer *serv);
int swReactorProcess_onClose(swReactor *reactor, swEvent *event);

#ifdef __cplusplus
}
#endif

#endif /* SW_SERVER_H_ */
