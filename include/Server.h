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

#ifdef __cplusplus
extern "C" {
#endif

#define SW_REACTOR_NUM           SW_CPU_NUM
#define SW_WRITER_NUM            SW_CPU_NUM
#define SW_PIPES_NUM             (SW_WORKER_NUM/SW_WRITER_NUM + 1) //每个写线程pipes数组大小
#define SW_WORKER_NUM            (SW_CPU_NUM*2)

#define SW_DISPATCH_ROUND        1
#define SW_DISPATCH_FDMOD        2
#define SW_DISPATCH_QUEUE        3

#define SW_WORKER_BUSY           1
#define SW_WORKER_IDLE           0

#define SW_BACKLOG                 512

#define SW_TCP_KEEPCOUNT           5
#define SW_TCP_KEEPIDLE            3600 //1小时
#define SW_TCP_KEEPINTERVAL        60

#define SW_HEARTBEAT_IDLE          0   //心跳存活最大时间
#define SW_HEARTBEAT_CHECK         0   //心跳定时侦测时间

#define SW_TASK_BLOCKING           1
#define SW_TASK_NONBLOCK           0

#define SW_EVENT_TCP               0
#define SW_EVENT_UDP               1
#define SW_EVENT_CLOSE             5
#define SW_EVENT_CONNECT           6
#define SW_EVENT_TIMER             7
#define SW_EVENT_FINISH            8
#define SW_EVENT_PACKAGE_START     9
#define SW_EVENT_PACKAGE_TRUNK     10
#define SW_EVENT_PACKAGE_END       11
#define SW_EVENT_SENDFILE          12

#define SW_TRUNK_DATA              0 //send data
#define SW_TRUNK_SENDFILE          1 //send file

#define SW_STATUS_EMPTY            0
#define SW_STATUS_ACTIVE           1
#define SW_STATUS_CLOSED           2

#define SW_HOST_MAXSIZE            48
#define SW_MAX_TMP_PKG             1000
#define SW_LOG_FILENAME            128

#define SW_NUM_SHORT               (1u << 1)
#define SW_NUM_INT                 (1u << 2)
#define SW_NUM_NET                 (1u << 3)
#define SW_NUM_HOST                (1u << 4)
#define SW_NUM_UNSIGN              (1u << 5)
#define SW_NUM_SIGN                (1u << 6)

typedef struct _swUdpFd{
	struct sockaddr addr;
	int sock;
} swUdpFd;

typedef struct _swThreadPoll
{
	pthread_t ptid; //线程ID
	swReactor reactor;
	swUdpFd *udp_addrs;
	swCloseQueue close_queue;
	int c_udp_fd;
} swThreadPoll;

typedef struct _swListenList_node
{
	struct _swListenList_node *next, *prev;
	int type;
	int port;
	int sock;
	char host[SW_HOST_MAXSIZE];
} swListenList_node;

typedef struct {
	char *filename;
	uint16_t name_len;
	int fd;
	off_t filesize;
	off_t offset;
} swTask_sendfile;

typedef struct _swConnection {
	uint8_t active;     //0表示非活动,1表示活动
	int fd;             //文件描述符
	uint16_t from_id;   //Reactor Id
	uint16_t from_fd;   //从哪个ServerFD引发的
	struct sockaddr_in addr; //socket的地址

	swString *string_buffer;    //缓存区

	swBuffer *in_buffer;
	swBuffer *out_buffer;

	time_t connect_time; //连接时间戳
	time_t last_time;	 //最近一次收到数据的时间
} swConnection;

struct swServer_s
{
	uint16_t backlog;
	uint16_t reactor_num;
	uint16_t writer_num;
	uint16_t worker_num;
	uint16_t task_worker_num;
	uint16_t reactor_pipe_num; //每个reactor维持的pipe数量

	uint8_t factory_mode;
	uint8_t daemonize;
	uint8_t dispatch_mode; //分配模式，1平均分配，2按FD取摸固定分配，3,使用抢占式队列(IPC消息队列)分配

	int worker_uid;
	int worker_groupid;
	int max_conn;

	int connect_count; //连接计数
	int max_request;
	int timeout_sec;
	int timeout_usec;

	int sock_client_buffer_size;    //client的socket缓存区设置
	int sock_server_buffer_size;    //server的socket缓存区设置

	char log_file[SW_LOG_FILENAME];      //日志文件

	int signal_fd;
	int event_fd;

	int ringbuffer_size;

	/*----------------------------Reactor schedule--------------------------------*/
	uint16_t reactor_round_i;   //轮询调度
	uint16_t reactor_next_i;    //平均算法调度
	uint16_t reactor_schedule_count;

	int udp_sock_buffer_size; //UDP临时包数量，超过数量未处理将会被丢弃

	uint8_t have_udp_sock;      //是否有UDP监听端口
	uint8_t have_tcp_sock;      //是否有TCP监听端口

	uint8_t open_cpu_affinity; //是否设置CPU亲和性
	uint8_t open_tcp_nodelay;  //是否关闭Nagle算法


	/* tcp keepalive */
	uint8_t open_tcp_keepalive; //开启keepalive
	uint16_t tcp_keepidle;      //如该连接在规定时间内没有任何数据往来,则进行探测
	uint16_t tcp_keepinterval;  //探测时发包的时间间隔
	uint16_t tcp_keepcount;     //探测尝试的次数

	/* heartbeat check time*/
	uint16_t heartbeat_idle_time;			//心跳存活时间
	uint16_t heartbeat_check_interval;		//心跳定时侦测时间, 必需小于heartbeat_idle_time

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
	uint8_t open_eof_check;    //检测数据EOF
	uint8_t package_eof_len;                //数据缓存结束符长度
	//int data_buffer_max_num;             //数据缓存最大个数(超过此数值的连接会被当作坏连接，将清除缓存&关闭连接)
	//uint8_t max_trunk_num;               //每个请求最大允许创建的trunk数
	char package_eof[SW_DATA_EOF_MAXLEN];   //数据缓存结束符

	/* one package: length check */
	uint8_t open_length_check;    //开启协议长度检测

	uint16_t package_length_type;  //length field type
	int package_length_offset;    //第几个字节开始表示长度
	int package_body_start ;      //第几个字节开始计算长度

	/* buffer output/input setting*/
	uint32_t buffer_output_size;
	uint32_t buffer_input_size;

	void *ptr2;

	swPipe main_pipe;
	swReactor reactor;
	swFactory factory;
	swThreadPoll *reactor_threads; //TCP监听线程
	swWorker *workers;
	swListenList_node *listen_list;

	swConnection *connection_list; //连接列表
	int connection_list_capacity;  //超过此容量，会自动扩容

	swReactor *reactor_ptr; //Main Reactor
	swFactory *factory_ptr; //Factory

	void (*onStart)(swServer *serv);
	int (*onReceive)(swFactory *factory, swEventData *data);
	void (*onClose)(swServer *serv, int fd, int from_id);
	void (*onConnect)(swServer *serv, int fd, int from_id);
	void (*onMasterClose)(swServer *serv, int fd, int from_id);
	void (*onMasterConnect)(swServer *serv, int fd, int from_id);
	void (*onShutdown)(swServer *serv);
	void (*onTimer)(swServer *serv, int interval);
	void (*onWorkerStart)(swServer *serv, int worker_id); //Only process mode
	void (*onWorkerStop)(swServer *serv, int worker_id);  //Only process mode
	void (*onWorkerError)(swServer *serv, int worker_id, pid_t worker_pid, int exit_code);   //Only process mode
	int (*onTask)(swServer *serv, swEventData *data);
	int (*onFinish)(swServer *serv, swEventData *data);
};

int swServer_onFinish(swFactory *factory, swSendData *resp);
int swServer_onFinish2(swFactory *factory, swSendData *resp);

void swServer_init(swServer *serv);
int swServer_start(swServer *serv);
int swServer_addListen(swServer *serv, int type, char *host,int port);
int swServer_create(swServer *serv);
int swServer_free(swServer *serv);
int swServer_close(swServer *factory, swDataHead *event);
int swServer_process_close(swServer *serv, swDataHead *event);
int swServer_shutdown(swServer *serv);
int swServer_addTimer(swServer *serv, int interval);
int swServer_reload(swServer *serv);
int swServer_send_udp_packet(swServer *serv, swSendData *resp);
int swServer_reactor_add(swServer *serv, int fd, int sock_type); //no use
int swServer_reactor_del(swServer *serv, int fd, int reacot_id); //no use
int swServer_get_manager_pid(swServer *serv);

int swTaskWorker_onTask(swProcessPool *pool, swEventData *task);
void swTaskWorker_onWorkerStart(swProcessPool *pool, int worker_id);

#define swPackage_data(task) ((task->info.type==SW_EVENT_PACKAGE_END)?SwooleWG.buffer_input[task->info.from_id]->str:task->data)
#define swPackage_length(task) ((task->info.type==SW_EVENT_PACKAGE_END)?SwooleWG.buffer_input[task->info.from_id]->length:task->info.len)

SWINLINE int swServer_new_connection(swServer *serv, swEvent *ev);
SWINLINE void swConnection_close(swServer *serv, int fd, int notify);
SWINLINE int swConnection_error(swConnection *conn, int err);

#define SW_SERVER_MAX_FD_INDEX        0
#define SW_SERVER_MIN_FD_INDEX        1

//使用connection_list[0]表示最大的FD
#define swServer_set_maxfd(serv,maxfd) (serv->connection_list[SW_SERVER_MAX_FD_INDEX].fd=maxfd)
#define swServer_get_maxfd(serv) (serv->connection_list[SW_SERVER_MAX_FD_INDEX].fd)
#define swServer_get_connection(serv,fd) ((fd>serv->max_conn|| fd<= 2)?NULL:&serv->connection_list[fd])
//使用connection_list[1]表示最小的FD
#define swServer_set_minfd(serv,maxfd) (serv->connection_list[SW_SERVER_MIN_FD_INDEX].fd=maxfd)
#define swServer_get_minfd(serv) (serv->connection_list[SW_SERVER_MIN_FD_INDEX].fd)
SWINLINE swString* swConnection_get_string_buffer(swConnection *conn);
SWINLINE void swConnection_clear_string_buffer(swConnection *conn);
SWINLINE swBuffer_trunk* swConnection_get_out_buffer(swConnection *conn, uint32_t type);

int swReactorThread_onClose(swReactor *reactor, swEvent *event);
int swReactorThread_onWrite(swReactor *reactor, swDataHead *ev);
int swReactorThread_send(swEventData *resp);
void swReactorThread_onTimeout(swReactor *reactor);
void swReactorThread_onFinish(swReactor *reactor);
int swReactorThread_close_queue(swReactor *reactor, swCloseQueue *close_queue);
int swReactorThread_onReceive_no_buffer(swReactor *reactor, swEvent *event);
int swReactorThread_onReceive_buffer_check_length(swReactor *reactor, swEvent *event);
int swReactorThread_onReceive_buffer_check_eof(swReactor *reactor, swEvent *event);

#ifdef __cplusplus
}
#endif

#endif /* SW_SERVER_H_ */
