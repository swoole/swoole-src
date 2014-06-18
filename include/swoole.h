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

#ifndef SWOOLE_H_
#define SWOOLE_H_

#if defined(HAVE_CONFIG_H) && !defined(COMPILE_DL_SWOOLE)
#include "config.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <assert.h>
#include <time.h>
#include <pthread.h>
#include <sched.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/select.h>
#include <sys/mman.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <sys/un.h>

#ifdef __MACH__
#include <mach/clock.h>
#include <mach/mach_time.h>

#define ORWL_NANO (+1.0E-9)
#define ORWL_GIGA UINT64_C(1000000000)

static double orwl_timebase = 0.0;
static uint64_t orwl_timestart = 0;

int clock_gettime(clock_id_t which_clock, struct timespec *t);
#endif

#ifndef HAVE_DAEMON
int daemon(int nochdir, int noclose);
#endif

/*----------------------------------------------------------------------------*/
#ifndef ulong
#define ulong unsigned long
#endif

#if __STDC_VERSION__ >= 199901L || defined(__cplusplus)
#define SWINLINE inline
#elif defined(_MSC_VER) || defined(__GNUC__)
#define SWINLINE __inline
#else
#define SWINLINE
#endif

#ifdef __MACH__
#undef SWINLINE
#define SWINLINE
#endif

#if defined(MAP_ANON) && !defined(MAP_ANONYMOUS)
#define MAP_ANONYMOUS MAP_ANON
#endif

#ifndef SOCK_NONBLOCK
#define SOCK_NONBLOCK O_NONBLOCK
#endif

#ifndef CLOCK_REALTIME
#define CLOCK_REALTIME 0
#endif

#define SW_START_LINE  "-------------------------START----------------------------"
#define SW_END_LINE    "-------------------------END------------------------------"
/*----------------------------------------------------------------------------*/

#include "swoole_config.h"
#include "atomic.h"
#include "hashmap.h"
#include "list.h"
#include "RingQueue.h"

#define SW_TIMEO_SEC           0
#define SW_TIMEO_USEC          3000000

#define SW_MAX_UINT            4294967295

#ifndef MAX
#define MAX(a, b)              (a)>(b)?a:b;
#endif
#ifndef MIN
#define MIN(a, b)              (a)<(b)?a:b;
#endif

#define SW_CPU_NUM             sysconf(_SC_NPROCESSORS_ONLN)

#define SW_STRL(s)             s, sizeof(s)
#define SW_START_SLEEP         usleep(100000)  //sleep 1s,wait fork and pthread_create

#define sw_malloc              malloc
#define sw_free(ptr)           if(ptr){free(ptr);ptr=NULL;}
#define sw_calloc              calloc
#define sw_realloc             realloc

#define METHOD_DEF(class,name,...)  class##_##name(class *object, ##__VA_ARGS__)
#define METHOD(class,name,...)      class##_##name(object, ##__VA_ARGS__)

#define SW_OK                  0
#define SW_ERR                -1

#define SW_TRUE                1
#define SW_FALSE               0

#define SW_FD_TCP              0 //tcp socket
#define SW_FD_LISTEN           1 //server socket
#define SW_FD_CLOSE            2 //socket closed
#define SW_FD_ERROR            3 //socket error
#define SW_FD_UDP              4 //udp socket
#define SW_FD_PIPE             5 //pipe
#define SW_FD_WRITE            7 //fd can write
#define SW_FD_TIMER            8 //timer fd
#define SW_FD_AIO              9 //linux native aio
#define SW_FD_SEND_TO_CLIENT   10 //sendtoclient
#define SW_FD_SIGNAL           11

#define SW_FD_USER             15 //SW_FD_USER or SW_FD_USER+n: for custom event

#define SW_MODE_BASE           1
#define SW_MODE_THREAD         2
#define SW_MODE_PROCESS        3
#define SW_MODE_SINGLE         4  //single thread mode

#define SW_SOCK_TCP            1
#define SW_SOCK_UDP            2
#define SW_SOCK_TCP6           3
#define SW_SOCK_UDP6           4
#define SW_SOCK_UNIX_DGRAM     5  //unix sock dgram
#define SW_SOCK_UNIX_STREAM    6  //unix sock stream

#define SW_LOG_DEBUG           0
#define SW_LOG_INFO            1
#define SW_LOG_WARN            2
#define SW_LOG_ERROR           3
#define SW_LOG_TRACE           4

#define swWarn(str,...)        SwooleG.lock.lock(&SwooleG.lock);\
snprintf(sw_error,SW_ERROR_MSG_SIZE,"%s: "str,__func__,##__VA_ARGS__);\
swLog_put(SW_LOG_WARN, sw_error);\
SwooleG.lock.unlock(&SwooleG.lock)

#define swError(str,...)       SwooleG.lock.lock(&SwooleG.lock);\
snprintf(sw_error, SW_ERROR_MSG_SIZE, str, ##__VA_ARGS__);\
swLog_put(SW_LOG_ERROR, sw_error);\
SwooleG.lock.unlock(&SwooleG.lock);\
exit(1)

#ifdef SW_DEBUG
#define swTrace(str,...)       {printf("[%s:%d@%s]"str"\n",__FILE__,__LINE__,__func__,##__VA_ARGS__);}
//#define swWarn(str,...)        {printf("[%s:%d@%s]"str"\n",__FILE__,__LINE__,__func__,##__VA_ARGS__);}
#else
#define swTrace(str,...)
//#define swWarn(str,...)        {printf(sw_error);}
#endif

enum
{
	SW_TRACE_SERVER = 1,
	SW_TRACE_CLIENT = 2,
	SW_TRACE_BUFFER = 3,
	SW_TRACE_CONN   = 4,
	SW_TRACE_EVENT  = 5,
	SW_TRACE_WORKER = 6,
	SW_TRACE_MEMORY = 7,
};

enum
{
	SW_CONTINUE,
	SW_WAIT,
	SW_CLOSE,
	SW_ERROR,
};

#if SW_LOG_TRACE_OPEN == 1
#define swTraceLog(id,str,...)      SwooleG.lock.lock(&SwooleG.lock);\
snprintf(sw_error,SW_ERROR_MSG_SIZE,"%s: "str,__func__,##__VA_ARGS__);\
swLog_put(SW_LOG_TRACE, sw_error);\
SwooleG.lock.unlock(&SwooleG.lock)
#elif SW_LOG_TRACE_OPEN == 0
#define swTraceLog(id,str,...)
#else
#define swTraceLog(id,str,...)      if (id==SW_LOG_TRACE_OPEN) {SwooleG.lock.lock(&SwooleG.lock);\
snprintf(sw_error,SW_ERROR_MSG_SIZE,"%s: "str,__func__,##__VA_ARGS__);\
swLog_put(SW_LOG_TRACE, sw_error);\
SwooleG.lock.unlock(&SwooleG.lock);}
#endif

#define swYield()              sched_yield() //or usleep(1)
//#define swYield()              usleep(500000)
#define SW_MAX_FDTYPE          32 //32 kinds of event
#define SW_ERROR_MSG_SIZE      512

//------------------Base--------------------
typedef struct _swDataHead
{
	int fd; //文件描述符
	uint16_t len; //长度
	int16_t from_id; //Reactor Id
	uint8_t type; //类型
	uint8_t from_fd; //从哪个ServerFD引发的
} swDataHead;

typedef struct _swEventData
{
	swDataHead info;
	char data[SW_BUFFER_SIZE];
} swEventData;

typedef struct _swSendData
{
	swDataHead info;

	/**
	 * for unix socket
	 */
	char *sun_path;
	uint8_t sun_path_len;

	/**
	 * for big package
	 */
	uint32_t length;

	char *data;
} swSendData;

typedef swDataHead swEvent;

//typedef struct _swEvent
//{
//	uint16_t from_id; //Reactor Id
//	uint8_t type; //类型
//	int fd;
//} swEvent;

typedef struct _swEventClose_queue {
	int events[SW_CLOSE_QLEN];
	int num;
} swCloseQueue;

typedef struct _swEventConnect
{
	int from_id; //Reactor Id
	int conn_fd;
	int serv_fd;
	struct sockaddr_in addr;
	socklen_t addrlen;
} swEventConnect;

typedef void * (*swThreadStartFunc)(void *);
typedef int (*swHandle)(swEventData *buf);
typedef void (*swSignalFunc)(int);
typedef void* (*swCallback)(void *);
typedef struct swReactor_s swReactor;
typedef int (*swReactor_handle)(swReactor *reactor, swDataHead *event);

//------------------Pipe--------------------
typedef struct _swPipe
{
	void *object;
	int blocking;
	double timeout;

	int (*read)(struct _swPipe *, void *recv, int length);
	int (*write)(struct _swPipe *, void *send, int length);
	int (*getFd)(struct _swPipe *, int isWriteFd);
	int (*close)(struct _swPipe *);
} swPipe;

int swPipeBase_create(swPipe *p, int blocking);
int swPipeEventfd_create(swPipe *p, int blocking, int semaphore, int timeout);
int swPipeUnsock_create(swPipe *p, int blocking, int protocol);
int swPipeNotify_auto(swPipe *p, int blocking, int semaphore);
void swBreakPoint(void);

//------------------Queue--------------------
typedef struct _swQueue_Data
{
	long mtype;		             /* type of received/sent message */
	char mdata[sizeof(swEventData)];  /* text of the message */
} swQueue_data;

typedef struct _swQueue
{
	void *object;
	int blocking;
	int (*in)(struct _swQueue *, swQueue_data *in, int data_length);
	int (*out)(struct _swQueue *, swQueue_data *out, int buffer_length);
	void (*free)(struct _swQueue *);
	int (*notify)(struct _swQueue *);
	int (*wait)(struct _swQueue *);
} swQueue;

int swQueueMsg_create(swQueue *p, int wait, int msg_key, long type);

//------------------Lock--------------------------------------

enum SW_LOCKS
{
	SW_RWLOCK = 1,
#define SW_RWLOCK SW_RWLOCK
	SW_FILELOCK = 2,
#define SW_FILELOCK SW_FILELOCK
	SW_MUTEX = 3,
#define SW_MUTEX SW_MUTEX
	SW_SEM = 4,
#define SW_SEM SW_SEM
	SW_SPINLOCK = 5,
#define SW_SPINLOCK SW_SPINLOCK
	SW_ATOMLOCK = 6,
#define SW_ATOMLOCK SW_ATOMLOCK
};

typedef struct _swLock swLock;

//文件锁
typedef struct _swFileLock
{
	struct flock lock_t;
	int fd;
} swFileLock;

//互斥锁
typedef struct _swMutex
{
	pthread_mutex_t _lock;
	pthread_mutexattr_t attr;
} swMutex;

//读写锁
typedef struct _swRWLock
{
	pthread_rwlock_t _lock;
	pthread_rwlockattr_t attr;

} swRWLock;

//自旋锁
#ifdef HAVE_SPINLOCK
typedef struct _swSpinLock
{
	pthread_spinlock_t lock_t;
} swSpinLock;
#endif

//原子锁Lock-Free
typedef struct _swAtomicLock
{
	atomic_t lock_t;
	uint32_t spin;
} swAtomicLock;

//信号量
typedef struct _swSem
{
	key_t key;
	int semid;
	int lock_num;
} swSem;

struct _swLock
{
	int type;
	union
	{
		swMutex mutex;
		swRWLock rwlock;
		swFileLock filelock;
		swSem sem;
		swAtomicLock atomlock;
#ifdef HAVE_SPINLOCK
		swSpinLock spinlock;
#endif
	} object;
	int (*lock_rd)(struct _swLock *lock);
	int (*lock)(struct _swLock *lock);
	int (*unlock)(struct _swLock *lock);
	int (*trylock_rd)(struct _swLock *lock);
	int (*trylock)(struct _swLock *lock);
	int (*free)(struct _swLock *lock);
};

//Cond
typedef struct _swCond
{
	swLock lock;
	pthread_cond_t cond;

	int (*wait)(struct _swCond *object);
	int (*timewait)(struct _swCond *object,long,long);
	int (*notify)(struct _swCond *object);
	int (*broadcast)(struct _swCond *object);
} swCond;


#define SW_SHM_MMAP_FILE_LEN  64
typedef struct _swShareMemory_mmap
{
	int size;
	char mapfile[SW_SHM_MMAP_FILE_LEN];
	int tmpfd;
	int key;
	int shmid;
	void *mem;
} swShareMemory;

void *swShareMemory_mmap_create(swShareMemory *object, int size, char *mapfile);
void *swShareMemory_sysv_create(swShareMemory *object, int size, int key);
int swShareMemory_sysv_free(swShareMemory *object, int rm);
int swShareMemory_mmap_free(swShareMemory *object);

//-------------------memory manager-------------------------
typedef struct _swString {
	uint32_t length;
	uint32_t size;
	char *str;
} swString;

#define swoole_tolower(c)      (u_char) ((c >= 'A' && c <= 'Z') ? (c | 0x20) : c)
#define swoole_toupper(c)      (u_char) ((c >= 'a' && c <= 'z') ? (c & ~0x20) : c)

size_t swoole_utf8_length(u_char *p, size_t n);
size_t swoole_utf8_length(u_char *p, size_t n);

swString *swString_new(size_t size);
void swString_free(swString *str);
int swString_append(swString *str, swString *append_str);
int swString_extend(swString *str, size_t new_size);

#define swString_length(s) (s->length)
#define swString_ptr(s) (s->str)

typedef struct _swMemoryPool
{
	void *object;
	void* (*alloc)(struct _swMemoryPool *pool, uint32_t size);
	void (*free)(struct _swMemoryPool *pool, void *ptr);
	void (*destroy)(struct _swMemoryPool *pool);
} swMemoryPool;

/**
 * FixedPool, random alloc/free fixed size memory
 */
swMemoryPool * swFixedPool_new(uint32_t size, uint32_t trunk_size, uint8_t shared);

/**
 * RingBuffer, In order for malloc / free
 */
swMemoryPool *swRingBuffer_new(size_t size, uint8_t shared);

/**
 * Global memory, the program life cycle only malloc / free one time
 */
swMemoryPool* swMemoryGlobal_new(int pagesize, char shared);

void swFixedPool_debug(swMemoryPool *pool);

/**
 * alloc shared memory
 */
void* sw_shm_malloc(size_t size);
void sw_shm_free(void *ptr);
void* sw_shm_calloc(size_t num, size_t _size);
void* sw_shm_realloc(void *ptr, size_t new_size);

int swRWLock_create(swLock *lock, int use_in_process);
int swSem_create(swLock *lock, key_t key, int n);
int swMutex_create(swLock *lock, int use_in_process);
int swFileLock_create(swLock *lock, int fd);
#ifdef HAVE_SPINLOCK
int swSpinLock_create(swLock *object, int spin);
#endif
int swAtomicLock_create(swLock *object, int spin);
SWINLINE int swAtomicLock_lock(swLock *lock);
SWINLINE int swAtomicLock_unlock(swLock *lock);
SWINLINE int swAtomicLock_trylock(swLock *lock);

int swCond_create(swCond *cond);
int swCond_notify(swCond *cond);
int swCond_broadcast(swCond *cond);
int swCond_timewait(swCond *cond, long sec, long nsec);
int swCond_wait(swCond *cond);
void swCond_free(swCond *cond);

typedef struct _swThreadParam
{
	void *object;
	int pti;
} swThreadParam;

extern int16_t sw_errno;
extern char sw_error[SW_ERROR_MSG_SIZE];

#define SW_PROCESS_MASTER      1
#define SW_PROCESS_WORKER      2
#define SW_PROCESS_MANAGER     3

#define swIsMaster()          (SwooleG.process_type==SW_PROCESS_MASTER)
#define swIsWorker()          (SwooleG.process_type==SW_PROCESS_WORKER)
#define swIsManager()         (SwooleG.process_type==SW_PROCESS_MANAGER)

//----------------------tool function---------------------
int swLog_init(char *logfile);
void swLog_put(int level, char *cnt);
void swLog_free(void);
#define sw_log(str,...)       {snprintf(sw_error,SW_ERROR_MSG_SIZE,str,##__VA_ARGS__);swLog_put(SW_LOG_INFO, sw_error);}

uint64_t swoole_hash_key(char *str, int str_len);
uint32_t swoole_common_multiple(uint32_t u, uint32_t v);
uint32_t swoole_common_divisor(uint32_t u, uint32_t v);
SWINLINE uint32_t swoole_unpack(char type, void *data);
void swoole_dump_bin(char *data, char type, int size);
int swoole_type_size(char type);
int swoole_mkdir_recursive(const char *dir);
char* swoole_dirname(char *file);
void swoole_dump_ascii(char *data, int size);
int swoole_sync_writefile(int fd, void *data, int len);
int swoole_sync_readfile(int fd, void *buf, int len);

//----------------------core function---------------------
SWINLINE int swSetTimeout(int sock, double timeout);
SWINLINE int swRead(int, void *, int);
SWINLINE int swWrite(int, void *, int);
SWINLINE int swAccept(int server_socket, struct sockaddr_in *addr, int addr_len);
SWINLINE void swSetNonBlock(int);
SWINLINE void swSetBlock(int);

void swoole_init(void);
void swoole_clean(void);
int swSocket_listen(int type, char *host, int port, int backlog);
SWINLINE int swSocket_create(int type);
SWINLINE int swSendto(int fd, void *__buf, size_t __n, int flag, struct sockaddr *__addr, socklen_t __addr_len);
SWINLINE void swFloat2timeval(float timeout, long int *sec, long int *usec);
swSignalFunc swSignal_set(int sig, swSignalFunc func, int restart, int mask);
void swSignal_add(int signo, swSignalFunc func);
void swSignal_none(void);

//------------------Factory--------------------
typedef struct _swFactory
{
	void *object;
	int max_request; //worker max request
	void *ptr; //server object
	int last_from_id;

	swReactor *reactor; //reserve for reactor

	int (*start)(struct _swFactory *);
	int (*shutdown)(struct _swFactory *);
	int (*dispatch)(struct _swFactory *, swEventData *);
	int (*finish)(struct _swFactory *, swSendData *);
	int (*notify)(struct _swFactory *, swEvent *);    //send a event notify
	int (*end)(struct _swFactory *, swDataHead *);

	int (*onTask)(struct _swFactory *, swEventData *task); //worker function.get a task,goto to work
	int (*onFinish)(struct _swFactory *, swSendData *result); //factory worker finish.callback
} swFactory;

struct swReactor_s
{
	void *object;
	void *ptr; //reserve
	uint32_t event_num;
	uint32_t max_event_num;
	uint16_t id; //Reactor ID
	uint16_t flag; //flag
	char running;

	swReactor_handle handle[SW_MAX_FDTYPE];       //默认事件
	swReactor_handle write_handle[SW_MAX_FDTYPE]; //扩展事件1(一般为写事件)
	swReactor_handle error_handle[SW_MAX_FDTYPE]; //扩展事件2(一般为错误事件,如socket关闭)

	swFactory *factory;

	int (*add)(swReactor *, int fd, int fdtype);
	int (*set)(swReactor *, int fd, int fdtype);
	int (*del)(swReactor *, int fd);
	int (*wait)(swReactor *, struct timeval *);
	void (*free)(swReactor *);
	int (*setHandle)(swReactor *, int fdtype, swReactor_handle);

	void (*onTimeout)(swReactor *); //发生超时时
	void (*onFinish)(swReactor *);  //完成一次轮询
};

typedef struct _swWorker swWorker;
typedef struct _swThread swThread;
typedef struct _swProcessPool swProcessPool;

struct _swWorker
{
	/**
	 * worker process
	 */
	pid_t pid;

	/**
	 * worker thread
	 */
	pthread_t tid;

	swProcessPool *pool;

	/**
	 * redirect stdout to pipe_master
	 */
	uint8_t redirect_stdout;

	/**
	 * redirect stdin to pipe_worker
	 */
	uint8_t redirect_stdin;

	/**
	 * worker id
	 */
	uint32_t id;

	/**
	 * eventfd, process notify
	 */
	swPipe *notify;

	/**
	 * share memory store
	 */
	struct
	{
		volatile uint8_t lock;
		void *ptr;
	} store;

	int pipe_master;
	int pipe_worker;
	int pipe;
	int reactor_id;
	void *ptr;
	void *ptr2;
};

struct _swProcessPool
{
	/**
	 * reloading
	 */
	uint8_t reloading;
	uint8_t reload_flag;
	/**
	 * use message queue IPC
	 */
	uint8_t use_msgqueue;
	/**
	 * message queue key
	 */
	key_t msgqueue_key;

	int worker_num;
	int max_request;

	int (*onTask)(struct _swProcessPool *pool, swEventData *task);
	void (*onWorkerStart)(struct _swProcessPool *pool, int worker_id);

	int (*main_loop)(struct _swProcessPool *pool, swWorker *worker);

	int round_id;

	swWorker *workers;
	swPipe *pipes;
	swHashMap map;
	swQueue queue;

	void *ptr;
	void *ptr2;
};

typedef struct _swFactoryProcess
{
	swWorker *workers;

	swPipe *pipes;
	swQueue rd_queue;
	swQueue wt_queue;

	//worker的忙闲状态
	//这里直接使用char来保存了，位运算速度会快，但需要前置计算
	char *workers_status;

	int writer_pti; //current writer id
	int worker_pti; //current worker id
} swFactoryProcess;

int swFactory_create(swFactory *factory);
int swFactory_start(swFactory *factory);
int swFactory_shutdown(swFactory *factory);
int swFactory_dispatch(swFactory *factory, swEventData *req);
int swFactory_finish(swFactory *factory, swSendData *_send);
int swFactory_notify(swFactory *factory, swEvent *event);
int swFactory_end(swFactory *factory, swDataHead *cev);
int swFactory_check_callback(swFactory *factory);

int swFactoryProcess_create(swFactory *factory, int writer_num, int worker_num);
int swFactoryProcess_start(swFactory *factory);
int swFactoryProcess_shutdown(swFactory *factory);
int swFactoryProcess_end(swFactory *factory, swDataHead *event);
int swFactoryProcess_worker_excute(swFactory *factory, swEventData *task);
int swFactoryProcess_send2worker(swFactory *factory, swEventData *data, int worker_id);

int swFactoryThread_create(swFactory *factory, int writer_num);
int swFactoryThread_start(swFactory *factory);
int swFactoryThread_shutdown(swFactory *factory);
int swFactoryThread_dispatch(swFactory *factory, swEventData *buf);
int swFactoryThread_finish(swFactory *factory, swSendData *data);

//------------------Reactor--------------------
enum SW_EVENTS
{
	SW_EVENT_DEAULT = 256,
	SW_EVENT_READ = 1u << 9,
	SW_EVENT_WRITE = 1u << 10,
	SW_EVENT_ERROR = 1u << 11,
};

SWINLINE int swReactor_error(swReactor *reactor);
SWINLINE int swReactor_fdtype(int fdtype);
SWINLINE int swReactor_event_read(int fdtype);
SWINLINE int swReactor_event_write(int fdtype);
SWINLINE int swReactor_event_error(int fdtype);
int swReactor_receive(swReactor *reactor, swEvent *event);
int swReactor_setHandle(swReactor *, int, swReactor_handle);
int swReactor_auto(swReactor *reactor, int max_event);
swReactor_handle swReactor_getHandle(swReactor *reactor, int event_type, int fdtype);
int swReactorEpoll_create(swReactor *reactor, int max_event_num);
int swReactorPoll_create(swReactor *reactor, int max_event_num);
int swReactorKqueue_create(swReactor *reactor, int max_event_num);
int swReactorSelect_create(swReactor *reactor);

/*----------------------------Process Pool-------------------------------*/
int swProcessPool_create(swProcessPool *pool, int worker_num, int max_request, key_t msgqueue_key);
int swProcessPool_wait(swProcessPool *pool);
int swProcessPool_start(swProcessPool *pool);
void swProcessPool_shutdown(swProcessPool *pool);
pid_t swProcessPool_spawn(swWorker *worker);
int swProcessPool_dispatch(swProcessPool *pool, swEventData *data, int worker_id);
int swProcessPool_add_worker(swProcessPool *pool, swWorker *worker);

#define swProcessPool_worker(ma,id) (ma->workers[id])

//-----------------------------Channel---------------------------
enum SW_CHANNEL_FLAGS
{
	SW_CHAN_LOCK = 1u << 1,
#define SW_CHAN_LOCK SW_CHAN_LOCK
	SW_CHAN_NOTIFY = 1u << 2,
#define SW_CHAN_NOTIFY SW_CHAN_NOTIFY
	SW_CHAN_SHM = 1u << 3,
#define SW_CHAN_SHM SW_CHAN_SHM
};
typedef struct _swChannel
{
	int head;    //头部，出队列方向
	int tail;    //尾部，入队列方向
	int size;    //队列总尺寸
	char head_tag;
	char tail_tag;
	int num;
	int flag;
	int maxlen;
	void *mem;   //内存块
	swLock lock;
	swPipe notify_fd;
} swChannel;

swChannel* swChannel_new(int size, int maxlen, int flag);
int swChannel_pop(swChannel *object, void *out, int buffer_length);
int swChannel_push(swChannel *object, void *in, int data_length);
int swChannel_out(swChannel *object, void *out, int buffer_length);
int swChannel_in(swChannel *object, void *in, int data_length);
int swChannel_wait(swChannel *object);
int swChannel_notify(swChannel *object);
void swChannel_free(swChannel *object);

/*----------------------------Thread Pool-------------------------------*/
typedef struct _swThreadPool
{
	pthread_mutex_t mutex;
	pthread_cond_t cond;

	swThread *threads;
	swThreadParam *params;

#ifdef SW_THREADPOOL_USE_CHANNEL
	swChannel *chan;
#else
	swRingQueue queue;
#endif

	int thread_num;
	int shutdown;
	int task_num;

	int (*onTask)(struct _swThreadPool *pool, void *task, int task_len);

} swThreadPool;

struct _swThread
{
	pthread_t tid;
	int id;
	swThreadPool *pool;
};

int swThreadPool_dispatch(swThreadPool *pool, void *task, int task_len);
int swThreadPool_create(swThreadPool *pool, int max_num);
int swThreadPool_run(swThreadPool *pool);
int swThreadPool_free(swThreadPool *pool);

//-----------------------------------------------
typedef struct _swTimer_node
{
	struct _swTimerList_node *next, *prev;
	uint64_t lasttime;
	int interval;
} swTimer_node;

typedef struct _swTimer
{
	swHashMap list;
	int num;
	int interval;
	int use_pipe;
	int lasttime;
	int fd;
	swPipe pipe;
	void (*onTimer)(struct _swTimer *timer, int interval);
} swTimer;

int swTimer_create(swTimer *timer, int interval_ms, int no_pipe);
void swTimer_del(swTimer *timer, int ms);
int swTimer_free(swTimer *timer);
int swTimer_add(swTimer *timer, int ms);
void swTimer_signal_handler(int sig);
int swTimer_event_handler(swReactor *reactor, swEvent *event);
int swTimer_select(swTimer *timer);
SWINLINE uint64_t swTimer_get_ms();

typedef struct _swModule
{
	char *name;
	void (*test)(void);
	int (*shutdown)(struct _swModule*);

} swModule;

int swModule_load(char *so_file);

typedef struct swServer_s swServer;

typedef struct
{
	swTimer timer;
	int no_timerfd;
	int running;
	int error;
	int process_type;
	int signal_alarm; //for timer with message queue
	int signal_fd;
	int log_fd;

	uint8_t use_timerfd;
	uint8_t use_signalfd;
	uint8_t task_ipc_mode;

	/**
	 *  task worker process num
	 */
	uint16_t task_worker_num;

	/**
	 * Unix socket default buffer size
	 */
	uint32_t unixsock_buffer_size;


	swServer *serv;
	swFactory *factory;
	swLock lock;

	swProcessPool task_workers;
	swProcessPool *event_workers;

	swMemoryPool *memory_pool;
	swReactor *main_reactor;
	//swPipe *task_notify; //for taskwait
	//swEventData *task_result; //for taskwait
	pthread_t heartbeat_pidt;
} swServerG;

//Share Memory
typedef struct
{
	pid_t master_pid;
	pid_t manager_pid;
	uint8_t start; //after swServer_start will set start=1
	time_t now;
} swServerGS;

//Worker process global Variable
typedef struct
{
	/**
	 * Always run
	 */
	uint8_t run_always;

	/**
	 * Current Proccess Worker's id
	 */
	int id;

	swString **buffer_input;

} swWorkerG;

typedef struct
{
	volatile uint8_t factory_lock_target;
	volatile int16_t factory_target_worker;
	atomic_uint_t worker_round_i;
} swThreadG;

extern swServerG SwooleG;    //Local Global Variable
extern swServerGS *SwooleGS; //Share Memory Global Variable
extern swWorkerG SwooleWG;   //Worker Global Variable
extern __thread swThreadG SwooleTG;   //Thread Global Variable

//-----------------------------------------------
//OS Feature
#ifdef HAVE_SIGNALFD
void swSignalfd_init();
void swSignalfd_add(int signo, __sighandler_t callback);
int swSignalfd_setup(swReactor *reactor);
#endif

#ifdef HAVE_KQUEUE
int swoole_sendfile(int out_fd, int in_fd, off_t *offset, size_t size);
#else
#include <sys/sendfile.h>
#define swoole_sendfile(out_fd, in_fd, offset, limit)    sendfile(out_fd, in_fd, offset, limit)
#endif

#ifdef __cplusplus
}
#endif

#endif /* SWOOLE_H_ */
