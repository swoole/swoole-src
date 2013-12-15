/**
 *  swoole.h
 *  Created on: 2012-6-16
 *  Author: tianfeng.han
 */
#ifndef SWOOLE_H_
#define SWOOLE_H_

//坑爹的PHP编译器，这里要包含下PHP生成的config.h文件
#if defined(HAVE_CONFIG_H) && !defined(COMPILE_DL_SWOOLE)
#include "config.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <assert.h>

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifndef __USE_GNU
#define __USE_GNU
#endif

#include <sched.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/select.h>
#include <sys/mman.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <pthread.h>

#ifdef HAVE_TIMERFD
#include <sys/timerfd.h>
#endif

#ifdef __MACH__
#include <mach/clock.h>
#include <mach/mach_time.h>

#define ORWL_NANO (+1.0E-9)
#define ORWL_GIGA UINT64_C(1000000000)

static double orwl_timebase = 0.0;
static uint64_t orwl_timestart = 0;

int clock_gettime(clock_id_t which_clock, struct timespec *t);
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
#define sw_free(s)             free(s)
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

#define SW_FD_USER             15 //SW_FD_USER or SW_FD_USER+n: for custom event

#define SW_MODE_BASE           1
#define SW_MODE_THREAD         2
#define SW_MODE_PROCESS        3
#define SW_MODE_SINGLE         4  //single thread mode

#define SW_SOCK_TCP            1
#define SW_SOCK_UDP            2
#define SW_SOCK_TCP6           3
#define SW_SOCK_UDP6           4

#define SW_DISPATCH_ROUND      1
#define SW_DISPATCH_FDMOD      2
#define SW_DISPATCH_QUEUE      3

#define SW_LOG_DEBUG           0
#define SW_LOG_INFO            1
#define SW_LOG_WARN            2
#define SW_LOG_ERROR           3

#ifdef SW_LOG_NO_SRCINFO
#define swWarn(str,...)       snprintf(sw_error,SW_ERROR_MSG_SIZE,"%s: "str,__func__,##__VA_ARGS__);swLog_put(SW_LOG_WARN, sw_error)
#define swError(str,...)       snprintf(sw_error,SW_ERROR_MSG_SIZE,str,##__VA_ARGS__);swLog_put(SW_LOG_ERROR, sw_error);exit(1)
#else
#define swWarn(str,...)       {snprintf(sw_error,SW_ERROR_MSG_SIZE,"[%s:%d@%s]"str,__FILE__,__LINE__,__func__,##__VA_ARGS__);swLog_put(SW_LOG_WARN, sw_error);}
#define swError(str,...)       {snprintf(sw_error,SW_ERROR_MSG_SIZE,"[%s:%d@%s]"str,__FILE__,__LINE__,__func__,##__VA_ARGS__);swLog_put(SW_LOG_ERROR, sw_error);exit(1);}
#endif

#ifdef SW_DEBUG
#define swTrace(str,...)       {printf("[%s:%d@%s]"str"\n",__FILE__,__LINE__,__func__,##__VA_ARGS__);}
//#define swWarn(str,...)        {printf("[%s:%d@%s]"str"\n",__FILE__,__LINE__,__func__,##__VA_ARGS__);}
#else
#define swTrace(str,...)
//#define swWarn(str,...)        {printf(sw_error);}
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
	char *data;
} swSendData;

typedef swDataHead swEvent;

//typedef struct _swEvent
//{
//	uint16_t from_id; //Reactor Id
//	uint8_t type; //类型
//	int fd;
//} swEvent;

typedef struct _swEventClose
{
	int from_id; //Reactor Id
	int fd;
} swEventClose;

typedef struct _swEventClose_queue {
	swEventClose events[SW_CLOSE_QLEN];
	int num;
	char open;
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
	int (*read)(struct _swPipe *, void *recv, int length);
	int (*write)(struct _swPipe *, void *send, int length);
	int (*getFd)(struct _swPipe *, int isWriteFd);
	int (*close)(struct _swPipe *);
} swPipe;

int swPipeBase_create(swPipe *p, int blocking);
int swPipeEventfd_create(swPipe *p, int blocking, int semaphore);
int swPipeUnsock_create(swPipe *p, int blocking, int protocol);
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

//-------------------share memory-------------------------
typedef struct _swMemoryPoolSlab
{
	char tag; //1表示被占用 0未使用
	struct _swMemoryPoolSlab *next;
	struct _swMemoryPoolSlab *pre;
	void *data; //读写区
} swMemoryPoolSlab;

typedef struct _swMemoryPool
{
	swMemoryPoolSlab *head;
	swMemoryPoolSlab *tail;
	int block_size; //每次扩容的长度
	int memory_limit; //最大内存占用
	int memory_usage; //内存使用量
	int slab_size; //每个slab的长度
	char shared; //是否使用共享内存
} swMemoryPool;

typedef struct _swAllocator {
	void *object;
	void* (*alloc)(struct _swAllocator *alloc, int size);
	void (*free)(struct _swAllocator *alloc, void *ptr);
	void (*destroy)(struct _swAllocator *alloc);
} swAllocator;

typedef struct _swMemoryGlobal
{
	int size;  //总容量
	void *mem; //剩余内存的指针
	int offset; //内存分配游标
	char shared;
	int pagesize;
	swLock lock; //锁
	void *root_page;
	void *cur_page;
} swMemoryGlobal;

/**
 * 内存池
 */
int swMemoryPool_create(swMemoryPool *pool, int memory_limit, int slab_size);
void swMemoryPool_free(swMemoryPool *pool, void *data);
void* swMemoryPool_alloc(swMemoryPool *pool);

/**
 * 全局内存,程序生命周期内只分配/释放一次
 */
swAllocator* swMemoryGlobal_create(int pagesize, char shared);

/**
 * 共享内存分配
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

//全局变量
extern char swoole_running;
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

//----------------------core function---------------------
SWINLINE int swSetTimeout(int sock, float timeout);
SWINLINE int swRead(int, void *, int);
SWINLINE int swWrite(int, void *, int);
SWINLINE int swAccept(int server_socket, struct sockaddr_in *addr, int addr_len);
SWINLINE void swSetNonBlock(int);
SWINLINE void swSetBlock(int);

void swoole_init(void);
void swoole_clean(void);
int swSocket_listen(int type, char *host, int port, int backlog);
int swSocket_create(int type);
swSignalFunc swSignalSet(int sig, swSignalFunc func, int restart, int mask);
void swSingalNone();

typedef struct _swFactory swFactory;
typedef int (*swEventCallback)(swFactory *factory, swEventData *event);
//------------------Factory--------------------
struct _swFactory
{
	void *object;
	int max_request; //worker进程最大请求数量
	void *ptr; //server object
	uint16_t last_from_id;
	swReactor *reactor; //reserve for reactor

	int (*start)(struct _swFactory *);
	int (*shutdown)(struct _swFactory *);
	int (*dispatch)(struct _swFactory *, swEventData *);
	int (*finish)(struct _swFactory *, swSendData *);
	int (*notify)(struct _swFactory *, swEvent *);    //发送一个事件通知
	int (*event)(struct _swFactory *, swEventData *); //控制器事件
	int (*end)(struct _swFactory *, swDataHead *);

	int (*onTask)(struct _swFactory *, swEventData *task); //worker function.get a task,goto to work
	int (*onFinish)(struct _swFactory *, swSendData *result); //factory worker finish.callback
};

struct swReactor_s
{
	void *object;
	void *ptr; //reserve
	uint16_t id; //Reactor ID
	uint16_t flag; //flag
	char timeout;
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
};

typedef struct _swWorker swWorker;
typedef struct _swThread swThread;

typedef int (*swWorkerCall)(swWorker *worker);

struct _swWorker
{
	pid_t pid;
	pthread_t tid;
	int id;
	int pipe_master;
	int pipe_worker;
	int writer_id;
	void *ptr;
	void *ptr2;
	swWorkerCall call;
};

typedef struct _swProcessPool
{
	char reloading;
	char reload_flag;
	int worker_num;
	int max_request;
	int (*onTask)(struct _swProcessPool *pool, swEventData *task);
	int (*onStart)(struct _swProcessPool *pool, swWorker *worker);
	int round_id;
	swWorker *workers;
	swHashMap map;
	void *ptr;
	void *ptr2;
} swProcessPool;

typedef struct _swThreadWriter
{
	pthread_t ptid; //线程ID
	int pipe_num; //writer thread's pipe num
	int *pipes; //worker pipes
	int c_pipe; //current pipe
	swReactor reactor;
	swShareMemory shm; //共享内存
	swPipe evfd;       //eventfd
} swThreadWriter;

typedef struct _swFactoryProcess
{
	swThreadWriter *writers;
	swWorker *workers;

	swPipe *pipes;
	swQueue rd_queue;
	swQueue wt_queue;

	int manager_pid; //管理进程ID
	int writer_num; //writer thread num
	int worker_num; //worker child process num
	int writer_pti; //current writer id
	int worker_pti; //current worker id
} swFactoryProcess;

int swFactory_create(swFactory *factory);
int swFactory_start(swFactory *factory);
int swFactory_shutdown(swFactory *factory);
int swFactory_dispatch(swFactory *factory, swEventData *req);
int swFactory_finish(swFactory *factory, swSendData *resp);
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
#define SW_EVENT_DEAULT SW_EVENT_DEAULT
	SW_EVENT_READ = 1u << 9,
#define SW_EVENT_READ SW_EVENT_READ
	SW_EVENT_WRITE = 1u << 10,
#define SW_EVENT_WRITE SW_EVENT_WRITE
	SW_EVENT_ERROR = 1u << 11,
#define SW_EVENT_ERROR SW_EVENT_ERROR
};

SWINLINE int swReactor_error(swReactor *reactor);
SWINLINE int swReactor_fdtype(int fdtype);
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
int swProcessPool_create(swProcessPool *pool, int worker_num, int max_request);
int swProcessPool_wait(swProcessPool *pool);
int swProcessPool_start(swProcessPool *pool);
void swProcessPool_shutdown(swProcessPool *pool);
pid_t swProcessPool_spawn(swProcessPool *pool, swWorker *worker);
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

swChannel* swChannel_create(int size, int maxlen, int flag);
int swChannel_pop(swChannel *object, void *out, int buffer_length);
int swChannel_push(swChannel *object, void *in, int data_length);
int swChannel_out(swChannel *object, void *out, int buffer_length);
int swChannel_in(swChannel *object, void *in, int data_length);
int swChannel_wait(swChannel *object);
int swChannel_notify(swChannel *object);
void swChannel_free(swChannel *object);

/*----------------------------Thread Pool-------------------------------*/

typedef struct _swThread_task
{
	void *(*call)(void *arg);
	void *arg;
} swThread_task;

typedef struct
{
	pthread_mutex_t mutex;
	pthread_cond_t cond;

	swThread *threads;
	swThreadParam *params;
	swChannel *chan;

	int thread_num;
	int shutdown;
	int task_num;

} swThreadPool;

struct _swThread
{
	pthread_t tid;
	int id;
	swThreadPool *pool;
};

int swThreadPool_task(swThreadPool *pool, void *(*call)(void *arg), void *arg);
int swThreadPool_create(swThreadPool *pool, int max_num);
int swThreadPool_run(swThreadPool *pool);
int swThreadPool_free(swThreadPool *pool);

//-----------------------------------------------
typedef struct _swTimer_node
{
	struct _swTimerList_node *next, *prev;
	time_t lasttime;
	int interval;
} swTimer_node;

typedef struct _swTimer
{
	swHashMap list;
	int num;
	int interval_ms;
	int use_pipe;
	int lasttime;
	int fd;
	swPipe pipe;
} swTimer;

int swTimer_start(swTimer *timer, int interval_ms);
void swTimer_del(swTimer *timer, int ms);
int swTimer_free(swTimer *timer);
int swTimer_add(swTimer *timer, int ms);
SWINLINE time_t swTimer_get_ms();

typedef struct _swServerG{
	swTimer timer;
	int no_timerfd;
	int running;
	int sw_errno;
	int process_type;
	swProcessPool task_workers;
	swAllocator *memory_pool;
	swReactor *main_reactor;
} swServerG;

extern swServerG SwooleG;

#ifdef __cplusplus
}
#endif

#endif /* SWOOLE_H_ */
