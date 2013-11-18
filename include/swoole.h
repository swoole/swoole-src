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
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/select.h>
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

#ifdef HAVE_EPOLL
#include <sys/epoll.h>
#endif

#ifdef HAVE_KQUEUE
#include <sys/event.h>
#endif

#ifdef HAVE_EVENTFD
#include <sys/eventfd.h>
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
#include "memory.h"
#include "atomic.h"
#include "hashmap.h"
#include "list.h"

#define SW_TIMEO_SEC           0
#define SW_TIMEO_USEC          3000000

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

#define SW_FD_TCP              0
#define SW_FD_LISTEN           1 //server socket
#define SW_FD_CLOSE            2 //socket closed
#define SW_FD_ERROR            3 //socket error
#define SW_FD_UDP              4 //udp socket
#define SW_FD_PIPE             5 //pipe
#define SW_FD_CLOSE_QUEUE      6 //close queue
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
#define swWarn(str,...)       snprintf(sw_error,SW_ERROR_MSG_SIZE,str,##__VA_ARGS__);swLog_put(SW_LOG_WARN, sw_error)
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
	uint16_t from_id; //Reactor Id
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
} swEventClose_queue;

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
	void (*close)(struct _swPipe *);
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

int swQueueRing_create(swQueue *q, int size, int maxlen);
int swQueueMsg_create(swQueue *p, int wait, int msg_key, long type);

//------------------Lock--------------------------------------
typedef struct _swFileLock
{
	struct flock rwlock;
	int fd;
	int (*lock_rd)(struct _swFileLock *object);
	int (*lock)(struct _swFileLock *object);
	int (*trylock_rd)(struct _swFileLock *object);
	int (*trylock)(struct _swFileLock *object);
	int (*unlock)(struct _swFileLock *object);
	int (*free)(struct _swFileLock *object);
} swFileLock;

typedef struct _swMutex
{
	pthread_mutex_t mutex;
	pthread_mutexattr_t attr;
	int (*lock)(struct _swMutex *object);
	int (*unlock)(struct _swMutex *object);
	int (*trylock)(struct _swMutex *object);
	int (*free)(struct _swMutex *object);
} swMutex;

typedef struct _swRWLock
{
	pthread_rwlock_t rwlock;
	pthread_rwlockattr_t attr;
	int (*lock_rd)(struct _swRWLock *object);
	int (*lock)(struct _swRWLock *object);
	int (*unlock)(struct _swRWLock *object);
	int (*trylock_rd)(struct _swRWLock *object);
	int (*trylock)(struct _swRWLock *object);
	int (*free)(struct _swRWLock *object);
} swRWLock;

#ifdef HAVE_SPINLOCK
typedef struct _swSpinLock
{
	pthread_spinlock_t lock_t;
	int (*lock)(struct _swSpinLock *object);
	int (*unlock)(struct _swSpinLock *object);
	int (*trylock)(struct _swSpinLock *object);
	int (*free)(struct _swSpinLock *object);
} swSpinLock;
#endif

typedef struct _swCond
{
	swMutex mutex;
	pthread_cond_t cond;

	int (*wait)(struct _swCond *object);
	int (*timewait)(struct _swCond *object,long,long);
	int (*notify)(struct _swCond *object);
	int (*broadcast)(struct _swCond *object);

	int (*lock)(struct _swCond *object);
	int (*unlock)(struct _swCond *object);
	int (*trylock)(struct _swCond *object);
	void (*free)(struct _swCond *object);
} swCond;

typedef struct _swAtomicLock
{
	atomic_t lock_t;
	uint32_t spin;
	int (*lock)(struct _swAtomicLock *object);
	int (*unlock)(struct _swAtomicLock *object);
	int (*trylock)(struct _swAtomicLock *object);
	int (*free)(struct _swAtomicLock *object);
} swAtomicLock;

typedef struct _swSem
{
	key_t key;
	int semid;
	int lock_num;
	int (*lock)(struct _swSem *object);
	int (*unlock)(struct _swSem *object);
	int (*free)(struct _swMutex *object);
} swSem;

int swRWLock_create(swRWLock *object, int use_in_process);
int swRWLock_lock_rd(swRWLock *object);
int swRWLock_lock_rw(swRWLock *object);
int swRWLock_unlock(swRWLock *object);
int swRWLock_trylock_rw(swRWLock *object);
int swRWLock_trylock_rd(swRWLock *object);
int swRWLock_free(swRWLock *object);

int swSem_create(swSem *object, key_t key, int n);
int swSem_lock(swSem *object);
int swSem_unlock(swSem *object);
int swSem_free(swSem *object);

int swMutex_create(swMutex *object, int use_in_process);
int swMutex_lock(swMutex *object);
int swMutex_unlock(swMutex *object);
int swMutex_trylock(swMutex *object);
int swMutex_free(swMutex *object);

int swFileLock_create(swFileLock *object, int fd);
int swFileLock_lock_rd(swFileLock *object);
int swFileLock_lock_rw(swFileLock *object);
int swFileLock_unlock(swFileLock *object);
int swFileLock_trylock_rw(swFileLock *object);
int swFileLock_trylock_rd(swFileLock *object);

int swCond_create(swCond *cond);

#ifdef HAVE_SPINLOCK
int swSpinLock_create(swSpinLock *object, int spin);
int swSpinLock_lock(swSpinLock *object);
int swSpinLock_unlock(swSpinLock *object);
int swSpinLock_trylock(swSpinLock *object);
int swSpinLock_free(swSpinLock *object);
#endif

int swAtomicLock_create(swAtomicLock *object, int spin);
int swAtomicLock_lock(swAtomicLock *object);
int swAtomicLock_unlock(swAtomicLock *object);
int swAtomicLock_trylock(swAtomicLock *object);

typedef struct _swThreadParam
{
	void *object;
	int pti;
} swThreadParam;

//全局变量
char swoole_running;
int16_t sw_errno;
uint8_t sw_process_type; //进程类型
char sw_error[SW_ERROR_MSG_SIZE];
swAllocator *sw_memory_pool;

#define SW_PROCESS_MASTER      1
#define SW_PROCESS_WORKER      2
#define SW_PROCESS_MANAGER     3

#define swIsMaster()          (sw_process_type==SW_PROCESS_MASTER)
#define swIsWorker()          (sw_process_type==SW_PROCESS_WORKER)
#define swIsManager()         (sw_process_type==SW_PROCESS_MANAGER)

//----------------------tool function---------------------
int swLog_init(char *logfile);
void swLog_put(int level, char *cnt);
void swLog_free(void);
#define sw_log(str,...)       {snprintf(sw_error,SW_ERROR_MSG_SIZE,str,##__VA_ARGS__);swLog_put(SW_LOG_INFO, sw_error);}

//----------------------core function---------------------
SWINLINE int swSetTimeout(int sock, float timeout);
SWINLINE int swRead(int, char *, int);
SWINLINE int swWrite(int, char *, int);
SWINLINE int swAccept(int server_socket, struct sockaddr_in *addr, int addr_len);
SWINLINE void swSetNonBlock(int);
SWINLINE void swSetBlock(int);
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
	int (*notify)(struct _swFactory *, swEvent *);                       //发送一个事件通知
	int (*event)(struct _swFactory *, int controller_id, swEventData *); //控制器事件
	int (*controller)(struct _swFactory *factory, swEventCallback cb);   //增加一个控制器进程
	int (*end)(struct _swFactory *, swDataHead *);

	int (*onTask)(struct _swFactory *, swEventData *task); //worker function.get a task,goto to work
	int (*onFinish)(struct _swFactory *, swSendData *result); //factory worker finish.callback
};

struct swReactor_s
{
	void *object;
	void *ptr; //reserve
	uint16_t id; //Reactor ID
	char running;

	swReactor_handle handle[SW_MAX_FDTYPE];
	swFactory *factory;

	int (*add)(swReactor *, int fd, int fdtype);
	int (*set)(swReactor *, int fd, int fdtype);
	int (*del)(swReactor *, int fd);
	int (*wait)(swReactor *, struct timeval *);
	void (*free)(swReactor *);
	int (*setHandle)(swReactor *, int fdtype, swReactor_handle);
};

typedef struct _swWorker swWorker;
typedef int (*swWorkerCall)(swWorker *worker);

struct _swWorker
{
	pid_t pid;
	int id;
	int pipe_master;
	int pipe_worker;
	int writer_id;
	void *ptr;
	void *ptr2;
	swWorkerCall call;
};

typedef struct
{
	char reloading;
	char reload_flag;
	int max_num;
	int worker_num;
	swWorker *workers;
	swHashMap map;
} swManager;

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
int swReactorEpoll_create(swReactor *reactor, int max_event_num);
int swReactorPoll_create(swReactor *reactor, int max_event_num);
int swReactorKqueue_create(swReactor *reactor, int max_event_num);
int swReactorSelect_create(swReactor *reactor);

int swManager_create(swManager *ma, int max_num);
int swManager_add_worker(swManager *ma, swWorkerCall cb);
int swManager_run(swManager *ma);
void swManager_shutdown(swManager *ma);
#define swManager_worker(ma,id) (ma->workers[id])


#ifdef __cplusplus
}
#endif

#endif /* SWOOLE_H_ */
