/**
 *  swoole.h
 *  Created on: 2012-6-16
 *  Author: tianfeng.han
 */
#ifndef SWOOLE_H_
#define SWOOLE_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
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

#ifdef HAVE_EPOLL
#include <sys/epoll.h>
#endif

#ifdef HAVE_KQUEUE
#include <sys/event.h>
#endif

#ifdef HAVE_EVENTFD
#include <sys/eventfd.h>
#endif

#include <sys/select.h>

#include <pthread.h>

#include "swoole_config.h"
#include "hashtable.h"

#define SW_MAX_FDS             (1024*10)
#define SW_THREAD_NUM          2
#define SW_WRITER_NUM          2  //写线程数量
#define SW_TASK_THREAD         4 //Task线程
#define SW_PIPES_NUM           (SW_WORKER_NUM/SW_WRITER_NUM + 1) //每个写线程pipes数组大小
#define SW_WORKER_NUM          4 //Worker进程数量
#define SW_BUFFER_SIZE         65495 //65535 - 28 - 12(UDP最大包 - 包头 - 3个INT)
#define SW_BACKLOG             512
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
#define SW_START_SLEEP         sleep(1)  //sleep 1s,wait fork and pthread_create

#ifndef CLOCK_REALTIME
#define CLOCK_REALTIME         0
#endif

#ifdef SW_USE_PHP
#define sw_malloc              emalloc
#define sw_free                efree
#define sw_calloc              ecalloc
#define sw_realloc             erealloc
#else
#define sw_malloc              malloc
#define sw_free(s)             free(s)
#define sw_calloc              calloc
#define sw_realloc             realloc
#endif

#define SW_OK                  0
#define SW_ERR                 -1

#define SW_FD_TCP              0
#define SW_FD_LISTEN           1
#define SW_FD_CLOSE            2
#define SW_FD_ERROR            3
#define SW_FD_UDP              4
#define SW_FD_PIPE             5

#define SW_MODE_CALL           1
#define SW_MODE_THREAD         2
#define SW_MODE_PROCESS        3

#define SW_SOCK_TCP            1
#define SW_SOCK_UDP            2
#define SW_SOCK_TCP6           3
#define SW_SOCK_UDP6           4

#ifdef SW_DEBUG
#define swTrace(str,...)       {printf("[%s:%d:%s]"str,__FILE__,__LINE__,__func__,##__VA_ARGS__);}
#else
#define swTrace(str,...)
#endif

#ifdef SW_DEBUG
#define swError(str,...)       {printf("[%s:%d:%s]"str,__FILE__,__LINE__,__func__,##__VA_ARGS__);exit(1);}
#else
#define swError(str,...)       {snprintf(sw_error,SW_ERROR_MSG_SIZE,"[%s:%d:%s]"str,__FILE__,__LINE__,__func__,##__VA_ARGS__);}
#endif

#ifdef SW_DEBUG
#define swWarn(str,...)       {printf("[%s:%d:%s]"str,__FILE__,__LINE__,__func__,##__VA_ARGS__);}
#else
#define swWarn(str,...)       {snprintf(sw_error,SW_ERROR_MSG_SIZE,"[%s:%d:%s]"str,__FILE__,__LINE__,__func__,##__VA_ARGS__);}
#endif

#define swYield()              sched_yield() //or usleep(1)

#define SW_MAX_FDTYPE          32 //32 kinds of event
#define SW_ERROR_MSG_SIZE      256
#define SW_MAX_REQUEST         10000

#ifndef ulong
#define ulong unsigned long
#endif

typedef struct _swEventData
{
	int fd;
	int len;
	int from_id; //Reactor Id
	char data[SW_BUFFER_SIZE];
} swEventData;

typedef struct _swSendData
{
	int fd;
	int len;
	int from_id;
	char *data;
} swSendData;

typedef struct _swEvent
{
	int from_id; //Reactor Id
	int fd;
	int type;
} swEvent;

typedef struct _swEventClose
{
	int from_id; //Reactor Id
	int fd;
} swEventClose;

typedef struct _swEventConnect
{
	int from_id; //Reactor Id
	int conn_fd;
	int serv_fd;
	struct sockaddr_in addr;
	socklen_t addrlen;
} swEventConnect;

typedef struct _swHashTable_FdInfo
{
	int fd;
	int key;
	UT_hash_handle hh;
} swHashTable_FdInfo;

typedef int (*swHandle)(swEventData *buf);
typedef void (*swSignalFunc)(int);
typedef void (*swCallback)(void *);
typedef struct swReactor_s swReactor;
typedef int (*swReactor_handle)(swReactor *reactor, swEvent *event);

typedef struct _swFactory
{
	void *object;
	int id; //Factory ID
	int running;
	int max_request; //worker进程最大请求数量
	void *ptr; //server object
	int last_from_id;
	swReactor *reactor; //reserve for reactor


	int (*start)(struct _swFactory *);
	int (*shutdown)(struct _swFactory *);
	int (*dispatch)(struct _swFactory *, swEventData *);
	int (*finish)(struct _swFactory *, swSendData *);

	int (*onTask)(struct _swFactory *, swEventData *task); //worker function.get a task,goto to work
	int (*onFinish)(struct _swFactory *, swSendData *result); //factory worker finish.callback
} swFactory;

typedef struct _swThreadParam
{
	void *object;
	int pti;
} swThreadParam;

typedef struct _swPipe
{
	void *object;
	int blocking;
	int (*read)(struct _swPipe *, void *recv, int length);
	int (*write)(struct _swPipe *, void *send, int length);
	int (*getFd)(struct _swPipe *, int isWriteFd);
	void (*close)(struct _swPipe *);
} swPipe;

struct swReactor_s
{
	void *object;
	void *ptr; //reserve
	int id; //Reactor ID
	int running;

	swReactor_handle handle[SW_MAX_FDTYPE];
	swFactory *factory;

	int (*add)(swReactor *, int, int);
	int (*del)(swReactor *, int);
	int (*wait)(swReactor *, struct timeval *);
	void (*free)(swReactor *);
	int (*setHandle)(swReactor *, int, swReactor_handle);
};

typedef struct _swThreadWriter
{
	pthread_t ptid; //线程ID
	int pipe_num; //writer thread's pipe num
	int *pipes; //worker pipes
	int c_pipe; //current pipe
	swReactor reactor;
	swPipe evfd; //eventfd
} swThreadWriter;

char swoole_running;
uint16_t sw_errno;
char sw_error[SW_ERROR_MSG_SIZE];


inline int swReactor_error(swReactor *reactor);
int swReactor_setHandle(swReactor *, int, swReactor_handle);
int swReactorEpoll_create(swReactor *reactor, int max_event_num);
int swReactorPoll_create(swReactor *reactor, int max_event_num);
int swReactorKqueue_create(swReactor *reactor, int max_event_num);
int swReactorSelect_create(swReactor *reactor);

inline ulong swHashFunc(const char *arKey, uint nKeyLength);
inline int swRead(int, char *, int);
inline int swWrite(int, char *, int);
inline void swSetNonBlock(int);
inline void swSetBlock(int);
inline int swSocket_listen(int type, char *host, int port, int backlog);
inline int swSocket_create(int type);
swSignalFunc swSignalSet(int sig, swSignalFunc func, int restart, int mask);

int swFactory_create(swFactory *factory);
int swFactory_start(swFactory *factory);
int swFactory_shutdown(swFactory *factory);
int swFactory_dispatch(swFactory *factory, swEventData *req);
int swFactory_finish(swFactory *factory, swSendData *resp);
int swFactory_check_callback(swFactory *factory);

int swFactoryProcess_create(swFactory *factory, int writer_num, int worker_num);
int swFactoryProcess_start(swFactory *factory);
int swFactoryProcess_shutdown(swFactory *factory);
int swFactoryProcess_dispatch(swFactory *factory, swEventData *buf);
int swFactoryProcess_finish(swFactory *factory, swSendData *data);

int swFactoryThread_create(swFactory *factory, int writer_num);
int swFactoryThread_start(swFactory *factory);
int swFactoryThread_shutdown(swFactory *factory);
int swFactoryThread_dispatch(swFactory *factory, swEventData *buf);
int swFactoryThread_finish(swFactory *factory, swSendData *data);

int swPipeBase_create(swPipe *p, int blocking);
int swPipeEventfd_create(swPipe *p, int blocking);
int swPipeMsg_create(swPipe *p, int blocking, int msg_key, long type);
int swPipeUnsock_create(swPipe *p, int blocking, int protocol);

//------------------Lock--------------------------------------
typedef struct _swFileLock
{
	struct flock rwlock;
	int fd;
	int (*lock_rd)(struct _swFileLock *this);
	int (*lock)(struct _swFileLock *this);
	int (*trylock_rd)(struct _swFileLock *this);
	int (*trylock)(struct _swFileLock *this);
	int (*unlock)(struct _swFileLock *this);
} swFileLock;

typedef struct _swMutex
{
	pthread_mutex_t rwlock;
	pthread_mutexattr_t attr;
	int (*lock) (struct _swMutex *this);
	int (*unlock) (struct _swMutex *this);
	int (*trylock) (struct _swMutex *this);
} swMutex;

typedef struct _swRWLock
{
	pthread_rwlock_t rwlock;
	pthread_rwlockattr_t attr;
	int (*lock_rd) (struct _swRWLock *this);
	int (*lock) (struct _swRWLock *this);
	int (*unlock) (struct _swRWLock *this);
	int (*trylock_rd) (struct _swRWLock *this);
	int (*trylock) (struct _swRWLock *this);
} swRWLock;

typedef struct _swSem
{
	key_t key;
	int semid;
	int (*lock)(struct _swSem *this);
	int (*unlock)(struct _swSem *this);
} swSem;

typedef struct _swWorkerChild
{
	pid_t pid;
	int pipe_fd;
	int writer_id;
} swWorkerChild;

typedef struct _swFactoryProcess
{
	swThreadWriter *writers;
	swWorkerChild *workers;

	int manager_pid; //管理进程ID
	int writer_num; //writer thread num
	int worker_num; //worker child process num
	int writer_pti; //current writer id
	int worker_pti; //current worker id
} swFactoryProcess;

int swRWLock_create(swRWLock *this);
int swRWLock_lock_rd(swRWLock *this);
int swRWLock_lock_rw(swRWLock *this);
int swRWLock_unlock(swRWLock *this);
int swRWLock_trylock_rw(swRWLock *this);
int swRWLock_trylock_rd(swRWLock *this);

int swSem_create(swSem *this, key_t key, int n);
int swSem_lock(swSem *this);
int swSem_unlock(swSem *this);

int swMutex_create(swMutex *this);
int swMutex_lock(swMutex *this);
int swMutex_unlock(swMutex *this);
int swMutex_trylock(swMutex *this);

int swFileLock_create(swFileLock *this, int fd);
int swFileLock_lock_rd(swFileLock *this);
int swFileLock_lock_rw(swFileLock *this);
int swFileLock_unlock(swFileLock *this);
int swFileLock_trylock_rw(swFileLock *this);
int swFileLock_trylock_rd(swFileLock *this);

#endif /* SWOOLE_H_ */
