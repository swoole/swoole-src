/*
 * swoole.h
 *
 *  Created on: 2012-6-16
 *      Author: htf
 */

#ifndef SWOOLE_H_
#define SWOOLE_H_

#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/select.h>
#include <pthread.h>

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
#define SW_START_SLEEP         usleep(1000*10)  //sleep 10ms,wait fork and pthread_create

#ifdef SW_USE_PHP
#define sw_malloc              emalloc
#define sw_free                efree
#define sw_calloc              ecalloc
#define sw_realloc             erealloc
#else
#define sw_malloc              malloc
#define sw_free                free
#define sw_calloc              calloc
#define sw_realloc             realloc
#endif

#define SW_OK                  0
#define SW_ERR                 -1

#define SW_FD_CONN             0
#define SW_FD_LISTEN           1
#define SW_FD_CLOSE            2
#define SW_FD_ERROR            3
#define swTrace(str,...)       {}
//#define swTrace(str,...)       {/*printf("ThreadID=%ld\n",pthread_self());*/printf("[%s:%d:%s]"str,__FILE__,__LINE__,__func__,##__VA_ARGS__);}

#define SW_MAX_FDTYPE 32 //32 kinds of event
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

typedef int (*swHandle)(swEventData *buf);
typedef void (*swSignalFunc)(int);
typedef void (*swCallback)(void *);
typedef struct swReactor_s swReactor;
typedef int (*swReactor_handle)(swReactor *reactor, swEvent *event);

typedef struct _swNetClient
{
	int sock;
	int id;
} swNetClient;

typedef struct _swFactory
{
	void *object;
	int id; //Factory ID
	void *ptr; //reserve
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


struct swReactor_s
{
	void *object;
	void *ptr; //reserve
	int id; //Reactor ID

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
	int evfd; //eventfd
	int pipe_num; //writer thread's pipe num
	int *pipes; //worker pipes
	int c_pipe; //current pipe
	swReactor reactor;
} swThreadWriter;

int swoole_running;
inline int swReactor_error(swReactor *reactor);
int swReactor_setHandle(swReactor *, int, swReactor_handle);
int swReactorEpoll_create(swReactor *reactor, int max_event_num);
int swReactorSelect_create(swReactor *reactor);

int swRead(int, char *, int);
int swWrite(int, char *, int);
void swSetNonBlock(int);
void swSetBlock(int);
swSignalFunc swSignalSet(int sig, swSignalFunc func, int restart, int mask);
void swSignalHanlde(int sig);

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

#endif /* SWOOLE_H_ */
