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
#include <sys/wait.h>
#include <sys/un.h>

#ifdef __MACH__
#include <mach/clock.h>
#include <mach/mach_time.h>
#include <sys/sysctl.h>

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

#if defined(__GNUC__)
#if __GNUC__ >= 3
#define sw_inline inline __attribute__((always_inline))
#else
#define sw_inline inline
#endif
#elif defined(_MSC_VER)
#define sw_inline __forceinline
#else
#define sw_inline inline
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

#if !defined(__GNUC__) || __GNUC__ < 3
#define __builtin_expect(x, expected_value) (x)
#endif
#ifndef likely
#define likely(x)        __builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
#define unlikely(x)      __builtin_expect(!!(x), 0)
#endif

#define SW_START_LINE  "-------------------------START----------------------------"
#define SW_END_LINE    "-------------------------END------------------------------"
#define SW_SPACE       ' '
#define SW_CRLF        "\r\n"
/*----------------------------------------------------------------------------*/

#include "swoole_config.h"
#include "atomic.h"
#include "hashmap.h"
#include "list.h"
#include "RingQueue.h"
#include "array.h"

#define SW_TIMEO_SEC           0
#define SW_TIMEO_USEC          3000000

#define SW_MAX_UINT            4294967295

#ifndef MAX
#define MAX(a, b)              (a)>(b)?a:b;
#endif
#ifndef MIN
#define MIN(a, b)              (a)<(b)?a:b;
#endif

#define SW_STRL(s)             s, sizeof(s)
#define SW_START_SLEEP         usleep(100000)  //sleep 1s,wait fork and pthread_create

#ifdef SW_MALLOC_DEBUG
#define sw_malloc(__size)      malloc(__size);swWarn("malloc(%ld)", __size)
#define sw_free(ptr)           if(ptr){free(ptr);ptr=NULL;swWarn("free");}
#else
#define sw_malloc              malloc
#define sw_free(ptr)           if(ptr){free(ptr);ptr=NULL;}
#endif

#define sw_calloc              calloc
#define sw_realloc             realloc

#define METHOD_DEF(class,name,...)  class##_##name(class *object, ##__VA_ARGS__)
#define METHOD(class,name,...)      class##_##name(object, ##__VA_ARGS__)
//-------------------------------------------------------------------------------
#define SW_OK                  0
#define SW_ERR                -1
#define SW_AGAIN              -2
#define SW_BUSY               -3
#define SW_DONE               -4
#define SW_DECLINED           -5
#define SW_ABORT              -6
//-------------------------------------------------------------------------------
#define SW_TRUE                1
#define SW_FALSE               0
//-------------------------------------------------------------------------------
enum swFd_type
{
    SW_FD_TCP             = 0, //tcp socket
    SW_FD_LISTEN          = 1, //server socket
    SW_FD_CLOSE           = 2, //socket closed
    SW_FD_ERROR           = 3, //socket error
    SW_FD_UDP             = 4, //udp socket
    SW_FD_PIPE            = 5, //pipe
    SW_FD_WRITE           = 7, //fd can write
    SW_FD_TIMER           = 8, //timer fd
    SW_FD_AIO             = 9, //linux native aio
    SW_FD_SIGNAL          = 11, //signalfd
    SW_FD_DNS_RESOLVER    = 12, //dns resolver
    SW_FD_USER            = 15, //SW_FD_USER or SW_FD_USER+n: for custom event
};
//-------------------------------------------------------------------------------
enum swServer_mode
{
    SW_MODE_BASE          =  1,
    SW_MODE_THREAD        =  2,
    SW_MODE_PROCESS       =  3,
    SW_MODE_SINGLE        =  4,
};
//-------------------------------------------------------------------------------
enum swSocket_type
{
    SW_SOCK_TCP          =  1,
    SW_SOCK_UDP          =  2,
    SW_SOCK_TCP6         =  3,
    SW_SOCK_UDP6         =  4,
    SW_SOCK_UNIX_DGRAM   =  5,  //unix sock dgram
    SW_SOCK_UNIX_STREAM  =  6,  //unix sock stream
};

#define SW_SOCK_SSL            (1u << 9)
//-------------------------------------------------------------------------------
enum swLogLevel
{
    SW_LOG_DEBUG = 0,
    SW_LOG_TRACE,
    SW_LOG_INFO,
    SW_LOG_NOTICE,
    SW_LOG_WARN,
    SW_LOG_ERROR,

};
//-------------------------------------------------------------------------------
enum swDispatchMode
{
    SW_DISPATCH_ROUND = 1,
    SW_DISPATCH_FDMOD = 2,
    SW_DISPATCH_QUEUE = 3,
    SW_DISPATCH_IPMOD = 4,
    SW_DISPATCH_UIDMOD = 5,
};
enum swWorkerStatus
{
    SW_WORKER_DEL = 2,
    SW_WORKER_BUSY = 1,
    SW_WORKER_IDLE = 0,
};
//-------------------------------------------------------------------------------

#define swWarn(str,...)        SwooleG.lock.lock(&SwooleG.lock);\
snprintf(sw_error,SW_ERROR_MSG_SIZE,"%s: "str,__func__,##__VA_ARGS__);\
swLog_put(SW_LOG_WARN, sw_error);\
SwooleG.lock.unlock(&SwooleG.lock)

#define swNotice(str,...)        SwooleG.lock.lock(&SwooleG.lock);\
snprintf(sw_error,SW_ERROR_MSG_SIZE,str,##__VA_ARGS__);\
swLog_put(SW_LOG_NOTICE, sw_error);\
SwooleG.lock.unlock(&SwooleG.lock)

#define swError(str,...)       SwooleG.lock.lock(&SwooleG.lock);\
snprintf(sw_error, SW_ERROR_MSG_SIZE, str, ##__VA_ARGS__);\
swLog_put(SW_LOG_ERROR, sw_error);\
SwooleG.lock.unlock(&SwooleG.lock);\
exit(1)

#define swSysError(str,...) SwooleG.lock.lock(&SwooleG.lock);\
snprintf(sw_error,SW_ERROR_MSG_SIZE,"%s: "str" Error: %s[%d].",__func__,##__VA_ARGS__,strerror(errno),errno);\
swLog_put(SW_LOG_WARN, sw_error);\
SwooleG.lock.unlock(&SwooleG.lock)

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
	SW_CONTINUE = 1,
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

//------------------------------Base--------------------------------
#ifndef uchar
typedef unsigned char uchar;
#endif

typedef struct
{
    union
    {
        struct sockaddr_in inet_v4;
        struct sockaddr_in6 inet_v6;
        struct sockaddr_un un;
    } addr;
    socklen_t len;
} swSocketAddress;

//------------------------------String--------------------------------
typedef struct _swString
{
    size_t length;
    size_t size;
    off_t offset;
    char *str;
} swString;

#define swoole_tolower(c)      (u_char) ((c >= 'A' && c <= 'Z') ? (c | 0x20) : c)
#define swoole_toupper(c)      (u_char) ((c >= 'a' && c <= 'z') ? (c & ~0x20) : c)

size_t swoole_utf8_length(u_char *p, size_t n);
size_t swoole_utf8_length(u_char *p, size_t n);

static sw_inline size_t swoole_size_align(size_t size, int pagesize)
{
    return size + (pagesize - (size % pagesize));
}

swString *swString_new(size_t size);
swString *swString_dup(char *src_str, int length);
swString *swString_dup2(swString *src);
void swString_print(swString *str);
void swString_free(swString *str);
int swString_append(swString *str, swString *append_str);
int swString_append_ptr(swString *str, char *append_str, int length);

int swString_extend(swString *str, size_t new_size);

#define swString_length(s) (s->length)
#define swString_ptr(s) (s->str)
//------------------------------Base--------------------------------

typedef struct _swDataHead
{
    int fd;  //文件描述符
    uint16_t len;  //长度
    int16_t from_id;  //Reactor Id
    uint8_t type;  //类型
    uint8_t from_fd;  //从哪个ServerFD引发的
} swDataHead;

typedef struct _swEvent
{
    int fd;
    int16_t from_id;
    uint8_t type;
    void *object;
} swEvent;

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

//typedef struct _swEvent
//{
//	uint16_t from_id; //Reactor Id
//	uint8_t type; //类型
//	int fd;
//} swEvent;

#define SW_SIGNO_MAX         128

typedef void * (*swThreadStartFunc)(void *);
typedef int (*swHandle)(swEventData *buf);
typedef void (*swSignalFunc)(int);
typedef void* (*swCallback)(void *);
typedef struct swReactor_s swReactor;
typedef int (*swReactor_handle)(swReactor *reactor, swEvent *event);

//------------------Pipe--------------------
typedef struct _swPipe
{
    void *object;
    int blocking;
    double timeout;

    struct _swBuffer *worker_buffer;
    struct _swBuffer *master_buffer;

    int (*read)(struct _swPipe *, void *recv, int length);
    int (*write)(struct _swPipe *, void *send, int length);
    int (*getFd)(struct _swPipe *, int isWriteFd);
    int (*close)(struct _swPipe *);
} swPipe;

int swPipeBase_create(swPipe *p, int blocking);
int swPipeEventfd_create(swPipe *p, int blocking, int semaphore, int timeout);
int swPipeUnsock_create(swPipe *p, int blocking, int protocol);

static inline int swPipeNotify_auto(swPipe *p, int blocking, int semaphore)
{
#ifdef HAVE_EVENTFD
    return swPipeEventfd_create(p, blocking, semaphore, 0);
#else
    return swPipeBase_create(p, blocking);
#endif
}

void swBreakPoint(void);

//------------------Queue--------------------
typedef struct _swQueue_Data
{
    long mtype; /* type of received/sent message */
    char mdata[sizeof(swEventData)]; /* text of the message */
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

int swQueueMsg_create(swQueue *p, int wait, key_t msg_key, long type);
void swQueueMsg_set_blocking(swQueue *p, uint8_t blocking);
void swQueueMsg_set_destory(swQueue *p, uint8_t destory);

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

#ifdef HAVE_RWLOCK
//读写锁
typedef struct _swRWLock
{
    pthread_rwlock_t _lock;
    pthread_rwlockattr_t attr;

} swRWLock;
#endif

//自旋锁
#ifdef HAVE_SPINLOCK
typedef struct _swSpinLock
{
    pthread_spinlock_t lock_t;
} swSpinLock;
#endif

typedef struct _swAtomicLock
{
    sw_atomic_t lock_t;
    uint32_t spin;
} swAtomicLock;

typedef struct _swSem
{
    key_t key;
    int semid;
} swSem;

typedef struct _swLock
{
	int type;
    union
    {
        swMutex mutex;
#ifdef HAVE_RWLOCK
        swRWLock rwlock;
#endif
        swFileLock filelock;
        swSem sem;
        swAtomicLock atomlock;
#ifdef HAVE_SPINLOCK
        swSpinLock spinlock;
#endif
    } object;

	int (*lock_rd)(struct _swLock *);
	int (*lock)(struct _swLock *);
	int (*unlock)(struct _swLock *);
	int (*trylock_rd)(struct _swLock *);
	int (*trylock)(struct _swLock *);
	int (*free)(struct _swLock *);
} swLock;

//Thread Condition
typedef struct _swCond
{
    swLock lock;
    pthread_cond_t cond;

    int (*wait)(struct _swCond *object);
    int (*timewait)(struct _swCond *object, long, long);
    int (*notify)(struct _swCond *object);
    int (*broadcast)(struct _swCond *object);
    void (*free)(struct _swCond *object);
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
typedef struct _swMemoryPool
{
	void *object;
	void* (*alloc)(struct _swMemoryPool *pool, uint32_t size);
	void (*free)(struct _swMemoryPool *pool, void *ptr);
	void (*destroy)(struct _swMemoryPool *pool);
} swMemoryPool;


typedef struct _swFixedPool_slice
{
    uint8_t lock;
    struct _swFixedPool_slice *next;
    struct _swFixedPool_slice *pre;
    char data[0];

} swFixedPool_slice;

typedef struct _swFixedPool
{
    void *memory;
    size_t size;

    swFixedPool_slice *head;
    swFixedPool_slice *tail;

    /**
     * total memory size
     */
    uint32_t slice_num;

    /**
     * memory usage
     */
    uint32_t slice_use;

    /**
     * Fixed slice size, not include the memory used by swFixedPool_slice
     */
    uint32_t slice_size;

    /**
     * use shared memory
     */
    uint8_t shared;

} swFixedPool;
/**
 * FixedPool, random alloc/free fixed size memory
 */
swMemoryPool* swFixedPool_new(uint32_t slice_num, uint32_t slice_size, uint8_t shared);
swMemoryPool* swFixedPool_new2(uint32_t slice_size, void *memory, size_t size);
swMemoryPool* swMalloc_new();

/**
 * RingBuffer, In order for malloc / free
 */
swMemoryPool *swRingBuffer_new(uint32_t size, uint8_t shared);

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
#ifdef HAVE_RWLOCK
int swRWLock_create(swLock *lock, int use_in_process);
#endif
int swSem_create(swLock *lock, key_t key);
int swMutex_create(swLock *lock, int use_in_process);
int swMutex_lockwait(swLock *lock, int timeout_msec);
int swFileLock_create(swLock *lock, int fd);
#ifdef HAVE_SPINLOCK
int swSpinLock_create(swLock *object, int spin);
#endif
int swAtomicLock_create(swLock *object, int spin);
int swCond_create(swCond *cond);

typedef struct _swThreadParam
{
	void *object;
	int pti;
} swThreadParam;

extern int16_t sw_errno;
extern char sw_error[SW_ERROR_MSG_SIZE];

enum swProcessType
{
    SW_PROCESS_MASTER     = 1,
    SW_PROCESS_WORKER     = 2,
    SW_PROCESS_MANAGER    = 3,
    SW_PROCESS_TASKWORKER = 4,
};

#define swIsMaster()          (SwooleG.process_type==SW_PROCESS_MASTER)
#define swIsWorker()          (SwooleG.process_type==SW_PROCESS_WORKER)
#define swIsTaskWorker()      (SwooleG.process_type==SW_PROCESS_TASKWORKER)
#define swIsManager()         (SwooleG.process_type==SW_PROCESS_MANAGER)

//----------------------tool function---------------------
int swLog_init(char *logfile);
void swLog_put(int level, char *cnt);
void swLog_free(void);
#define sw_log(str,...)       {snprintf(sw_error,SW_ERROR_MSG_SIZE,str,##__VA_ARGS__);swLog_put(SW_LOG_INFO, sw_error);}

uint64_t swoole_hash_key(char *str, int str_len);
uint32_t swoole_common_multiple(uint32_t u, uint32_t v);
uint32_t swoole_common_divisor(uint32_t u, uint32_t v);

static sw_inline uint32_t swoole_unpack(char type, void *data)
{
    int64_t tmp;

    switch(type)
    {
    /*-------------------------16bit-----------------------------*/
    /**
     * signed short (always 16 bit, machine byte order)
     */
    case 's':
        return *((int16_t *) data);
    /**
     * unsigned short (always 16 bit, machine byte order)
     */
    case 'S':
        return *((uint16_t *) data);
    /**
     * unsigned short (always 16 bit, big endian byte order)
     */
    case 'n':
        return ntohs(*((uint16_t *) data));

    /*-------------------------32bit-----------------------------*/
    /**
     * unsigned long (always 32 bit, big endian byte order)
     */
    case 'N':
        tmp = *((uint32_t *) data);
        return ntohl(tmp);
    /**
     * unsigned long (always 32 bit, machine byte order)
     */
    case 'L':
        return *((uint32_t *) data);
    /**
     * signed long (always 32 bit, machine byte order)
     */
    case 'l':
        return *((int *) data);

    default:
        return *((uint32_t *) data);
    }
}

void swoole_dump_bin(char *data, char type, int size);
int swoole_type_size(char type);
int swoole_mkdir_recursive(const char *dir);
char* swoole_dirname(char *file);
void swoole_dump_ascii(char *data, int size);
int swoole_sync_writefile(int fd, void *data, int len);
int swoole_sync_readfile(int fd, void *buf, int len);
int swoole_system_random(int min, int max);
swString* swoole_file_get_contents(char *filename);

void swoole_ioctl_set_block(int sock, int nonblock);
void swoole_fcntl_set_block(int sock, int nonblock);

//----------------------core function---------------------
int swSetTimeout(int sock, double timeout);
int swRead(int, void *, int);
int swWrite(int, void *, int);
int swAccept(int server_socket, struct sockaddr_in *addr, int addr_len);

#ifdef SW_USE_IOCTL
#define swSetNonBlock(sock)   swoole_ioctl_set_block(sock, 1)
#define swSetBlock(sock)      swoole_ioctl_set_block(sock, 0)
#else
#define swSetNonBlock(sock)   swoole_fcntl_set_block(sock, 1)
#define swSetBlock(sock)      swoole_fcntl_set_block(sock, 0)
#endif

void swoole_init(void);
void swoole_clean(void);
void swoole_update_time(void);

int swSocket_listen(int type, char *host, int port, int backlog);
int swSocket_create(int type);
int swSocket_wait(int fd, int timeout_ms, int events);
void swSocket_clean(int fd, void *buf, int len);
int swSendto(int fd, void *__buf, size_t __n, int flag, struct sockaddr *__addr, socklen_t __addr_len);
int swSocket_sendfile_sync(int sock, char *filename, double timeout);

static sw_inline int swSocket_write(int fd, void *data, int len)
{
    int n;
    while (1)
    {
        n = write(fd, data, len);
        if (n < 0 && errno == EINTR)
        {
            continue;
        }
        break;
    }
    return n;
}

static sw_inline int swWaitpid(pid_t __pid, int *__stat_loc, int __options)
{
    int ret;
    do
    {
        ret = waitpid(__pid, __stat_loc, __options);
        if (ret < 0 && errno == EINTR)
        {
            continue;
        }
        break;
    } while(1);
    return ret;
}

#ifdef TCP_NOPUSH
static sw_inline int swSocket_tcp_nopush(int sock, int nopush)
{
    return setsockopt(sock, IPPROTO_TCP, TCP_NOPUSH, (const void *) &nopush, sizeof(int));
}

#elif defined(TCP_CORK)
static sw_inline int swSocket_tcp_nopush(int sock, int nopush)
{
    return setsockopt(sock, IPPROTO_TCP, TCP_CORK, (const void *) &nopush, sizeof(int));
}
#endif

void swFloat2timeval(float timeout, long int *sec, long int *usec);
swSignalFunc swSignal_set(int sig, swSignalFunc func, int restart, int mask);
void swSignal_add(int signo, swSignalFunc func);
void swSignal_callback(int signo);
#ifdef HAVE_SIGNALFD
int swSignalfd_onSignal(swReactor *reactor, swEvent *event);
#endif
void swSignal_none(void);

struct swReactor_s
{
	void *object;
	void *ptr; //reserve

	/**
	 * last signal number
	 */
	int singal_no;

	uint8_t check_timer;
	uint8_t check_signalfd;

	uint32_t event_num;
	uint32_t max_event_num;

	/**
	 * reactor->wait timeout (millisecond)
	 */
	uint32_t timeout_msec;
	uint16_t id; //Reactor ID
	uint16_t flag; //flag

	swReactor_handle handle[SW_MAX_FDTYPE];       //默认事件
	swReactor_handle write_handle[SW_MAX_FDTYPE]; //扩展事件1(一般为写事件)
	swReactor_handle error_handle[SW_MAX_FDTYPE]; //扩展事件2(一般为错误事件,如socket关闭)

	int (*add)(swReactor *, int fd, int fdtype);
	int (*set)(swReactor *, int fd, int fdtype);
	int (*del)(swReactor *, int fd);
	int (*wait)(swReactor *, struct timeval *);
	void (*free)(swReactor *);
	int (*setHandle)(swReactor *, int fdtype, swReactor_handle);

	void (*onTimeout)(swReactor *);
	void (*onFinish)(swReactor *);
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

	swMemoryPool *pool_output;

	swQueue *queue;

	/**
	 * redirect stdout to pipe_master
	 */
	uint8_t redirect_stdout;

	/**
	 * worker status, IDLE or BUSY
	 */
	uint8_t status;
	uint8_t type;
	uint8_t ipc_mode;
        
        uint8_t del;
        
         /**
	 * tasking num 
	 */
	sw_atomic_t tasking_num;

	/**
	 * redirect stdin to pipe_worker
	 */
	uint8_t redirect_stdin;

	/**
	 * worker id
	 */
	uint32_t id;

	swLock lock;

	void *send_shm;

	swPipe *pipe_object;

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
	uint8_t dispatch_mode;

	/**
	 * process type
	 */
	uint8_t type;

	/**
	 * worker->id = start_id + i
	 */
	uint16_t start_id;

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
	void (*onWorkerStop)(struct _swProcessPool *pool, int worker_id);

	int (*main_loop)(struct _swProcessPool *pool, swWorker *worker);

	int round_id;

	swWorker *workers;
	swPipe *pipes;
	swHashMap *map;
	swQueue queue;

	void *ptr;
	void *ptr2;
};

//----------------------------------------Reactor---------------------------------------
enum SW_EVENTS
{
	SW_EVENT_DEAULT = 256,
	SW_EVENT_READ = 1u << 9,
	SW_EVENT_WRITE = 1u << 10,
	SW_EVENT_ERROR = 1u << 11,
};

static sw_inline int swReactor_error(swReactor *reactor)
{
	switch (errno)
	{
    case EINTR:
        if (reactor->singal_no)
        {
            swSignal_callback(reactor->singal_no);
            reactor->singal_no = 0;
        }
		return SW_OK;
	}
	return SW_ERR;
}

static sw_inline int swReactor_fdtype(int fdtype)
{
	return fdtype & (~SW_EVENT_READ) & (~SW_EVENT_WRITE) & (~SW_EVENT_ERROR);
}

static sw_inline int swReactor_event_read(int fdtype)
{
	return (fdtype < SW_EVENT_DEAULT) || (fdtype & SW_EVENT_READ);
}

static sw_inline int swReactor_event_write(int fdtype)
{
	return fdtype & SW_EVENT_WRITE;
}

static sw_inline int swReactor_event_error(int fdtype)
{
	return fdtype & SW_EVENT_ERROR;
}

int swReactor_auto(swReactor *reactor, int max_event);
int swReactor_setHandle(swReactor *, int, swReactor_handle);

swReactor_handle swReactor_getHandle(swReactor *reactor, int event_type, int fdtype);
int swReactorEpoll_create(swReactor *reactor, int max_event_num);
int swReactorPoll_create(swReactor *reactor, int max_event_num);
int swReactorKqueue_create(swReactor *reactor, int max_event_num);
int swReactorSelect_create(swReactor *reactor);

/*----------------------------Process Pool-------------------------------*/
int swProcessPool_create(swProcessPool *pool, int worker_num, int max_request, key_t msgqueue_key, int nopipe);
int swProcessPool_wait(swProcessPool *pool);
int swProcessPool_start(swProcessPool *pool);
void swProcessPool_shutdown(swProcessPool *pool);
pid_t swProcessPool_spawn(swWorker *worker);
int swProcessPool_dispatch(swProcessPool *pool, swEventData *data, int *worker_id);
int swProcessPool_add_worker(swProcessPool *pool, swWorker *worker);

static sw_inline swWorker* swProcessPool_get_worker(swProcessPool *pool, int worker_id)
{
    return &(pool->workers[worker_id - pool->start_id]);
}

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
enum swThread_type
{
    SW_THREAD_MASTER = 1,
    SW_THREAD_REACTOR,
    SW_THREAD_WRITER,
    SW_THREAD_UDP,
    SW_THREAD_UNIX_DGRAM,
    SW_THREAD_HEARTBEAT,
};

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

//--------------------------------timer------------------------------
typedef struct _swTimer_interval_node
{
    struct _swTimerList_node *next, *prev;
    struct timeval lasttime;
    uint32_t interval;
} swTimer_interval_node;



typedef struct _swTimer_node
{
    struct _swTimer_node *next, *prev;
    void *data;
    uint32_t exec_msec;
    uint32_t interval;
} swTimer_node;



typedef struct _swTimer
{
	swTimer_node *root;
	/*--------------timerfd & signal timer--------------*/
	swHashMap *list;
	int num;
	int interval;
	int use_pipe;
	int lasttime;
	int fd;
	swPipe pipe;
	/*-----------------for EventTimer-------------------*/
	struct timeval basetime;
	/*--------------------------------------------------*/
	int (*add)(struct _swTimer *timer, int _msec, int _interval, void *data);
	int (*del)(struct _swTimer *timer, int _interval_ms);
	int (*select)(struct _swTimer *timer);
	void (*free)(struct _swTimer *timer);
	/*-----------------event callback-------------------*/
	void (*onTimer)(struct _swTimer *timer, int interval_msec);
	void (*onTimeout)(struct _swTimer *timer, void *data);
} swTimer;

int swTimer_init(int interval_ms, int no_pipe);
int swEventTimer_init();
void swTimer_signal_handler(int sig);
int swTimer_event_handler(swReactor *reactor, swEvent *event);
void swTimer_node_insert(swTimer_node **root, swTimer_node *new_node);
void swTimer_node_print(swTimer_node **root);
int swTimer_node_delete(swTimer_node **root, int interval_msec);
void swTimer_node_destory(swTimer_node **root);

//--------------------------------------------------------------
typedef struct _swModule
{
	char *name;
	void (*test)(void);
	int (*shutdown)(struct _swModule*);

} swModule;

int swModule_load(char *so_file);

//Share Memory
typedef struct
{
	pid_t master_pid;
	pid_t manager_pid;
	uint8_t start; //after swServer_start will set start=1
	time_t now;
        uint16_t task_num;
        sw_atomic_t task_round;
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
	uint32_t id;

	/**
	 * Write to reactor
	 */
	uint16_t pipe_round;

	/**
	 * pipe_worker
	 */
	int pipe_used;

	swString **buffer_input;
    swWorker *worker;

} swWorkerG;

typedef struct
{
    uint16_t id;
    uint8_t type;
	uint8_t factory_lock_target;
	int16_t factory_target_worker;
	sw_atomic_t worker_round_i;
} swThreadG;

typedef struct _swServer swServer;
typedef struct _swFactory swFactory;

typedef struct
{
    swTimer timer;

    int running;
    int error;
    int process_type;
    int signal_alarm; //for timer with message queue
    int signal_fd;
    int log_fd;
    int null_fd;

    uint8_t use_timerfd;
    uint8_t use_signalfd;

    /**
     * Timer used pipe
     */
    uint8_t use_timer_pipe;

    /**
     *  task worker process num
     */
    uint16_t task_worker_num;
     /**
      *  task worker process max
    */
    uint16_t task_worker_max;
    
    uint8_t task_recycle_num;
    
    char *task_tmpdir;
    uint16_t task_tmpdir_len;
    uint16_t cpu_num;

    uint8_t task_ipc_mode;
    uint8_t task_dispatch_mode;

    uint32_t pagesize;
    uint32_t max_sockets;

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

    swPipe *task_notify;
    swEventData *task_result;

    pthread_t heartbeat_pidt;

} swServerG;

typedef struct
{
    time_t start_time;
    sw_atomic_t connection_num;
    sw_atomic_t accept_count;
    sw_atomic_t close_count;
    sw_atomic_t tasking_num;
} swServerStats;

extern swServerG SwooleG;              //Local Global Variable
extern swServerGS *SwooleGS;           //Share Memory Global Variable
extern swWorkerG SwooleWG;             //Worker Global Variable
extern __thread swThreadG SwooleTG;   //Thread Global Variable
extern swServerStats *SwooleStats;

#define SW_CPU_NUM                    (SwooleG.cpu_num)

//-----------------------------------------------
//OS Feature
#ifdef HAVE_SIGNALFD
void swSignalfd_init();
void swSignalfd_add(int signo, __sighandler_t callback);
int swSignalfd_setup(swReactor *reactor);
void swSignalfd_clear();
#endif

#if defined(HAVE_KQUEUE) || !defined(HAVE_SENDFILE)
int swoole_sendfile(int out_fd, int in_fd, off_t *offset, size_t size);
#else
#include <sys/sendfile.h>
#define swoole_sendfile(out_fd, in_fd, offset, limit)    sendfile(out_fd, in_fd, offset, limit)
#endif

static sw_inline void sw_spinlock(sw_atomic_t *lock)
{
    uint32_t i, n;
    while (1)
    {
        if (*lock == 0 && sw_atomic_cmp_set(lock, 0, 1))
        {
            return;
        }
        if (SW_CPU_NUM > 1)
        {
            for (n = 1; n < SW_SPINLOCK_LOOP_N; n <<= 1)
            {
                for (i = 0; i < n; i++)
                {
                    sw_atomic_cpu_pause();
                }

                if (*lock == 0 && sw_atomic_cmp_set(lock, 0, 1))
                {
                    return;
                }
            }
        }
        swYield();
    }
}

#ifdef __cplusplus
}
#endif

#endif /* SWOOLE_H_ */
