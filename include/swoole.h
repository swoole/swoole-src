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
  | license@swoole.com so we can mail you a copy immediately.            |
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
#include <sys/types.h>
#include <sys/utsname.h>

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
#define SW_MAX_INT             2147483647

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
enum swReturnType
{
    SW_CONTINUE = 1,
    SW_WAIT     = 2,
    SW_CLOSE    = 3,
    SW_ERROR    = 4,
};
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

enum swBool_type
{
    SW_TRUE = 1,
    SW_FALSE = 0,
};

//-------------------------------------------------------------------------------
enum swServer_mode
{
    SW_MODE_BASE          =  1,
    SW_MODE_THREAD        =  2,
    SW_MODE_PROCESS       =  3,
    SW_MODE_SINGLE        =  4,
};

#define SW_MODE_PACKET		0x10 
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
    SW_WORKER_BUSY = 1,
    SW_WORKER_IDLE = 2,
    SW_WORKER_DEL  = 3,
};
//-------------------------------------------------------------------------------

#define swWarn(str,...)        SwooleGS->lock.lock(&SwooleGS->lock);\
snprintf(sw_error,SW_ERROR_MSG_SIZE,"%s: "str,__func__,##__VA_ARGS__);\
swLog_put(SW_LOG_WARN, sw_error);\
SwooleGS->lock.unlock(&SwooleGS->lock)

#define swNotice(str,...)        SwooleGS->lock.lock(&SwooleGS->lock);\
snprintf(sw_error,SW_ERROR_MSG_SIZE,str,##__VA_ARGS__);\
swLog_put(SW_LOG_NOTICE, sw_error);\
SwooleGS->lock.unlock(&SwooleGS->lock)

#define swError(str,...)       SwooleGS->lock.lock(&SwooleGS->lock);\
snprintf(sw_error, SW_ERROR_MSG_SIZE, str, ##__VA_ARGS__);\
swLog_put(SW_LOG_ERROR, sw_error);\
SwooleGS->lock.unlock(&SwooleGS->lock);\
exit(1)

#define swSysError(str,...) SwooleGS->lock.lock(&SwooleGS->lock);\
snprintf(sw_error,SW_ERROR_MSG_SIZE,"%s#%d: "str" Error: %s[%d].",__func__,__LINE__,##__VA_ARGS__,strerror(errno),errno);\
swLog_put(SW_LOG_WARN, sw_error);\
SwooleGS->lock.unlock(&SwooleGS->lock)

#ifdef SW_DEBUG_REMOTE_OPEN
#define swDebug(str,...) int __debug_log_n = snprintf(sw_error,SW_ERROR_MSG_SIZE,str,##__VA_ARGS__);\
write(SwooleG.debug_fd, sw_error, __debug_log_n);
#else
#define swDebug(str,...)
#endif

#ifdef SW_DEBUG
#define swTrace(str,...)       {printf("[%s:%d@%s]"str"\n",__FILE__,__LINE__,__func__,##__VA_ARGS__);}
//#define swWarn(str,...)        {printf("[%s:%d@%s]"str"\n",__FILE__,__LINE__,__func__,##__VA_ARGS__);}
#else
#define swTrace(str,...)
//#define swWarn(str,...)        {printf(sw_error);}
#endif

enum swTraceType
{
    SW_TRACE_SERVER  = 1,
    SW_TRACE_CLIENT  = 2,
    SW_TRACE_BUFFER  = 3,
    SW_TRACE_CONN    = 4,
    SW_TRACE_EVENT   = 5,
    SW_TRACE_WORKER  = 6,
    SW_TRACE_MEMORY  = 7,
    SW_TRACE_REACTOR = 8,
};

#if SW_LOG_TRACE_OPEN == 1
#define swTraceLog(id,str,...)      SwooleGS->lock.lock(&SwooleGS->lock);\
snprintf(sw_error,SW_ERROR_MSG_SIZE,"%s: "str,__func__,##__VA_ARGS__);\
swLog_put(SW_LOG_TRACE, sw_error);\
SwooleGS->lock.unlock(&SwooleGS->lock)
#elif SW_LOG_TRACE_OPEN == 0
#define swTraceLog(id,str,...)
#else
#define swTraceLog(id,str,...)      if (id==SW_LOG_TRACE_OPEN) {SwooleGS->lock.lock(&SwooleGS->lock);\
snprintf(sw_error,SW_ERROR_MSG_SIZE,"%s: "str,__func__,##__VA_ARGS__);\
swLog_put(SW_LOG_TRACE, sw_error);\
SwooleGS->lock.unlock(&SwooleGS->lock);}
#endif

#define swYield()              sched_yield() //or usleep(1)
//#define swYield()              usleep(500000)
#define SW_MAX_FDTYPE          32 //32 kinds of event
#define SW_ERROR_MSG_SIZE      512

//------------------------------Base--------------------------------
#ifndef uchar
typedef unsigned char uchar;
#endif

#ifdef SW_USE_OPENSSL
#include <openssl/ssl.h>
#endif

typedef struct
{
    uint32_t id;
    uint32_t fd :24;
    uint32_t reactor_id :8;
} swSession;

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

typedef struct _swConnection
{
    /**
     * file descript
     */
    int fd;

    /**
     * session id
     */
    uint32_t session_id :24;

    /**
     * socket type, SW_SOCK_TCP or SW_SOCK_UDP
     */
    uint8_t socket_type;

    /**
     * fd type, SW_FD_TCP or SW_FD_PIPE or SW_FD_TIMERFD
     */
    uint8_t fdtype;

    int events;

    /**
     * is active
     * system fd must be 0. en: timerfd, signalfd, listen socket
     */
    uint32_t active :1;

    uint32_t connect_notify :1;

    uint32_t recv_wait :1;
    uint32_t send_wait :1;

    uint32_t direct_send :1;

    uint32_t close_wait :1;
    uint32_t closed :1;
    uint32_t closing :1;
    uint32_t close_force :1;

    uint32_t removed :1;
    uint32_t overflow :1;

    uint32_t tcp_nopush :1;
    uint32_t tcp_nodelay :1;

    uint32_t http_buffered :1;

    /**
     * ReactorThread id
     */
    uint16_t from_id;

    /**
     * from which socket fd
     */
    uint16_t from_fd;

    /**
     * socket address
     */
    swSocketAddress info;

    /**
     * link any thing, for kernel, do not use with application.
     */
    void *object;

    /**
     * input buffer
     */
    struct _swBuffer *in_buffer;

    /**
     * output buffer
     */
    struct _swBuffer *out_buffer;

    /**
     * connect time(seconds)
     */
    time_t connect_time;

    /**
     * received time with last data
     */
    time_t last_time;

    /**
     * bind uid
     */
    long uid;

    /**
     *  upgarde websocket
     */
    uint8_t websocket_status;

#ifdef SW_USE_OPENSSL
    SSL *ssl;
    uint32_t ssl_state;
#endif
    sw_atomic_t lock;
} swConnection;

typedef struct _swProtocol
{
    /* one package: eof check */
    uint8_t split_by_eof;
    uint8_t package_eof_len;  //数据缓存结束符长度
    char package_eof[SW_DATA_EOF_MAXLEN + 1];  //数据缓存结束符

    char package_length_type;  //length field type
    uint8_t package_length_size;
    uint16_t package_length_offset;  //第几个字节开始表示长度
    uint16_t package_body_offset;  //第几个字节开始计算长度
    uint32_t package_max_length;

    int (*onPackage)(swConnection *conn, char *data, uint32_t length);
    int (*get_package_length)(struct _swProtocol *protocol, swConnection *conn, char *data, uint32_t length);
} swProtocol;
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

static sw_inline void swString_clear(swString *str)
{
    str->length = 0;
    str->offset = 0;
}

swString *swString_new(size_t size);
swString *swString_dup(const char *src_str, int length);
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
    swConnection *socket;
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
     * for big package
     */
    uint32_t length;
    char *data;
} swSendData;

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
typedef struct _swRWLock
{
    pthread_rwlock_t _lock;
    pthread_rwlockattr_t attr;

} swRWLock;
#endif

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
#ifdef HAVE_SPINLOCK
        swSpinLock spinlock;
#endif
        swFileLock filelock;
        swSem sem;
        swAtomicLock atomlock;
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

static sw_inline int32_t swoole_unpack(char type, void *data)
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

static inline char* swoole_strnstr(char *haystack, char *needle, uint32_t length)
{
    int i;
    uint32_t needle_length = strlen(needle);
    assert(needle_length > 0);

    for (i = 0; i < (int) (length - needle_length + 1); i++)
    {
        if ((haystack[0] == needle[0]) && (0 == memcmp(haystack, needle, needle_length)))
        {
            return (char *) haystack;
        }
        haystack++;
    }

    return NULL;
}

static inline int swoole_strnpos(char *haystack, uint32_t haystack_length, char *needle, uint32_t needle_length)
{
    assert(needle_length > 0);
    uint32_t i;

    for (i = 0; i < (int) (haystack_length - needle_length + 1); i++)
    {
        if ((haystack[0] == needle[0]) && (0 == memcmp(haystack, needle, needle_length)))
        {
            return i;
        }
        haystack++;
    }

    return -1;
}

static inline int swoole_strrnpos(char *haystack, char *needle, uint32_t length)
{
    uint32_t needle_length = strlen(needle);
    assert(needle_length > 0);
    uint32_t i;
    haystack += (length - needle_length);

    for (i = length - needle_length; i > 0; i--)
    {
        if ((haystack[0] == needle[0]) && (0 == memcmp(haystack, needle, needle_length)))
        {
            return i;
        }
        haystack--;
    }

    return -1;
}

void swoole_dump_bin(char *data, char type, int size);
int swoole_type_size(char type);
int swoole_mkdir_recursive(const char *dir);
char* swoole_dirname(char *file);
void swoole_dump_ascii(char *data, int size);
int swoole_sync_writefile(int fd, void *data, int len);
int swoole_sync_readfile(int fd, void *buf, int len);
int swoole_rand(int min, int max);
int swoole_system_random(int min, int max);
long swoole_file_get_size(FILE *fp);
int swoole_tmpfile(char *filename);
swString* swoole_file_get_contents(char *filename);
void swoole_open_remote_debug(void);
char *swoole_dec2hex(int value, int base);
int swoole_version_compare(char *version1, char *version2);

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
double swoole_microtime(void);
void swoole_rtrim(char *str, int len);
uint64_t swoole_ntoh64(uint64_t n64);

int swSocket_listen(int type, char *host, int port, int backlog);
int swSocket_create(int type);
int swSocket_wait(int fd, int timeout_ms, int events);
void swSocket_clean(int fd, void *buf, int len);
int swSocket_sendto_blocking(int fd, void *__buf, size_t __n, int flag, struct sockaddr *__addr, socklen_t __addr_len);
int swSocket_set_buffer_size(int fd, int buffer_size);
int swSocket_udp_sendto(int server_sock, char *dst_ip, int dst_port, char *data, uint32_t len);
int swSocket_udp_sendto6(int server_sock, char *dst_ip, int dst_port, char *data, uint32_t len);
int swSocket_sendfile_sync(int sock, char *filename, double timeout);
int swSocket_write_blocking(int __fd, void *__data, int __len);

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

#if defined(TCP_NOPUSH) || defined(TCP_CORK)
#define HAVE_TCP_NOPUSH
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
#else
#define swSocket_tcp_nopush(sock, nopush)
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
    void *ptr;  //reserve

    /**
     * last signal number
     */
    int singal_no;

    uint32_t event_num;
    uint32_t max_event_num;

    uint32_t check_timer :1;
    uint32_t running :1;

    /**
     * disable accept new connection
     */
    uint32_t disable_accept :1;

    uint32_t check_signalfd :1;

    /**
     * multi-thread reactor, cannot realloc sockets.
     */
    uint32_t thread :1;

	/**
	 * reactor->wait timeout (millisecond) or -1
	 */
	int32_t timeout_msec;

	uint16_t id; //Reactor ID
	uint16_t flag; //flag

    uint32_t max_socket;

    /**
     * for thread
     */
    swConnection *socket_list;

    /**
     * for process
     */
    swArray *socket_array;

    swReactor_handle handle[SW_MAX_FDTYPE];        //默认事件
    swReactor_handle write_handle[SW_MAX_FDTYPE];  //扩展事件1(一般为写事件)
    swReactor_handle error_handle[SW_MAX_FDTYPE];  //扩展事件2(一般为错误事件,如socket关闭)

    int (*add)(swReactor *, int fd, int fdtype);
    int (*set)(swReactor *, int fd, int fdtype);
    int (*del)(swReactor *, int fd);
    int (*wait)(swReactor *, struct timeval *);
    void (*free)(swReactor *);
    int (*setHandle)(swReactor *, int fdtype, swReactor_handle);

    void (*onTimeout)(swReactor *);
    void (*onFinish)(swReactor *);

    void (*enable_accept)(swReactor *);

    int (*write)(swReactor *, int __fd, void *__buf, int __n);
    int (*close)(swReactor *, int __fd);
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

    uint8_t deleted;
    uint8_t child_process;

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

    sw_atomic_t round_id;
    sw_atomic_t run_worker_num;

    swWorker *workers;
    swPipe *pipes;
    swHashMap *map;
    swReactor *reactor;
    swQueue *queue;

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

static sw_inline int swReactor_fdtype(int fdtype)
{
    return fdtype & (~SW_EVENT_READ) & (~SW_EVENT_WRITE) & (~SW_EVENT_ERROR);
}

static sw_inline int swReactor_events(int fdtype)
{
    int events = 0;
    if (swReactor_event_read(fdtype))
    {
        events |= SW_EVENT_READ;
    }
    if (swReactor_event_write(fdtype))
    {
        events |= SW_EVENT_WRITE;
    }
    if (swReactor_event_error(fdtype))
    {
        events |= SW_EVENT_ERROR;
    }
    return events;
}

int swReactor_create(swReactor *reactor, int max_event);
int swReactor_setHandle(swReactor *, int, swReactor_handle);
int swReactor_add(swReactor *reactor, int fd, int type);
swConnection* swReactor_get(swReactor *reactor, int fd);
int swReactor_del(swReactor *reactor, int fd);
int swReactor_onWrite(swReactor *reactor, swEvent *ev);
int swReactor_close(swReactor *reactor, int fd);
int swReactor_write(swReactor *reactor, int fd, void *buf, int n);
int swReactor_wait_write_buffer(swReactor *reactor, int fd);
void swReactor_set(swReactor *reactor, int fd, int fdtype);

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
int swProcessPool_dispatch_blocking(swProcessPool *pool, swEventData *data, int *dst_worker_id);
int swProcessPool_add_worker(swProcessPool *pool, swWorker *worker);

static sw_inline swWorker* swProcessPool_get_worker(swProcessPool *pool, int worker_id)
{
    return &(pool->workers[worker_id - pool->start_id]);
}

//-----------------------------Channel---------------------------
enum SW_CHANNEL_FLAGS
{
    SW_CHAN_LOCK     = 1u << 1,
    SW_CHAN_NOTIFY   = 1u << 2,
    SW_CHAN_SHM      = 1u << 3,
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
    SW_THREAD_REACTOR = 2,
    SW_THREAD_WORKER = 3,
    SW_THREAD_UDP = 4,
    SW_THREAD_UNIX_DGRAM = 5,
    SW_THREAD_HEARTBEAT = 6,
};

typedef struct _swThreadPool
{
    pthread_mutex_t mutex;
    pthread_cond_t cond;

    swThread *threads;
    swThreadParam *params;

    void *ptr1;
    void *ptr2;

#ifdef SW_THREADPOOL_USE_CHANNEL
    swChannel *chan;
#else
    swRingQueue queue;
#endif

    int thread_num;
    int shutdown;
    sw_atomic_t task_num;

    void (*onStart)(struct _swThreadPool *pool, int id);
    void (*onStop)(struct _swThreadPool *pool, int id);
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

//--------------------------------protocol------------------------------
int swProtocol_get_package_length(swProtocol *protocol, swConnection *conn, char *data, uint32_t size);
int swProtocol_recv_check_length(swProtocol *protocol, swConnection *conn, swString *buffer);
int swProtocol_recv_check_eof(swProtocol *protocol, swConnection *conn, swString *buffer);

//--------------------------------timer------------------------------
typedef struct _swTimer_node
{
    struct _swTimer_node *next, *prev;
    struct timeval lasttime;
    void *data;
    uint32_t exec_msec;
    uint32_t interval;
    long id;
    uint8_t remove :1;
    uint8_t restart :1;
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
    int lock;
    long _next_id;
    long _current_id;
    long _delete_id;
    swPipe pipe;
    /*-----------------for EventTimer-------------------*/
    struct timeval basetime;
    /*-----------------wait delete----------------------*/
    swArray *delete_list;
    swArray *insert_list;
    /*--------------------------------------------------*/
    long (*add)(struct _swTimer *timer, int _msec, int _interval, void *data);
    void* (*del)(struct _swTimer *timer, int _interval_ms, long id);
    int (*select)(struct _swTimer *timer);
    void (*free)(struct _swTimer *timer);
    /*-----------------event callback-------------------*/
    void (*onTimer)(struct _swTimer *timer, swTimer_node *event);
    void (*onTimeout)(struct _swTimer *timer, swTimer_node *event);
} swTimer;

int swTimer_init(int interval_ms, int no_pipe);
int swEventTimer_init();
void swTimer_signal_handler(int sig);
int swTimer_event_handler(swReactor *reactor, swEvent *event);
void swTimer_node_insert(swTimer_node **root, swTimer_node *new_node);
void swTimer_node_print(swTimer_node **root);
swTimer_node* swTimer_node_find(swTimer_node **root, int interval_msec, long id);
void swTimer_node_delete(swTimer_node **root, swTimer_node *node);
void swTimer_node_remove(swTimer_node **root, swTimer_node *node);
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

    uint32_t session_round :24;
    uint8_t start;  //after swServer_start will set start=1

    time_t now;

    sw_atomic_t spinlock;
    swLock lock;

    swProcessPool task_workers;
    swProcessPool event_workers;

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
     * pipe_worker
     */
    int pipe_used;

    uint32_t reactor_wait_onexit :1;
    uint32_t reactor_init :1;
    uint32_t reactor_ready :1;
    uint32_t in_client :1;
    uint32_t shutdown :1;

    uint32_t request_count;

    int max_request;

    swString **buffer_input;
    swString **buffer_output;
    swWorker *worker;

} swWorkerG;

typedef struct
{
    uint16_t id;
    uint8_t type;
    uint8_t factory_lock_target;
    int16_t factory_target_worker;
} swThreadG;

typedef struct _swServer swServer;
typedef struct _swFactory swFactory;

typedef struct
{
    swTimer timer;

    uint8_t running :1;
    uint8_t use_timerfd :1;
    uint8_t use_signalfd :1;
    uint8_t reuse_port :1;

    /**
     * Timer used pipe
     */
    uint8_t use_timer_pipe :1;

    int error;
    int process_type;
    pid_t pid;

    int signal_alarm;  //for timer with message queue
    int signal_fd;
    int log_fd;
    int null_fd;
    int debug_fd;

    /**
     * worker(worker and task_worker) process chroot / user / group
     */
    char *chroot;
    char *user;
    char *group;

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
    uint8_t task_ipc_mode;
    uint16_t task_max_request;

    uint16_t cpu_num;

    uint32_t pagesize;
    uint32_t max_sockets;
    struct utsname uname;

    /**
     * Unix socket default buffer size
     */
    uint32_t socket_buffer_size;

    swServer *serv;
    swFactory *factory;

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
    sw_atomic_t request_count;
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
