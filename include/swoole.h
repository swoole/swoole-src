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

#ifdef SW_STATIC_COMPILATION
#include "php_config.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

/*--- C standard library ---*/
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef __sun
#include <strings.h>
#endif
#include <signal.h>
#include <time.h>
#include <limits.h>

#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#if defined(HAVE_CPU_AFFINITY)
#ifdef __FreeBSD__
#include <sys/types.h>
#include <sys/cpuset.h>
#include <pthread_np.h>
typedef cpuset_t cpu_set_t;
#else
#include <sched.h>
#endif
#endif

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
#ifndef HAVE_CLOCK_GETTIME
int clock_gettime(clock_id_t which_clock, struct timespec *t);
#endif
#endif

#ifndef HAVE_DAEMON
int daemon(int nochdir, int noclose);
#endif

/*----------------------------------------------------------------------------*/
#ifndef ulong
#define ulong unsigned long
#endif
typedef unsigned long ulong_t;

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

#if defined(__GNUC__) && __GNUC__ >= 4
#define SW_API __attribute__ ((visibility("default")))
#else
#define SW_API
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
#define SW_ECHO_RED               "\e[31m%s\e[0m"
#define SW_ECHO_GREEN             "\e[32m%s\e[0m"
#define SW_ECHO_YELLOW            "\e[33m%s\e[0m"
#define SW_ECHO_BLUE              "\e[34m%s\e[0m"
#define SW_ECHO_MAGENTA           "\e[35m%s\e[0m"
#define SW_ECHO_CYAN              "\e[36m%s\e[0m"
#define SW_ECHO_WHITE             "\e[37m%s\e[0m"
#define SW_COLOR_RED              1
#define SW_COLOR_GREEN            2
#define SW_COLOR_YELLOW           3
#define SW_COLOR_BLUE             4
#define SW_COLOR_MAGENTA          5
#define SW_COLOR_CYAN             6
#define SW_COLOR_WHITE            7

#define SW_SPACE       ' '
#define SW_CRLF        "\r\n"
#define SW_CRLF_LEN    2
#define SW_ASCII_CODE_0     64
#define SW_ASCII_CODE_Z     106
/*----------------------------------------------------------------------------*/

#include "swoole_config.h"
#include "atomic.h"
#include "hashmap.h"
#include "list.h"
#include "heap.h"
#include "ring_queue.h"
#include "array.h"
#include "error.h"

#define SW_MAX_UINT            UINT_MAX
#define SW_MAX_INT             INT_MAX

#ifndef MAX
#define MAX(a, b)              (a)>(b)?a:b;
#endif
#ifndef MIN
#define MIN(a, b)              (a)<(b)?a:b;
#endif

#define SW_STRL(s)             s, sizeof(s)
#define SW_START_SLEEP         usleep(100000)  //sleep 1s,wait fork and pthread_create

#ifdef SW_USE_JEMALLOC
#include <jemalloc/jemalloc.h>
#define sw_malloc              je_malloc
#define sw_free                je_free
#define sw_calloc              je_calloc
#define sw_realloc             je_realloc
#else
#define sw_malloc              malloc
#define sw_free                free
#define sw_calloc              calloc
#define sw_realloc             realloc
#endif

static sw_inline char* swoole_strdup(const char *s)
{
    size_t l = strlen(s) + 1;
    char *p = (char *)sw_malloc(l);
    memcpy(p, s, l);
    return p;
}

static sw_inline char* swoole_strndup(const char *s, size_t n)
{
    char *p = (char *)sw_malloc(n + 1);
    strncpy(p, s, n);
    p[n] = '\0';
    return p;
}

#if defined(SW_USE_JEMALLOC) || defined(SW_USE_TCMALLOC)
#define sw_strdup              swoole_strdup
#define sw_strndup             swoole_strndup
#else
#define sw_strdup              strdup
#define sw_strndup             strndup
#endif

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
    SW_READY    = 5,
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
    SW_FD_STREAM          = 6, //stream socket
    SW_FD_WRITE           = 7, //fd can write
    SW_FD_TIMER           = 8, //timer fd
    SW_FD_AIO             = 9, //linux native aio
    SW_FD_CORO_SOCKET     = 10, //CoroSocket
    SW_FD_SIGNAL          = 11, //signalfd
    SW_FD_DNS_RESOLVER    = 12, //dns resolver
    SW_FD_INOTIFY         = 13, //server socket
    SW_FD_CHAN_PIPE       = 14, //channel pipe
    SW_FD_USER            = 15, //SW_FD_USER or SW_FD_USER+n: for custom event
    SW_FD_STREAM_CLIENT   = 16, //swClient stream
    SW_FD_DGRAM_CLIENT    = 17, //swClient dgram
};

enum swBool_type
{
    SW_TRUE = 1,
    SW_FALSE = 0,
};

enum swEvent_type
{
    SW_EVENT_DEAULT = 256,
    SW_EVENT_READ = 1u << 9,
    SW_EVENT_WRITE = 1u << 10,
    SW_EVENT_ERROR = 1u << 11,
    SW_EVENT_ONCE = 1u << 12,
};

enum swPipe_type
{
    SW_PIPE_READ = 0,
    SW_PIPE_WRITE = 1,
};

enum swGlobal_hook_type
{
    SW_GLOBAL_HOOK_BEFORE_SERVER_START,
    SW_GLOBAL_HOOK_BEFORE_CLIENT_START,
    SW_GLOBAL_HOOK_ON_CORO_START,
    SW_GLOBAL_HOOK_ON_CORO_STOP,
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
enum swLog_level
{
    SW_LOG_DEBUG = 0,
    SW_LOG_TRACE,
    SW_LOG_INFO,
    SW_LOG_NOTICE,
    SW_LOG_WARNING,
    SW_LOG_ERROR,
};
//-------------------------------------------------------------------------------
enum swFactory_dispatch_mode
{
    SW_DISPATCH_ROUND    = 1,
    SW_DISPATCH_FDMOD    = 2,
    SW_DISPATCH_QUEUE    = 3,
    SW_DISPATCH_IPMOD    = 4,
    SW_DISPATCH_UIDMOD   = 5,
    SW_DISPATCH_USERFUNC = 6,
    SW_DISPATCH_STREAM   = 7,
};

enum swWorker_status
{
    SW_WORKER_BUSY = 1,
    SW_WORKER_IDLE = 2,
    SW_WORKER_DEL  = 3,
};
//-------------------------------------------------------------------------------

#define swWarn(str,...)        SwooleGS->lock_2.lock(&SwooleGS->lock_2);\
snprintf(sw_error,SW_ERROR_MSG_SIZE,"%s: " str,__func__,##__VA_ARGS__);\
swLog_put(SW_LOG_WARNING, sw_error);\
SwooleGS->lock_2.unlock(&SwooleGS->lock_2)

#define swNotice(str,...)        if (SW_LOG_NOTICE >= SwooleG.log_level){\
    SwooleGS->lock_2.lock(&SwooleGS->lock_2);\
    snprintf(sw_error,SW_ERROR_MSG_SIZE,str,##__VA_ARGS__);\
    swLog_put(SW_LOG_NOTICE, sw_error);\
    SwooleGS->lock_2.unlock(&SwooleGS->lock_2);}

#define swError(str,...)       SwooleGS->lock_2.lock(&SwooleGS->lock_2);\
snprintf(sw_error, SW_ERROR_MSG_SIZE, str, ##__VA_ARGS__);\
swLog_put(SW_LOG_ERROR, sw_error);\
SwooleGS->lock_2.unlock(&SwooleGS->lock_2);\
exit(1)

#define swSysError(str,...) SwooleGS->lock_2.lock(&SwooleGS->lock_2);\
    snprintf(sw_error,SW_ERROR_MSG_SIZE,"%s(:%d): " str " Error: %s[%d].",__func__,__LINE__,##__VA_ARGS__,strerror(errno),errno);\
    swLog_put(SW_LOG_ERROR, sw_error);\
    SwooleG.error=errno;\
    SwooleGS->lock_2.unlock(&SwooleGS->lock_2)

#define swoole_error_log(level, __errno, str, ...)      do{SwooleG.error=__errno;\
    if (level >= SwooleG.log_level){\
    snprintf(sw_error, SW_ERROR_MSG_SIZE, "%s (ERROR %d): " str,__func__,__errno,##__VA_ARGS__);\
    SwooleGS->lock_2.lock(&SwooleGS->lock_2);\
    swLog_put(level, sw_error);\
    SwooleGS->lock_2.unlock(&SwooleGS->lock_2);}}while(0)

#ifdef SW_DEBUG_REMOTE_OPEN
#define swDebug(str,...) int __debug_log_n = snprintf(sw_error, SW_ERROR_MSG_SIZE, str, ##__VA_ARGS__);\
write(SwooleG.debug_fd, sw_error, __debug_log_n);
#elif defined(SW_DEBUG)
#define swDebug(str,...) if (SW_LOG_DEBUG >= SwooleG.log_level){\
    SwooleGS->lock_2.lock(&SwooleGS->lock_2);\
    snprintf(sw_error, SW_ERROR_MSG_SIZE, "%s(:%d): " str, __func__, __LINE__, ##__VA_ARGS__);\
    swLog_put(SW_LOG_DEBUG, sw_error);\
    SwooleGS->lock_2.unlock(&SwooleGS->lock_2);}
#else
#define swDebug(str,...)
#endif

enum swTraceType
{
    SW_TRACE_SERVER           = 1u << 1,
    SW_TRACE_CLIENT           = 1u << 2,
    SW_TRACE_BUFFER           = 1u << 3,
    SW_TRACE_CONN             = 1u << 4,
    SW_TRACE_EVENT            = 1u << 5,
    SW_TRACE_WORKER           = 1u << 6,
    SW_TRACE_MEMORY           = 1u << 7,
    SW_TRACE_REACTOR          = 1u << 8,
    SW_TRACE_PHP              = 1u << 9,
    SW_TRACE_HTTP2            = 1u << 10,
    SW_TRACE_EOF_PROTOCOL     = 1u << 11,
    SW_TRACE_LENGTH_PROTOCOL  = 1u << 12,
    SW_TRACE_CLOSE            = 1u << 13,
    SW_TRACE_HTTP_CLIENT      = 1u << 14,
    SW_TRACE_COROUTINE        = 1u << 15,
    SW_TRACE_REDIS_CLIENT     = 1u << 16,
    SW_TRACE_MYSQL_CLIENT     = 1u << 17,
    SW_TRACE_AIO              = 1u << 18,
    SW_TRACE_SSL              = 1u << 19,
    SW_TRACE_NORMAL           = 1u << 20,
};

#ifdef SW_LOG_TRACE_OPEN
#define swTraceLog(what,str,...)      if (SW_LOG_TRACE >= SwooleG.log_level && (what & SwooleG.trace_flags)) {\
    SwooleGS->lock_2.lock(&SwooleGS->lock_2);\
    snprintf(sw_error,SW_ERROR_MSG_SIZE,"%s(:%d): " str, __func__, __LINE__, ##__VA_ARGS__);\
    swLog_put(SW_LOG_TRACE, sw_error);\
    SwooleGS->lock_2.unlock(&SwooleGS->lock_2);}
#else
#define swTraceLog(id,str,...)
#endif

#define swTrace(str,...)       swTraceLog(SW_TRACE_NORMAL, str, ##__VA_ARGS__)

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

typedef void (*swDestructor)(void *data);
typedef void (*swCallback)(void *data);

typedef struct
{
    uint32_t id;
    uint32_t fd :24;
    uint32_t reactor_id :8;
} swSession;

typedef struct _swString
{
    size_t length;
    size_t size;
    off_t offset;
    char *str;
} swString;

typedef void* swObject;

typedef struct _swLinkedList_node
{
    struct _swLinkedList_node *prev;
    struct _swLinkedList_node *next;
    ulong_t priority;
    void *data;
} swLinkedList_node;

typedef struct
{
    uint32_t num;
    uint8_t type;
    swLinkedList_node *head;
    swLinkedList_node *tail;
    swDestructor dtor;
} swLinkedList;

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
    uint32_t session_id;

    /**
     * socket type, SW_SOCK_TCP or SW_SOCK_UDP
     */
    uint16_t socket_type;

    /**
     * fd type, SW_FD_TCP or SW_FD_PIPE
     */
    uint16_t fdtype;

    int events;

    //--------------------------------------------------------------
    /**
     * is active
     * system fd must be 0. en: signalfd, listen socket
     */
    uint8_t active;
    uint8_t connect_notify;
    uint8_t direct_send;
    uint8_t ssl_send;
    //--------------------------------------------------------------
    uint8_t listen_wait;
    uint8_t recv_wait;
    uint8_t send_wait;
    uint8_t close_wait;
    uint8_t overflow;
    uint8_t high_watermark;
    uint8_t removed;
    uint8_t tcp_nopush;
    uint8_t dontwait;
    //--------------------------------------------------------------
    uint8_t tcp_nodelay;
    uint8_t ssl_want_read;
    uint8_t ssl_want_write;
    uint8_t http_upgrade;
    uint8_t http2_stream;
    uint8_t skip_recv;
    //--------------------------------------------------------------
    /**
     * server is actively close the connection
     */
    uint8_t close_actively;
    uint8_t closed;
    uint8_t closing;
    uint8_t close_reset;
    /**
     * protected connection, cannot be closed by heartbeat thread.
     */
    uint8_t protect;
    uint8_t nonblock;
    //--------------------------------------------------------------
    uint8_t close_notify;
    uint8_t close_force;
    //--------------------------------------------------------------
    /**
     * ReactorThread id
     */
    uint16_t from_id;

    /**
     * close error code
     */
    uint16_t close_errno;

    /**
     * from which socket fd
     */
    sw_atomic_t from_fd;

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
     * for receive data buffer
     */
    swString *recv_buffer;

    /**
     * connect time(seconds)
     */
    time_t connect_time;

    /**
     * received time with last data
     */
    time_t last_time;

#ifdef SW_BUFFER_RECV_TIME
    /**
     * received time(microseconds) with last data
     */
    double last_time_usec;
#endif

    /**
     * bind uid
     */
    uint32_t uid;

    /**
     * memory buffer size;
     */
    int buffer_size;

    /**
     * upgarde websocket
     */
    uint8_t websocket_status;

    /**
     * unfinished data frame
     */
    swString *websocket_buffer;

#ifdef SW_USE_OPENSSL
    SSL *ssl;
    uint32_t ssl_state;
    swString ssl_client_cert;
#endif
    sw_atomic_t lock;

#ifdef SW_DEBUG
    size_t total_recv_bytes;
    size_t total_send_bytes;
#endif

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

    void *private_data;
    uint16_t real_header_length;

    int (*onPackage)(swConnection *conn, char *data, uint32_t length);
    int (*get_package_length)(struct _swProtocol *protocol, swConnection *conn, char *data, uint32_t length);
} swProtocol;
typedef int (*swProtocol_length_function)(struct _swProtocol *, swConnection *, char *, uint32_t);
//------------------------------String--------------------------------
#define swoole_tolower(c)      (u_char) ((c >= 'A' && c <= 'Z') ? (c | 0x20) : c)
#define swoole_toupper(c)      (u_char) ((c >= 'a' && c <= 'z') ? (c & ~0x20) : c)

uint32_t swoole_utf8_decode(u_char **p, size_t n);
size_t swoole_utf8_length(u_char *p, size_t n);
void swoole_random_string(char *buf, size_t size);
char* swoole_get_mimetype(char *file);

static sw_inline char *swoole_strlchr(char *p, char *last, char c)
{
    while (p < last)
    {
        if (*p == c)
        {
            return p;
        }
        p++;
    }
    return NULL;
}

static sw_inline size_t swoole_size_align(size_t size, int pagesize)
{
    return size + (pagesize - (size % pagesize));
}

static sw_inline void swString_clear(swString *str)
{
    str->length = 0;
    str->offset = 0;
}

static sw_inline void swString_free(swString *str)
{
    sw_free(str->str);
    sw_free(str);
}

static sw_inline size_t swString_length(swString *str)
{
    return str->length;
}

static sw_inline size_t swString_size(swString *str)
{
    return str->size;
}

swString *swString_new(size_t size);
swString *swString_dup(const char *src_str, int length);
swString *swString_dup2(swString *src);

void swString_print(swString *str);
void swString_free(swString *str);
int swString_append(swString *str, swString *append_str);
int swString_append_ptr(swString *str, const char *append_str, int length);
int swString_write(swString *str, off_t offset, swString *write_str);
int swString_write_ptr(swString *str, off_t offset, char *write_str, int length);
int swString_extend(swString *str, size_t new_size);
char* swString_alloc(swString *str, size_t __size);

#define SWSTRING_CURRENT_VL(buffer) buffer->str + buffer->offset, buffer->length - buffer->offset

static sw_inline int swString_extend_align(swString *str, size_t _new_size)
{
    size_t align_size = str->size * 2;
    while (align_size < _new_size)
    {
        align_size *= 2;
    }
    return swString_extend(str, align_size);
}

#define swString_length(s) (s->length)
#define swString_ptr(s) (s->str)
//------------------------------Base--------------------------------
typedef struct _swDataHead
{
    int fd;
    uint16_t len;
    int16_t from_id;
    uint8_t type;
    uint8_t flags;
    uint16_t from_fd;
#ifdef SW_BUFFER_RECV_TIME
    double time;
#endif
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

typedef struct _swDgramPacket
{
    union
    {
        struct in6_addr v6;
        struct in_addr v4;
        struct
        {
            uint16_t path_length;
        } un;
    } addr;
    uint16_t port;
    uint32_t length;
    char data[0];
} swDgramPacket;

typedef struct _swSendData
{
    swDataHead info;
    /**
     * for big package
     */
    uint32_t length;
    char *data;
} swSendData;

typedef struct
{
    off_t offset;
    size_t length;
    char filename[0];
} swSendFile_request;

//------------------TimeWheel--------------------
typedef struct
{
    uint16_t current;
    uint16_t size;
    swHashMap **wheel;

} swTimeWheel;

typedef void * (*swThreadStartFunc)(void *);
typedef int (*swHandle)(swEventData *buf);
typedef void (*swSignalHander)(int);
typedef struct _swReactor swReactor;

typedef int (*swReactor_handle)(swReactor *reactor, swEvent *event);
//------------------Pipe--------------------
typedef struct _swPipe
{
    void *object;
    int blocking;
    double timeout;

    int (*read)(struct _swPipe *, void *recv, int length);
    int (*write)(struct _swPipe *, void *send, int length);
    int (*getFd)(struct _swPipe *, int master);
    int (*close)(struct _swPipe *);
} swPipe;

enum _swPipe_close_which
{
    SW_PIPE_CLOSE_MASTER = 1,
    SW_PIPE_CLOSE_WORKER = 2,
    SW_PIPE_CLOSE_READ   = 3,
    SW_PIPE_CLOSE_WRITE  = 4,
    SW_PIPE_CLOSE_BOTH   = 0,
};

int swPipeBase_create(swPipe *p, int blocking);
int swPipeEventfd_create(swPipe *p, int blocking, int semaphore, int timeout);
int swPipeUnsock_create(swPipe *p, int blocking, int protocol);
int swPipeUnsock_close_ext(swPipe *p, int which);

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

typedef struct _swMsgQueue
{
    int blocking;
    int msg_id;
    int flags;
    int perms;
} swMsgQueue;

int swMsgQueue_create(swMsgQueue *q, int blocking, key_t msg_key, int perms);
void swMsgQueue_set_blocking(swMsgQueue *q, uint8_t blocking);
int swMsgQueue_push(swMsgQueue *q, swQueue_data *in, int data_length);
int swMsgQueue_pop(swMsgQueue *q, swQueue_data *out, int buffer_length);
int swMsgQueue_stat(swMsgQueue *q, int *queue_num, int *queue_bytes);
int swMsgQueue_free(swMsgQueue *q);

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

enum swDNSLookup_cache_type
{
    SW_DNS_LOOKUP_RANDOM  = (1u << 11),
};

typedef struct
{
    char *hostname;
    char *service;
    int family;
    int socktype;
    int protocol;
    int error;
    void *result;
    int count;
} swRequest_getaddrinfo;

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
    swLock _lock;
    pthread_cond_t _cond;

    int (*wait)(struct _swCond *object);
    int (*timewait)(struct _swCond *object, long, long);
    int (*notify)(struct _swCond *object);
    int (*broadcast)(struct _swCond *object);
    void (*free)(struct _swCond *object);
    int (*lock)(struct _swCond *object);
    int (*unlock)(struct _swCond *object);
} swCond;

#define SW_SHM_MMAP_FILE_LEN  64

typedef struct _swShareMemory_mmap
{
    size_t size;
    char mapfile[SW_SHM_MMAP_FILE_LEN];
    int tmpfd;
    int key;
    int shmid;
    void *mem;
} swShareMemory;

void *swShareMemory_mmap_create(swShareMemory *object, size_t size, char *mapfile);
void *swShareMemory_sysv_create(swShareMemory *object, size_t size, int key);
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
swMemoryPool* swMemoryGlobal_new(uint32_t pagesize, uint8_t shared);

void swFixedPool_debug(swMemoryPool *pool);

/**
 * alloc shared memory
 */
void* sw_shm_malloc(size_t size);
void sw_shm_free(void *ptr);
void* sw_shm_calloc(size_t num, size_t _size);
int sw_shm_protect(void *addr, int flags);
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
    SW_PROCESS_USERWORKER = 5,
};

#define swIsMaster()          (SwooleG.process_type==SW_PROCESS_MASTER)
#define swIsWorker()          (SwooleG.process_type==SW_PROCESS_WORKER)
#define swIsTaskWorker()      (SwooleG.process_type==SW_PROCESS_TASKWORKER)
#define swIsManager()         (SwooleG.process_type==SW_PROCESS_MANAGER)
#define swIsUserWorker()      (SwooleG.process_type==SW_PROCESS_USERWORKER)

//----------------------tool function---------------------
int swLog_init(char *logfile);
void swLog_put(int level, char *cnt);
void swLog_free(void);
#define sw_log(str,...)       {snprintf(sw_error,SW_ERROR_MSG_SIZE,str,##__VA_ARGS__);swLog_put(SW_LOG_INFO, sw_error);}

uint64_t swoole_hash_key(char *str, int str_len);
uint32_t swoole_common_multiple(uint32_t u, uint32_t v);
uint32_t swoole_common_divisor(uint32_t u, uint32_t v);

static sw_inline uint16_t swoole_swap_endian16(uint16_t x)
{
    return (((x & 0xff) << 8) | ((x & 0xff00) >> 8));
}

static sw_inline uint32_t swoole_swap_endian32(uint32_t x)
{
    return (((x & 0xff) << 24) | ((x & 0xff00) << 8) | ((x & 0xff0000) >> 8) | ((x & 0xff000000) >> 24));
}

static sw_inline int32_t swoole_unpack(char type, void *data)
{
    switch(type)
    {
    /*-------------------------16bit-----------------------------*/
    case 'c':
        return *((int8_t *) data);
    case 'C':
        return *((uint8_t *) data);
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
    /**
     * unsigned short (always 32 bit, little endian byte order)
     */
    case 'v':
        return swoole_swap_endian16(ntohs(*((uint16_t *) data)));

    /*-------------------------32bit-----------------------------*/
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
    /**
     * unsigned long (always 32 bit, big endian byte order)
     */
    case 'N':
        return ntohl(*((uint32_t *) data));
    /**
     * unsigned short (always 32 bit, little endian byte order)
     */
    case 'V':
        return swoole_swap_endian32(ntohl(*((uint32_t *) data)));

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

    if (likely(needle_length <= haystack_length))
    {
        for (i = 0; i < haystack_length - needle_length + 1; i++)
        {
            if ((haystack[0] == needle[0]) && (0 == memcmp(haystack, needle, needle_length)))
            {
                return i;
            }
            haystack++;
        }
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

static inline void swoole_strtolower(char *str, int length)
{
    char *c, *e;

    c = str;
    e = c + length;

    while (c < e)
    {
        *c = tolower(*c);
        c++;
    }
}

int swoole_itoa(char *buf, long value);
void swoole_dump_bin(char *data, char type, int size);
void swoole_dump_hex(char *data, int outlen);
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
int swoole_file_put_contents(char *filename, char *content, size_t length);
long swoole_file_size(char *filename);
void swoole_open_remote_debug(void);
char *swoole_dec2hex(int value, int base);
int swoole_version_compare(char *version1, char *version2);
#ifdef HAVE_EXECINFO
void swoole_print_trace(void);
#endif
void swoole_ioctl_set_block(int sock, int nonblock);
void swoole_fcntl_set_option(int sock, int nonblock, int cloexec);
int swoole_gethostbyname(int type, char *name, char *addr);
int swoole_getaddrinfo(swRequest_getaddrinfo *req);
char* swoole_string_format(size_t n, const char *format, ...);
//----------------------core function---------------------
int swSocket_set_timeout(int sock, double timeout);
int swSocket_create_server(int type, char *address, int port, int backlog);
//----------------------------------------Socket---------------------------------------
static sw_inline int swSocket_is_dgram(uint8_t type)
{
    return (type == SW_SOCK_UDP || type == SW_SOCK_UDP6 || type == SW_SOCK_UNIX_DGRAM);
}

static sw_inline int swSocket_is_stream(uint8_t type)
{
    return (type == SW_SOCK_TCP || type == SW_SOCK_TCP6 || type == SW_SOCK_UNIX_STREAM);
}

#ifdef SW_USE_IOCTL
#define swSetNonBlock(sock)   swoole_ioctl_set_block(sock, 1)
#define swSetBlock(sock)      swoole_ioctl_set_block(sock, 0)
#else
#define swSetNonBlock(sock)   swoole_fcntl_set_option(sock, 1, -1)
#define swSetBlock(sock)      swoole_fcntl_set_option(sock, 0, -1)
#endif

void swoole_init(void);
void swoole_clean(void);
double swoole_microtime(void);
void swoole_rtrim(char *str, int len);
void swoole_redirect_stdout(int new_fd);
int swoole_shell_exec(char *command, pid_t *pid);
SW_API int swoole_add_function(const char *name, void* func);
SW_API void* swoole_get_function(char *name, uint32_t length);
SW_API int swoole_add_hook(enum swGlobal_hook_type type, swCallback func, int push_back);
SW_API void swoole_call_hook(enum swGlobal_hook_type type, void *arg);

static sw_inline uint64_t swoole_hton64(uint64_t host)
{
    uint64_t ret = 0;
    uint32_t high, low;

    low = host & 0xFFFFFFFF;
    high = (host >> 32) & 0xFFFFFFFF;
    low = htonl(low);
    high = htonl(high);

    ret = low;
    ret <<= 32;
    ret |= high;
    return ret;
}

static sw_inline uint64_t swoole_ntoh64(uint64_t net)
{
    uint64_t ret = 0;
    uint32_t high, low;

    low = net & 0xFFFFFFFF;
    high = (net >> 32) & 0xFFFFFFFF;
    low = ntohl(low);
    high = ntohl(high);
    ret = low;
    ret <<= 32;
    ret |= high;
    return ret;
}

int swSocket_create(int type);
int swSocket_bind(int sock, int type, char *host, int *port);
int swSocket_wait(int fd, int timeout_ms, int events);
int swSocket_wait_multi(int *list_of_fd, int n_fd, int timeout_ms, int events);
void swSocket_clean(int fd);
ssize_t swSocket_sendto_blocking(int fd, void *__buf, size_t __n, int flag, struct sockaddr *__addr, socklen_t __addr_len);
int swSocket_set_buffer_size(int fd, int buffer_size);
ssize_t swSocket_udp_sendto(int server_sock, char *dst_ip, int dst_port, char *data, uint32_t len);
ssize_t swSocket_udp_sendto6(int server_sock, char *dst_ip, int dst_port, char *data, uint32_t len);
ssize_t swSocket_unix_sendto(int server_sock, char *dst_path, char *data, uint32_t len);
int swSocket_sendfile_sync(int sock, char *filename, off_t offset, size_t length, double timeout);
int swSocket_write_blocking(int __fd, void *__data, int __len);
int swSocket_recv_blocking(int fd, void *__data, size_t __len, int flags);

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

static sw_inline int swKill(pid_t __pid, int __sig)
{
    int ret;
    do
    {
        ret = kill(__pid, __sig);
        if (ret < 0 && errno == EINTR)
        {
            continue;
        }
        break;
    } while (1);
    return ret;
}

#ifdef TCP_CORK
#define HAVE_TCP_NOPUSH
static sw_inline int swSocket_tcp_nopush(int sock, int nopush)
{
    return setsockopt(sock, IPPROTO_TCP, TCP_CORK, (const void *) &nopush, sizeof(int));
}
#else
#define swSocket_tcp_nopush(sock, nopush)
#endif

swSignalHander swSignal_set(int sig, swSignalHander func, int restart, int mask);
void swSignal_add(int signo, swSignalHander func);
void swSignal_callback(int signo);
void swSignal_clear(void);
void swSignal_none(void);

#ifdef HAVE_SIGNALFD
void swSignalfd_init();
int swSignalfd_setup(swReactor *reactor);
#endif

typedef struct _swDefer_callback
{
    struct _swDefer_callback *next, *prev;
    swCallback callback;
    void *data;
} swDefer_callback;

struct _swReactor
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
    uint32_t start :1;
    uint32_t once :1;

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

#ifdef SW_USE_MALLOC_TRIM
    time_t last_malloc_trim_time;
#endif

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
    swDefer_callback *defer_tasks;
    swDefer_callback idle_task;
    swDefer_callback future_task;

    void (*onTimeout)(swReactor *);
    void (*onFinish)(swReactor *);
    void (*onBegin)(swReactor *);

    void (*enable_accept)(swReactor *);
    int (*can_exit)(swReactor *);

    int (*write)(swReactor *, int, void *, int);
    int (*close)(swReactor *, int);
    int (*defer)(swReactor *, swCallback, void *);
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

	swMsgQueue *queue;

	/**
	 * redirect stdout to pipe_master
	 */
	uint8_t redirect_stdout;

	/**
     * redirect stdin to pipe_worker
     */
    uint8_t redirect_stdin;

    /**
     * redirect stderr to pipe_worker
     */
    uint8_t redirect_stderr;

	/**
	 * worker status, IDLE or BUSY
	 */
    uint8_t status;
    uint8_t type;
    uint8_t ipc_mode;
    uint8_t child_process;

    uint8_t traced;
    void (*tracer)(struct _swWorker *);

    /**
     * tasking num
     */
    sw_atomic_t tasking_num;

    time_t start_time;
    time_t request_time;

    long request_count;

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

typedef struct
{
    int socket;
    int last_connection;
    char *socket_file;
    swString *response_buffer;
} swStreamInfo;

struct _swProcessPool
{
    /**
     * reloading
     */
    uint8_t reloading;
    uint8_t reload_init;
    uint8_t dispatch_mode;
    uint8_t ipc_mode;
    uint8_t started;

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
     * use stream socket IPC
     */
    uint8_t use_socket;

    char *packet_buffer;
    uint32_t max_packet_size;

    /**
     * message queue key
     */
    key_t msgqueue_key;


    int worker_num;
    int max_request;

    int (*onTask)(struct _swProcessPool *pool, swEventData *task);

    void (*onWorkerStart)(struct _swProcessPool *pool, int worker_id);
    void (*onMessage)(struct _swProcessPool *pool, char *data, uint32_t length);
    void (*onWorkerStop)(struct _swProcessPool *pool, int worker_id);

    int (*main_loop)(struct _swProcessPool *pool, swWorker *worker);
    int (*onWorkerNotFound)(struct _swProcessPool *pool, pid_t pid, int status);

    sw_atomic_t round_id;
    sw_atomic_t run_worker_num;

    swWorker *workers;
    swPipe *pipes;
    swHashMap *map;
    swReactor *reactor;
    swMsgQueue *queue;
    swStreamInfo *stream;

    void *ptr;
    void *ptr2;
};

//----------------------------------------Reactor---------------------------------------
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
    if (fdtype & SW_EVENT_ONCE)
    {
        events |= SW_EVENT_ONCE;
    }
    return events;
}

int swReactor_create(swReactor *reactor, int max_event);
int swReactor_setHandle(swReactor *, int, swReactor_handle);
int swReactor_empty(swReactor *reactor);

static sw_inline swConnection* swReactor_get(swReactor *reactor, int fd)
{
    if (reactor->thread)
    {
        return &reactor->socket_list[fd];
    }
    swConnection *socket = (swConnection*) swArray_alloc(reactor->socket_array, fd);
    if (socket == NULL)
    {
        return NULL;
    }
    if (!socket->active)
    {
        socket->fd = fd;
    }
    return socket;
}

static sw_inline int swReactor_handle_isset(swReactor *reactor, int _fdtype)
{
    return reactor->handle[_fdtype] != NULL;
}

static sw_inline void swReactor_add(swReactor *reactor, int fd, int type)
{
    swConnection *socket = swReactor_get(reactor, fd);
    socket->fdtype = swReactor_fdtype(type);
    socket->events = swReactor_events(type);
    socket->removed = 0;
}

static sw_inline void swReactor_set(swReactor *reactor, int fd, int type)
{
    swConnection *socket = swReactor_get(reactor, fd);
    socket->events = swReactor_events(type);
}

static sw_inline void swReactor_del(swReactor *reactor, int fd)
{
    swConnection *socket = swReactor_get(reactor, fd);
    socket->events = 0;
    socket->removed = 1;
}

int swReactor_onWrite(swReactor *reactor, swEvent *ev);
int swReactor_close(swReactor *reactor, int fd);
int swReactor_write(swReactor *reactor, int fd, void *buf, int n);
int swReactor_wait_write_buffer(swReactor *reactor, int fd);
void swReactor_activate_future_task(swReactor *reactor);

static sw_inline int swReactor_add_event(swReactor *reactor, int fd, enum swEvent_type event_type)
{
    swConnection *conn = swReactor_get(reactor, fd);
    if (!(conn->events & event_type))
    {
        return reactor->set(reactor, fd, conn->fdtype | conn->events | event_type);
    }
    return SW_OK;
}

static sw_inline int swReactor_del_event(swReactor *reactor, int fd, enum swEvent_type event_type)
{
    swConnection *conn = swReactor_get(reactor, fd);
    if (conn->events & event_type)
    {
        return reactor->set(reactor, fd, conn->fdtype | (conn->events & (~event_type)));
    }
    return SW_OK;
}

static sw_inline int swReactor_remove_read_event(swReactor *reactor, int fd)
{
    swConnection *conn = swReactor_get(reactor, fd);
    if (conn->events & SW_EVENT_WRITE)
    {
        conn->events &= (~SW_EVENT_READ);
        return reactor->set(reactor, fd, conn->fdtype | conn->events);
    }
    else
    {
        return reactor->del(reactor, fd);
    }
}

static sw_inline int swReactor_remove_write_event(swReactor *reactor, int fd)
{
    swConnection *conn = swReactor_get(reactor, fd);
    if (conn->events & SW_EVENT_READ)
    {
        conn->events &= (~SW_EVENT_WRITE);
        return reactor->set(reactor, fd, conn->fdtype | conn->events);
    }
    else
    {
        return reactor->del(reactor, fd);
    }
}

static sw_inline swReactor_handle swReactor_getHandle(swReactor *reactor, int event_type, int fdtype)
{
    if (event_type == SW_EVENT_WRITE)
    {
        return (reactor->write_handle[fdtype] != NULL) ? reactor->write_handle[fdtype] : reactor->handle[SW_FD_WRITE];
    }
    else if (event_type == SW_EVENT_ERROR)
    {
        return (reactor->error_handle[fdtype] != NULL) ? reactor->error_handle[fdtype] : reactor->handle[SW_FD_CLOSE];
    }
    return reactor->handle[fdtype];
}

int swReactorEpoll_create(swReactor *reactor, int max_event_num);
int swReactorPoll_create(swReactor *reactor, int max_event_num);
int swReactorKqueue_create(swReactor *reactor, int max_event_num);
int swReactorSelect_create(swReactor *reactor);

/*----------------------------Process Pool-------------------------------*/
int swProcessPool_create(swProcessPool *pool, int worker_num, int max_request, key_t msgqueue_key, int ipc_mode);
int swProcessPool_create_unix_socket(swProcessPool *pool, char *socket_file, int blacklog);
int swProcessPool_create_tcp_socket(swProcessPool *pool, char *host, int port, int blacklog);
int swProcessPool_set_protocol(swProcessPool *pool, int task_protocol, uint32_t max_packet_size);
int swProcessPool_wait(swProcessPool *pool);
int swProcessPool_start(swProcessPool *pool);
void swProcessPool_shutdown(swProcessPool *pool);
pid_t swProcessPool_spawn(swProcessPool *pool, swWorker *worker);
int swProcessPool_dispatch(swProcessPool *pool, swEventData *data, int *worker_id);
int swProcessPool_response(swProcessPool *pool, char *data, int length);
int swProcessPool_dispatch_blocking(swProcessPool *pool, swEventData *data, int *dst_worker_id);
int swProcessPool_add_worker(swProcessPool *pool, swWorker *worker);
int swProcessPool_del_worker(swProcessPool *pool, swWorker *worker);

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
    off_t head;
    off_t tail;
    size_t size;
    char head_tag;
    char tail_tag;
    int num;
    int max_num;
    /**
     * Data length, excluding structure
     */
    size_t bytes;
    int flag;
    int maxlen;
    /**
     * memory point
     */
    void *mem;
    swLock lock;
    swPipe notify_fd;
} swChannel;

swChannel* swChannel_new(size_t size, int maxlen, int flag);
#define swChannel_empty(ch) (ch->num == 0)
#define swChannel_full(ch) ((ch->head == ch->tail && ch->tail_tag != ch->head_tag) || (ch->bytes + sizeof(int) * ch->num == ch->size))
int swChannel_pop(swChannel *object, void *out, int buffer_length);
int swChannel_push(swChannel *object, void *in, int data_length);
int swChannel_out(swChannel *object, void *out, int buffer_length);
int swChannel_in(swChannel *object, void *in, int data_length);
int swChannel_peek(swChannel *object, void *out, int buffer_length);
int swChannel_wait(swChannel *object);
int swChannel_notify(swChannel *object);
void swChannel_free(swChannel *object);
void swChannel_print(swChannel *);

/*----------------------------LinkedList-------------------------------*/
swLinkedList* swLinkedList_new(uint8_t type, swDestructor dtor);
int swLinkedList_append(swLinkedList *ll, void *data);
void swLinkedList_remove_node(swLinkedList *ll, swLinkedList_node *remove_node);
int swLinkedList_prepend(swLinkedList *ll, void *data);
void* swLinkedList_pop(swLinkedList *ll);
void* swLinkedList_shift(swLinkedList *ll);
swLinkedList_node* swLinkedList_find(swLinkedList *ll, void *data);
void swLinkedList_free(swLinkedList *ll);
#define swLinkedList_remove(ll, data) (swLinkedList_remove_node(ll, swLinkedList_find(ll, data)))
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
    swCond cond;

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
typedef struct _swTimer swTimer;
typedef struct _swTimer_node swTimer_node;

typedef void (*swTimerCallback)(swTimer *, swTimer_node *);

struct _swTimer_node
{
    swHeap_node *heap_node;
    void *data;
    swTimerCallback callback;
    int64_t exec_msec;
    uint32_t interval;
    uint64_t round;
    long id;
    int type;                 //0 normal node 1 node for client_coro
    uint8_t remove;
};

enum swTimer_type
{
    SW_TIMER_TYPE_KERNEL,
    SW_TIMER_TYPE_PHP,
    SW_TIMER_TYPE_CORO_READ,
    SW_TIMER_TYPE_CORO_WRITE,
    SW_TIMER_TYPE_CORO_ALL,
};

struct _swTimer
{
    /*--------------signal timer--------------*/
    swHeap *heap;
    swHashMap *map;
    int num;
    int use_pipe;
    int lasttime;
    int fd;
    uint64_t round;
    long _next_id;
    long _current_id;
    long _next_msec;
    swPipe pipe;
    /*-----------------for EventTimer-------------------*/
    struct timeval basetime;
    /*--------------------------------------------------*/
    int (*set)(swTimer *timer, long exec_msec);
    swTimer_node* (*add)(swTimer *timer, int _msec, int persistent, void *data, swTimerCallback callback);
};

int swTimer_init(long msec);
int swTimer_del(swTimer *timer, swTimer_node *node);
void swTimer_free(swTimer *timer);
int swTimer_select(swTimer *timer);
int swTimer_now(struct timeval *time);

static sw_inline swTimer_node* swTimer_get(swTimer *timer, long id)
{
    return (swTimer_node*) swHashMap_find_int(timer->map, id);
}

int swSystemTimer_init(int msec, int use_pipe);
void swSystemTimer_signal_handler(int sig);
int swSystemTimer_event_handler(swReactor *reactor, swEvent *event);

swTimeWheel* swTimeWheel_new(uint16_t size);
void swTimeWheel_free(swTimeWheel *tw);
void swTimeWheel_forward(swTimeWheel *tw, swReactor *reactor);
void swTimeWheel_add(swTimeWheel *tw, swConnection *conn);
void swTimeWheel_update(swTimeWheel *tw, swConnection *conn);
void swTimeWheel_remove(swTimeWheel *tw, swConnection *conn);
#define swTimeWheel_new_index(tw)   (tw->current == 0 ? tw->size - 1 : tw->current - 1)
//--------------------------------------------------------------
//Share Memory
typedef struct
{
    swLock lock;
    swLock lock_2;
} SwooleGS_t;

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
    uint32_t reactor_exit :1;
    uint32_t in_client :1;
    uint32_t shutdown :1;
    uint32_t wait_exit :1;

    int max_request;

    swString **buffer_input;
    swString **buffer_output;
    swWorker *worker;

} swWorkerG;

typedef struct
{
    uint16_t id;
    uint8_t type;
    uint8_t update_time;
    uint8_t factory_lock_target;
    int16_t factory_target_worker;
    swString **buffer_input;
    swString *buffer_stack;
    swReactor *reactor;
} swThreadG;

typedef struct
{
    union
    {
        char v4[INET_ADDRSTRLEN];
        char v6[INET6_ADDRSTRLEN];
    } address;
} swDNS_server;

typedef struct _swServer swServer;
typedef struct _swFactory swFactory;

typedef struct
{
    swTimer timer;

    uint8_t running :1;
    uint8_t enable_coroutine :1;
    uint8_t use_signalfd :1;
    uint8_t enable_signalfd :1;
    uint8_t reuse_port :1;
    uint8_t socket_dontwait :1;
    uint8_t dns_lookup_random :1;
    uint8_t use_async_resolver :1;

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

    uint8_t log_level;
    char *log_file;
    int trace_flags;

    uint16_t cpu_num;

    uint32_t pagesize;
    uint32_t max_sockets;
    struct utsname uname;

    /**
     * tcp socket default buffer size
     */
    uint32_t socket_buffer_size;

    swServer *serv;
    swFactory *factory;

    swMemoryPool *memory_pool;
    swReactor *main_reactor;

    char *task_tmpdir;
    uint16_t task_tmpdir_len;

    char *dns_server_v4;
    char *dns_server_v6;
    double dns_cache_refresh_time;

    swLock lock;
    swHashMap *functions;
    swLinkedList *hooks[SW_MAX_HOOK_TYPE];

} swServerG;

extern swServerG SwooleG;              //Local Global Variable
extern SwooleGS_t *SwooleGS;           //Share Memory Global Variable
extern swWorkerG SwooleWG;             //Worker Global Variable
extern __thread swThreadG SwooleTG;   //Thread Global Variable

#define SW_CPU_NUM                    (SwooleG.cpu_num)

//-----------------------------------------------
//OS Feature
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
