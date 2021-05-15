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
#elif defined(PHP_ATOM_INC) || defined(ZEND_SIGNALS)
#include "php_config.h"
#endif

#ifdef __cplusplus
#define SW_EXTERN_C_BEGIN extern "C" {
#define SW_EXTERN_C_END   }
#else
#define SW_EXTERN_C_BEGIN
#define SW_EXTERN_C_END
#endif

SW_EXTERN_C_BEGIN

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

/*--- C standard library ---*/
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <math.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <signal.h>
#include <time.h>

#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <poll.h>

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
#include <sys/stat.h>

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

/*----------------------------------------------------------------------------*/

#define SWOOLE_MAJOR_VERSION      4
#define SWOOLE_MINOR_VERSION      4
#define SWOOLE_RELEASE_VERSION    26
#define SWOOLE_EXTRA_VERSION      ""
#define SWOOLE_VERSION            "4.4.26"
#define SWOOLE_VERSION_ID         40426
#define SWOOLE_BUG_REPORT \
    "A bug occurred in Swoole-v" SWOOLE_VERSION ", please report it.\n"\
    "The Swoole developers probably don't know about it,\n"\
    "and unless you report it, chances are it won't be fixed.\n"\
    "You can read How to report a bug doc before submitting any bug reports:\n"\
    ">> https://github.com/swoole/swoole-src/blob/master/.github/ISSUE.md \n"\
    "Please do not send bug reports in the mailing list or personal letters.\n"\
    "The issue page is also suitable to submit feature requests.\n"

/*----------------------------------------------------------------------------*/

#ifndef ulong
#define ulong unsigned long
#endif
typedef unsigned long ulong_t;

#ifndef PRId64
#define PRId64 "lld"
#endif

#ifndef PRIu64
#define PRIu64 "llu"
#endif

#ifndef PRIx64
#define PRIx64 "llx"
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

#if defined(__GNUC__) && __GNUC__ >= 4
#define SW_API __attribute__ ((visibility("default")))
#else
#define SW_API
#endif

#if defined(MAP_ANON) && !defined(MAP_ANONYMOUS)
#define MAP_ANONYMOUS MAP_ANON
#endif

#if defined(MAP_HUGETLB) || defined(MAP_ALIGNED_SUPER)
#define MAP_HUGE_PAGE 1
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

#define sw_likely(x)        __builtin_expect(!!(x), 1)
#define sw_unlikely(x)      __builtin_expect(!!(x), 0)

#define SW_START_LINE  "-------------------------START----------------------------"
#define SW_END_LINE    "--------------------------END-----------------------------"
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

#define SW_SPACE                  ' '
#define SW_CRLF                   "\r\n"
#define SW_CRLF_LEN               2
#define SW_ASCII_CODE_0           64
#define SW_ASCII_CODE_Z           106
/*----------------------------------------------------------------------------*/

#include "swoole_config.h"
#include "atomic.h"
#include "hashmap.h"
#include "list.h"
#include "heap.h"
#include "ring_queue.h"
#include "array.h"
#include "error.h"

#define SW_MAX(A, B)           ((A) > (B) ? (A) : (B))
#define SW_MIN(A, B)           ((A) < (B) ? (A) : (B))

#ifndef MAX
#define MAX(A, B)              SW_MAX(A, B)
#endif
#ifndef MIN
#define MIN(A, B)              SW_MIN(A, B)
#endif

#define SW_NUM_BILLION   (1000 * 1000 *1000)
#define SW_NUM_MILLION   (1000 * 1000)

#ifdef SW_DEBUG
#define SW_ASSERT(e)           assert(e)
#define SW_ASSERT_1BYTE(v)     do { \
    size_t i = 0, n = 0; \
    for (; i < sizeof(v); i++) { \
        n += ((v >> i) & 1) ? 1 : 0; \
    } \
    assert(n == 1); \
} while (0)
#else
#define SW_ASSERT(e)
#define SW_ASSERT_1BYTE(v)
#endif
#define SW_START_SLEEP         usleep(100000)  //sleep 1s,wait fork and pthread_create

/*-----------------------------------Memory------------------------------------*/

// Evaluates to the number of elements in 'array'
#define SW_ARRAY_SIZE(array) (sizeof(array) / sizeof(array[0]))

#define SW_DEFAULT_ALIGNMENT   sizeof(unsigned long)
#define SW_MEM_ALIGNED_SIZE(size) \
        SW_MEM_ALIGNED_SIZE_EX(size, SW_DEFAULT_ALIGNMENT)
#define SW_MEM_ALIGNED_SIZE_EX(size, alignment) \
        (((size) + ((alignment) - 1LL)) & ~((alignment) - 1LL))

#ifdef SW_USE_EMALLOC
#define sw_malloc              emalloc
#define sw_free                efree
#define sw_calloc              ecalloc
#define sw_realloc             erealloc
#else
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
#endif

static sw_inline int sw_mem_equal(const void *v1, size_t s1, const void *v2, size_t s2)
{
    return s1 == s2 && memcmp(v1, v2, s2) == 0;
}

/*----------------------------------String-------------------------------------*/

#define SW_STRS(s)             s, sizeof(s)
#define SW_STRL(s)             s, sizeof(s)-1

#if defined(SW_USE_JEMALLOC) || defined(SW_USE_TCMALLOC)
#define sw_strdup              swoole_strdup
#define sw_strndup             swoole_strndup
#else
#define sw_strdup              strdup
#define sw_strndup             strndup
#endif

#define SW_Z_BEST_SPEED 1

/** always return less than size, zero termination  */
size_t sw_snprintf(char *buf, size_t size, const char *format, ...);
size_t sw_vsnprintf(char *buf, size_t size, const char *format, va_list args);

static sw_inline char* swoole_strdup(const char *s)
{
    size_t l = strlen(s) + 1;
    char *p = (char *) sw_malloc(l);
    if (sw_likely(p))
    {
        memcpy(p, s, l);
    }
    return p;
}

static sw_inline char* swoole_strndup(const char *s, size_t n)
{
    char *p = (char *) sw_malloc(n + 1);
    if (sw_likely(p))
    {
        strncpy(p, s, n)[n] = '\0';
    }
    return p;
}

/* string equal */
static sw_inline unsigned int swoole_streq(const char *str1, size_t len1, const char *str2, size_t len2)
{
    return (len1 == len2) && (strncmp(str1, str2, len1) == 0);
}

static sw_inline unsigned int swoole_strcaseeq(const char *str1, size_t len1, const char *str2, size_t len2)
{
    return (len1 == len2) && (strncasecmp(str1, str2, len1) == 0);
}

static sw_inline unsigned int swoole_strct(const char *pstr, size_t plen, const char *sstr, size_t slen)
{
    return (plen >= slen) && (strncmp(pstr, sstr, slen) == 0);
}

static sw_inline unsigned int swoole_strcasect(const char *pstr, size_t plen, const char *sstr, size_t slen)
{
    return (plen >= slen) && (strncasecmp(pstr, sstr, slen) == 0);
}

#define SW_STREQ(str, len, const_str)      swoole_streq(str, len, SW_STRL(const_str))
#define SW_STRCASEEQ(str, len, const_str)  swoole_strcaseeq(str, len, SW_STRL(const_str))

/* string contain */
#define SW_STRCT(str, len, const_sub_str)      swoole_strct(str, len, SW_STRL(const_sub_str))
#define SW_STRCASECT(str, len, const_sub_str)  swoole_strcasect(str, len, SW_STRL(const_sub_str))

/*--------------------------------Constants------------------------------------*/
enum swResult_code
{
    SW_OK = 0,
    SW_ERR = -1,
};

enum swReturn_code
{
    SW_CONTINUE = 1,
    SW_WAIT     = 2,
    SW_CLOSE    = 3,
    SW_ERROR    = 4,
    SW_READY    = 5,
};

enum swFd_type
{
    SW_FD_SESSION,       //server stream session
    SW_FD_STREAM_SERVER, //server stream port
    SW_FD_DGRAM_SERVER,  //server dgram port
    SW_FD_PIPE,
    SW_FD_STREAM,
    SW_FD_AIO,
    /**
     * Coroutine Socket
     */
    SW_FD_CORO_SOCKET,
    /**
     * socket poll fd [coroutine::socket_poll]
     */
    SW_FD_CORO_POLL,
    SW_FD_SIGNAL, //signalfd
    SW_FD_DNS_RESOLVER,//dns resolver
    /**
     * c-ares
     */
    SW_FD_ARES,
    /**
     * SW_FD_USER or SW_FD_USER+n: for custom event
     */
    SW_FD_USER = 16,
    SW_FD_STREAM_CLIENT,
    SW_FD_DGRAM_CLIENT,
};

enum swBool_type
{
    SW_TRUE = 1,
    SW_FALSE = 0,
};

enum swEvent_type
{
    SW_EVENT_NULL   = 0,
    SW_EVENT_DEAULT = 1u << 8,
    SW_EVENT_READ   = 1u << 9,
    SW_EVENT_WRITE  = 1u << 10,
    SW_EVENT_RDWR   = SW_EVENT_READ | SW_EVENT_WRITE,
    SW_EVENT_ERROR  = 1u << 11,
    SW_EVENT_ONCE   = 1u << 12,
};

enum swPipe_type
{
    SW_PIPE_READ  = 0,
    SW_PIPE_WRITE = 1,
};

enum swGlobal_hook_type
{
    SW_GLOBAL_HOOK_BEFORE_SERVER_START,
    SW_GLOBAL_HOOK_BEFORE_CLIENT_START,
    SW_GLOBAL_HOOK_BEFORE_WORKER_START,
    SW_GLOBAL_HOOK_ON_CORO_START,
    SW_GLOBAL_HOOK_ON_CORO_STOP,
    SW_GLOBAL_HOOK_ON_REACTOR_CREATE,
};

enum swFork_type
{
    SW_FORK_SPAWN    = 0,
    SW_FORK_EXEC     = 1 << 1,
    SW_FORK_DAEMON   = 1 << 2,
    SW_FORK_PRECHECK = 1 << 3,
};

//-------------------------------------------------------------------------------
enum swServer_mode
{
    SW_MODE_BASE         =  1,
    SW_MODE_PROCESS      =  2,
};
//-------------------------------------------------------------------------------
enum swSocket_type
{
    SW_SOCK_TCP          =  1,
    SW_SOCK_UDP          =  2,
    SW_SOCK_TCP6         =  3,
    SW_SOCK_UDP6         =  4,
    SW_SOCK_UNIX_STREAM  =  5,  //unix sock stream
    SW_SOCK_UNIX_DGRAM   =  6,  //unix sock dgram
};
#define SW_SOCK_SSL         (1u << 9)
//-------------------------------------------------------------------------------
enum swLog_level
{
    SW_LOG_DEBUG = 0,
    SW_LOG_TRACE,
    SW_LOG_INFO,
    SW_LOG_NOTICE,
    SW_LOG_WARNING,
    SW_LOG_ERROR,
    SW_LOG_NONE,
};
//-------------------------------------------------------------------------------
enum swWorker_status
{
    SW_WORKER_BUSY = 1,
    SW_WORKER_IDLE = 2,
};
//-------------------------------------------------------------------------------

#define swInfo(str,...) \
    if (SW_LOG_INFO >= SwooleG.log_level) { \
        size_t _sw_error_len = sw_snprintf(sw_error,SW_ERROR_MSG_SIZE,str,##__VA_ARGS__); \
        SwooleG.write_log(SW_LOG_INFO, sw_error, _sw_error_len); \
    }

#define swNotice(str,...) \
    if (SW_LOG_NOTICE >= SwooleG.log_level) { \
        size_t _sw_error_len = sw_snprintf(sw_error,SW_ERROR_MSG_SIZE,str,##__VA_ARGS__); \
        SwooleG.write_log(SW_LOG_NOTICE, sw_error, _sw_error_len); \
    }

#define swSysNotice(str,...) \
    do{ \
        SwooleG.error = errno; \
        if (SW_LOG_ERROR >= SwooleG.log_level) { \
            size_t _sw_error_len = sw_snprintf(sw_error,SW_ERROR_MSG_SIZE,"%s(:%d): " str ", Error: %s[%d]",__func__,__LINE__,##__VA_ARGS__,swoole_strerror(errno),errno); \
            SwooleG.write_log(SW_LOG_NOTICE, sw_error, _sw_error_len); \
        } \
    } while(0)

#define swWarn(str,...) \
    do{ \
        if (SW_LOG_WARNING >= SwooleG.log_level) { \
            size_t _sw_error_len = sw_snprintf(sw_error,SW_ERROR_MSG_SIZE,"%s: " str,__func__,##__VA_ARGS__); \
            SwooleG.write_log(SW_LOG_WARNING, sw_error, _sw_error_len); \
        } \
    } while(0)

#define swSysWarn(str,...) \
    do{ \
        SwooleG.error = errno; \
        if (SW_LOG_ERROR >= SwooleG.log_level) { \
            size_t _sw_error_len = sw_snprintf(sw_error,SW_ERROR_MSG_SIZE,"%s(:%d): " str ", Error: %s[%d]",__func__,__LINE__,##__VA_ARGS__,swoole_strerror(errno),errno); \
            SwooleG.write_log(SW_LOG_WARNING, sw_error, _sw_error_len); \
        } \
    } while(0)

#define swError(str,...) \
    do{ \
        size_t _sw_error_len = sw_snprintf(sw_error, SW_ERROR_MSG_SIZE, str, ##__VA_ARGS__); \
        SwooleG.write_log(SW_LOG_ERROR, sw_error, _sw_error_len); \
        exit(1); \
    } while(0)

#define swSysError(str,...) \
    do{ \
        size_t _sw_error_len = sw_snprintf(sw_error,SW_ERROR_MSG_SIZE,"%s(:%d): " str ", Error: %s[%d]",__func__,__LINE__,##__VA_ARGS__,swoole_strerror(errno),errno); \
        SwooleG.write_log(SW_LOG_ERROR, sw_error, _sw_error_len); \
        exit(1); \
    } while(0)

#define swFatalError(code, str,...) \
    do { \
        SwooleG.fatal_error(code, str, ##__VA_ARGS__); \
        abort(); \
    } while (0)

#define swoole_error_log(level, __errno, str, ...) \
    do{ \
        SwooleG.error = __errno; \
        if (level >= SwooleG.log_level){ \
            size_t _sw_error_len = sw_snprintf(sw_error, SW_ERROR_MSG_SIZE, "%s (ERRNO %d): " str,__func__,__errno,##__VA_ARGS__); \
            SwooleG.write_log(level, sw_error, _sw_error_len); \
        } \
    } while(0)

#ifdef SW_DEBUG
#define swDebug(str,...) \
    if (SW_LOG_DEBUG >= SwooleG.log_level) { \
        size_t _sw_error_len = sw_snprintf(sw_error, SW_ERROR_MSG_SIZE, "%s(:%d): " str, __func__, __LINE__, ##__VA_ARGS__); \
        SwooleG.write_log(SW_LOG_DEBUG, sw_error, _sw_error_len); \
    }

#define swHexDump(data, length) \
    do { \
        const char *__data = (data); \
        size_t __length = (length); \
        swDebug("+----------+------------+-----------+-----------+------------+------------------+"); \
        for (size_t of = 0; of < __length; of += 16) \
        { \
            char hex[16 * 3 + 1]; \
            char str[16 + 1]; \
            size_t i, hof = 0, sof = 0; \
            for (i = of; i < of + 16 && i < __length; i++) \
            { \
                hof += sprintf(hex + hof, "%02x ", (__data)[i] & 0xff); \
                sof += sprintf(str + sof, "%c", isprint((int) (__data)[i]) ? (__data)[i] : '.'); \
            } \
            swDebug("| %08x | %-48s| %-16s |", of, hex, str); \
        } \
        swDebug("+----------+------------+-----------+-----------+------------+------------------+"); \
    } while (0)
#else
#define swDebug(str,...)
#define swHexDump(data, length)
#endif

enum swTrace_type
{
    /**
     * Server
     */
    SW_TRACE_SERVER           = 1u << 1,
    SW_TRACE_CLIENT           = 1u << 2,
    SW_TRACE_BUFFER           = 1u << 3,
    SW_TRACE_CONN             = 1u << 4,
    SW_TRACE_EVENT            = 1u << 5,
    SW_TRACE_WORKER           = 1u << 6,
    SW_TRACE_MEMORY           = 1u << 7,
    SW_TRACE_REACTOR          = 1u << 8,
    SW_TRACE_PHP              = 1u << 9,
    SW_TRACE_HTTP             = 1u << 10,
    SW_TRACE_HTTP2            = 1u << 11,
    SW_TRACE_EOF_PROTOCOL     = 1u << 12,
    SW_TRACE_LENGTH_PROTOCOL  = 1u << 13,
    SW_TRACE_CLOSE            = 1u << 14,
    SW_TRACE_WEBSOCEKT        = 1u << 15,
    /**
     * Client
     */
    SW_TRACE_REDIS_CLIENT     = 1u << 16,
    SW_TRACE_MYSQL_CLIENT     = 1u << 17,
    SW_TRACE_HTTP_CLIENT      = 1u << 18,
    SW_TRACE_AIO              = 1u << 19,
    SW_TRACE_SSL              = 1u << 20,
    SW_TRACE_NORMAL           = 1u << 21,
    /**
     * Coroutine
     */
    SW_TRACE_CHANNEL          = 1u << 22,
    SW_TRACE_TIMER            = 1u << 23,
    SW_TRACE_SOCKET           = 1u << 24,
    SW_TRACE_COROUTINE        = 1u << 25,
    SW_TRACE_CONTEXT          = 1u << 26,
    SW_TRACE_CO_HTTP_SERVER   = 1u << 27,

    SW_TRACE_ALL              = 0xffffffff
};

#ifdef SW_LOG_TRACE_OPEN
#define swTraceLog(what,str,...) \
    if (SW_LOG_TRACE >= SwooleG.log_level && (what & SwooleG.trace_flags)) {\
        size_t _sw_error_len = sw_snprintf(sw_error,SW_ERROR_MSG_SIZE,"%s(:%d): " str, __func__, __LINE__, ##__VA_ARGS__);\
        SwooleG.write_log(SW_LOG_TRACE, sw_error, _sw_error_len);\
    }
#else
#define swTraceLog(what,str,...)
#endif

#define swTrace(str,...)       swTraceLog(SW_TRACE_NORMAL, str, ##__VA_ARGS__)

#define swYield()              sched_yield() //or usleep(1)
#define SW_MAX_FDTYPE          32 //32 kinds of event

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

typedef struct _swSocket
{
    int fd;
    enum swFd_type fdtype;
    enum swSocket_type socket_type;
    int events;

    uchar removed :1;
    uchar nonblock :1;
    uchar direct_send :1;
#ifdef SW_USE_OPENSSL
    uchar ssl_send :1;
    uchar ssl_want_read :1;
    uchar ssl_want_write :1;
    uchar ssl_renegotiation :1;
    uchar ssl_handshake_buffer_set :1;
#endif
    uchar dontwait :1;
    uchar close_wait :1;
    uchar send_wait :1;
    uchar listen_wait :1;
    uchar tcp_nopush :1;
    uchar tcp_nodelay :1;
    uchar skip_recv :1;
    uchar recv_wait :1;
    uchar event_hup :1;

    /**
     * memory buffer size;
     */
    uint32_t buffer_size;

    void *object;

#ifdef SW_USE_OPENSSL
    SSL *ssl;
    uint32_t ssl_state;
#endif

    swSocketAddress info;

    struct _swBuffer *out_buffer;
    struct _swBuffer *in_buffer;
    swString *recv_buffer;

#ifdef SW_DEBUG
    size_t total_recv_bytes;
    size_t total_send_bytes;
#endif

} swSocket;

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
    enum swSocket_type socket_type;
    //--------------------------------------------------------------
    /**
     * is active
     * system fd must be 0. en: signalfd, listen socket
     */
    uint8_t active;
#ifdef SW_USE_OPENSSL
    uint8_t ssl;
    uint8_t ssl_ready;
#endif
    //--------------------------------------------------------------
    uint8_t overflow;
    uint8_t high_watermark;
    //--------------------------------------------------------------
    uint8_t http_upgrade;
#ifdef SW_USE_HTTP2
    uint8_t http2_stream;
#endif
#ifdef SW_HAVE_ZLIB
    uint8_t websocket_compression;
#endif
    //--------------------------------------------------------------
    /**
     * server is actively close the connection
     */
    uint8_t close_actively;
    uint8_t closed;
    uint8_t close_queued;
    uint8_t closing;
    uint8_t close_reset;
    uint8_t peer_closed;
    /**
     * protected connection, cannot be closed by heartbeat thread.
     */
    uint8_t protect;
    //--------------------------------------------------------------
    uint8_t close_notify;
    uint8_t close_force;
    //--------------------------------------------------------------
    /**
     * ReactorThread id
     */
    uint16_t reactor_id;
    /**
     * close error code
     */
    uint16_t close_errno;
    /**
     * from which socket fd
     */
    sw_atomic_t server_fd;
    /**
     * socket address
     */
    swSocketAddress info;
    /**
     * link any thing, for kernel, do not use with application.
     */
    void *object;
    /**
     * socket info
     */
    swSocket *socket;
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
     * upgarde websocket
     */
    uint8_t websocket_status;
    /**
     * unfinished data frame
     */
    swString *websocket_buffer;

#ifdef SW_USE_OPENSSL
    swString *ssl_client_cert;
    uint16_t ssl_client_cert_pid;
#endif
    sw_atomic_t lock;

} swConnection;

typedef struct _swProtocol
{
    /* one package: eof check */
    uint8_t split_by_eof;
    uint8_t package_eof_len;
    char package_eof[SW_DATA_EOF_MAXLEN];

    char package_length_type;
    uint8_t package_length_size;
    uint16_t package_length_offset;
    uint16_t package_body_offset;
    uint32_t package_max_length;

    void *private_data;
    void *private_data_2;
    uint16_t real_header_length;

    int (*onPackage)(struct _swProtocol *, swSocket *, char *, uint32_t);
    ssize_t (*get_package_length)(struct _swProtocol *, swSocket *, char *, uint32_t);
    uint8_t (*get_package_length_size)(swSocket *);
} swProtocol;

typedef ssize_t (*swProtocol_length_function)(struct _swProtocol *, swSocket *, char *, uint32_t);
//------------------------------String--------------------------------
#define swoole_tolower(c)      (uchar) ((c >= 'A' && c <= 'Z') ? (c | 0x20) : c)
#define swoole_toupper(c)      (uchar) ((c >= 'a' && c <= 'z') ? (c & ~0x20) : c)

uint32_t swoole_utf8_decode(uchar **p, size_t n);
size_t swoole_utf8_length(uchar *p, size_t n);
void swoole_random_string(char *buf, size_t size);

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

#define SW_STRINGL(s)      s->str, s->length
#define SW_STRINGS(s)      s->str, s->size
#define SW_STRINGCVL(s)    s->str + s->offset, s->length - s->offset

swString *swString_new(size_t size);
swString *swString_dup(const char *src_str, size_t length);
swString *swString_dup2(swString *src);

void swString_print(swString *str);
int swString_append(swString *str, swString *append_str);
int swString_append_ptr(swString *str, const char *append_str, size_t length);
int swString_write(swString *str, off_t offset, swString *write_str);
int swString_write_ptr(swString *str, off_t offset, char *write_str, size_t length);
int swString_extend(swString *str, size_t new_size);
char* swString_alloc(swString *str, size_t __size);

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

static sw_inline int swString_extend_align(swString *str, size_t _new_size)
{
    size_t align_size = SW_MEM_ALIGNED_SIZE(str->size * 2);
    while (align_size < _new_size)
    {
        align_size *= 2;
    }
    return swString_extend(str, align_size);
}

static sw_inline int swString_grow(swString *str, size_t incr_value)
{
    str->length += incr_value;
    if (str->length == str->size && swString_extend(str, str->size * 2) < 0)
    {
        return SW_ERR;
    }
    else
    {
        return SW_OK;
    }
}

/**
 * migrate data to head, [offset, length - offset] -> [0, length - offset]
 */
static sw_inline void swString_pop_front(swString *str, off_t offset)
{
    assert(offset >= 0 && (size_t ) offset <= str->length);
    if (sw_unlikely(offset == 0)) return;
    str->length = str->length - offset;
    str->offset = 0;
    if (str->length == 0) return;
    memmove(str->str, str->str + offset, str->length);
}

static sw_inline void swString_sub(swString *str, off_t start, size_t length)
{
    char *from = str->str + start + (start >= 0 ? 0 : str->length);
    str->length = length != 0 ? length : str->length - start;
    str->offset = 0;
    if (sw_likely(str->length > 0))
    {
        memmove(str->str, from, str->length);
    }
}

//------------------------------Base--------------------------------
enum _swEventData_flag
{
    SW_EVENT_DATA_NORMAL,
    SW_EVENT_DATA_PTR = 1u << 1,
    SW_EVENT_DATA_CHUNK = 1u << 2,
    SW_EVENT_DATA_END = 1u << 3,
};

typedef struct _swDataHead
{
    int fd;
    uint32_t len;
    int16_t reactor_id;
    uint8_t type;
    uint8_t flags;
    uint16_t server_fd;
#ifdef SW_BUFFER_RECV_TIME
    double time;
#endif
} swDataHead;

void swDataHead_dump(const swDataHead *data);

typedef struct _swEvent
{
    int fd;
    int16_t reactor_id;
    enum swFd_type type;
    swSocket *socket;
} swEvent;

typedef struct
{
    swDataHead info;
    char data[SW_IPC_BUFFER_SIZE];
} swEventData;

typedef struct
{
    swDataHead info;
    char data[0];
} swPipeBuffer;

typedef struct _swDgramPacket
{
    int socket_type;
    swSocketAddress socket_addr;
    uint32_t length;
    char data[0];
} swDgramPacket;

typedef struct _swSendData
{
    swDataHead info;
    char *data;
} swSendData;

typedef struct
{
    off_t offset;
    size_t length;
    char filename[0];
} swSendFile_request;

typedef void (*swSignalHandler)(int);
typedef struct _swReactor swReactor;

typedef int (*swReactor_handler)(swReactor *reactor, swEvent *event);
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

enum swPipe_close_which
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
int swMsgQueue_set_capacity(swMsgQueue *q, int queue_bytes);
int swMsgQueue_push(swMsgQueue *q, swQueue_data *in, int data_length);
int swMsgQueue_pop(swMsgQueue *q, swQueue_data *out, int buffer_length);
int swMsgQueue_stat(swMsgQueue *q, int *queue_num, int *queue_bytes);
int swMsgQueue_free(swMsgQueue *q);
//------------------Lock--------------------------------------
enum SW_LOCKS
{
    SW_RWLOCK = 1,
    SW_FILELOCK = 2,
    SW_MUTEX = 3,
    SW_SEM = 4,
    SW_SPINLOCK = 5,
    SW_ATOMLOCK = 6,
};

enum swDNSLookup_cache_type
{
    SW_DNS_LOOKUP_RANDOM  = (1u << 11),
};

typedef struct
{
    const char *hostname;
    const char *service;
    int family;
    int socktype;
    int protocol;
    int error;
    void *result;
    int count;
} swRequest_getaddrinfo;

typedef struct _swMutex
{
    pthread_mutex_t _lock;
    pthread_mutexattr_t attr;
} swMutex;

typedef struct _swFileLock
{
    struct flock lock_t;
    int fd;
} swFileLock;

#ifdef HAVE_RWLOCK
typedef struct _swRWLock
{
    pthread_rwlock_t _lock;
    pthread_rwlockattr_t attr;

} swRWLock;

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
#endif

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
#ifdef SEM_UNDO
int swSem_create(swLock *lock, key_t key);
#endif
int swFileLock_create(swLock *lock, int fd);
#ifdef HAVE_SPINLOCK
int swSpinLock_create(swLock *object, int spin);
#endif
int swAtomicLock_create(swLock *object, int spin);

int swMutex_create(swLock *lock, int use_in_process);
int swMutex_lockwait(swLock *lock, int timeout_msec);
int swCond_create(swCond *cond);

typedef struct _swThreadParam
{
    void *object;
    int pti;
} swThreadParam;


#ifdef __MACH__
char* sw_error_();
#define sw_error     sw_error_()
#else
extern __thread char sw_error[SW_ERROR_MSG_SIZE];
#endif

enum swProcess_type
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

//----------------------Logger---------------------
int swLog_init(char *logfile);
void swLog_put(int level, char *content, size_t length);
void swLog_reopen(enum swBool_type redirect);
void swLog_free(void);

//----------------------Tool Function---------------------
uint64_t swoole_hash_key(char *str, int str_len);
uint32_t swoole_common_multiple(uint32_t u, uint32_t v);
uint32_t swoole_common_divisor(uint32_t u, uint32_t v);

extern void swoole_sha1(const char *str, int _len, unsigned char *digest);
extern void swoole_sha256(const char *str, int _len, unsigned char *digest);

static sw_inline uint16_t swoole_swap_endian16(uint16_t x)
{
    return (((x & 0xff) << 8) | ((x & 0xff00) >> 8));
}

static sw_inline uint32_t swoole_swap_endian32(uint32_t x)
{
    return (((x & 0xff) << 24) | ((x & 0xff00) << 8) | ((x & 0xff0000) >> 8) | ((x & 0xff000000) >> 24));
}

static sw_inline int32_t swoole_unpack(char type, const void *data)
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

static inline char* swoole_strnstr(const char *haystack, const char *needle, uint32_t length)
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

static inline int swoole_strnpos(const char *haystack, uint32_t haystack_length, const char *needle, uint32_t needle_length)
{
    assert(needle_length > 0);
    uint32_t i;

    if (sw_likely(needle_length <= haystack_length))
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

static inline int swoole_strrnpos(const char *haystack, const char *needle, uint32_t length)
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
void swoole_dump_ascii(const char *data, size_t size);
void swoole_dump_bin(const char *data, char type, size_t size);
void swoole_dump_hex(const char *data, size_t outlen);
int swoole_type_size(char type);
int swoole_mkdir_recursive(const char *dir);
char* swoole_dirname(char *file);
size_t swoole_sync_writefile(int fd, const void *data, size_t len);
size_t swoole_sync_readfile(int fd, void *buf, size_t len);
swString* swoole_sync_readfile_eof(int fd);
int swoole_rand(int min, int max);
int swoole_system_random(int min, int max);
long swoole_file_get_size(FILE *fp);
int swoole_tmpfile(char *filename);
swString* swoole_file_get_contents(const char *filename);
int swoole_file_put_contents(const char *filename, const char *content, size_t length);
long swoole_file_size(const char *filename);
char *swoole_dec2hex(int value, int base);
size_t swoole_hex2dec(char** hex);
int swoole_version_compare(const char *version1, const char *version2);
#ifdef HAVE_EXECINFO
void swoole_print_trace(void);
#endif
int swoole_ioctl_set_block(int sock, int nonblock);
int swoole_fcntl_set_option(int sock, int nonblock, int cloexec);
int swoole_gethostbyname(int type, const char *name, char *addr);
int swoole_getaddrinfo(swRequest_getaddrinfo *req);
char* swoole_string_format(size_t n, const char *format, ...);
//----------------------core function---------------------
int swSocket_set_timeout(int sock, double timeout);
int swSocket_create_server(int type, const char *address, int port, int backlog);
//----------------------------------------Socket---------------------------------------
static sw_inline int swSocket_is_dgram(uint8_t type)
{
    return (type == SW_SOCK_UDP || type == SW_SOCK_UDP6 || type == SW_SOCK_UNIX_DGRAM);
}

static sw_inline int swSocket_is_stream(uint8_t type)
{
    return (type == SW_SOCK_TCP || type == SW_SOCK_TCP6 || type == SW_SOCK_UNIX_STREAM);
}

void swoole_init(void);
void swoole_clean(void);
pid_t swoole_fork(int flags);
double swoole_microtime(void);
void swoole_rtrim(char *str, int len);
void swoole_redirect_stdout(int new_fd);
int swoole_shell_exec(const char *command, pid_t *pid, uint8_t get_error_stream);
int swoole_daemon(int nochdir, int noclose);

SW_API const char* swoole_version(void);
SW_API int swoole_version_id(void);

SW_API int swoole_add_function(const char *name, void* func);
SW_API void* swoole_get_function(const char *name, uint32_t length);
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
    high = net >> 32;
    low = ntohl(low);
    high = ntohl(high);

    ret = low;
    ret <<= 32;
    ret |= high;
    return ret;
}

int swSocket_create(int type);
int swSocket_bind(int sock, int type, const char *host, int *port);
int swSocket_accept(int fd, swSocketAddress *sa);
int swSocket_wait(int fd, int timeout_ms, int events);
int swSocket_wait_multi(int *list_of_fd, int n_fd, int timeout_ms, int events);
void swSocket_clean(int fd);
ssize_t swSocket_sendto_blocking(int fd, const void *buf, size_t n, int flag, struct sockaddr *addr, socklen_t addr_len);
int swSocket_set_buffer_size(int fd, uint32_t buffer_size);
ssize_t swSocket_udp_sendto(int server_sock, const char *dst_ip, int dst_port, const char *data, uint32_t len);
ssize_t swSocket_udp_sendto6(int server_sock, const char *dst_ip, int dst_port, const char *data, uint32_t len);
ssize_t swSocket_unix_sendto(int server_sock, const char *dst_path, const char *data, uint32_t len);
int swSocket_sendfile_sync(int sock, const char *filename, off_t offset, size_t length, double timeout);
int swSocket_write_blocking(int __fd, const void *__data, int __len);
int swSocket_recv_blocking(int fd, void *__data, size_t __len, int flags);

static sw_inline int swSocket_set_nonblock(int sock)
{
    return swoole_fcntl_set_option(sock, 1, -1);
}

static sw_inline int swSocket_set_blocking(int sock)
{
    return swoole_fcntl_set_option(sock, 0, -1);
}

static sw_inline int swoole_waitpid(pid_t __pid, int *__stat_loc, int __options)
{
    int ret;
    do
    {
        ret = waitpid(__pid, __stat_loc, __options);
    } while (ret < 0 && errno == EINTR);
    return ret;
}

static sw_inline int swoole_kill(pid_t __pid, int __sig)
{
    if (__pid <= 0)
    {
        return -1;
    }
    return kill(__pid, __sig);
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

swSignalHandler swSignal_set(int sig, swSignalHandler func, int restart, int mask);
void swSignal_add(int signo, swSignalHandler func);
void swSignal_callback(int signo);
swSignalHandler swSignal_get_handler(int signo);
void swSignal_clear(void);
void swSignal_none(void);
char* swSignal_str(int sig);

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
    uint32_t signal_listener_num;

    uchar check_timer :1;
    uchar running :1;
    uchar start :1;
    uchar once :1;
    uchar wait_exit :1;
    /**
     * callback signal
     */
    uchar check_signalfd :1;
    /**
     * reactor->wait timeout (millisecond) or -1
     */
    int32_t timeout_msec;

    uint16_t id; //Reactor ID
    uint16_t flag; //flag

    uint32_t max_socket;

    swArray *socket_array;

#ifdef SW_USE_MALLOC_TRIM
    time_t last_malloc_trim_time;
#endif

    swReactor_handler read_handler[SW_MAX_FDTYPE];
    swReactor_handler write_handler[SW_MAX_FDTYPE];
    swReactor_handler error_handler[SW_MAX_FDTYPE];

    swReactor_handler default_write_handler;
    swReactor_handler default_error_handler;

    struct _swTimer *timer;

    int (*add)(swReactor *, int fd, int fdtype);
    int (*set)(swReactor *, int fd, int fdtype);
    int (*del)(swReactor *, int fd);
    int (*wait)(swReactor *, struct timeval *);
    void (*free)(swReactor *);

    void *defer_tasks;
    void *destroy_callbacks;

    swDefer_callback idle_task;
    swDefer_callback future_task;

    void (*onTimeout)(swReactor *);
    void (*onFinish)(swReactor *);
    void (*onBegin)(swReactor *);

    int (*is_empty)(swReactor *);

    int (*write)(swReactor *, int, const void *, int);
    int (*close)(swReactor *, int);
    void (*defer)(swReactor *, swCallback, void *);
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
    uchar redirect_stdout :1;

    /**
     * redirect stdin to pipe_worker
     */
    uchar redirect_stdin :1;

    /**
     * redirect stderr to pipe_worker
     */
    uchar redirect_stderr :1;

    /**
     * worker status, IDLE or BUSY
     */
    uint8_t status;
    uint8_t type;
    uint8_t ipc_mode;
    uint8_t child_process;

    /**
     * tasking num
     */
    sw_atomic_t tasking_num;

    time_t start_time;

    long dispatch_count;
    long request_count;

    /**
     * worker id
     */
    uint32_t id;

    swLock lock;

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
    uint32_t reload_worker_i;
    uint32_t max_wait_time;
    swWorker *reload_workers;

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


    uint32_t worker_num;
    uint32_t max_request;
    uint32_t max_request_grace;

    int (*onTask)(struct _swProcessPool *pool, swEventData *task);

    void (*onWorkerStart)(struct _swProcessPool *pool, int worker_id);
    void (*onMessage)(struct _swProcessPool *pool, char *data, uint32_t length);
    void (*onWorkerStop)(struct _swProcessPool *pool, int worker_id);

    int (*main_loop)(struct _swProcessPool *pool, swWorker *worker);
    int (*onWorkerNotFound)(struct _swProcessPool *pool, pid_t pid, int status);

    sw_atomic_t round_id;

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

static sw_inline enum swFd_type swReactor_fdtype(int flags)
{
    return (enum swFd_type) (flags & (~SW_EVENT_READ) & (~SW_EVENT_WRITE) & (~SW_EVENT_ERROR) & (~SW_EVENT_ONCE));
}

static sw_inline int swReactor_events(int flags)
{
    int events = 0;
    if (swReactor_event_read(flags))
    {
        events |= SW_EVENT_READ;
    }
    if (swReactor_event_write(flags))
    {
        events |= SW_EVENT_WRITE;
    }
    if (swReactor_event_error(flags))
    {
        events |= SW_EVENT_ERROR;
    }
    if (flags & SW_EVENT_ONCE)
    {
        events |= SW_EVENT_ONCE;
    }
    return events;
}

int swReactor_create(swReactor *reactor, int max_event);
void swReactor_destroy(swReactor *reactor);
void swReactor_add_destroy_callback(swReactor *reactor, swCallback cb, void *data);

static inline void swReactor_before_wait(swReactor *reactor)
{
    reactor->running = 1;
    reactor->start = 1;
}

#define SW_REACTOR_CONTINUE   if (reactor->once) {break;} else {continue;}

int swReactor_empty(swReactor *reactor);
swSocket* swReactor_get(swReactor *reactor, int fd);

static sw_inline int swReactor_isset_handler(swReactor *reactor, int fdtype)
{
    return reactor->read_handler[fdtype] != NULL;
}

static sw_inline void swReactor_add(swReactor *reactor, int fd, int fdtype)
{
    swSocket *_socket = swReactor_get(reactor, fd);
    _socket->fd = fd;
    _socket->fdtype = swReactor_fdtype(fdtype);
    _socket->events = swReactor_events(fdtype);
    _socket->removed = 0;
    reactor->event_num++;
}

static sw_inline void swReactor_set(swReactor *reactor, int fd, int type)
{
    swSocket *_socket = swReactor_get(reactor, fd);
    _socket->events = swReactor_events(type);
}

static sw_inline void swReactor_del(swReactor *reactor, int fd)
{
    swSocket *_socket = swReactor_get(reactor, fd);
    _socket->events = 0;
    _socket->removed = 1;
    reactor->event_num--;
}

static sw_inline int swReactor_exists(swReactor *reactor, int fd)
{
    swSocket *_socket = swReactor_get(reactor, fd);
    return !_socket->removed && _socket->events;
}

static sw_inline int swReactor_get_timeout_msec(swReactor *reactor)
{
    return reactor->defer_tasks ? 0 : reactor->timeout_msec;
}

int swReactor_onWrite(swReactor *reactor, swEvent *ev);
int swReactor_close(swReactor *reactor, int fd);
int swReactor_write(swReactor *reactor, int fd, const void *buf, int n);
int swReactor_wait_write_buffer(swReactor *reactor, int fd);
void swReactor_activate_future_task(swReactor *reactor);

static sw_inline int swReactor_add_event(swReactor *reactor, int fd, enum swEvent_type event_type)
{
    swSocket *_socket = swReactor_get(reactor, fd);
    if (!(_socket->events & event_type))
    {
        return reactor->set(reactor, fd, _socket->fdtype | _socket->events | event_type);
    }
    return SW_OK;
}

static sw_inline int swReactor_del_event(swReactor *reactor, int fd, enum swEvent_type event_type)
{
    swSocket *_socket = swReactor_get(reactor, fd);
    if (_socket->events & event_type)
    {
        return reactor->set(reactor, fd, _socket->fdtype | (_socket->events & (~event_type)));
    }
    return SW_OK;
}

static sw_inline int swReactor_remove_read_event(swReactor *reactor, int fd)
{
    swSocket *_socket = swReactor_get(reactor, fd);
    if (_socket->events & SW_EVENT_WRITE)
    {
        _socket->events &= (~SW_EVENT_READ);
        return reactor->set(reactor, fd, _socket->fdtype | _socket->events);
    }
    else
    {
        return reactor->del(reactor, fd);
    }
}

static sw_inline int swReactor_remove_write_event(swReactor *reactor, int fd)
{
    swSocket *_socket = swReactor_get(reactor, fd);
    if (_socket->events & SW_EVENT_READ)
    {
        _socket->events &= (~SW_EVENT_WRITE);
        return reactor->set(reactor, fd, _socket->fdtype | _socket->events);
    }
    else
    {
        return reactor->del(reactor, fd);
    }
}

static sw_inline swReactor_handler swReactor_get_handler(swReactor *reactor, enum swEvent_type event_type, enum swFd_type fdtype)
{
    switch(event_type)
    {
    case SW_EVENT_READ:
        return reactor->read_handler[fdtype];
    case SW_EVENT_WRITE:
        return (reactor->write_handler[fdtype] != NULL) ? reactor->write_handler[fdtype] : reactor->default_write_handler;
    case SW_EVENT_ERROR:
        return (reactor->error_handler[fdtype] != NULL) ? reactor->error_handler[fdtype] : reactor->default_error_handler;
    default:
        abort();
        break;
    }
    return NULL;
}

int swReactor_set_handler(swReactor *, int, swReactor_handler);

static sw_inline int swReactor_trigger_close_event(swReactor *reactor, swEvent *event)
{
    return reactor->default_error_handler(reactor, event);
}

int swReactorEpoll_create(swReactor *reactor, int max_event_num);
int swReactorPoll_create(swReactor *reactor, int max_event_num);
int swReactorKqueue_create(swReactor *reactor, int max_event_num);
int swReactorSelect_create(swReactor *reactor);

/*----------------------------Process Pool-------------------------------*/
int swProcessPool_create(swProcessPool *pool, uint32_t worker_num, key_t msgqueue_key, int ipc_mode);
int swProcessPool_create_unix_socket(swProcessPool *pool, char *socket_file, int blacklog);
int swProcessPool_create_tcp_socket(swProcessPool *pool, char *host, int port, int blacklog);
int swProcessPool_set_protocol(swProcessPool *pool, int task_protocol, uint32_t max_packet_size);
void swProcessPool_set_max_request(swProcessPool *pool, uint32_t max_request, uint32_t max_request_grace);
int swProcessPool_wait(swProcessPool *pool);
int swProcessPool_start(swProcessPool *pool);
void swProcessPool_shutdown(swProcessPool *pool);
pid_t swProcessPool_spawn(swProcessPool *pool, swWorker *worker);
int swProcessPool_dispatch(swProcessPool *pool, swEventData *data, int *worker_id);
int swProcessPool_response(swProcessPool *pool, char *data, int length);
int swProcessPool_dispatch_blocking(swProcessPool *pool, swEventData *data, int *dst_worker_id);
int swProcessPool_add_worker(swProcessPool *pool, swWorker *worker);
int swProcessPool_del_worker(swProcessPool *pool, swWorker *worker);
int swProcessPool_get_max_request(swProcessPool *pool);

static sw_inline void swProcessPool_set_start_id(swProcessPool *pool, int start_id)
{
    uint32_t i;
    pool->start_id = start_id;
    for (i = 0; i < pool->worker_num; i++)
    {
        pool->workers[i].id = pool->start_id + i;
    }
}

static sw_inline void swProcessPool_set_type(swProcessPool *pool, int type)
{
    uint32_t i;
    pool->type = type;
    for (i = 0; i < pool->worker_num; i++)
    {
        pool->workers[i].type = type;
    }
}

static sw_inline swWorker* swProcessPool_get_worker(swProcessPool *pool, int worker_id)
{
    return &(pool->workers[worker_id - pool->start_id]);
}

//-----------------------------Channel---------------------------
enum swChannel_flag
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
ssize_t swProtocol_get_package_length(swProtocol *protocol, swSocket *conn, char *data, uint32_t size);
int swProtocol_recv_check_length(swProtocol *protocol, swSocket *conn, swString *buffer);
int swProtocol_recv_check_eof(swProtocol *protocol, swSocket *conn, swString *buffer);

//--------------------------------timer------------------------------
#define SW_TIMER_MIN_MS  1
#define SW_TIMER_MIN_SEC 0.001
#define SW_TIMER_MAX_MS  LONG_MAX
#define SW_TIMER_MAX_SEC ((double) (LONG_MAX / 1000))

typedef struct _swTimer swTimer;
typedef struct _swTimer_node swTimer_node;

typedef void (*swTimerCallback)(swTimer *, swTimer_node *);
typedef void (*swTimerDtor)(swTimer_node *);

enum swTimer_type
{
    SW_TIMER_TYPE_KERNEL,
    SW_TIMER_TYPE_PHP,
};

struct _swTimer_node
{
    /*----------------properties--------------*/
    long id;
    enum swTimer_type type;
    int64_t exec_msec;
    int64_t interval;
    uint64_t round;
    uint8_t removed;
    swHeap_node *heap_node;
    /*-----------------callback---------------*/
    swTimerCallback callback;
    void *data;
    /*-----------------destructor-------------*/
    swTimerDtor dtor;
};

struct _swTimer
{
    /*--------------signal timer--------------*/
    swReactor *reactor;
    swHeap *heap;
    swHashMap *map;
    uint32_t num;
    uint64_t round;
    long _next_id;
    long _current_id;
    long _next_msec;
    /*---------------event timer--------------*/
    struct timeval basetime;
    /*---------------system timer-------------*/
    long lasttime;
    /*----------------------------------------*/
    int (*set)(swTimer *timer, long exec_msec);
    void (*close)(swTimer *timer);
};

int swTimer_init(swTimer *timer, long msec);
void swTimer_reinit(swTimer *timer, swReactor *reactor);
swTimer_node* swTimer_add(swTimer *timer, long _msec, int interval, void *data, swTimerCallback callback);
enum swBool_type swTimer_del(swTimer *timer, swTimer_node *node);
void swTimer_free(swTimer *timer);
int swTimer_select(swTimer *timer);
int swTimer_now(struct timeval *time);

static sw_inline swTimer_node* swTimer_get(swTimer *timer, long id)
{
    return (swTimer_node*) swHashMap_find_int(timer->map, id);
}

static sw_inline swTimer_node* swTimer_get_ex(swTimer *timer, long id, const enum swTimer_type type)
{
    swTimer_node* tnode = swTimer_get(timer, id);
    return (tnode && tnode->type == type) ? tnode : NULL;
}

int swSystemTimer_init(swTimer *timer, long msec);
void swSystemTimer_signal_handler(int sig);
//--------------------------------------------------------------

//Worker process global Variable
typedef struct
{
    /**
     * Always run
     */
    uint8_t run_always;

    /**
     * for timer with block io
     */
    uint8_t signal_alarm;

    /**
     * Current Proccess Worker's id
     */
    uint32_t id;

    /**
     * pipe_worker
     */
    int pipe_used;

    uchar shutdown :1;

    uint32_t max_request;

    swString **buffer_input;
    swString **buffer_output;
    swWorker *worker;
    time_t exit_time;

} swWorkerGlobal_t;

typedef struct
{
    uint16_t id;
    uint8_t type;
    uint8_t update_time;
    swString *buffer_stack;
    swReactor *reactor;
    swTimer *timer;
    uint8_t aio_init;
    uint8_t aio_schedule;
    uint32_t aio_task_num;
    swPipe aio_pipe;
    int aio_pipe_read;
    int aio_pipe_write;
#ifdef SW_AIO_WRITE_LOCK
    swLock aio_lock;
#endif
} swThreadGlobal_t;

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
    uchar init :1;
    uchar running :1;
    uchar enable_coroutine :1;
    uchar use_signalfd :1;
    uchar enable_signalfd :1;
    uchar reuse_port :1;
    uchar socket_dontwait :1;
    uchar dns_lookup_random :1;
    uchar use_async_resolver :1;

    int error;
    int process_type;
    pid_t pid;

    int signal_fd;
    int log_fd;
    int null_fd;

    /**
     * worker(worker and task_worker) process chroot / user / group
     */
    char *chroot;
    char *user;
    char *group;

    uint32_t log_level;
    char *log_file;
    uint32_t trace_flags;

    void (*write_log)(int level, char *content, size_t len);
    void (*fatal_error)(int code, const char *str, ...);

    //-----------------------[System]--------------------------
    uint16_t cpu_num;
    uint32_t pagesize;
    struct utsname uname;

    //-----------------------[Socket]--------------------------
    uint32_t max_sockets;
    /**
     * tcp socket default buffer size
     */
    uint32_t socket_buffer_size;
    swArray *socket_array;
    double socket_send_timeout;

    swServer *serv;

    swMemoryPool *memory_pool;
    swLock lock;

    char *task_tmpdir;
    uint16_t task_tmpdir_len;

    char *dns_server_v4;
    char *dns_server_v6;
    double dns_cache_refresh_time;

    /**
     * aio-threads
     */
    uint32_t aio_core_worker_num;
    uint32_t aio_worker_num;
    double aio_max_wait_time;
    double aio_max_idle_time;
    int aio_default_pipe_fd;

    swHashMap *functions;
    swLinkedList *hooks[SW_MAX_HOOK_TYPE];

} swGlobal_t;

extern swGlobal_t SwooleG;              //Local Global Variable
extern swWorkerGlobal_t SwooleWG;             //Worker Global Variable
extern __thread swThreadGlobal_t SwooleTG;   //Thread Global Variable

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

static sw_inline int64_t swTimer_get_relative_msec()
{
    struct timeval now;
    if (!SwooleTG.timer)
    {
        return SW_ERR;
    }
    if (swTimer_now(&now) < 0)
    {
        return SW_ERR;
    }
    int64_t msec1 = (now.tv_sec - SwooleTG.timer->basetime.tv_sec) * 1000;
    int64_t msec2 = (now.tv_usec - SwooleTG.timer->basetime.tv_usec) / 1000;
    return msec1 + msec2;
}

static sw_inline int64_t swTimer_get_absolute_msec()
{
    struct timeval now;
    if (swTimer_now(&now) < 0)
    {
        return SW_ERR;
    }
    int64_t msec1 = (now.tv_sec) * 1000;
    int64_t msec2 = (now.tv_usec) / 1000;
    return msec1 + msec2;
}

#ifdef HAVE_CLOCK_GETTIME
#define swoole_clock_gettime     clock_gettime
#else
int swoole_clock_gettime(clock_id_t which_clock, struct timespec *t);
#endif

static inline struct timespec swoole_time_until(int milliseconds) {
    struct timespec t;
    swoole_clock_gettime(CLOCK_REALTIME, &t);

    int sec = milliseconds / 1000;
    int msec = milliseconds - (sec * 1000);

    t.tv_sec += sec;
    t.tv_nsec += msec * 1000 * 1000;

    if (t.tv_nsec > SW_NUM_BILLION) {
        int _sec = t.tv_nsec / SW_NUM_BILLION;
        t.tv_sec += _sec;
        t.tv_nsec -= _sec * SW_NUM_BILLION;
    }

    return t;
}

SW_EXTERN_C_END

#endif /* SWOOLE_H_ */
