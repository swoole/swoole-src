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
  |         Twosee  <twose@qq.com>                                       |
  +----------------------------------------------------------------------+
*/

#pragma once

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

#include <list>
#include <memory>
#include <string>
#include <cstdio>
#include <functional>
#include <vector>
#include <set>
#include <map>
#include <chrono>
#include <unordered_map>

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
#include "swoole_version.h"
#include "atomic.h"
#include "buffer.h"
#include "ring_queue.h"
#include "error.h"

#define SW_MAX(A, B)           ((A) > (B) ? (A) : (B))
#define SW_MIN(A, B)           ((A) < (B) ? (A) : (B))

#ifndef MAX
#define MAX(A, B)              SW_MAX(A, B)
#endif
#ifndef MIN
#define MIN(A, B)              SW_MIN(A, B)
#endif

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

#define sw_memset_zero(s, n)   memset(s, '\0', n)

static sw_inline int sw_mem_equal(const void *v1, size_t s1, const void *v2, size_t s2)
{
    return s1 == s2 && memcmp(v1, v2, s2) == 0;
}

/*-------------------------------Declare Struct--------------------------------*/
namespace swoole {
class Reactor;
}
typedef swoole::Reactor swReactor;
struct swTimer_node;
struct swTimer;
struct swMsgQueue;
struct swPipe;
struct swString;
struct swHeap_node;
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

static sw_inline char *swoole_strndup(const char *s, size_t n)
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
    /**
     * event waiter
     */
    SW_FD_CORO_EVENT,
    /**
     * signalfd
     */
    SW_FD_SIGNAL,
    SW_FD_DNS_RESOLVER,
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

enum swLog_rotation_type
{
    SW_LOG_ROTATION_SINGLE = 0,
    SW_LOG_ROTATION_DAILY,
};
//-------------------------------------------------------------------------------

#define swInfo(str,...) \
    if (SW_LOG_INFO >= swLog_get_level()) { \
        size_t _sw_error_len = sw_snprintf(sw_error,SW_ERROR_MSG_SIZE,str,##__VA_ARGS__); \
        SwooleG.write_log(SW_LOG_INFO, sw_error, _sw_error_len); \
    }

#define swNotice(str,...) \
    if (SW_LOG_NOTICE >= swLog_get_level()) { \
        size_t _sw_error_len = sw_snprintf(sw_error,SW_ERROR_MSG_SIZE,str,##__VA_ARGS__); \
        SwooleG.write_log(SW_LOG_NOTICE, sw_error, _sw_error_len); \
    }

#define swSysNotice(str,...) \
    do{ \
        SwooleG.error = errno; \
        if (SW_LOG_ERROR >= swLog_get_level()) { \
            size_t _sw_error_len = sw_snprintf(sw_error,SW_ERROR_MSG_SIZE,"%s(:%d): " str ", Error: %s[%d]",__func__,__LINE__,##__VA_ARGS__,swoole_strerror(errno),errno); \
            SwooleG.write_log(SW_LOG_NOTICE, sw_error, _sw_error_len); \
        } \
    } while(0)

#define swWarn(str,...) \
    do{ \
        if (SW_LOG_WARNING >= swLog_get_level()) { \
            size_t _sw_error_len = sw_snprintf(sw_error,SW_ERROR_MSG_SIZE,"%s: " str,__func__,##__VA_ARGS__); \
            SwooleG.write_log(SW_LOG_WARNING, sw_error, _sw_error_len); \
        } \
    } while(0)

#define swSysWarn(str,...) \
    do{ \
        SwooleG.error = errno; \
        if (SW_LOG_ERROR >= swLog_get_level()) { \
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
        if (level >= swLog_get_level()){ \
            size_t _sw_error_len = sw_snprintf(sw_error, SW_ERROR_MSG_SIZE, "%s (ERRNO %d): " str,__func__,__errno,##__VA_ARGS__); \
            SwooleG.write_log(level, sw_error, _sw_error_len); \
        } \
    } while(0)

#ifdef SW_DEBUG
#define swDebug(str,...) \
    if (SW_LOG_DEBUG >= swLog_get_level()) { \
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
    if (SW_LOG_TRACE >= swLog_get_level() && (what & SwooleG.trace_flags)) {\
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
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
#define SW_SUPPORT_DTLS
#endif
#endif

typedef void (*swDestructor)(void *data);
typedef std::function<void(void *)> swCallback;

struct swAllocator
{
    void* (*malloc)(size_t size);
    void* (*calloc)(size_t nmemb, size_t size);
    void* (*realloc)(void *ptr, size_t size);
    void (*free)(void *ptr);
};

struct swSocketAddress
{
    union
    {
        struct sockaddr ss;
        struct sockaddr_in inet_v4;
        struct sockaddr_in6 inet_v6;
        struct sockaddr_un un;
    } addr;
    socklen_t len;
};

struct swSocket
{
    int fd;
    enum swFd_type fdtype;
    enum swSocket_type socket_type;
    int events;

    uchar removed :1;
    uchar nonblock :1;
    uchar cloexec :1;
    uchar direct_send :1;
#ifdef SW_USE_OPENSSL
    uchar ssl_send :1;
    uchar ssl_want_read :1;
    uchar ssl_want_write :1;
    uchar ssl_renegotiation :1;
    uchar ssl_handshake_buffer_set :1;
    uchar ssl_quiet_shutdown :1;
#ifdef SW_SUPPORT_DTLS
    uchar dtls :1;
#endif
#endif
    uchar dontwait :1;
    uchar close_wait :1;
    uchar send_wait :1;
    uchar tcp_nopush :1;
    uchar tcp_nodelay :1;
    uchar skip_recv :1;
    uchar recv_wait :1;
    uchar event_hup :1;

    /**
     * memory buffer size;
     */
    uint32_t buffer_size;
    uint32_t chunk_size;

    void *object;

#ifdef SW_USE_OPENSSL
    SSL *ssl;
    uint32_t ssl_state;
#endif

    swSocketAddress info;

    swBuffer *out_buffer;
    swBuffer *in_buffer;
    swString *recv_buffer;

#ifdef SW_DEBUG
    size_t total_recv_bytes;
    size_t total_send_bytes;
#endif
};

typedef struct _swTask_sendfile
{
    char *filename;
    uint16_t name_len;
    int fd;
    size_t length;
    off_t offset;
} swTask_sendfile;

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
    uint16_t ext_flags;

    int (*onPackage)(struct _swProtocol *, swSocket *, const char *, uint32_t);
    ssize_t (*get_package_length)(struct _swProtocol *, swSocket *, const char *, uint32_t);
    uint8_t (*get_package_length_size)(swSocket *);
} swProtocol;

typedef ssize_t (*swProtocol_length_function)(struct _swProtocol *, swSocket *, const char *, uint32_t);
//------------------------------String--------------------------------
#define swoole_tolower(c)      (uchar) ((c >= 'A' && c <= 'Z') ? (c | 0x20) : c)
#define swoole_toupper(c)      (uchar) ((c >= 'a' && c <= 'z') ? (c & ~0x20) : c)

uint32_t swoole_utf8_decode(uchar **p, size_t n);
size_t swoole_utf8_length(uchar *p, size_t n);
void swoole_random_string(char *buf, size_t size);
size_t swoole_random_bytes(char *buf, size_t size);

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


//------------------------------Base--------------------------------
enum _swEventData_flag
{
    SW_EVENT_DATA_NORMAL,
    SW_EVENT_DATA_PTR = 1u << 1,
    SW_EVENT_DATA_CHUNK = 1u << 2,
    SW_EVENT_DATA_END = 1u << 3,
    SW_EVENT_DATA_OBJ_PTR = 1u << 4,
    SW_EVENT_DATA_POP_PTR = 1u << 5,
};

typedef struct _swDataHead
{
    int fd;
    uint32_t len;
    int16_t reactor_id;
    uint8_t type;
    uint8_t flags;
    uint16_t server_fd;
    uint16_t ext_flags;
#ifdef SW_BUFFER_RECV_TIME
    double time;
#endif
} swDataHead;

void swDataHead_dump(const swDataHead *data);

#define swTask_type(task)                  ((task)->info.server_fd)

/**
 * use swDataHead->server_fd, 1 byte 8 bit
 */
enum swTask_type
{
    SW_TASK_TMPFILE    = 1,  //tmp file
    SW_TASK_SERIALIZE  = 2,  //php serialize
    SW_TASK_NONBLOCK   = 4,  //task
    SW_TASK_CALLBACK   = 8,  //callback
    SW_TASK_WAITALL    = 16, //for taskWaitAll
    SW_TASK_COROUTINE  = 32, //coroutine
    SW_TASK_PEEK       = 64, //peek
    SW_TASK_NOREPLY    = 128, //don't reply
};

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
    const char *data;
} swSendData;

typedef struct
{
    off_t offset;
    size_t length;
    char filename[0];
} swSendFile_request;

typedef void (*swSignalHandler)(int);

typedef int (*swReactor_handler)(swReactor *reactor, swEvent *event);
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

void *swShareMemory_mmap_create(swShareMemory *object, size_t size, const char *mapfile);
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
swMemoryPool *swFixedPool_new(uint32_t slice_num, uint32_t slice_size, uint8_t shared);
swMemoryPool *swFixedPool_new2(uint32_t slice_size, void *memory, size_t size);

/**
 * RingBuffer, In order for malloc / free
 */
swMemoryPool *swRingBuffer_new(uint32_t size, uint8_t shared);

/**
 * Global memory, the program life cycle only malloc / free one time
 */
swMemoryPool *swMemoryGlobal_new(uint32_t pagesize, uint8_t shared);

void swFixedPool_debug(swMemoryPool *pool);

/**
 * alloc shared memory
 */
void *sw_shm_malloc(size_t size);
void sw_shm_free(void *ptr);
void *sw_shm_calloc(size_t num, size_t _size);
int sw_shm_protect(void *addr, int flags);
void *sw_shm_realloc(void *ptr, size_t new_size);

#ifdef __MACH__
char *sw_error_();
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

enum swIPC_type
{
    SW_IPC_NONE     = 0,
    SW_IPC_UNIXSOCK = 1,
    SW_IPC_MSGQUEUE = 2,
    SW_IPC_SOCKET   = 3,
};

enum swPipe_type
{
    SW_PIPE_WORKER     = 0,
    SW_PIPE_MASTER     = 1,
    SW_PIPE_READ       = 0,
    SW_PIPE_WRITE      = 1,
    SW_PIPE_NONBLOCK   = 2,
};

#define swIsMaster()          (SwooleG.process_type==SW_PROCESS_MASTER)
#define swIsWorker()          (SwooleG.process_type==SW_PROCESS_WORKER)
#define swIsTaskWorker()      (SwooleG.process_type==SW_PROCESS_TASKWORKER)
#define swIsManager()         (SwooleG.process_type==SW_PROCESS_MANAGER)
#define swIsUserWorker()      (SwooleG.process_type==SW_PROCESS_USERWORKER)

//----------------------Logger---------------------
int swLog_open(const char *logfile);
void swLog_put(int level, const char *content, size_t length);
void swLog_reopen();
void swLog_close(void);
void swLog_reset();
void swLog_set_level(int lv);
int swLog_get_level();
int swLog_set_date_format(const char *format);
void swLog_set_rotation(int rotation);
const char *swLog_get_real_file();
const char *swLog_get_file();
int swLog_is_opened();
int swLog_redirect_stdout_and_stderr(int enable);
void swLog_set_date_with_microseconds(uchar enable);

//----------------------Tool Function---------------------
uint64_t swoole_hash_key(const char *str, int str_len);
uint32_t swoole_common_multiple(uint32_t u, uint32_t v);
uint32_t swoole_common_divisor(uint32_t u, uint32_t v);

extern void swoole_sha1(const char *str, int _len, uchar *digest);
extern void swoole_sha256(const char *str, int _len, uchar *digest);

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

static inline const char *swoole_strnstr(const char *haystack, uint32_t haystack_length, const char *needle, uint32_t needle_length)
{
    assert(needle_length > 0);
    uint32_t i;

    if (sw_likely(needle_length <= haystack_length))
    {
        for (i = 0; i < haystack_length - needle_length + 1; i++)
        {
            if ((haystack[0] == needle[0]) && (0 == memcmp(haystack, needle, needle_length)))
            {
                return haystack;
            }
            haystack++;
        }
    }

    return NULL;
}

static inline ssize_t swoole_strnpos(const char *haystack, uint32_t haystack_length, const char *needle, uint32_t needle_length)
{
    assert(needle_length > 0);
    const char *pos;

    pos = swoole_strnstr(haystack, haystack_length, needle, needle_length);
    return pos == NULL ? -1 : pos - haystack;
}

static inline ssize_t swoole_strrnpos(const char *haystack, const char *needle, uint32_t length)
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
swString *swoole_sync_readfile_eof(int fd);
int swoole_rand(int min, int max);
int swoole_system_random(int min, int max);
long swoole_file_get_size(FILE *fp);
int swoole_tmpfile(char *filename);
swString *swoole_file_get_contents(const char *filename);
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
int swoole_get_systemd_listen_fds();

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
SW_API void *swoole_get_function(const char *name, uint32_t length);
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

//------------------------------Socket--------------------------------


//------------------------------Process--------------------------------
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

typedef struct _swDefer_callback
{
    struct _swDefer_callback *next, *prev;
    swCallback callback;
    void *data;
} swDefer_callback;

namespace swoole {

struct Callback
{
    swCallback fn_;
    void *private_data_;

    Callback(swCallback fn, void *private_data) :
            fn_(fn), private_data_(private_data)
    {

    }
};

class CallbackManager
{
public:
    inline void append(swCallback fn, void *private_data)
    {
        list_.emplace_back(fn, private_data);
    }
    inline void prepend(swCallback fn, void *private_data)
    {
        list_.emplace_front(fn, private_data);
    }
    inline void execute()
    {
        while (!list_.empty())
        {
            std::pair<swCallback, void *> task = list_.front();
            list_.pop_front();
            task.first(task.second);
        }
    }
protected:
    std::list<std::pair<swCallback, void *>> list_;
};
}


typedef struct
{
    swSocket *socket;
    swSocket *last_connection;
    char *socket_file;
    swString *response_buffer;
} swStreamInfo;

//--------------------------------protocol------------------------------
ssize_t swProtocol_get_package_length(swProtocol *protocol, swSocket *socket, const char *data, uint32_t size);
int swProtocol_recv_check_length(swProtocol *protocol, swSocket *socket, swString *buffer);
int swProtocol_recv_check_eof(swProtocol *protocol, swSocket *socket, swString *buffer);

//--------------------------------timer------------------------------

typedef void (*swTimerCallback)(swTimer *, swTimer_node *);
typedef void (*swTimerDtor)(swTimer_node *);

enum swTimer_type
{
    SW_TIMER_TYPE_KERNEL,
    SW_TIMER_TYPE_PHP,
};

struct swTimer_node
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

//--------------------------------------------------------------

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
    swPipe *aio_pipe;
    swSocket *aio_read_socket;
    swSocket *aio_write_socket;
    uint32_t signal_listener_num;
    uint32_t co_signal_listener_num;
    int error;
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

typedef struct
{
    uchar init :1;
    uchar running :1;
    uchar enable_coroutine :1;
    uchar use_signalfd :1;
    uchar wait_signal :1;
    uchar enable_signalfd :1;
    uchar socket_dontwait :1;
    uchar dns_lookup_random :1;
    uchar use_async_resolver :1;

    int error;

    int process_type;
    uint32_t process_id;
    pid_t pid;

    int signal_fd;
    bool signal_alarm;

    uint32_t trace_flags;

    void (*write_log)(int level, const char *content, size_t len);
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
    double socket_send_timeout;

    swMemoryPool *memory_pool;
    swAllocator std_allocator;

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
    swSocket *aio_default_socket;

    std::unordered_map<std::string, void*> *functions;
    void *hooks[SW_MAX_HOOK_TYPE];
    std::function<bool(swReactor *reactor, int &event_num)> user_exit_condition;
} swGlobal_t;

extern swGlobal_t SwooleG;              //Local Global Variable
extern thread_local swThreadGlobal_t SwooleTG;   //Thread Global Variable

#define SW_CPU_NUM                    (SwooleG.cpu_num)

static sw_inline void swoole_set_last_error(int error)
{
    SwooleTG.error = error;
}

static sw_inline int swoole_get_last_error()
{
    return SwooleTG.error;
}

SW_API const char* swoole_strerror(int code);
SW_API void swoole_throw_error(int code);

//-----------------------------------------------
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

namespace swoole
{
//-------------------------------------------------------------------------------
namespace std_string
{
template<typename ...Args>
inline std::string format(const char *format, Args ...args)
{
    size_t size = snprintf(nullptr, 0, format, args...) + 1; // Extra space for '\0'
    std::unique_ptr<char[]> buf(new char[size]);
    snprintf(buf.get(), size, format, args...);
    return std::string(buf.get(), buf.get() + size - 1); // We don't want the '\0' inside
}

inline std::string vformat(const char *format, va_list args)
{
    va_list _args;
    va_copy(_args, args);
    size_t size = vsnprintf(nullptr, 0, format, _args) + 1; // Extra space for '\0'
    va_end(_args);
    std::unique_ptr<char[]> buf(new char[size]);
    vsnprintf(buf.get(), size, format, args);
    return std::string(buf.get(), buf.get() + size - 1); // We don't want the '\0' inside
}
}

static inline int hook_add(void **hooks, int type, swCallback func, int push_back)
{
    if (hooks[type] == nullptr)
    {
        hooks[type] = new std::list<swCallback>;
    }

    std::list<swCallback> *l = static_cast<std::list<swCallback>*>(hooks[type]);
    if (push_back)
    {
        l->push_back(func);
    }
    else
    {
        l->push_front(func);
    }

    return SW_OK;
}

static inline void hook_call(void **hooks, int type, void *arg)
{
    std::list<swCallback> *l = static_cast<std::list<swCallback>*>(hooks[type]);
    for (auto i = l->begin(); i != l->end(); i++)
    {
        (*i)(arg);
    }
}

template<typename T>
static inline long time(bool steady = false)
{
    if (steady)
    {
        auto now = std::chrono::steady_clock::now();
        return std::chrono::duration_cast<T>(now.time_since_epoch()).count();
    }
    else
    {
        auto now = std::chrono::system_clock::now();
        return std::chrono::duration_cast<T>(now.time_since_epoch()).count();
    }
}

std::string intersection(std::vector<std::string> &vec1, std::set<std::string> &vec2);

}
