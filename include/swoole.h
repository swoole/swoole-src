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
#define SW_EXTERN_C_END }
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
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <sched.h> /* sched_yield() */
#include <pthread.h>

#include <sys/utsname.h>
#include <sys/time.h>

#include <memory>
#include <functional>

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
#define SW_API __attribute__((visibility("default")))
#else
#define SW_API
#endif

#if !defined(__GNUC__) || __GNUC__ < 3
#define __builtin_expect(x, expected_value) (x)
#endif

#define sw_likely(x) __builtin_expect(!!(x), 1)
#define sw_unlikely(x) __builtin_expect(!!(x), 0)

#define SW_START_LINE "-------------------------START----------------------------"
#define SW_END_LINE "--------------------------END-----------------------------"
#define SW_ECHO_RED "\e[31m%s\e[0m"
#define SW_ECHO_GREEN "\e[32m%s\e[0m"
#define SW_ECHO_YELLOW "\e[33m%s\e[0m"
#define SW_ECHO_BLUE "\e[34m%s\e[0m"
#define SW_ECHO_MAGENTA "\e[35m%s\e[0m"
#define SW_ECHO_CYAN "\e[36m%s\e[0m"
#define SW_ECHO_WHITE "\e[37m%s\e[0m"
#define SW_COLOR_RED 1
#define SW_COLOR_GREEN 2
#define SW_COLOR_YELLOW 3
#define SW_COLOR_BLUE 4
#define SW_COLOR_MAGENTA 5
#define SW_COLOR_CYAN 6
#define SW_COLOR_WHITE 7

#define SW_SPACE ' '
#define SW_CRLF "\r\n"
#define SW_CRLF_LEN 2
#define SW_ASCII_CODE_0 64
#define SW_ASCII_CODE_Z 106
/*----------------------------------------------------------------------------*/

#include "swoole_config.h"
#include "swoole_version.h"
#include "swoole_log.h"
#include "swoole_atomic.h"
#include "swoole_error.h"

#define SW_MAX(A, B) ((A) > (B) ? (A) : (B))
#define SW_MIN(A, B) ((A) < (B) ? (A) : (B))

#ifndef MAX
#define MAX(A, B) SW_MAX(A, B)
#endif
#ifndef MIN
#define MIN(A, B) SW_MIN(A, B)
#endif

#define SW_NUM_BILLION   (1000 * 1000 * 1000)
#define SW_NUM_MILLION   (1000 * 1000)

#ifdef SW_DEBUG
#define SW_ASSERT(e) assert(e)
#define SW_ASSERT_1BYTE(v)                                                                                             \
    do {                                                                                                               \
        size_t i = 0, n = 0;                                                                                           \
        for (; i < sizeof(v); i++) {                                                                                   \
            n += ((v >> i) & 1) ? 1 : 0;                                                                               \
        }                                                                                                              \
        assert(n == 1);                                                                                                \
    } while (0)
#else
#define SW_ASSERT(e)
#define SW_ASSERT_1BYTE(v)
#endif
#define SW_START_SLEEP usleep(100000)  // sleep 1s,wait fork and pthread_create

/*-----------------------------------Memory------------------------------------*/

// Evaluates to the number of elements in 'array'
#define SW_ARRAY_SIZE(array) (sizeof(array) / sizeof(array[0]))

#define SW_DEFAULT_ALIGNMENT sizeof(unsigned long)
#define SW_MEM_ALIGNED_SIZE(size) SW_MEM_ALIGNED_SIZE_EX(size, SW_DEFAULT_ALIGNMENT)
#define SW_MEM_ALIGNED_SIZE_EX(size, alignment) (((size) + ((alignment) -1LL)) & ~((alignment) -1LL))

#ifdef SW_USE_EMALLOC
#define sw_malloc emalloc
#define sw_free efree
#define sw_calloc ecalloc
#define sw_realloc erealloc
#else
#ifdef SW_USE_JEMALLOC
#include <jemalloc/jemalloc.h>
#define sw_malloc je_malloc
#define sw_free je_free
#define sw_calloc je_calloc
#define sw_realloc je_realloc
#else
#define sw_malloc malloc
#define sw_free free
#define sw_calloc calloc
#define sw_realloc realloc
#endif
#endif

/*-------------------------------Declare Struct--------------------------------*/
namespace swoole {
class Reactor;
class String;
class Timer;
struct TimerNode;
struct Event;
struct Pipe;
namespace network {
struct Socket;
struct Address;
}  // namespace network
struct Protocol;
struct EventData;
struct DataHead;
typedef int (*ReactorHandler)(Reactor *reactor, Event *event);
typedef std::function<void(void *)> Callback;
typedef std::function<void(Timer *, TimerNode *)> TimerCallback;
}  // namespace swoole

typedef swoole::Reactor swReactor;
typedef swoole::String swString;
typedef swoole::Timer swTimer;
typedef swoole::network::Socket swSocket;
typedef swoole::Protocol swProtocol;
typedef swoole::EventData swEventData;
typedef swoole::DataHead swDataHead;
typedef swoole::Event swEvent;
typedef swoole::Pipe swPipe;
typedef swoole::Callback swCallback;

struct swMemoryPool;
/*----------------------------------String-------------------------------------*/

#define SW_STRS(s) s, sizeof(s)
#define SW_STRL(s) s, sizeof(s) - 1

#define SW_STREQ(str, len, const_str) swoole_streq(str, len, SW_STRL(const_str))
#define SW_STRCASEEQ(str, len, const_str) swoole_strcaseeq(str, len, SW_STRL(const_str))

/* string contain */
#define SW_STRCT(str, len, const_sub_str) swoole_strct(str, len, SW_STRL(const_sub_str))
#define SW_STRCASECT(str, len, const_sub_str) swoole_strcasect(str, len, SW_STRL(const_sub_str))

#if defined(SW_USE_JEMALLOC) || defined(SW_USE_TCMALLOC)
#define sw_strdup swoole_strdup
#define sw_strndup swoole_strndup
#else
#define sw_strdup strdup
#define sw_strndup strndup
#endif

/** always return less than size, zero termination  */
size_t sw_snprintf(char *buf, size_t size, const char *format, ...);
size_t sw_vsnprintf(char *buf, size_t size, const char *format, va_list args);

#define sw_memset_zero(s, n) memset(s, '\0', n)

static sw_inline int sw_mem_equal(const void *v1, size_t s1, const void *v2, size_t s2) {
    return s1 == s2 && memcmp(v1, v2, s2) == 0;
}

static inline size_t swoole_strlcpy(char *dest, const char *src, size_t size) {
    const size_t len = strlen(src);
    if (size != 0) {
        const size_t n = std::min(len, size - 1);
        memcpy(dest, src, n);
        dest[n] = '\0';
    }
    return len;
}

static inline char *swoole_strdup(const char *s) {
    size_t l = strlen(s) + 1;
    char *p = (char *) sw_malloc(l);
    if (sw_likely(p)) {
        memcpy(p, s, l);
    }
    return p;
}

static inline char *swoole_strndup(const char *s, size_t n) {
    char *p = (char *) sw_malloc(n + 1);
    if (sw_likely(p)) {
        strncpy(p, s, n)[n] = '\0';
    }
    return p;
}

/* string equal */
static inline unsigned int swoole_streq(const char *str1, size_t len1, const char *str2, size_t len2) {
    return (len1 == len2) && (strncmp(str1, str2, len1) == 0);
}

static inline unsigned int swoole_strcaseeq(const char *str1, size_t len1, const char *str2, size_t len2) {
    return (len1 == len2) && (strncasecmp(str1, str2, len1) == 0);
}

static inline unsigned int swoole_strct(const char *pstr, size_t plen, const char *sstr, size_t slen) {
    return (plen >= slen) && (strncmp(pstr, sstr, slen) == 0);
}

static inline unsigned int swoole_strcasect(const char *pstr, size_t plen, const char *sstr, size_t slen) {
    return (plen >= slen) && (strncasecmp(pstr, sstr, slen) == 0);
}

static inline const char *swoole_strnstr(const char *haystack,
                                         uint32_t haystack_length,
                                         const char *needle,
                                         uint32_t needle_length) {
    assert(needle_length > 0);
    uint32_t i;

    if (sw_likely(needle_length <= haystack_length)) {
        for (i = 0; i < haystack_length - needle_length + 1; i++) {
            if ((haystack[0] == needle[0]) && (0 == memcmp(haystack, needle, needle_length))) {
                return haystack;
            }
            haystack++;
        }
    }

    return NULL;
}

static inline ssize_t swoole_strnpos(const char *haystack,
                                     uint32_t haystack_length,
                                     const char *needle,
                                     uint32_t needle_length) {
    assert(needle_length > 0);
    const char *pos;

    pos = swoole_strnstr(haystack, haystack_length, needle, needle_length);
    return pos == NULL ? -1 : pos - haystack;
}

static inline ssize_t swoole_strrnpos(const char *haystack, const char *needle, uint32_t length) {
    uint32_t needle_length = strlen(needle);
    assert(needle_length > 0);
    uint32_t i;
    haystack += (length - needle_length);

    for (i = length - needle_length; i > 0; i--) {
        if ((haystack[0] == needle[0]) && (0 == memcmp(haystack, needle, needle_length))) {
            return i;
        }
        haystack--;
    }

    return -1;
}

static inline void swoole_strtolower(char *str, int length) {
    char *c, *e;

    c = str;
    e = c + length;

    while (c < e) {
        *c = tolower(*c);
        c++;
    }
}

/*--------------------------------Constants------------------------------------*/
enum swResult_code {
    SW_OK  = 0,
    SW_ERR = -1,
};

enum swReturn_code {
    SW_CONTINUE = 1,
    SW_WAIT     = 2,
    SW_CLOSE    = 3,
    SW_ERROR    = 4,
    SW_READY    = 5,
};

enum swFd_type {
    SW_FD_SESSION,        // server stream session
    SW_FD_STREAM_SERVER,  // server stream port
    SW_FD_DGRAM_SERVER,   // server dgram port
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

enum swSocket_flag {
    SW_SOCK_NONBLOCK = 1 << 2,
    SW_SOCK_CLOEXEC  = 1 << 3,
    SW_SOCK_SSL      = (1u << 9),
};

enum swSocket_type {
    SW_SOCK_TCP         = 1,
    SW_SOCK_UDP         = 2,
    SW_SOCK_TCP6        = 3,
    SW_SOCK_UDP6        = 4,
    SW_SOCK_UNIX_STREAM = 5,  // unix sock stream
    SW_SOCK_UNIX_DGRAM  = 6,  // unix sock dgram
};

enum swEvent_type {
    SW_EVENT_NULL   = 0,
    SW_EVENT_DEAULT = 1u << 8,
    SW_EVENT_READ   = 1u << 9,
    SW_EVENT_WRITE  = 1u << 10,
    SW_EVENT_RDWR   = SW_EVENT_READ | SW_EVENT_WRITE,
    SW_EVENT_ERROR  = 1u << 11,
    SW_EVENT_ONCE   = 1u << 12,
};

enum swFork_type {
    SW_FORK_SPAWN    = 0,
    SW_FORK_EXEC     = 1 << 1,
    SW_FORK_DAEMON   = 1 << 2,
    SW_FORK_PRECHECK = 1 << 3,
};

//-------------------------------------------------------------------------------
#define sw_yield() sched_yield()

//------------------------------Base--------------------------------
#ifndef uchar
typedef unsigned char uchar;
#endif

struct swAllocator {
    void *(*malloc)(size_t size);
    void *(*calloc)(size_t nmemb, size_t size);
    void *(*realloc)(void *ptr, size_t size);
    void (*free)(void *ptr);
};

#define swoole_tolower(c) (uchar)((c >= 'A' && c <= 'Z') ? (c | 0x20) : c)
#define swoole_toupper(c) (uchar)((c >= 'a' && c <= 'z') ? (c & ~0x20) : c)

void swoole_random_string(char *buf, size_t size);
size_t swoole_random_bytes(char *buf, size_t size);

static sw_inline char *swoole_strlchr(char *p, char *last, char c) {
    while (p < last) {
        if (*p == c) {
            return p;
        }
        p++;
    }
    return NULL;
}

static sw_inline size_t swoole_size_align(size_t size, int pagesize) {
    return size + (pagesize - (size % pagesize));
}

//------------------------------Base--------------------------------
enum swEventData_flag {
    SW_EVENT_DATA_NORMAL,
    SW_EVENT_DATA_PTR     = 1u << 1,
    SW_EVENT_DATA_CHUNK   = 1u << 2,
    SW_EVENT_DATA_END     = 1u << 3,
    SW_EVENT_DATA_OBJ_PTR = 1u << 4,
    SW_EVENT_DATA_POP_PTR = 1u << 5,
};

namespace swoole {
struct Event {
    int fd;
    int16_t reactor_id;
    enum swFd_type type;
    network::Socket *socket;
};

struct DataHead {
    int fd;
    uint32_t len;
    int16_t reactor_id;
    uint8_t type;
    uint8_t flags;
    uint16_t server_fd;
    uint16_t ext_flags;
    double time;
    size_t dump(char *buf, size_t len);
};

struct EventData {
    DataHead info;
    char data[SW_IPC_BUFFER_SIZE];
    bool pack(const void *data, size_t data_len);
    bool unpack(String *buffer);
};

}  // namespace swoole

#define swTask_type(task) ((task)->info.server_fd)

/**
 * use swDataHead->server_fd, 1 byte 8 bit
 */
enum swTask_type {
    SW_TASK_TMPFILE   = 1,    // tmp file
    SW_TASK_SERIALIZE = 2,    // php serialize
    SW_TASK_NONBLOCK  = 4,    // task
    SW_TASK_CALLBACK  = 8,    // callback
    SW_TASK_WAITALL   = 16,   // for taskWaitAll
    SW_TASK_COROUTINE = 32,   // coroutine
    SW_TASK_PEEK      = 64,   // peek
    SW_TASK_NOREPLY   = 128,  // don't reply
};

enum swDNSLookup_cache_type {
    SW_DNS_LOOKUP_RANDOM = (1u << 11),
};

#ifdef __MACH__
char *sw_error_();
#define sw_error sw_error_()
#else
extern __thread char sw_error[SW_ERROR_MSG_SIZE];
#endif

enum swProcess_type {
    SW_PROCESS_MASTER     = 1,
    SW_PROCESS_WORKER     = 2,
    SW_PROCESS_MANAGER    = 3,
    SW_PROCESS_TASKWORKER = 4,
    SW_PROCESS_USERWORKER = 5,
};

enum swPipe_type {
    SW_PIPE_WORKER   = 0,
    SW_PIPE_MASTER   = 1,
    SW_PIPE_READ     = 0,
    SW_PIPE_WRITE    = 1,
    SW_PIPE_NONBLOCK = 2,
};

//----------------------Tool Function---------------------
uint32_t swoole_common_multiple(uint32_t u, uint32_t v);
uint32_t swoole_common_divisor(uint32_t u, uint32_t v);

int swoole_itoa(char *buf, long value);
bool swoole_mkdir_recursive(const std::string &dir);

int swoole_rand(int min, int max);
int swoole_system_random(int min, int max);

int swoole_version_compare(const char *version1, const char *version2);
#ifdef HAVE_EXECINFO
void swoole_print_trace(void);
#endif
char *swoole_string_format(size_t n, const char *format, ...);
bool swoole_get_env(const char *name, int *value);
int swoole_get_systemd_listen_fds();

void swoole_init(void);
void swoole_clean(void);
pid_t swoole_fork(int flags);
double swoole_microtime(void);
void swoole_rtrim(char *str, int len);
void swoole_redirect_stdout(int new_fd);
int swoole_shell_exec(const char *command, pid_t *pid, bool get_error_stream);
int swoole_daemon(int nochdir, int noclose);
bool swoole_set_task_tmpdir(const std::string &dir);
int swoole_tmpfile(char *filename);

#ifdef HAVE_CPU_AFFINITY
#ifdef __FreeBSD__
#include <sys/types.h>
#include <sys/cpuset.h>
#include <pthread_np.h>
typedef cpuset_t cpu_set_t;
#endif
int swoole_set_cpu_affinity(cpu_set_t *set);
#endif

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

struct swThreadGlobal {
    uint16_t id;
    uint8_t type;
    uint8_t update_time;
    swoole::String *buffer_stack;
    swoole::Reactor *reactor;
    swoole::Timer *timer;
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
};

struct swGlobal {
    uchar init : 1;
    uchar running : 1;
    uchar enable_coroutine : 1;
    uchar use_signalfd : 1;
    uchar wait_signal : 1;
    uchar enable_signalfd : 1;
    uchar socket_dontwait : 1;
    uchar dns_lookup_random : 1;
    uchar use_async_resolver : 1;

    int process_type;
    uint32_t process_id;
    long task_id;
    pid_t pid;

    int signal_fd;
    bool signal_alarm;

    uint32_t trace_flags;

    void (*fatal_error)(int code, const char *str, ...);

    //-----------------------[System]--------------------------
    uint16_t cpu_num;
    uint32_t pagesize;
    struct utsname uname;
    uint32_t max_sockets;
    //-----------------------[Memory]--------------------------
    swMemoryPool *memory_pool;
    swAllocator std_allocator;
    std::string task_tmpfile;
    //-----------------------[DNS]--------------------------
    char *dns_server_v4;
    char *dns_server_v6;
    double dns_cache_refresh_time;
    //-----------------------[AIO]--------------------------
    uint32_t aio_core_worker_num;
    uint32_t aio_worker_num;
    double aio_max_wait_time;
    double aio_max_idle_time;
    swoole::network::Socket *aio_default_socket;
    //-----------------------[Hook]--------------------------
    void *hooks[SW_MAX_HOOK_TYPE];
    std::function<bool(swoole::Reactor *reactor, int &event_num)> user_exit_condition;
};

extern swGlobal SwooleG;                  // Local Global Variable
extern __thread swThreadGlobal SwooleTG;  // Thread Global Variable

#define SW_CPU_NUM (SwooleG.cpu_num)

static inline void swoole_set_last_error(int error) {
    SwooleTG.error = error;
}

static inline int swoole_get_last_error() {
    return SwooleTG.error;
}

static inline int swoole_get_thread_id() {
    return SwooleTG.id;
}

static inline int swoole_get_process_type() {
    return SwooleG.process_type;
}

static inline int swoole_get_process_id() {
    return SwooleG.process_id;
}

SW_API const char *swoole_strerror(int code);
SW_API void swoole_throw_error(int code);

//-----------------------------------------------
static sw_inline void sw_spinlock(sw_atomic_t *lock) {
    uint32_t i, n;
    while (1) {
        if (*lock == 0 && sw_atomic_cmp_set(lock, 0, 1)) {
            return;
        }
        if (SW_CPU_NUM > 1) {
            for (n = 1; n < SW_SPINLOCK_LOOP_N; n <<= 1) {
                for (i = 0; i < n; i++) {
                    sw_atomic_cpu_pause();
                }

                if (*lock == 0 && sw_atomic_cmp_set(lock, 0, 1)) {
                    return;
                }
            }
        }
        sw_yield();
    }
}

static sw_inline swoole::String *sw_tg_buffer() {
   return SwooleTG.buffer_stack;
}

namespace swoole {
std::string dirname(const std::string &file);
int hook_add(void **hooks, int type, const Callback &func, int push_back);
void hook_call(void **hooks, int type, void *arg);
}  // namespace swoole
