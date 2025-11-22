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
  | Author: Tianfeng Han  <rango@swoole.com>                             |
  |         Twosee  <twose@qq.com>                                       |
  +----------------------------------------------------------------------+
*/

#pragma once

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(ENABLE_PHP_SWOOLE)
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

#ifndef _PTHREAD_PSHARED
#define _PTHREAD_PSHARED
#endif

/*--- C standard library ---*/
#include <cassert>
#include <cctype>
#include <cstdarg>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <climits>
#include <unistd.h>
#include <pthread.h>
#include <inttypes.h>

#include <sys/uio.h>
#include <sys/utsname.h>

#include <string>
#include <memory>
#include <list>
#include <functional>
#include <mutex>

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

#define SW_ECHO_LEN_RED "\e[31m%.*s\e[0m"
#define SW_ECHO_LEN_GREEN "\e[32m%.*s\e[0m"
#define SW_ECHO_LEN_YELLOW "\e[33m%.*s\e[0m"
#define SW_ECHO_LEN_BLUE "\e[34m%.*s\e[0m"
#define SW_ECHO_LEN_MAGENTA "\e[35m%.*s\e[0m"
#define SW_ECHO_LEN_CYAN "\e[36m%.*s\e[0m"
#define SW_ECHO_LEN_WHITE "\e[37m%.*s\e[0m"

#define SW_ECHO_RED_BG "\e[41m%s\e[0m"
#define SW_ECHO_GREEN_BG "\e[42m%s\e[0m"

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
#define SW_LOOP_N(n) for (decltype(n) i = 0; i < n; i++)
#define SW_LOOP for (;;)

#ifndef MAYBE_UNUSED
#ifdef __GNUC__
#define MAYBE_UNUSED __attribute__((used))
#else
#define MAYBE_UNUSED
#endif
#endif

#ifndef MAX
#define MAX(A, B) SW_MAX(A, B)
#endif
#ifndef MIN
#define MIN(A, B) SW_MIN(A, B)
#endif

#define SW_NUM_BILLION (1000 * 1000 * 1000)
#define SW_NUM_MILLION (1000 * 1000)

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
#define SW_START_SLEEP usleep(100000)  // sleep 0.1s, wait fork and pthread_create

#ifdef SW_THREAD
#define SW_THREAD_LOCAL thread_local
extern std::mutex sw_thread_lock;
#else
#define SW_THREAD_LOCAL
#endif

/**
 * API naming rules
 * -----------------------------------
 * - starts with swoole_, means it is ready or has been used as an external API
 * - starts with sw_, internal use only
 */

/*-----------------------------------Memory------------------------------------*/
void *sw_malloc(size_t size);
void sw_free(void *ptr);
void *sw_calloc(size_t nmemb, size_t size);
void *sw_realloc(void *ptr, size_t size);

// Evaluates to the number of elements in 'array'
#define SW_ARRAY_SIZE(array) (sizeof(array) / sizeof(array[0]))

#define SW_DEFAULT_ALIGNMENT sizeof(unsigned long)
#define SW_MEM_ALIGNED_SIZE(size) SW_MEM_ALIGNED_SIZE_EX(size, SW_DEFAULT_ALIGNMENT)
#define SW_MEM_ALIGNED_SIZE_EX(size, alignment) (((size) + ((alignment) -1LL)) & ~((alignment) -1LL))

/*-------------------------------Declare Struct--------------------------------*/
namespace swoole {
class MemoryPool;
class Reactor;
class String;
class Timer;
struct TimerNode;
struct Event;
class Pipe;
class MessageBus;
class Server;
namespace network {
struct Socket;
struct Address;
}  // namespace network
class AsyncThreads;
#ifdef SW_USE_IOURING
class Iouring;
#endif
namespace async {
class ThreadPool;
}
struct Protocol;
struct EventData;
struct DataHead;
typedef int (*ReactorHandler)(Reactor *reactor, Event *event);
typedef std::function<void(void *)> Callback;
typedef std::function<void(Timer *, TimerNode *)> TimerCallback;
}  // namespace swoole

typedef swoole::DataHead swDataHead;

/*----------------------------------String-------------------------------------*/

#define SW_STRS(s) s, sizeof(s)
#define SW_STRL(s) s, sizeof(s) - 1

#define SW_STREQ(str, len, const_str) swoole_streq(str, len, SW_STRL(const_str))
#define SW_STRCASEEQ(str, len, const_str) swoole_strcaseeq(str, len, SW_STRL(const_str))

#define SW_STR_STARTS_WITH(str, len, const_sub_str) swoole_str_starts_with(str, len, SW_STRL(const_sub_str))
#define SW_STR_ISTARTS_WITH(str, len, const_sub_str) swoole_str_istarts_with(str, len, SW_STRL(const_sub_str))

#if defined(SW_USE_JEMALLOC) || defined(SW_USE_TCMALLOC)
#define sw_strdup swoole_strdup
#define sw_strndup swoole_strndup
#else
#define sw_strdup strdup
#define sw_strndup strndup
#endif

/** always return less than size, zero termination  */
size_t sw_snprintf(char *buf, size_t size, const char *format, ...) __attribute__((format(printf, 3, 4)));
size_t sw_vsnprintf(char *buf, size_t size, const char *format, va_list args);
int sw_printf(const char *format, ...);
bool sw_wait_for(const std::function<bool()> &fn, int timeout_ms);

static inline long sw_atol(const char *str) {
    return std::strtol(str, nullptr, 10);
}

static inline int sw_atoi(const char *str) {
    return static_cast<int>(sw_atol(str));
}

static inline void sw_memset_zero(void *s, size_t n) {
    memset(s, '\0', n);
}

#define sw_unset_bit(val, bit) val &= ~bit
#define sw_set_bit(val, bit) val |= bit

static inline int sw_mem_equal(const void *v1, size_t s1, const void *v2, size_t s2) {
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
    char *p = static_cast<char *>(sw_malloc(l));
    if (sw_likely(p)) {
        memcpy(p, s, l);
    }
    return p;
}

static inline char *swoole_strndup(const char *s, const size_t n) {
    char *p = static_cast<char *>(sw_malloc(n + 1));
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

static inline unsigned int swoole_str_starts_with(const char *pstr, size_t plen, const char *sstr, size_t slen) {
    return (plen >= slen) && (strncmp(pstr, sstr, slen) == 0);
}

static inline unsigned int swoole_str_istarts_with(const char *pstr, size_t plen, const char *sstr, size_t slen) {
    return (plen >= slen) && (strncasecmp(pstr, sstr, slen) == 0);
}

static inline const char *swoole_strnstr(const char *haystack,
                                         uint32_t haystack_length,
                                         const char *needle,
                                         uint32_t needle_length) {
    assert(needle_length > 0);

    if (sw_likely(needle_length <= haystack_length)) {
        for (uint32_t i = 0; i < haystack_length - needle_length + 1; i++) {
            if ((haystack[0] == needle[0]) && (0 == memcmp(haystack, needle, needle_length))) {
                return haystack;
            }
            haystack++;
        }
    }

    return nullptr;
}

static inline const char *swoole_strncasestr(const char *haystack,
                                             uint32_t haystack_length,
                                             const char *needle,
                                             uint32_t needle_length) {
    assert(needle_length > 0);

    if (sw_likely(needle_length <= haystack_length)) {
        for (uint32_t i = 0; i < haystack_length - needle_length + 1; i++) {
            if ((haystack[0] == needle[0]) && (0 == strncasecmp(haystack, needle, needle_length))) {
                return haystack;
            }
            haystack++;
        }
    }

    return nullptr;
}

static inline ssize_t swoole_strnpos(const char *haystack,
                                     uint32_t haystack_length,
                                     const char *needle,
                                     uint32_t needle_length) {
    assert(needle_length > 0);

    const char *pos = swoole_strnstr(haystack, haystack_length, needle, needle_length);
    return pos == nullptr ? -1 : pos - haystack;
}

static inline ssize_t swoole_strrnpos(const char *haystack, const char *needle, uint32_t length) {
    uint32_t needle_length = strlen(needle);
    assert(needle_length > 0);
    haystack += (length - needle_length);

    for (uint32_t i = length - needle_length; i > 0; i--) {
        if ((haystack[0] == needle[0]) && (0 == memcmp(haystack, needle, needle_length))) {
            return i;
        }
        haystack--;
    }

    return -1;
}

static inline void swoole_strtolower(char *str, const int length) {
    char *c = str;
    const char *e = c + length;

    while (c < e) {
        *c = static_cast<char>(tolower(*c));
        c++;
    }
}

/*--------------------------------Constants------------------------------------*/
enum swResultCode {
    SW_OK = 0,
    SW_ERR = -1,
};

enum swReturnCode {
    SW_SUCCESS = 0,
    SW_CONTINUE = 1,
    SW_WAIT = 2,
    SW_CLOSE = 3,
    SW_ERROR = 4,
    SW_READY = 5,
    SW_INVALID = 6,
    SW_REDUCE_SIZE = 7,
};

enum swFdType {
    SW_FD_SESSION,        // server stream session
    SW_FD_STREAM_SERVER,  // server stream port
    SW_FD_DGRAM_SERVER,   // server dgram port
    SW_FD_PIPE,
    SW_FD_STREAM,
    SW_FD_AIO,
    /**
     * Coroutine Socket
     */
    SW_FD_CO_SOCKET,
    /**
     * socket poll fd [coroutine::socket_poll]
     */
    SW_FD_CO_POLL,
    /**
     * event waiter
     */
    SW_FD_CO_EVENT,
    /**
     * signalfd
     */
    SW_FD_SIGNAL,
    SW_FD_DNS_RESOLVER,
    SW_FD_CARES,
    /**
     * io_uring
     */
    SW_FD_IOURING,
    /**
     * SW_FD_USER or SW_FD_USER+n: for custom event
     */
    SW_FD_USER = 16,
    SW_FD_STREAM_CLIENT,
    SW_FD_DGRAM_CLIENT,
};

enum swSocketFlag {
    SW_SOCK_NONBLOCK = 1 << 2,
    SW_SOCK_CLOEXEC = 1 << 3,
    SW_SOCK_SSL = (1u << 9),
};

enum swSocketType {
    SW_SOCK_TCP = 1,
    SW_SOCK_UDP = 2,
    SW_SOCK_TCP6 = 3,
    SW_SOCK_UDP6 = 4,
    SW_SOCK_UNIX_STREAM = 5,  // unix sock stream
    SW_SOCK_UNIX_DGRAM = 6,   // unix sock dgram
    SW_SOCK_RAW = 7,
    SW_SOCK_RAW6 = 8,
};

enum swTimeoutType {
    SW_TIMEOUT_DNS = 1 << 0,
    SW_TIMEOUT_CONNECT = 1 << 1,
    SW_TIMEOUT_READ = 1 << 2,
    SW_TIMEOUT_WRITE = 1 << 3,
    SW_TIMEOUT_RDWR = SW_TIMEOUT_READ | SW_TIMEOUT_WRITE,
    SW_TIMEOUT_ALL = SW_TIMEOUT_DNS | SW_TIMEOUT_CONNECT | SW_TIMEOUT_RDWR,
};

enum swEventType {
    SW_EVENT_NULL = 0,
    SW_EVENT_DEAULT = 1u << 8,
    SW_EVENT_READ = 1u << 9,
    SW_EVENT_WRITE = 1u << 10,
    SW_EVENT_RDWR = SW_EVENT_READ | SW_EVENT_WRITE,
    SW_EVENT_ERROR = 1u << 11,
    SW_EVENT_ONCE = 1u << 12,
};

enum swForkType {
    SW_FORK_SPAWN = 0,
    SW_FORK_EXEC = 1 << 1,
    SW_FORK_DAEMON = 1 << 2,
    SW_FORK_PRECHECK = 1 << 3,
};

enum swTraverseOperation {
    SW_TRAVERSE_KEEP = 0,
    SW_TRAVERSE_REMOVE = 1,
    SW_TRAVERSE_STOP = 2,
};

//------------------------------Base--------------------------------
#ifndef uchar
typedef unsigned char uchar;
#endif

#define swoole_tolower(c) (uchar)((c >= 'A' && c <= 'Z') ? (c | 0x20) : c)
#define swoole_toupper(c) (uchar)((c >= 'a' && c <= 'z') ? (c & ~0x20) : c)

/**
 * This function appends a '\0' at the end of the string,
 * so the allocated memory buffer must be len + 1.
 */
void swoole_random_string(char *buf, size_t len);
void swoole_random_string(std::string &str, size_t len);
uint64_t swoole_random_int();
size_t swoole_random_bytes(char *buf, size_t size);

static inline char *swoole_strlchr(char *p, const char *last, char c) {
    while (p < last) {
        if (*p == c) {
            return p;
        }
        p++;
    }
    return nullptr;
}

static inline size_t swoole_size_align(size_t size, int pagesize) {
    return size + (pagesize - (size % pagesize));
}

//------------------------------Base--------------------------------
enum swEventDataFlag {
    SW_EVENT_DATA_NORMAL,
    SW_EVENT_DATA_PTR = 1u << 1,
    SW_EVENT_DATA_CHUNK = 1u << 2,
    SW_EVENT_DATA_BEGIN = 1u << 3,
    SW_EVENT_DATA_END = 1u << 4,
    SW_EVENT_DATA_OBJ_PTR = 1u << 5,
    SW_EVENT_DATA_POP_PTR = 1u << 6,
};

enum swTaskFlag {
    SW_TASK_TMPFILE = 1,
    SW_TASK_SERIALIZE = 1u << 1,
    SW_TASK_NONBLOCK = 1u << 2,
    SW_TASK_CALLBACK = 1u << 3,
    SW_TASK_WAITALL = 1u << 4,
    SW_TASK_COROUTINE = 1u << 5,
    SW_TASK_PEEK = 1u << 6,
    SW_TASK_NOREPLY = 1u << 7,
};

enum swDNSLookupFlag {
    SW_DNS_LOOKUP_RANDOM = (1u << 11),
};

extern thread_local char sw_error[SW_ERROR_MSG_SIZE];

enum swPipeType {
    SW_PIPE_WORKER = 0,
    SW_PIPE_MASTER = 1,
    SW_PIPE_READ = 0,
    SW_PIPE_WRITE = 1,
    SW_PIPE_NONBLOCK = 2,
};

//----------------------Tool Function---------------------
uint32_t swoole_common_multiple(uint32_t u, uint32_t v);
uint32_t swoole_common_divisor(uint32_t u, uint32_t v);

int swoole_itoa(char *buf, long value);
bool swoole_mkdir_recursive(const std::string &dir);

int swoole_rand();
int swoole_rand(int min, int max);
int swoole_system_random(int min, int max);

int swoole_version_compare(const char *version1, const char *version2);
void swoole_print_backtrace();
void swoole_print_backtrace_on_error();
char *swoole_string_format(size_t n, const char *format, ...);
bool swoole_get_env(const char *name, int *value);
int swoole_get_systemd_listen_fds();

void swoole_init();
void swoole_clean();
void swoole_exit(int _status);
pid_t swoole_fork(int flags);
pid_t swoole_fork_exec(const std::function<void()> &child_fn);
pid_t swoole_waitpid(pid_t _pid, int *_stat_loc, int _options);
void swoole_thread_init(bool main_thread = false);
void swoole_thread_clean(bool main_thread = false);
void swoole_redirect_stdout(int new_fd);
void swoole_redirect_stdout(const char *file);
int swoole_shell_exec(const char *command, pid_t *pid, bool get_error_stream);
int swoole_daemon(int nochdir, int noclose);
bool swoole_is_root_user();
void swoole_set_isolation(const std::string &group_, const std::string &user_, const std::string &chroot_);
bool swoole_set_task_tmpdir(const std::string &dir);
void swoole_set_process_death_signal(int signal);
const std::string &swoole_get_task_tmpdir();
int swoole_tmpfile(char *filename);

#ifdef HAVE_CPU_AFFINITY
#ifdef __FreeBSD__
#include <sys/types.h>
#include <sys/cpuset.h>
#include <pthread_np.h>
typedef cpuset_t cpu_set_t;
#endif
int swoole_set_cpu_affinity(cpu_set_t *set);
int swoole_get_cpu_affinity(cpu_set_t *set);
#endif

namespace swoole {
typedef long SessionId;
typedef long TaskId;
typedef uint8_t ReactorId;
typedef uint32_t WorkerId;
typedef swEventType EventType;
typedef swSocketType SocketType;
typedef swTimeoutType TimeoutType;
typedef swFdType FdType;
typedef swReturnCode ReturnCode;
typedef swResultCode ResultCode;

struct Event {
    int fd;
    int16_t reactor_id;
    FdType type;
    network::Socket *socket;
};

struct DataHead {
    SessionId fd;
    uint64_t msg_id;
    uint32_t len;
    int16_t reactor_id;
    uint8_t type;
    uint8_t flags;
    uint16_t server_fd;
    uint16_t ext_flags;
    uint32_t reserved;
    double time;
    size_t dump(char *buf, size_t len);
    void print();
};

struct EventData {
    DataHead info;
    char data[SW_IPC_BUFFER_SIZE];

    uint32_t size() const {
        return sizeof(info) + len();
    }

    uint32_t len() const {
        return info.len;
    }
};

struct ThreadGlobal {
    uint16_t id;
    uint8_t type;
    bool main_thread;
    int32_t error;
    String *buffer_stack;
    Reactor *reactor;
    Timer *timer;
    MessageBus *message_bus;
    AsyncThreads *async_threads;
#ifdef SW_USE_IOURING
    Iouring *iouring;
#endif
    bool signal_blocking_all;
};

struct Allocator {
    void *(*malloc)(size_t size);
    void *(*calloc)(size_t nmemb, size_t size);
    void *(*realloc)(void *ptr, size_t size);
    void (*free)(void *ptr);
};

struct NameResolver {
    enum Type {
        TYPE_KERNEL,
        TYPE_PHP,
        TYPE_USER,
    };
    struct Context {
        int type;
        double timeout;
        void *private_data;
        bool with_port;
        bool cluster_;
        bool final_;
        std::function<void(Context *ctx)> dtor;

        ~Context() {
            if (private_data && dtor) {
                dtor(this);
            }
        }
    };
    std::function<std::string(const std::string &, Context *, void *)> resolve;
    void *private_data;
    Type type;
};

struct DnsServer {
    std::string host;
    int port;
};

struct Global {
    uchar init : 1;
    uchar running : 1;
    uchar wait_signal : 1;
    uchar enable_signalfd : 1;
    /**
     * Under macOS or FreeBSD, kqueue does not support listening for writable events on pipes. When a large amount of
     * data is written to a pipe in process A, and the buffer becomes full, listening for writable events will not work.
     * In process B, even after consuming the data from the pipe, the writable event in process A cannot be triggered.
     * As a result, the functionality of Task and Process Server cannot be supported, making all scenarios relying on
     * pipes for inter-process communication unable to function properly.
     */
    uchar enable_kqueue : 1;
    uchar dns_lookup_random : 1;
    uchar use_async_resolver : 1;
    uchar use_name_resolver : 1;
    uchar enable_coroutine : 1;
    uchar print_backtrace_on_error : 1;

    TaskId current_task_id;

    int signal_fd;
    bool signal_alarm;
    bool signal_dispatch;
    uint32_t signal_listener_num;
    uint32_t signal_async_listener_num;

    long trace_flags;

    void (*fatal_error)(int code, const char *str, ...);

    //-----------------------[System]--------------------------
    uint16_t cpu_num;
    uint32_t pagesize;
    struct utsname uname;
    uint32_t max_sockets;
    uint32_t max_file_content;
    //-----------------------[Memory]--------------------------
    MemoryPool *memory_pool;
    Allocator std_allocator;
    std::string task_tmpfile;
    //------------------[Single Instance]----------------------
    Logger *logger;
    Server *server;
    FILE *stdout_;
    //-----------------------[DNS]-----------------------------
    DnsServer dns_server;
    double dns_cache_refresh_time;
    int dns_tries;
    std::string dns_resolvconf_path;
    std::string dns_hosts_path;
    std::list<NameResolver> name_resolvers;
    //-----------------------[AIO]----------------------------
    uint32_t aio_core_worker_num;
    uint32_t aio_worker_num;
#ifdef SW_USE_IOURING
    uint32_t iouring_entries = 0;
    uint32_t iouring_workers = 0;
    uint32_t iouring_flag = 0;
#endif
    double aio_max_wait_time;
    double aio_max_idle_time;
    network::Socket *aio_default_socket;
    //-----------------------[Hook]--------------------------
    void *hooks[SW_MAX_HOOK_TYPE];
    std::function<bool(Reactor *reactor, size_t &event_num)> user_exit_condition;
    // bug report message
    std::string bug_report_message;
};

std::string dirname(const std::string &file);
void hook_add(void **hooks, int type, const Callback &func, int push_back);
void hook_call(void **hooks, int type, void *arg);
double microtime();
void realtime_get(timespec *time);
void realtime_add(timespec *time, int64_t add_msec);
}  // namespace swoole

extern swoole::Global SwooleG;                      // Local Global Variable
extern thread_local swoole::ThreadGlobal SwooleTG;  // Thread Global Variable

#define SW_CPU_NUM (SwooleG.cpu_num)

static inline void swoole_set_last_error(int error) {
    SwooleTG.error = error;
}

static inline int swoole_get_last_error() {
    return SwooleTG.error;
}

static inline void swoole_clear_last_error() {
    SwooleTG.error = 0;
}

void swoole_clear_last_error_msg();
const char *swoole_get_last_error_msg();

static inline int swoole_get_thread_id() {
    return SwooleTG.id;
}

static inline int swoole_get_thread_type() {
    return SwooleTG.type;
}

static inline void swoole_set_thread_id(uint16_t id) {
    SwooleTG.id = id;
}

static inline void swoole_set_thread_type(uint8_t type) {
    SwooleTG.type = type;
}

static inline uint32_t swoole_pagesize() {
    return SwooleG.pagesize;
}

SW_API const char *swoole_strerror(int code);
SW_API void swoole_throw_error(int code);
SW_API void swoole_ignore_error(int code);
SW_API bool swoole_is_ignored_error(int code);
SW_API bool swoole_is_main_thread();
SW_API void swoole_set_log_level(int level);
SW_API void swoole_set_log_file(const char *file);
SW_API void swoole_set_trace_flags(long flags);
SW_API void swoole_set_print_backtrace_on_error(bool enable = true);
SW_API void swoole_set_stdout_stream(FILE *fp);
SW_API void swoole_set_dns_server(const std::string &server);
SW_API void swoole_set_hosts_path(const std::string &hosts_file);
SW_API swoole::DnsServer swoole_get_dns_server();
SW_API bool swoole_load_resolv_conf();
SW_API void swoole_name_resolver_add(const swoole::NameResolver &resolver, bool append = true);
SW_API void swoole_name_resolver_each(
    const std::function<enum swTraverseOperation(const std::list<swoole::NameResolver>::iterator &iter)> &fn);
SW_API std::string swoole_name_resolver_lookup(const std::string &host_name, swoole::NameResolver::Context *ctx);
SW_API int swoole_get_log_level();
SW_API FILE *swoole_get_stdout_stream();

enum swEventInitFlag {
    SW_EVENTLOOP_WAIT_EXIT = 1,
};

/**
 * manually_trigger:
 * Once enabled, the timer will no longer be triggered by event polling or the operating system's timer;
 * instead, it will be managed directly at the user space.
 */
SW_API swoole::Timer *swoole_timer_create(bool manually_trigger = false);
SW_API long swoole_timer_after(long ms, const swoole::TimerCallback &callback, void *private_data = nullptr);
SW_API long swoole_timer_tick(long ms, const swoole::TimerCallback &callback, void *private_data = nullptr);
SW_API swoole::TimerNode *swoole_timer_add(double ms,
                                           bool persistent,
                                           const swoole::TimerCallback &callback,
                                           void *private_data = nullptr);
SW_API swoole::TimerNode *swoole_timer_add(long ms,
                                           bool persistent,
                                           const swoole::TimerCallback &callback,
                                           void *private_data = nullptr);
SW_API bool swoole_timer_del(swoole::TimerNode *tnode);
SW_API bool swoole_timer_exists(long timer_id);
SW_API void swoole_timer_delay(swoole::TimerNode *tnode, long delay_ms);
SW_API swoole::TimerNode *swoole_timer_get(long timer_id);
SW_API bool swoole_timer_clear(long timer_id);
SW_API void swoole_timer_free();
SW_API void swoole_timer_select();
SW_API int64_t swoole_timer_get_next_msec();
SW_API bool swoole_timer_is_available();

SW_API int swoole_event_init(int flags);
SW_API int swoole_event_add(swoole::network::Socket *socket, int events);
SW_API int swoole_event_set(swoole::network::Socket *socket, int events);
SW_API int swoole_event_add_or_update(swoole::network::Socket *socket, int event);
SW_API int swoole_event_del(swoole::network::Socket *socket);
SW_API void swoole_event_defer(const swoole::Callback &cb, void *private_data);
SW_API ssize_t swoole_event_write(swoole::network::Socket *socket, const void *data, size_t len);
SW_API ssize_t swoole_event_writev(swoole::network::Socket *socket, const iovec *iov, size_t iovcnt);
SW_API swoole::network::Socket *swoole_event_get_socket(int fd);
SW_API int swoole_event_wait();
SW_API int swoole_event_free();
SW_API void swoole_event_set_handler(int fd_type, int event, swoole::ReactorHandler handler);
SW_API bool swoole_event_isset_handler(int fd_type, int event);
SW_API bool swoole_event_is_available();
SW_API bool swoole_event_is_running();

static sw_inline swoole::String *sw_tg_buffer() {
    return SwooleTG.buffer_stack;
}

static sw_inline swoole::MemoryPool *sw_mem_pool() {
    return SwooleG.memory_pool;
}

static sw_inline const swoole::Allocator *sw_std_allocator() {
    return &SwooleG.std_allocator;
}

static sw_inline swoole::Reactor *sw_reactor() {
    return SwooleTG.reactor;
}

static sw_inline swoole::Timer *sw_timer() {
    return SwooleTG.timer;
}
