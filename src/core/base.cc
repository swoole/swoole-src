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

#include "swoole.h"

#include <stdarg.h>
#include <assert.h>

#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/ioctl.h>

#ifdef HAVE_EXECINFO
#include <execinfo.h>
#endif

#ifdef __MACH__
#include <sys/syslimits.h>
#endif

#include <regex>
#include <algorithm>
#include <list>
#include <set>
#include <unordered_map>

#include "swoole_api.h"
#include "swoole_string.h"
#include "swoole_signal.h"
#include "swoole_memory.h"
#include "swoole_protocol.h"
#include "swoole_util.h"
#include "swoole_log.h"
#include "atomic.h"
#include "swoole_async.h"
#include "coroutine_c_api.h"

using swoole::String;

#ifdef HAVE_GETRANDOM
#include <sys/random.h>
#else
static ssize_t getrandom(void *buffer, size_t size, unsigned int __flags) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        return -1;
    }

    size_t read_bytes;
    ssize_t n;
    for (read_bytes = 0; read_bytes < size; read_bytes += (size_t) n) {
        n = read(fd, (char *) buffer + read_bytes, size - read_bytes);
        if (n <= 0) {
            break;
        }
    }

    close(fd);

    return read_bytes;
}
#endif

swGlobal_t SwooleG;
__thread swThreadGlobal_t SwooleTG;

static std::unordered_map<std::string, void *> functions;
static swoole::Logger *g_logger_instance = nullptr;

#ifdef __MACH__
static __thread char _sw_error_buf[SW_ERROR_MSG_SIZE];
char *sw_error_() {
    return _sw_error_buf;
}
#else
__thread char sw_error[SW_ERROR_MSG_SIZE];
#endif

static void swoole_fatal_error(int code, const char *format, ...);

swoole::Logger *sw_logger() {
    return g_logger_instance;
}

void swoole_init(void) {
    if (SwooleG.init) {
        return;
    }

    SwooleG = {};
    sw_memset_zero(sw_error, SW_ERROR_MSG_SIZE);

    SwooleG.running = 1;
    SwooleG.init = 1;
    SwooleG.enable_coroutine = 1;

    SwooleG.std_allocator.malloc = sw_malloc;
    SwooleG.std_allocator.calloc = sw_calloc;
    SwooleG.std_allocator.realloc = sw_realloc;
    SwooleG.std_allocator.free = sw_free;

    SwooleG.fatal_error = swoole_fatal_error;

    SwooleG.cpu_num = SW_MAX(1, sysconf(_SC_NPROCESSORS_ONLN));
    SwooleG.pagesize = getpagesize();
    // get system uname
    uname(&SwooleG.uname);
    // random seed
    srandom(time(nullptr));

    SwooleG.pid = getpid();

    g_logger_instance = new swoole::Logger;

#ifdef SW_DEBUG
    sw_logger()->set_level(0);
    SwooleG.trace_flags = 0x7fffffff;
#else
    sw_logger()->set_level(SW_LOG_INFO);
#endif

    // init global shared memory
    SwooleG.memory_pool = swMemoryGlobal_new(SW_GLOBAL_MEMORY_PAGESIZE, 1);
    if (SwooleG.memory_pool == nullptr) {
        printf("[Core] Fatal Error: global memory allocation failure");
        exit(1);
    }

    SwooleG.max_sockets = SW_MAX_SOCKETS_DEFAULT;
    struct rlimit rlmt;
    if (getrlimit(RLIMIT_NOFILE, &rlmt) < 0) {
        swSysWarn("getrlimit() failed");
    } else {
        SwooleG.max_sockets = SW_MAX((uint32_t) rlmt.rlim_cur, SW_MAX_SOCKETS_DEFAULT);
        SwooleG.max_sockets = SW_MIN((uint32_t) rlmt.rlim_cur, SW_SESSION_LIST_SIZE);
    }

    SwooleTG.buffer_stack = swString_new(SW_STACK_BUFFER_SIZE);
    if (SwooleTG.buffer_stack == nullptr) {
        exit(3);
    }

    if (!SwooleG.task_tmpdir) {
        SwooleG.task_tmpdir = sw_strndup(SW_TASK_TMP_FILE, sizeof(SW_TASK_TMP_FILE));
        SwooleG.task_tmpdir_len = sizeof(SW_TASK_TMP_FILE);
    }

    char *tmp_dir = swoole_dirname(SwooleG.task_tmpdir);
    // create tmp dir
    if (access(tmp_dir, R_OK) < 0 && swoole_mkdir_recursive(tmp_dir) < 0) {
        swWarn("create task tmp dir(%s) failed", tmp_dir);
    }
    if (tmp_dir) {
        sw_free(tmp_dir);
    }

    // init signalfd
#ifdef HAVE_SIGNALFD
    swSignalfd_init();
    SwooleG.use_signalfd = 1;
    SwooleG.enable_signalfd = 1;
#endif
}

SW_API const char *swoole_version(void) {
    return SWOOLE_VERSION;
}

SW_API int swoole_version_id(void) {
    return SWOOLE_VERSION_ID;
}

void swoole_clean(void) {
    if (SwooleG.task_tmpdir) {
        sw_free(SwooleG.task_tmpdir);
    }
    if (SwooleTG.timer) {
        swoole_timer_free();
    }
    if (SwooleTG.reactor) {
        swoole_event_free();
    }
    if (SwooleG.memory_pool != nullptr) {
        SwooleG.memory_pool->destroy(SwooleG.memory_pool);
    }
    if (g_logger_instance) {
        delete g_logger_instance;
        g_logger_instance = nullptr;
    }
    SwooleG = {};
}

pid_t swoole_fork(int flags) {
    if (!(flags & SW_FORK_EXEC)) {
        if (swoole_coroutine_is_in()) {
            swFatalError(SW_ERROR_OPERATION_NOT_SUPPORT, "must be forked outside the coroutine");
        }
        if (SwooleTG.aio_init) {
            printf("aio_init=%d, aio_task_num=%d, reactor=%p\n",
                   SwooleTG.aio_init,
                   SwooleTG.aio_task_num,
                   SwooleTG.reactor);
            swFatalError(SW_ERROR_OPERATION_NOT_SUPPORT, "can not create server after using async file operation");
        }
    }
    if (flags & SW_FORK_PRECHECK) {
        return 0;
    }

    pid_t pid = fork();
    if (pid == 0) {
        SwooleG.pid = getpid();
        if (flags & SW_FORK_DAEMON) {
            return pid;
        }
        /**
         * [!!!] All timers and event loops must be cleaned up after fork
         */
        if (SwooleTG.timer) {
            swoole_timer_free();
        }
        if (SwooleG.memory_pool) {
            SwooleG.memory_pool->destroy(SwooleG.memory_pool);
        }
        if (!(flags & SW_FORK_EXEC)) {
            /**
             * reset SwooleG.memory_pool
             */
            SwooleG.memory_pool = swMemoryGlobal_new(SW_GLOBAL_MEMORY_PAGESIZE, 1);
            if (SwooleG.memory_pool == nullptr) {
                printf("[Worker] Fatal Error: global memory allocation failure");
                exit(1);
            }
            /**
             * reopen log file
             */
            sw_logger()->reopen();
            /**
             * reset eventLoop
             */
            if (SwooleTG.reactor) {
                swoole_event_free();
                swTraceLog(SW_TRACE_REACTOR, "reactor has been destroyed");
            }
        } else {
            /**
             * close log fd
             */
            sw_logger()->close();
        }
        /**
         * reset signal handler
         */
        swSignal_clear();
    }

    return pid;
}

void swoole_dump_ascii(const char *data, size_t size) {
    for (size_t i = 0; i < size; i++) {
        printf("%d ", (unsigned) data[i]);
    }
    printf("\n");
}

void swoole_dump_bin(const char *data, char type, size_t size) {
    int i;
    int type_size = swoole_type_size(type);
    if (type_size <= 0) {
        return;
    }
    int n = size / type_size;

    for (i = 0; i < n; i++) {
        printf("%d,", swoole_unpack(type, data + type_size * i));
    }
    printf("\n");
}

void swoole_dump_hex(const char *data, size_t outlen) {
    for (size_t i = 0; i < outlen; ++i) {
        if ((i & 0x0fu) == 0) {
            printf("%08zX: ", i);
        }
        printf("%02X ", data[i]);
        if (((i + 1) & 0x0fu) == 0) {
            printf("\n");
        }
    }
    printf("\n");
}

/**
 * Recursive directory creation
 */
int swoole_mkdir_recursive(const char *dir) {
    char tmp[PATH_MAX];
    int i, len = strlen(dir);

    if (len + 1 > PATH_MAX) /* PATH_MAX limit includes string trailing null character */
    {
        swWarn("mkdir(%s) failed. Path exceeds the limit of %d characters", dir, PATH_MAX - 1);
        return -1;
    }
    strncpy(tmp, dir, PATH_MAX);

    if (dir[len - 1] != '/') {
        strcat(tmp, "/");
    }

    len = strlen(tmp);

    for (i = 1; i < len; i++) {
        if (tmp[i] == '/') {
            tmp[i] = 0;
            if (access(tmp, R_OK) != 0) {
                if (mkdir(tmp, 0755) == -1) {
                    swSysWarn("mkdir(%s) failed", tmp);
                    return -1;
                }
            }
            tmp[i] = '/';
        }
    }
    return 0;
}

/**
 * get parent dir name
 */
char *swoole_dirname(char *file) {
    char *dirname = sw_strdup(file);
    if (dirname == nullptr) {
        swWarn("strdup() failed");
        return nullptr;
    }

    int i = strlen(dirname);

    if (dirname[i - 1] == '/') {
        i -= 2;
    }

    for (; i > 0; i--) {
        if ('/' == dirname[i]) {
            dirname[i] = 0;
            break;
        }
    }
    return dirname;
}

int swoole_type_size(char type) {
    switch (type) {
    case 'c':
    case 'C':
        return 1;
    case 's':
    case 'S':
    case 'n':
    case 'v':
        return 2;
    case 'l':
    case 'L':
    case 'N':
    case 'V':
        return 4;
    default:
        return 0;
    }
}

char *swoole_dec2hex(ulong_t value, int base) {
    assert(base > 1 && base < 37);

    static char digits[] = "0123456789abcdefghijklmnopqrstuvwxyz";
    char buf[(sizeof(ulong_t) << 3) + 1];
    char *ptr, *end;

    end = ptr = buf + sizeof(buf) - 1;
    *ptr = '\0';

    do {
        *--ptr = digits[value % base];
        value /= base;
    } while (ptr > buf && value);

    return sw_strndup(ptr, end - ptr);
}

ulong_t swoole_hex2dec(const char *hex, size_t *parsed_bytes) {
    size_t value = 0;
    *parsed_bytes = 0;
    const char *p = hex;

    if (strncasecmp(hex, "0x", 2) == 0) {
        p += 2;
    }

    while (1) {
        char c = *p;
        if ((c >= '0') && (c <= '9')) {
            value = value * 16 + (c - '0');
        } else {
            c = toupper(c);
            if ((c >= 'A') && (c <= 'Z')) {
                value = value * 16 + (c - 'A') + 10;
            } else {
                break;
            }
        }
        p++;
    }
    *parsed_bytes = p - hex;
    return value;
}

size_t swoole_sync_writefile(int fd, const void *data, size_t len) {
    ssize_t n = 0;
    size_t count = len, towrite, written = 0;

    while (count > 0) {
        towrite = count;
        if (towrite > SW_FILE_CHUNK_SIZE) {
            towrite = SW_FILE_CHUNK_SIZE;
        }
        n = write(fd, data, towrite);
        if (n > 0) {
            data = (char *) data + n;
            count -= n;
            written += n;
        } else if (n == 0) {
            break;
        } else {
            if (errno == EINTR || errno == EAGAIN) {
                continue;
            }
            swSysWarn("write(%d, %zu) failed", fd, towrite);
            break;
        }
    }
    return written;
}

#ifndef RAND_MAX
#define RAND_MAX 2147483647
#endif

int swoole_rand(int min, int max) {
    static int _seed = 0;
    assert(max > min);

    if (_seed == 0) {
        _seed = time(nullptr);
        srand(_seed);
    }

    int _rand = rand();
    _rand = min + (int) ((double) ((double) (max) - (min) + 1.0) * ((_rand) / ((RAND_MAX) + 1.0)));
    return _rand;
}

int swoole_system_random(int min, int max) {
    static int dev_random_fd = -1;
    char *next_random_byte;
    int bytes_to_read;
    unsigned random_value;

    assert(max > min);

    if (dev_random_fd == -1) {
        dev_random_fd = open("/dev/urandom", O_RDONLY);
        if (dev_random_fd < 0) {
            return swoole_rand(min, max);
        }
    }

    next_random_byte = (char *) &random_value;
    bytes_to_read = sizeof(random_value);

    if (read(dev_random_fd, next_random_byte, bytes_to_read) < bytes_to_read) {
        swSysWarn("read() from /dev/urandom failed");
        return SW_ERR;
    }
    return min + (random_value % (max - min + 1));
}

void swoole_redirect_stdout(int new_fd) {
    if (dup2(new_fd, STDOUT_FILENO) < 0) {
        swSysWarn("dup2(STDOUT_FILENO) failed");
    }
    if (dup2(new_fd, STDERR_FILENO) < 0) {
        swSysWarn("dup2(STDERR_FILENO) failed");
    }
}

int swoole_version_compare(const char *version1, const char *version2) {
    int result = 0;

    while (result == 0) {
        char *tail1;
        char *tail2;

        unsigned long ver1 = strtoul(version1, &tail1, 10);
        unsigned long ver2 = strtoul(version2, &tail2, 10);

        if (ver1 < ver2) {
            result = -1;
        } else if (ver1 > ver2) {
            result = +1;
        } else {
            version1 = tail1;
            version2 = tail2;
            if (*version1 == '\0' && *version2 == '\0') {
                break;
            } else if (*version1 == '\0') {
                result = -1;
            } else if (*version2 == '\0') {
                result = +1;
            } else {
                version1++;
                version2++;
            }
        }
    }
    return result;
}

double swoole_microtime(void) {
    struct timeval t;
    gettimeofday(&t, nullptr);
    return (double) t.tv_sec + ((double) t.tv_usec / 1000000);
}

void swoole_rtrim(char *str, int len) {
    int i;
    for (i = len; i > 0;) {
        switch (str[--i]) {
        case ' ':
        case '\0':
        case '\n':
        case '\r':
        case '\t':
        case '\v':
            str[i] = 0;
            break;
        default:
            return;
        }
    }
}

int swoole_tmpfile(char *filename) {
#if defined(HAVE_MKOSTEMP) && defined(HAVE_EPOLL)
    int tmp_fd = mkostemp(filename, O_WRONLY | O_CREAT);
#else
    int tmp_fd = mkstemp(filename);
#endif

    if (tmp_fd < 0) {
        swSysWarn("mkstemp(%s) failed", filename);
        return SW_ERR;
    } else {
        return tmp_fd;
    }
}

ssize_t swoole_file_get_size(FILE *fp) {
    long pos = ftell(fp);
    if (fseek(fp, 0L, SEEK_END) < 0) {
        return SW_ERR;
    }
    long size = ftell(fp);
    if (fseek(fp, pos, SEEK_SET) < 0) {
        return SW_ERR;
    }
    return size;
}

ssize_t swoole_file_size(const char *filename) {
    struct stat file_stat;
    if (lstat(filename, &file_stat) < 0) {
        swSysWarn("lstat(%s) failed", filename);
        swoole_set_last_error(errno);
        return -1;
    }
    if ((file_stat.st_mode & S_IFMT) != S_IFREG) {
        swoole_set_last_error(EISDIR);
        return -1;
    }
    return file_stat.st_size;
}

std::shared_ptr<String> swoole_file_get_contents(const char *filename) {
    long filesize = swoole_file_size(filename);
    if (filesize < 0) {
        return nullptr;
    } else if (filesize == 0) {
        swoole_error_log(SW_LOG_TRACE, SW_ERROR_FILE_EMPTY, "file[%s] is empty", filename);
        return nullptr;
    } else if (filesize > SW_MAX_FILE_CONTENT) {
        swoole_error_log(SW_LOG_WARNING, SW_ERROR_FILE_TOO_LARGE, "file[%s] is too large", filename);
        return nullptr;
    }

    swoole::FileDescriptor _handler(open(filename, O_RDONLY));
    int fd = _handler.get();
    if (fd < 0) {
        swSysWarn("open(%s) failed", filename);
        return nullptr;
    }

    std::shared_ptr<String> content(swString_new(filesize + 1));
    ssize_t read_bytes = 0;

    while (read_bytes < filesize) {
        ssize_t n = pread(fd, content->str + read_bytes, filesize - read_bytes, read_bytes);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            } else {
                swSysWarn("pread(%d, %ld, %d) failed", fd, filesize - read_bytes, read_bytes);
                return content;
            }
        }
        read_bytes += n;
    }

    content->length = read_bytes;
    content->str[read_bytes] = '\0';
    return content;
}

bool swoole_file_put_contents(const char *filename, const char *content, size_t length) {
    if (length <= 0) {
        swoole_error_log(SW_LOG_TRACE, SW_ERROR_FILE_EMPTY, "content is empty");
        return false;
    }
    if (length > SW_MAX_FILE_CONTENT) {
        swoole_error_log(SW_LOG_WARNING, SW_ERROR_FILE_TOO_LARGE, "content is too large");
        return false;
    }

    swoole::FileDescriptor _handler(open(filename, O_WRONLY | O_TRUNC | O_CREAT, 0666));

    int fd = _handler.get();
    if (fd < 0) {
        swSysWarn("open(%s) failed", filename);
        return false;
    }

    size_t chunk_size, written = 0;
    ssize_t n = 0;

    while (written < length) {
        chunk_size = length - written;
        if (chunk_size > SW_BUFFER_SIZE_BIG) {
            chunk_size = SW_BUFFER_SIZE_BIG;
        }
        n = write(fd, content + written, chunk_size);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            } else {
                swSysWarn("write(%d, %d) failed", fd, chunk_size);
                return -1;
            }
        }
        written += n;
    }
    return true;
}

size_t swoole_sync_readfile(int fd, void *buf, size_t len) {
    ssize_t n = 0;
    size_t count = len, toread, readn = 0;

    while (count > 0) {
        toread = count;
        if (toread > SW_FILE_CHUNK_SIZE) {
            toread = SW_FILE_CHUNK_SIZE;
        }
        n = read(fd, buf, toread);
        if (n > 0) {
            buf = (char *) buf + n;
            count -= n;
            readn += n;
        } else if (n == 0) {
            break;
        } else {
            if (errno == EINTR || errno == EAGAIN) {
                continue;
            }
            swSysWarn("read() failed");
            break;
        }
    }
    return readn;
}

swString *swoole_sync_readfile_eof(int fd) {
    ssize_t n = 0;
    swString *data = new swString(SW_BUFFER_SIZE_STD);
    if (data == nullptr) {
        return data;
    }

    while (1) {
        n = read(fd, data->str + data->length, data->size - data->length);
        if (n <= 0) {
            return data;
        } else {
            if (!data->grow((size_t) n)) {
                return data;
            }
        }
    }

    return data;
}

/**
 * Maximum common divisor
 */
uint32_t swoole_common_divisor(uint32_t u, uint32_t v) {
    assert(u > 0);
    assert(v > 0);
    uint32_t t;
    while (u > 0) {
        if (u < v) {
            t = u;
            u = v;
            v = t;
        }
        u = u - v;
    }
    return v;
}

/**
 * The least common multiple
 */
uint32_t swoole_common_multiple(uint32_t u, uint32_t v) {
    assert(u > 0);
    assert(v > 0);

    uint32_t m_cup = u;
    uint32_t n_cup = v;
    int res = m_cup % n_cup;

    while (res != 0) {
        m_cup = n_cup;
        n_cup = res;
        res = m_cup % n_cup;
    }
    return u * v / n_cup;
}

size_t sw_snprintf(char *buf, size_t size, const char *format, ...) {
    va_list args;
    va_start(args, format);
    int retval = vsnprintf(buf, size, format, args);
    va_end(args);

    if (size == 0) {
        return retval;
    } else if (sw_unlikely(retval < 0)) {
        retval = 0;
        buf[0] = '\0';
    } else if (sw_unlikely(retval >= (int) size)) {
        retval = size - 1;
        buf[retval] = '\0';
    }
    return retval;
}

size_t sw_vsnprintf(char *buf, size_t size, const char *format, va_list args) {
    int retval = vsnprintf(buf, size, format, args);
    if (sw_unlikely(retval < 0)) {
        retval = 0;
        buf[0] = '\0';
    } else if (sw_unlikely(retval >= (int) size)) {
        retval = size - 1;
        buf[retval] = '\0';
    }
    return retval;
}

int swoole_ioctl_set_block(int sock, int nonblock) {
    int ret;
    do {
        ret = ioctl(sock, FIONBIO, &nonblock);
    } while (ret == -1 && errno == EINTR);

    if (ret < 0) {
        swSysWarn("ioctl(%d, FIONBIO, %d) failed", sock, nonblock);
        return SW_ERR;
    } else {
        return SW_OK;
    }
}

int swoole_fcntl_set_option(int sock, int nonblock, int cloexec) {
    int opts, ret;

    if (nonblock >= 0) {
        do {
            opts = fcntl(sock, F_GETFL);
        } while (opts < 0 && errno == EINTR);

        if (opts < 0) {
            swSysWarn("fcntl(%d, GETFL) failed", sock);
        }

        if (nonblock) {
            opts = opts | O_NONBLOCK;
        } else {
            opts = opts & ~O_NONBLOCK;
        }

        do {
            ret = fcntl(sock, F_SETFL, opts);
        } while (ret < 0 && errno == EINTR);

        if (ret < 0) {
            swSysWarn("fcntl(%d, SETFL, opts) failed", sock);
            return SW_ERR;
        }
    }

#ifdef FD_CLOEXEC
    if (cloexec >= 0) {
        do {
            opts = fcntl(sock, F_GETFD);
        } while (opts < 0 && errno == EINTR);

        if (opts < 0) {
            swSysWarn("fcntl(%d, GETFL) failed", sock);
        }

        if (cloexec) {
            opts = opts | FD_CLOEXEC;
        } else {
            opts = opts & ~FD_CLOEXEC;
        }

        do {
            ret = fcntl(sock, F_SETFD, opts);
        } while (ret < 0 && errno == EINTR);

        if (ret < 0) {
            swSysWarn("fcntl(%d, SETFD, opts) failed", sock);
            return SW_ERR;
        }
    }
#endif
    return SW_OK;
}

static int *swoole_kmp_borders(char *needle, size_t nlen) {
    if (!needle) {
        return nullptr;
    }

    int i, j, *borders = (int *) sw_malloc((nlen + 1) * sizeof(*borders));
    if (!borders) {
        return nullptr;
    }

    i = 0;
    j = -1;
    borders[i] = j;
    while ((uint32_t) i < nlen) {
        while (j >= 0 && needle[i] != needle[j]) {
            j = borders[j];
        }
        ++i;
        ++j;
        borders[i] = j;
    }
    return borders;
}

static char *swoole_kmp_search(char *haystack, size_t haylen, char *needle, uint32_t nlen, int *borders) {
    uint32_t max_index = haylen - nlen, i = 0, j = 0;

    while (i <= max_index) {
        while (j < nlen && *haystack && needle[j] == *haystack) {
            ++j;
            ++haystack;
        }
        if (j == nlen) {
            return haystack - nlen;
        }
        if (!(*haystack)) {
            return nullptr;
        }
        if (j == 0) {
            ++haystack;
            ++i;
        } else {
            do {
                i += j - (uint32_t) borders[j];
                j = borders[j];
            } while (j > 0 && needle[j] != *haystack);
        }
    }
    return nullptr;
}

int swoole_itoa(char *buf, long value) {
    long i = 0, j;
    long sign_mask;
    unsigned long nn;

    sign_mask = value >> (sizeof(long) * 8 - 1);
    nn = (value + sign_mask) ^ sign_mask;
    do {
        buf[i++] = nn % 10 + '0';
    } while (nn /= 10);

    buf[i] = '-';
    i += sign_mask & 1;
    buf[i] = '\0';

    int s_len = i;
    char swap;

    for (i = 0, j = s_len - 1; i < j; ++i, --j) {
        swap = buf[i];
        buf[i] = buf[j];
        buf[j] = swap;
    }
    buf[s_len] = 0;
    return s_len;
}

char *swoole_kmp_strnstr(char *haystack, char *needle, uint32_t length) {
    if (!haystack || !needle) {
        return nullptr;
    }
    size_t nlen = strlen(needle);
    if (length < nlen) {
        return nullptr;
    }
    int *borders = swoole_kmp_borders(needle, nlen);
    if (!borders) {
        return nullptr;
    }
    char *match = swoole_kmp_search(haystack, length, needle, nlen, borders);
    sw_free(borders);
    return match;
}

SW_API int swoole_add_function(const char *name, void *func) {
    std::string _name(name);
    auto iter = functions.find(_name);
    if (iter != functions.end()) {
        swWarn("Function '%s' has already been added", name);
        return SW_ERR;
    } else {
        functions.emplace(std::make_pair(_name, func));
        return SW_OK;
    }
}

SW_API void *swoole_get_function(const char *name, uint32_t length) {
    auto iter = functions.find(std::string(name));
    if (iter != functions.end()) {
        return iter->second;
    } else {
        return nullptr;
    }
}

SW_API int swoole_add_hook(enum swGlobal_hook_type type, swCallback func, int push_back) {
    return swoole::hook_add(SwooleG.hooks, type, func, push_back);
}

SW_API void swoole_call_hook(enum swGlobal_hook_type type, void *arg) {
    swoole::hook_call(SwooleG.hooks, type, arg);
}

int swoole_shell_exec(const char *command, pid_t *pid, bool get_error_stream) {
    pid_t child_pid;
    int fds[2];
    if (pipe(fds) < 0) {
        return SW_ERR;
    }

    if ((child_pid = fork()) == -1) {
        swSysWarn("fork() failed");
        close(fds[0]);
        close(fds[1]);
        return SW_ERR;
    }

    if (child_pid == 0) {
        close(fds[SW_PIPE_READ]);

        if (get_error_stream) {
            if (fds[SW_PIPE_WRITE] == fileno(stdout)) {
                dup2(fds[SW_PIPE_WRITE], fileno(stderr));
            } else if (fds[SW_PIPE_WRITE] == fileno(stderr)) {
                dup2(fds[SW_PIPE_WRITE], fileno(stdout));
            } else {
                dup2(fds[SW_PIPE_WRITE], fileno(stdout));
                dup2(fds[SW_PIPE_WRITE], fileno(stderr));
                close(fds[SW_PIPE_WRITE]);
            }
        } else {
            if (fds[SW_PIPE_WRITE] != fileno(stdout)) {
                dup2(fds[SW_PIPE_WRITE], fileno(stdout));
                close(fds[SW_PIPE_WRITE]);
            }
        }

        execl("/bin/sh", "sh", "-c", command, nullptr);
        exit(127);
    } else {
        *pid = child_pid;
        close(fds[SW_PIPE_WRITE]);
    }
    return fds[SW_PIPE_READ];
}

char *swoole_string_format(size_t n, const char *format, ...) {
    char *buf = (char *) sw_malloc(n);
    if (!buf) {
        return nullptr;
    }

    int ret;
    va_list va_list;
    va_start(va_list, format);
    ret = vsnprintf(buf, n, format, va_list);
    va_end(va_list);
    if (ret >= 0) {
        return buf;
    }
    sw_free(buf);
    return nullptr;
}

void swoole_random_string(char *buf, size_t size) {
    static char characters[] = {
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U',
        'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p',
        'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
    };
    size_t i = 0;
    for (; i < size; i++) {
        buf[i] = characters[swoole_rand(0, sizeof(characters) - 1)];
    }
    buf[i] = '\0';
}

size_t swoole_random_bytes(char *buf, size_t size) {
    size_t read_bytes = 0;
    ssize_t n;

    while (read_bytes < size) {
        size_t amount_to_read = size - read_bytes;
        n = getrandom(buf + read_bytes, amount_to_read, 0);
        if (n == -1) {
            if (errno == EINTR || errno == EAGAIN) {
                continue;
            } else {
                break;
            }
        }
        read_bytes += (size_t) n;
    }

    return read_bytes;
}

int swoole_get_systemd_listen_fds() {
    int ret;
    char *e;

    e = getenv("LISTEN_FDS");
    if (!e) {
        return 0;
    }
    ret = atoi(e);
    if (ret < 1) {
        swWarn("invalid LISTEN_FDS");
        return 0;
    } else if (ret >= SW_MAX_LISTEN_PORT) {
        swoole_error_log(SW_LOG_ERROR, SW_ERROR_SERVER_TOO_MANY_LISTEN_PORT, "LISTEN_FDS is too big");
        return 0;
    }
    return ret;
}

#ifdef HAVE_EXECINFO
void swoole_print_trace(void) {
    int size = 16;
    void *array[16];
    int stack_num = backtrace(array, size);
    char **stacktrace = backtrace_symbols(array, stack_num);
    int i;

    for (i = 0; i < stack_num; ++i) {
        printf("%s\n", stacktrace[i]);
    }
    free(stacktrace);
}
#endif

static void swoole_fatal_error(int code, const char *format, ...) {
    size_t retval = 0;
    va_list args;

    retval += sw_snprintf(sw_error, SW_ERROR_MSG_SIZE, "(ERROR %d): ", code);
    va_start(args, format);
    retval += sw_vsnprintf(sw_error + retval, SW_ERROR_MSG_SIZE - retval, format, args);
    va_end(args);
    sw_logger()->put(SW_LOG_ERROR, sw_error, retval);
    exit(1);
}

size_t swDataHead::dump(char *_buf, size_t _len) {
    return sw_snprintf(_buf,
                       _len,
                       "swDataHead[%p]\n"
                       "{\n"
                       "    int fd = %d;\n"
                       "    uint32_t len = %d;\n"
                       "    int16_t reactor_id = %d;\n"
                       "    uint8_t type = %d;\n"
                       "    uint8_t flags = %d;\n"
                       "    uint16_t server_fd = %d;\n"
                       "}\n",
                       this,
                       fd,
                       len,
                       reactor_id,
                       type,
                       flags,
                       server_fd);
}

namespace swoole {
//-------------------------------------------------------------------------------
int hook_add(void **hooks, int type, const swCallback &func, int push_back) {
    if (hooks[type] == nullptr) {
        hooks[type] = new std::list<swCallback>;
    }

    std::list<swCallback> *l = reinterpret_cast<std::list<swCallback> *>(hooks[type]);
    if (push_back) {
        l->push_back(func);
    } else {
        l->push_front(func);
    }

    return SW_OK;
}

void hook_call(void **hooks, int type, void *arg) {
    std::list<swCallback> *l = reinterpret_cast<std::list<swCallback> *>(hooks[type]);
    for (auto i = l->begin(); i != l->end(); i++) {
        (*i)(arg);
    }
}

/**
 * return the first file of the intersection, in order of vec1
 */
std::string intersection(std::vector<std::string> &vec1, std::set<std::string> &vec2) {
    std::string result = "";

    std::find_if(vec1.begin(), vec1.end(), [&](std::string &str) -> bool {
        auto iter = std::find(vec2.begin(), vec2.end(), str);
        if (iter != vec2.end()) {
            result = *iter;
            return true;
        }
        return false;
    });

    return result;
}
//-------------------------------------------------------------------------------
};  // namespace swoole
