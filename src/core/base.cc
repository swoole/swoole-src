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

#include "swoole_api.h"
#include "swoole_cxx.h"
#include "atomic.h"
#include "async.h"
#include "coroutine_c_api.h"

#include <stdarg.h>

#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/ioctl.h>

#include <algorithm>

#ifdef HAVE_EXECINFO
#include <execinfo.h>
#endif

#include <list>
#include <set>

swGlobal_t SwooleG;
swWorkerGlobal_t SwooleWG;
__thread swThreadGlobal_t SwooleTG;

#ifdef __MACH__
static __thread char _sw_error_buf[SW_ERROR_MSG_SIZE];
char* sw_error_()
{
    return _sw_error_buf;
}
#else
__thread char sw_error[SW_ERROR_MSG_SIZE];
#endif

static void swoole_fatal_error(int code, const char *format, ...);

void swoole_init(void)
{
    if (SwooleG.init)
    {
        return;
    }

    bzero(&SwooleG, sizeof(SwooleG));
    bzero(&SwooleWG, sizeof(SwooleWG));
    bzero(sw_error, SW_ERROR_MSG_SIZE);

    SwooleG.running = 1;
    SwooleG.init = 1;
    SwooleG.enable_coroutine = 1;

    SwooleG.log_fd = STDOUT_FILENO;
    SwooleG.write_log = swLog_put;
    SwooleG.fatal_error = swoole_fatal_error;

    SwooleG.cpu_num = SW_MAX(1, sysconf(_SC_NPROCESSORS_ONLN));
    SwooleG.pagesize = getpagesize();
    //get system uname
    uname(&SwooleG.uname);
    //random seed
    srandom(time(NULL));

    SwooleG.pid = getpid();

#ifdef SW_DEBUG
    SwooleG.log_level = 0;
    SwooleG.trace_flags = 0x7fffffff;
#else
    SwooleG.log_level = SW_LOG_INFO;
#endif

    //init global shared memory
    SwooleG.memory_pool = swMemoryGlobal_new(SW_GLOBAL_MEMORY_PAGESIZE, 1);
    if (SwooleG.memory_pool == NULL)
    {
        printf("[Core] Fatal Error: global memory allocation failure");
        exit(1);
    }

    if (swMutex_create(&SwooleG.lock, 0) < 0)
    {
        printf("[Core] mutex init failure");
        exit(1);
    }

    SwooleG.max_sockets = SW_MAX_SOCKETS_DEFAULT;
    struct rlimit rlmt;
    if (getrlimit(RLIMIT_NOFILE, &rlmt) < 0)
    {
        swSysWarn("getrlimit() failed");
    }
    else
    {
        SwooleG.max_sockets = SW_MAX((uint32_t) rlmt.rlim_cur, SW_MAX_SOCKETS_DEFAULT);
        SwooleG.max_sockets = SW_MIN((uint32_t) rlmt.rlim_cur, SW_SESSION_LIST_SIZE);
    }

    SwooleG.socket_buffer_size = SW_SOCKET_BUFFER_SIZE;
    SwooleG.socket_send_timeout = SW_SOCKET_SEND_TIMEOUT;

    SwooleTG.buffer_stack = swString_new(SW_STACK_BUFFER_SIZE);
    if (SwooleTG.buffer_stack == NULL)
    {
        exit(3);
    }

    if (!SwooleG.task_tmpdir)
    {
        SwooleG.task_tmpdir = sw_strndup(SW_TASK_TMP_FILE, sizeof(SW_TASK_TMP_FILE));
        SwooleG.task_tmpdir_len = sizeof(SW_TASK_TMP_FILE);
    }

    char *tmp_dir = swoole_dirname(SwooleG.task_tmpdir);
    //create tmp dir
    if (access(tmp_dir, R_OK) < 0 && swoole_mkdir_recursive(tmp_dir) < 0)
    {
        swWarn("create task tmp dir(%s) failed", tmp_dir);
    }
    if (tmp_dir)
    {
        sw_free(tmp_dir);
    }

    //init signalfd
#ifdef HAVE_SIGNALFD
    swSignalfd_init();
    SwooleG.use_signalfd = 1;
    SwooleG.enable_signalfd = 1;
#endif
}

SW_API const char* swoole_version(void)
{
    return SWOOLE_VERSION;
}

SW_API int swoole_version_id(void)
{
    return SWOOLE_VERSION_ID;
}

void swoole_clean(void)
{
    if (SwooleG.task_tmpdir)
    {
        sw_free(SwooleG.task_tmpdir);
    }
    if (SwooleTG.timer)
    {
        swoole_timer_free();
    }
    if (SwooleTG.reactor)
    {
        swoole_event_free();
    }
    if (SwooleG.memory_pool != NULL)
    {
        SwooleG.memory_pool->destroy(SwooleG.memory_pool);
    }
    bzero(&SwooleG, sizeof(SwooleG));
}

pid_t swoole_fork(int flags)
{
    if (!(flags & SW_FORK_EXEC))
    {
        if (swoole_coroutine_is_in())
        {
            swFatalError(SW_ERROR_OPERATION_NOT_SUPPORT, "must be forked outside the coroutine");
        }
        if (SwooleTG.aio_init)
        {
            swFatalError(SW_ERROR_OPERATION_NOT_SUPPORT, "can not create server after using async file operation");
        }
    }
    if (flags & SW_FORK_PRECHECK)
    {
        return 0;
    }

    pid_t pid = fork();
    if (pid == 0)
    {
        if (flags & SW_FORK_DAEMON)
        {
            SwooleG.pid = getpid();
            return pid;
        }
        /**
         * [!!!] All timers and event loops must be cleaned up after fork
         */
        if (SwooleTG.timer)
        {
            swoole_timer_free();
        }
        if (!(flags & SW_FORK_EXEC))
        {
            /**
             * reset SwooleG.memory_pool
             */
            SwooleG.memory_pool = swMemoryGlobal_new(SW_GLOBAL_MEMORY_PAGESIZE, 1);
            if (SwooleG.memory_pool == NULL)
            {
                printf("[Worker] Fatal Error: global memory allocation failure");
                exit(1);
            }
            /**
             * reopen log file
             */
            swLog_reopen(SW_FALSE);
            /**
             * reset eventLoop
             */
            if (SwooleTG.reactor)
            {
                swoole_event_free();
                swTraceLog(SW_TRACE_REACTOR, "reactor has been destroyed");
            }
        }
        else
        {
            /**
             * close log fd
             */
            swLog_close();
        }
        /**
         * reset signal handler
         */
        swSignal_clear();
        /**
         * reset global struct
         */
        bzero(&SwooleWG, sizeof(SwooleWG));
        SwooleG.pid = getpid();
    }
    return pid;
}

uint64_t swoole_hash_key(char *str, int str_len)
{
    uint64_t hash = 5381;
    int c, i = 0;
    for (c = *str++; i < str_len; i++)
    {
        hash = (*((hash * 33) + str)) & 0x7fffffff;
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

void swoole_dump_ascii(const char *data, size_t size)
{
    for (size_t i = 0; i < size; i++)
    {
        printf("%d ", (unsigned) data[i]);
    }
    printf("\n");
}

void swoole_dump_bin(const char *data, char type, size_t size)
{
    int i;
    int type_size = swoole_type_size(type);
    if (type_size <= 0)
    {
        return;
    }
    int n = size / type_size;

    for (i = 0; i < n; i++)
    {
        printf("%d,", swoole_unpack(type, data + type_size * i));
    }
    printf("\n");
}

void swoole_dump_hex(const char *data, size_t outlen)
{
    for (size_t i = 0; i < outlen; ++i)
    {
        if ((i & 0x0fu) == 0)
        {
            printf("%08zX: ", i);
        }
        printf("%02X ", data[i]);
        if (((i + 1) & 0x0fu) == 0)
        {
            printf("\n");
        }
    }
    printf("\n");
}

/**
 * Recursive directory creation
 */
int swoole_mkdir_recursive(const char *dir)
{
    char tmp[PATH_MAX];
    int i, len = strlen(dir);

    if (len + 1 > PATH_MAX) /* PATH_MAX limit includes string trailing null character */
    {
        swWarn("mkdir(%s) failed. Path exceeds the limit of %d characters", dir, PATH_MAX - 1);
        return -1;
    }
    strncpy(tmp, dir, PATH_MAX);

    if (dir[len - 1] != '/')
    {
        strcat(tmp, "/");
    }

    len = strlen(tmp);

    for (i = 1; i < len; i++)
    {
        if (tmp[i] == '/')
        {
            tmp[i] = 0;
            if (access(tmp, R_OK) != 0)
            {
                if (mkdir(tmp, 0755) == -1)
                {
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
char* swoole_dirname(char *file)
{
    char *dirname = sw_strdup(file);
    if (dirname == NULL)
    {
        swWarn("strdup() failed");
        return NULL;
    }

    int i = strlen(dirname);

    if (dirname[i - 1] == '/')
    {
        i -= 2;
    }

    for (; i > 0; i--)
    {
        if ('/' == dirname[i])
        {
            dirname[i] = 0;
            break;
        }
    }
    return dirname;
}

int swoole_type_size(char type)
{
    switch (type)
    {
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

char* swoole_dec2hex(int value, int base)
{
    assert(base > 1 && base < 37);

    static char digits[] = "0123456789abcdefghijklmnopqrstuvwxyz";
    char buf[(sizeof(unsigned long) << 3) + 1];
    char *ptr, *end;

    end = ptr = buf + sizeof(buf) - 1;
    *ptr = '\0';

    do
    {
        *--ptr = digits[value % base];
        value /= base;
    } while (ptr > buf && value);

    return sw_strndup(ptr, end - ptr);
}

size_t swoole_hex2dec(char** hex)
{
    size_t value = 0;
    while (1)
    {
        char c = **hex;
        if ((c >= '0') && (c <= '9'))
        {
            value = value * 16 + (c - '0');
        }
        else
        {
            c = toupper(c);
            if ((c >= 'A') && (c <= 'Z'))
            {
                value = value * 16 + (c - 'A') + 10;
            }
            else
            {
                break;
            }
        }
        (*hex)++;
    }
    return value;
}

size_t swoole_sync_writefile(int fd, const void *data, size_t len)
{
    ssize_t n = 0;
    size_t count = len, towrite, written = 0;

    while (count > 0)
    {
        towrite = count;
        if (towrite > SW_FILE_CHUNK_SIZE)
        {
            towrite = SW_FILE_CHUNK_SIZE;
        }
        n = write(fd, data, towrite);
        if (n > 0)
        {
            data = (char*) data + n;
            count -= n;
            written += n;
        }
        else if (n == 0)
        {
            break;
        }
        else
        {
            if (errno == EINTR || errno == EAGAIN)
            {
                continue;
            }
            swSysWarn("write(%d, %zu) failed", fd, towrite);
            break;
        }
    }
    return written;
}

#ifndef RAND_MAX
#define RAND_MAX   2147483647
#endif

int swoole_rand(int min, int max)
{
    static int _seed = 0;
    assert(max > min);

    if (_seed == 0)
    {
        _seed = time(NULL);
        srand(_seed);
    }

    int _rand = rand();
    _rand = min + (int) ((double) ((double) (max) - (min) + 1.0) * ((_rand) / ((RAND_MAX) + 1.0)));
    return _rand;
}

int swoole_system_random(int min, int max)
{
    static int dev_random_fd = -1;
    char *next_random_byte;
    int bytes_to_read;
    unsigned random_value;

    assert(max > min);

    if (dev_random_fd == -1)
    {
        dev_random_fd = open("/dev/urandom", O_RDONLY);
        if (dev_random_fd < 0)
        {
            return swoole_rand(min, max);
        }
    }

    next_random_byte = (char *) &random_value;
    bytes_to_read = sizeof(random_value);

    if (read(dev_random_fd, next_random_byte, bytes_to_read) < bytes_to_read)
    {
        swSysWarn("read() from /dev/urandom failed");
        return SW_ERR;
    }
    return min + (random_value % (max - min + 1));
}

void swoole_redirect_stdout(int new_fd)
{
    if (dup2(new_fd, STDOUT_FILENO) < 0)
    {
        swSysWarn("dup2(STDOUT_FILENO) failed");
    }
    if (dup2(new_fd, STDERR_FILENO) < 0)
    {
        swSysWarn("dup2(STDERR_FILENO) failed");
    }
}

int swoole_version_compare(const char *version1, const char *version2)
{
    int result = 0;

    while (result == 0)
    {
        char* tail1;
        char* tail2;

        unsigned long ver1 = strtoul(version1, &tail1, 10);
        unsigned long ver2 = strtoul(version2, &tail2, 10);

        if (ver1 < ver2)
        {
            result = -1;
        }
        else if (ver1 > ver2)
        {
            result = +1;
        }
        else
        {
            version1 = tail1;
            version2 = tail2;
            if (*version1 == '\0' && *version2 == '\0')
            {
                break;
            }
            else if (*version1 == '\0')
            {
                result = -1;
            }
            else if (*version2 == '\0')
            {
                result = +1;
            }
            else
            {
                version1++;
                version2++;
            }
        }
    }
    return result;
}

double swoole_microtime(void)
{
    struct timeval t;
    gettimeofday(&t, NULL);
    return (double) t.tv_sec + ((double) t.tv_usec / 1000000);
}

void swoole_rtrim(char *str, int len)
{
    int i;
    for (i = len; i > 0;)
    {
        switch (str[--i])
        {
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

int swoole_tmpfile(char *filename)
{
#if defined(HAVE_MKOSTEMP) && defined(HAVE_EPOLL)
    int tmp_fd = mkostemp(filename, O_WRONLY | O_CREAT);
#else
    int tmp_fd = mkstemp(filename);
#endif

    if (tmp_fd < 0)
    {
        swSysWarn("mkstemp(%s) failed", filename);
        return SW_ERR;
    }
    else
    {
        return tmp_fd;
    }
}

long swoole_file_get_size(FILE *fp)
{
    long pos = ftell(fp);
    if (fseek(fp, 0L, SEEK_END) < 0)
    {
        return SW_ERR;
    }
    long size = ftell(fp);
    if (fseek(fp, pos, SEEK_SET) < 0)
    {
        return SW_ERR;
    }
    return size;
}

long swoole_file_size(const char *filename)
{
    struct stat file_stat;
    if (lstat(filename, &file_stat) < 0)
    {
        swSysWarn("lstat(%s) failed", filename);
        swoole_set_last_error(errno);
        return -1;
    }
    if ((file_stat.st_mode & S_IFMT) != S_IFREG)
    {
        swoole_set_last_error(EISDIR);
        return -1;
    }
    return file_stat.st_size;
}

swString* swoole_file_get_contents(const char *filename)
{
    long filesize = swoole_file_size(filename);
    if (filesize < 0)
    {
        return NULL;
    }
    else if (filesize == 0)
    {
        swoole_error_log(SW_LOG_TRACE, SW_ERROR_FILE_EMPTY, "file[%s] is empty", filename);
        return NULL;
    }
    else if (filesize > SW_MAX_FILE_CONTENT)
    {
        swoole_error_log(SW_LOG_WARNING, SW_ERROR_FILE_TOO_LARGE, "file[%s] is too large", filename);
        return NULL;
    }

    int fd = open(filename, O_RDONLY);
    if (fd < 0)
    {
        swSysWarn("open(%s) failed", filename);
        return NULL;
    }
    swString *content = swString_new(filesize);
    if (!content)
    {
        close(fd);
        return NULL;
    }

    int readn = 0;
    int n;

    while(readn < filesize)
    {
        n = pread(fd, content->str + readn, filesize - readn, readn);
        if (n < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            else
            {
                swSysWarn("pread(%d, %ld, %d) failed", fd, filesize - readn, readn);
                swString_free(content);
                close(fd);
                return NULL;
            }
        }
        readn += n;
    }
    close(fd);
    content->length = readn;
    swString_append_ptr(content, "\0", 1);
    content->length--;

    return content;
}

int swoole_file_put_contents(const char *filename, const char *content, size_t length)
{
    if (length <= 0)
    {
        swoole_error_log(SW_LOG_TRACE, SW_ERROR_FILE_EMPTY, "content is empty");
        return SW_ERR;
    }
    if (length > SW_MAX_FILE_CONTENT)
    {
        swoole_error_log(SW_LOG_WARNING, SW_ERROR_FILE_TOO_LARGE, "content is too large");
        return SW_ERR;
    }

    int fd = open(filename, O_WRONLY | O_TRUNC | O_CREAT, 0666);
    if (fd < 0)
    {
        swSysWarn("open(%s) failed", filename);
        return SW_ERR;
    }

    size_t n, chunk_size, written = 0;

    while(written < length)
    {
        chunk_size = length - written;
        if (chunk_size > SW_BUFFER_SIZE_BIG)
        {
            chunk_size = SW_BUFFER_SIZE_BIG;
        }
        n = write(fd, content + written, chunk_size);
        if (n < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            else
            {
                swSysWarn("write(%d, %d) failed", fd, chunk_size);
                close(fd);
                return -1;
            }
        }
        written += n;
    }
    close(fd);
    return SW_OK;
}

size_t swoole_sync_readfile(int fd, void *buf, size_t len)
{
    ssize_t n = 0;
    size_t count = len, toread, readn = 0;

    while (count > 0)
    {
        toread = count;
        if (toread > SW_FILE_CHUNK_SIZE)
        {
            toread = SW_FILE_CHUNK_SIZE;
        }
        n = read(fd, buf, toread);
        if (n > 0)
        {
            buf = (char *) buf + n;
            count -= n;
            readn += n;
        }
        else if (n == 0)
        {
            break;
        }
        else
        {
            if (errno == EINTR || errno == EAGAIN)
            {
                continue;
            }
            swSysWarn("read() failed");
            break;
        }
    }
    return readn;
}

swString* swoole_sync_readfile_eof(int fd)
{
    ssize_t n = 0;
    swString *data = swString_new(SW_BUFFER_SIZE_STD);
    if (data == NULL)
    {
        return data;
    }

    while (1)
    {
        n = read(fd, data->str + data->length, data->size - data->length);
        if (n <= 0)
        {
            return data;
        }
        else
        {
            if (swString_grow(data, (size_t) n))
            {
                return data;
            }
        }
    }
    return data;
}

/**
 * Maximum common divisor
 */
uint32_t swoole_common_divisor(uint32_t u, uint32_t v)
{
    assert(u > 0);
    assert(v > 0);
    uint32_t t;
    while (u > 0)
    {
        if (u < v)
        {
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
uint32_t swoole_common_multiple(uint32_t u, uint32_t v)
{
    assert(u > 0);
    assert(v > 0);

    uint32_t m_cup = u;
    uint32_t n_cup = v;
    int res = m_cup % n_cup;

    while (res != 0)
    {
        m_cup = n_cup;
        n_cup = res;
        res = m_cup % n_cup;
    }
    return u * v / n_cup;
}

size_t sw_snprintf(char *buf, size_t size, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    int retval = vsnprintf(buf, size, format, args);
    va_end(args);
    if (sw_unlikely(retval < 0))
    {
        retval = 0;
        buf[0] = '\0';
    }
    else if (sw_unlikely(retval >= (int )size))
    {
        retval = size - 1;
        buf[retval] = '\0';
    }
    return retval;
}

size_t sw_vsnprintf(char *buf, size_t size, const char *format, va_list args)
{
    int retval = vsnprintf(buf, size, format, args);
    if (sw_unlikely(retval < 0))
    {
        retval = 0;
        buf[0] = '\0';
    }
    else if (sw_unlikely(retval >= (int )size))
    {
        retval = size - 1;
        buf[retval] = '\0';
    }
    return retval;
}

int swoole_ioctl_set_block(int sock, int nonblock)
{
    int ret;
    do
    {
        ret = ioctl(sock, FIONBIO, &nonblock);
    }
    while (ret == -1 && errno == EINTR);

    if (ret < 0)
    {
        swSysWarn("ioctl(%d, FIONBIO, %d) failed", sock, nonblock);
        return SW_ERR;
    }
    else
    {
        return SW_OK;
    }
}

int swoole_fcntl_set_option(int sock, int nonblock, int cloexec)
{
    int opts, ret;

    if (nonblock >= 0)
    {
        do
        {
            opts = fcntl(sock, F_GETFL);
        }
        while (opts < 0 && errno == EINTR);

        if (opts < 0)
        {
            swSysWarn("fcntl(%d, GETFL) failed", sock);
        }

        if (nonblock)
        {
            opts = opts | O_NONBLOCK;
        }
        else
        {
            opts = opts & ~O_NONBLOCK;
        }

        do
        {
            ret = fcntl(sock, F_SETFL, opts);
        }
        while (ret < 0 && errno == EINTR);

        if (ret < 0)
        {
            swSysWarn("fcntl(%d, SETFL, opts) failed", sock);
            return SW_ERR;
        }
    }

#ifdef FD_CLOEXEC
    if (cloexec >= 0)
    {
        do
        {
            opts = fcntl(sock, F_GETFD);
        }
        while (opts < 0 && errno == EINTR);

        if (opts < 0)
        {
            swSysWarn("fcntl(%d, GETFL) failed", sock);
        }

        if (cloexec)
        {
            opts = opts | FD_CLOEXEC;
        }
        else
        {
            opts = opts & ~FD_CLOEXEC;
        }

        do
        {
            ret = fcntl(sock, F_SETFD, opts);
        }
        while (ret < 0 && errno == EINTR);

        if (ret < 0)
        {
            swSysWarn("fcntl(%d, SETFD, opts) failed", sock);
            return SW_ERR;
        }
    }
#endif
    return SW_OK;
}

static int *swoole_kmp_borders(char *needle, size_t nlen)
{
    if (!needle)
    {
        return NULL;
    }

    int i, j, *borders = (int *) sw_malloc((nlen + 1) * sizeof(*borders));
    if (!borders)
    {
        return NULL;
    }

    i = 0;
    j = -1;
    borders[i] = j;
    while ((uint32_t) i < nlen)
    {
        while (j >= 0 && needle[i] != needle[j])
        {
            j = borders[j];
        }
        ++i;
        ++j;
        borders[i] = j;
    }
    return borders;
}

static char *swoole_kmp_search(char *haystack, size_t haylen, char *needle, uint32_t nlen, int *borders)
{
    uint32_t max_index = haylen - nlen, i = 0, j = 0;

    while (i <= max_index)
    {
        while (j < nlen && *haystack && needle[j] == *haystack)
        {
            ++j;
            ++haystack;
        }
        if (j == nlen)
        {
            return haystack - nlen;
        }
        if (!(*haystack))
        {
            return NULL;
        }
        if (j == 0)
        {
            ++haystack;
            ++i;
        }
        else
        {
            do
            {
                i += j - (uint32_t) borders[j];
                j = borders[j];
            } while (j > 0 && needle[j] != *haystack);
        }
    }
    return NULL;
}

int swoole_itoa(char *buf, long value)
{
    long i = 0, j;
    long sign_mask;
    unsigned long nn;

    sign_mask = value >> (sizeof(long) * 8 - 1);
    nn = (value + sign_mask) ^ sign_mask;
    do
    {
        buf[i++] = nn % 10 + '0';
    } while (nn /= 10);

    buf[i] = '-';
    i += sign_mask & 1;
    buf[i] = '\0';

    int s_len = i;
    char swap;

    for (i = 0, j = s_len - 1; i < j; ++i, --j)
    {
        swap = buf[i];
        buf[i] = buf[j];
        buf[j] = swap;
    }
    buf[s_len] = 0;
    return s_len;
}

char *swoole_kmp_strnstr(char *haystack, char *needle, uint32_t length)
{
    if (!haystack || !needle)
    {
        return NULL;
    }
    size_t nlen = strlen(needle);
    if (length < nlen)
    {
        return NULL;
    }
    int *borders = swoole_kmp_borders(needle, nlen);
    if (!borders)
    {
        return NULL;
    }
    char *match = swoole_kmp_search(haystack, length, needle, nlen, borders);
    sw_free(borders);
    return match;
}

/**
 * DNS lookup
 */
#ifdef HAVE_GETHOSTBYNAME2_R
int swoole_gethostbyname(int flags, const char *name, char *addr)
{
    int __af = flags & (~SW_DNS_LOOKUP_RANDOM);
    int index = 0;
    int rc, err;
    int buf_len = 256;
    struct hostent hbuf;
    struct hostent *result;

    char *buf = (char*) sw_malloc(buf_len);
    if (!buf)
    {
        return SW_ERR;
    }
    memset(buf, 0, buf_len);
    while ((rc = gethostbyname2_r(name, __af, &hbuf, buf, buf_len, &result, &err)) == ERANGE)
    {
        buf_len *= 2;
        char *tmp = (char*) sw_realloc(buf, buf_len);
        if (NULL == tmp)
        {
            sw_free(buf);
            return SW_ERR;
        }
        else
        {
            buf = tmp;
        }
    }

    if (0 != rc || NULL == result)
    {
        sw_free(buf);
        return SW_ERR;
    }

    union
    {
        char v4[INET_ADDRSTRLEN];
        char v6[INET6_ADDRSTRLEN];
    } addr_list[SW_DNS_HOST_BUFFER_SIZE];

    int i = 0;
    for (i = 0; i < SW_DNS_HOST_BUFFER_SIZE; i++)
    {
        if (hbuf.h_addr_list[i] == NULL)
        {
            break;
        }
        if (__af == AF_INET)
        {
            memcpy(addr_list[i].v4, hbuf.h_addr_list[i], hbuf.h_length);
        }
        else
        {
            memcpy(addr_list[i].v6, hbuf.h_addr_list[i], hbuf.h_length);
        }
    }
    if (__af == AF_INET)
    {
        memcpy(addr, addr_list[index].v4, hbuf.h_length);
    }
    else
    {
        memcpy(addr, addr_list[index].v6, hbuf.h_length);
    }

    sw_free(buf);

    return SW_OK;
}
#else
int swoole_gethostbyname(int flags, const char *name, char *addr)
{
    int __af = flags & (~SW_DNS_LOOKUP_RANDOM);
    int index = 0;

    struct hostent *host_entry;
    if (!(host_entry = gethostbyname2(name, __af)))
    {
        return SW_ERR;
    }

    union
    {
        char v4[INET_ADDRSTRLEN];
        char v6[INET6_ADDRSTRLEN];
    } addr_list[SW_DNS_HOST_BUFFER_SIZE];

    int i = 0;
    for (i = 0; i < SW_DNS_HOST_BUFFER_SIZE; i++)
    {
        if (host_entry->h_addr_list[i] == NULL)
        {
            break;
        }
        if (__af == AF_INET)
        {
            memcpy(addr_list[i].v4, host_entry->h_addr_list[i], host_entry->h_length);
        }
        else
        {
            memcpy(addr_list[i].v6, host_entry->h_addr_list[i], host_entry->h_length);
        }
    }
    if (__af == AF_INET)
    {
        memcpy(addr, addr_list[index].v4, host_entry->h_length);
    }
    else
    {
        memcpy(addr, addr_list[index].v6, host_entry->h_length);
    }
    return SW_OK;
}
#endif

int swoole_getaddrinfo(swRequest_getaddrinfo *req)
{
    struct addrinfo *result = NULL;
    struct addrinfo *ptr = NULL;
    struct addrinfo hints;

    bzero(&hints, sizeof(hints));
    hints.ai_family = req->family;
    hints.ai_socktype = req->socktype;
    hints.ai_protocol = req->protocol;

    int ret = getaddrinfo(req->hostname, req->service, &hints, &result);
    if (ret != 0)
    {
        req->error = ret;
        return SW_ERR;
    }

    void *buffer = req->result;
    int i = 0;
    for (ptr = result; ptr != NULL; ptr = ptr->ai_next)
    {
        switch (ptr->ai_family)
        {
        case AF_INET:
            memcpy((char *) buffer + (i * sizeof(struct sockaddr_in)), ptr->ai_addr, sizeof(struct sockaddr_in));
            break;
        case AF_INET6:
            memcpy((char *) buffer + (i * sizeof(struct sockaddr_in6)), ptr->ai_addr, sizeof(struct sockaddr_in6));
            break;
        default:
            swWarn("unknown socket family[%d]", ptr->ai_family);
            break;
        }
        i++;
        if (i == SW_DNS_HOST_BUFFER_SIZE)
        {
            break;
        }
    }
    freeaddrinfo(result);
    req->error = 0;
    req->count = i;
    return SW_OK;
}

SW_API int swoole_add_function(const char *name, void* func)
{
    if (SwooleG.functions == NULL)
    {
        SwooleG.functions = swHashMap_new(64, NULL);
        if (SwooleG.functions == NULL)
        {
            return SW_ERR;
        }
    }
    if (swHashMap_find(SwooleG.functions, (char *) name, strlen(name)) != NULL)
    {
        swWarn("Function '%s' has already been added", name);
        return SW_ERR;
    }
    return swHashMap_add(SwooleG.functions, (char *) name, strlen(name), func);
}

SW_API void* swoole_get_function(const char *name, uint32_t length)
{
    if (!SwooleG.functions)
    {
        return NULL;
    }
    return swHashMap_find(SwooleG.functions, name, length);
}

SW_API int swoole_add_hook(enum swGlobal_hook_type type, swCallback func, int push_back)
{
    return swoole::hook_add(SwooleG.hooks, type, func, push_back);
}

SW_API void swoole_call_hook(enum swGlobal_hook_type type, void *arg)
{
    swoole::hook_call(SwooleG.hooks, type, arg);
}

int swoole_shell_exec(const char *command, pid_t *pid, uint8_t get_error_stream)
{
    pid_t child_pid;
    int fds[2];
    if (pipe(fds) < 0)
    {
        return SW_ERR;
    }

    if ((child_pid = fork()) == -1)
    {
        swSysWarn("fork() failed");
        close(fds[0]);
        close(fds[1]);
        return SW_ERR;
    }

    if (child_pid == 0)
    {
        close(fds[SW_PIPE_READ]);

        if (get_error_stream)
        {
            if (fds[SW_PIPE_WRITE] == fileno(stdout))
            {
                dup2(fds[SW_PIPE_WRITE], fileno(stderr));
            }
            else if (fds[SW_PIPE_WRITE] == fileno(stderr))
            {
                dup2(fds[SW_PIPE_WRITE], fileno(stdout));
            }
            else
            {
                dup2(fds[SW_PIPE_WRITE], fileno(stdout));
                dup2(fds[SW_PIPE_WRITE], fileno(stderr));
                close(fds[SW_PIPE_WRITE]);
            }
        }
        else
        {
            if (fds[SW_PIPE_WRITE] != fileno(stdout))
            {
                dup2(fds[SW_PIPE_WRITE], fileno(stdout));
                close(fds[SW_PIPE_WRITE]);
            }
        }

        execl("/bin/sh", "sh", "-c", command, NULL);
        exit(127);
    }
    else
    {
        *pid = child_pid;
        close(fds[SW_PIPE_WRITE]);
    }
    return fds[SW_PIPE_READ];
}

char* swoole_string_format(size_t n, const char *format, ...)
{
    char *buf = (char*) sw_malloc(n);
    if (!buf)
    {
        return NULL;
    }

    int ret;
    va_list va_list;
    va_start(va_list, format);
    ret = vsnprintf(buf, n, format, va_list);
    va_end(va_list);
    if (ret >= 0)
    {
        return buf;
    }
    sw_free(buf);
    return NULL;
}

int swoole_get_systemd_listen_fds()
{
    int ret;
    char *e;

    e = getenv("LISTEN_FDS");
    if (!e)
    {
        return 0;
    }
    ret = atoi(e);
    if (ret < 1)
    {
        swWarn("invalid LISTEN_FDS");
        return 0;
    }
    else if (ret >= SW_MAX_LISTEN_PORT)
    {
        swoole_error_log(SW_LOG_ERROR, SW_ERROR_SERVER_TOO_MANY_LISTEN_PORT, "LISTEN_FDS is too big");
        return 0;
    }
    return ret;
}

#ifdef HAVE_EXECINFO
void swoole_print_trace(void)
{
    int size = 16;
    void* array[16];
    int stack_num = backtrace(array, size);
    char** stacktrace = backtrace_symbols(array, stack_num);
    int i;

    for (i = 0; i < stack_num; ++i)
    {
        printf("%s\n", stacktrace[i]);
    }
    free(stacktrace);
}
#endif

#ifndef HAVE_CLOCK_GETTIME
#ifdef __MACH__
int clock_gettime(clock_id_t which_clock, struct timespec *t)
{
    // be more careful in a multithreaded environement
    if (!orwl_timestart)
    {
        mach_timebase_info_data_t tb =
        {   0};
        mach_timebase_info(&tb);
        orwl_timebase = tb.numer;
        orwl_timebase /= tb.denom;
        orwl_timestart = mach_absolute_time();
    }
    double diff = (mach_absolute_time() - orwl_timestart) * orwl_timebase;
    t->tv_sec = diff * ORWL_NANO;
    t->tv_nsec = diff - (t->tv_sec * ORWL_GIGA);
    return 0;
}
#endif
#endif

static void swoole_fatal_error(int code, const char *format, ...)
{
    size_t retval = 0;
    va_list args;

    retval += sw_snprintf(sw_error, SW_ERROR_MSG_SIZE, "(ERROR %d): ", code);
    va_start(args, format);
    retval += sw_vsnprintf(sw_error + retval, SW_ERROR_MSG_SIZE - retval, format, args);
    va_end(args);
    SwooleG.write_log(SW_LOG_ERROR, sw_error, retval);
    exit(1);
}

void swDataHead_dump(const swDataHead *data)
{
    printf("swDataHead[%p]\n"
            "{\n"
            "    int fd = %d;\n"
            "    uint32_t len = %d;\n"
            "    int16_t reactor_id = %d;\n"
            "    uint8_t type = %d;\n"
            "    uint8_t flags = %d;\n"
            "    uint16_t server_fd = %d;\n"
            "}\n", data, data->fd, data->len, data->reactor_id, data->type, data->flags, data->server_fd);
}

/**
 * return the first file of the intersection, in order of vec1
 */
std::string swoole::intersection(std::vector<std::string> &vec1, std::set<std::string> &vec2)
{
    std::string result = "";

    std::find_if(vec1.begin(),vec1.end(), [&](std::string &str) -> bool
    {
        auto iter = std::find(vec2.begin(), vec2.end(), str);
        if (iter != vec2.end())
        {
            result = *iter;
            return true;
        }
        return false;
    });

    return result;
}
