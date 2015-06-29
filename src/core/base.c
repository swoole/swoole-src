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
#include "atomic.h"

#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/ioctl.h>

void swoole_init(void)
{
    struct rlimit rlmt;
    if (SwooleG.running)
    {
        return;
    }

    bzero(&SwooleG, sizeof(SwooleG));
    bzero(&SwooleWG, sizeof(SwooleWG));
    bzero(sw_error, SW_ERROR_MSG_SIZE);

    SwooleG.running = 1;
    sw_errno = 0;

    SwooleG.log_fd = STDOUT_FILENO;
    SwooleG.cpu_num = sysconf(_SC_NPROCESSORS_ONLN);
    SwooleG.pagesize = getpagesize();
    SwooleG.pid = getpid();

    //get system uname
    uname(&SwooleG.uname);

#if defined(HAVE_REUSEPORT) && defined(HAVE_EPOLL)
    if (swoole_version_compare(SwooleG.uname.release, "3.9.0") >= 0)
    {
        SwooleG.reuse_port = 1;
    }
#endif

    //random seed
    srandom(time(NULL));

    //init global shared memory
    SwooleG.memory_pool = swMemoryGlobal_new(SW_GLOBAL_MEMORY_PAGESIZE, 1);
    if (SwooleG.memory_pool == NULL)
    {
        printf("[Master] Fatal Error: create global memory failed.");
        exit(1);
    }
    SwooleGS = SwooleG.memory_pool->alloc(SwooleG.memory_pool, sizeof(swServerGS));
    if (SwooleGS == NULL)
    {
        printf("[Master] Fatal Error: alloc memory for SwooleGS failed.");
        exit(2);
    }

    //init global lock
    swMutex_create(&SwooleGS->lock, 1);

    if (getrlimit(RLIMIT_NOFILE, &rlmt) < 0)
    {
        swWarn("getrlimit() failed. Error: %s[%d]", strerror(errno), errno);
        SwooleG.max_sockets = 1024;
    }
    else
    {
        SwooleG.max_sockets = (uint32_t) rlmt.rlim_cur;
    }

    //init signalfd
#ifdef HAVE_SIGNALFD
    swSignalfd_init();
    SwooleG.use_signalfd = 1;
#endif
    //timerfd
#ifdef HAVE_TIMERFD
    SwooleG.use_timerfd = 1;
#endif

    SwooleG.use_timer_pipe = 1;

    SwooleStats = SwooleG.memory_pool->alloc(SwooleG.memory_pool, sizeof(swServerStats));
    if (SwooleStats == NULL)
    {
        swError("[Master] Fatal Error: alloc memory for SwooleStats failed.");
    }
    swoole_update_time();
}

void swoole_clean(void)
{
    //free the global memory
    if (SwooleG.memory_pool != NULL)
    {
        SwooleG.memory_pool->destroy(SwooleG.memory_pool);
        SwooleG.memory_pool = NULL;
        if (SwooleG.timer.fd > 0)
        {
            SwooleG.timer.free(&SwooleG.timer);
        }
        if (SwooleG.main_reactor)
        {
            SwooleG.main_reactor->free(SwooleG.main_reactor);
        }
        bzero(&SwooleG, sizeof(SwooleG));
    }
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

void swoole_dump_ascii(char *data, int size)
{
    int i;
    for (i = 0; i < size; i++)
    {
        printf("%d ", (unsigned) data[i]);
    }
    printf("\n");
}

void swoole_dump_bin(char *data, char type, int size)
{
    int i;
    int type_size = swoole_type_size(type);
    int n = size / type_size;

    for (i = 0; i < n; i++)
    {
        printf("%d,", swoole_unpack(type, data + type_size * i));
    }
    printf("\n");
}

/**
 * Recursive directory creation
 */
int swoole_mkdir_recursive(const char *dir)
{
    char tmp[1024];
    strncpy(tmp, dir, 1024);
    int i, len = strlen(tmp);

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
                    swWarn("mkdir(%s) failed. Error: %s[%d]", tmp, strerror(errno), errno);
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
    char *dirname = strdup(file);
    if (dirname == NULL)
    {
        swWarn("strdup() failed.");
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
    case 's':
    case 'S':
    case 'n':
        return 2;
    case 'l':
    case 'L':
    case 'N':
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

    if (base < 2 || base > 36)
    {
        return NULL;
    }

    end = ptr = buf + sizeof(buf) - 1;
    *ptr = '\0';

    do
    {
        *--ptr = digits[value % base];
        value /= base;
    } while (ptr > buf && value);

    return strndup(ptr, end - ptr);
}

int swoole_sync_writefile(int fd, void *data, int len)
{
    int n = 0;
    int count = len, towrite, written = 0;

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
            data += n;
            count -= n;
            written += n;
        }
        else
        {
            swWarn("write() failed. Error: %s[%d]", strerror(errno), errno);
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

    if (read(dev_random_fd, next_random_byte, bytes_to_read) < 0)
    {
        swSysError("read() failed.");
        return SW_ERR;
    }
    return min + (random_value % (max - min + 1));
}

void swoole_update_time(void)
{
    time_t now = time(NULL);
    if (now < 0)
    {
        swWarn("get time failed. Error: %s[%d]", strerror(errno), errno);
    }
    else
    {
        SwooleGS->now = now;
    }
}

int swoole_version_compare(char *version1, char *version2)
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

uint64_t swoole_ntoh64(uint64_t n64)
{
    uint32_t tmp;
    uint32_t n32[2];
    uint64_t *h64 = (uint64_t*) n32;
    memcpy(h64, &n64, sizeof(n64));
    *h64 = n64;

    tmp = n32[0];
    n32[0] = ntohl(n32[1]);
    n32[1] = ntohl(tmp);

    return *h64;
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
    for (i = len; i > 0; i--)
    {
        switch (str[i])
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
            break;
        }
    }
}

int swoole_tmpfile(char *filename)
{
#ifdef HAVE_MKOSTEMP
    int tmp_fd = mkostemp(filename, O_WRONLY);
#else
    int tmp_fd = mkstemp(filename);
#endif

    if (tmp_fd < 0)
    {
        swSysError("mkdtemp(%s) failed.", filename);
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
    fseek(fp, 0L, SEEK_END);
    long size = ftell(fp);
    fseek(fp, pos, SEEK_SET); 
    return size;
}

swString* swoole_file_get_contents(char *filename)
{
    struct stat file_stat;
    if (lstat(filename, &file_stat) < 0)
    {
        swWarn("lstat(%s) failed. Error: %s[%d]", filename, strerror(errno), errno);
        return NULL;
    }
    if (file_stat.st_size > SW_MAX_FILE_CONTENT)
    {
        swWarn("file is too big");
        return NULL;
    }
    int fd = open(filename, O_RDONLY);
    if (fd < 0)
    {
        swWarn("open(%s) failed. Error: %s[%d]", filename, strerror(errno), errno);
        return NULL;
    }

    swString *content = swString_new(file_stat.st_size);
    if (!content)
    {
        swWarn("malloc failed");
        return NULL;
    }

    int readn = 0;
    int n;

    while(readn < file_stat.st_size)
    {
        n = pread(fd, content->str + readn, file_stat.st_size - readn, readn);
        if (n < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            else
            {
                swWarn("pread() failed. Error: %s[%d]", strerror(errno), errno);
                swString_free(content);
                return NULL;
            }
        }
        readn += n;
    }
    return content;
}

int swoole_sync_readfile(int fd, void *buf, int len)
{
    int n = 0;
    int count = len, toread, readn = 0;

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
            buf += n;
            count -= n;
            readn += n;
        }
        else if (n == 0)
        {
            break;
        }
        else
        {
            swWarn("read() failed. Error: %s[%d]", strerror(errno), errno);
            break;
        }
    }
    return readn;
}

/**
 * 最大公约数
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
 * 最小公倍数
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


void swFloat2timeval(float timeout, long int *sec, long int *usec)
{
    *sec = (int) timeout;
    *usec = (int) ((timeout * 1000 * 1000) - ((*sec) * 1000 * 1000));
}

int swRead(int fd, void *buf, int len)
{
    int n = 0, nread;
    sw_errno = 0;

    while (1)
    {
        nread = recv(fd, buf + n, len - n, 0);

//        swWarn("Read Len=%d|Errno=%d", nread, errno);
        //遇到错误
        if (nread < 0)
        {
            //中断
            if (errno == EINTR)
            {
                continue;
            }
            //出错了
            else
            {
                if (errno == EAGAIN && n > 0)
                {
                    break;
                }
                else
                {
                    sw_errno = -1; //异常
                    return SW_ERR;
                }
            }
        }
        //连接已关闭
        //需要检测errno来区分是EAGAIN还是ECONNRESET
        else if (nread == 0)
        {
            //这里直接break,保证读到的数据被处理
            break;
        }
        else
        {
            n += nread;
            //内存读满了，还可能有数据
            if (n == len)
            {
                sw_errno = EAGAIN;
                break;
            }
            //已读完 n < len
            else
            {
                break;
            }
        }

    }
    return n;
}

/**
 * for GDB
 */
void swBreakPoint()
{

}

int swWrite(int fd, void *buf, int count)
{
    int nwritten = 0, totlen = 0;
    while (totlen != count)
    {
        nwritten = write(fd, buf, count - totlen);
        if (nwritten == 0)
        {
            return totlen;
        }
        if (nwritten == -1)
        {
            if (errno == EINTR)
            {
                continue;
            }
            else if (errno == EAGAIN)
            {
                swYield();
                continue;
            }
            else
            {
                return -1;
            }
        }
        totlen += nwritten;
        buf += nwritten;
    }
    return totlen;
}

void swoole_ioctl_set_block(int sock, int nonblock)
{
    int ret;
    do
    {
        ret = ioctl(sock, FIONBIO, &nonblock);
    }
    while (ret == -1 && errno == EINTR);

    if (ret < 0)
    {
        swSysError("ioctl(%d, FIONBIO, %d) failed.", sock, nonblock);
    }
}

void swoole_fcntl_set_block(int sock, int nonblock)
{
    int opts, ret;
    do
    {
        opts = fcntl(sock, F_GETFL);
    }
    while (opts < 0 && errno == EINTR);

    if (opts < 0)
    {
        swSysError("fcntl(%d, GETFL) failed.", sock);
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
        swSysError("fcntl(%d, SETFL, opts) failed.", sock);
    }
}

int swAccept(int server_socket, struct sockaddr_in *addr, int addr_len)
{
    int conn_fd;
    bzero(addr, addr_len);

    while (1)
    {
#ifdef SW_USE_ACCEPT4
        conn_fd = accept4(server_socket, (struct sockaddr *) addr, (socklen_t *) &addr_len, SOCK_NONBLOCK);
#else
        conn_fd = accept(server_socket, (struct sockaddr *) addr, (socklen_t *) &addr_len);
#endif
        if (conn_fd < 0)
        {
            //中断
            if (errno == EINTR)
            {
                continue;
            }
            else
            {
                swTrace("accept failed. Error: %s[%d]", strerror(errno), errno);
                return SW_ERR;
            }
        }
#ifndef SW_USE_ACCEPT4
        swSetNonBlock(conn_fd);
#endif
        break;
    }
    return conn_fd;
}

int swSetTimeout(int sock, double timeout)
{
    int ret;
    struct timeval timeo;
    timeo.tv_sec = (int) timeout;
    timeo.tv_usec = (int) ((timeout - timeo.tv_sec) * 1000 * 1000);
    ret = setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (void *) &timeo, sizeof(timeo));
    if (ret < 0)
    {
        swWarn("setsockopt(SO_SNDTIMEO) failed. Error: %s[%d]", strerror(errno), errno);
        return SW_ERR;
    }
    ret = setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (void *) &timeo, sizeof(timeo));
    if (ret < 0)
    {
        swWarn("setsockopt(SO_RCVTIMEO) failed. Error: %s[%d]", strerror(errno), errno);
        return SW_ERR;
    }
    return SW_OK;
}

static int *swoole_kmp_borders(char *needle, size_t nlen)
{
    if (!needle)
    {
        return NULL;
    }

    int i, j, *borders = malloc((nlen + 1) * sizeof(*borders));
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
    free(borders);
    return match;
}

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
