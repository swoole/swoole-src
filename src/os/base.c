/*
 +----------------------------------------------------------------------+
 | Swoole                                                               |
 +----------------------------------------------------------------------+
 | Copyright (c) 2012-2018 The Swoole Group                             |
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
#include "async.h"
#include <sys/file.h>
#include <sys/stat.h>

swAsyncIO SwooleAIO;
swPipe swoole_aio_pipe;

static void swAioBase_destroy();
static int swAioBase_read(int fd, void *inbuf, size_t size, off_t offset);
static int swAioBase_write(int fd, void *inbuf, size_t size, off_t offset);
static int swAioBase_thread_onTask(swThreadPool *pool, void *task, int task_len);
static int swAioBase_onFinish(swReactor *reactor, swEvent *event);

static void swAio_handler_read(swAio_event *event);
static void swAio_handler_write(swAio_event *event);
static void swAio_handler_gethostbyname(swAio_event *event);
static void swAio_handler_getaddrinfo(swAio_event *event);
static void swAio_handler_stream_get_line(swAio_event *event);
static void swAio_handler_read_file(swAio_event *event);
static void swAio_handler_write_file(swAio_event *event);

static swThreadPool swAioBase_thread_pool;
static int swAioBase_pipe_read;
static int swAioBase_pipe_write;

int swAio_init(void)
{
    if (SwooleAIO.init)
    {
        swWarn("AIO has already been initialized");
        return SW_ERR;
    }
    if (!SwooleG.main_reactor)
    {
        swWarn("No eventloop, cannot initialized");
        return SW_ERR;
    }

    int ret = 0;

    switch (SwooleAIO.mode)
    {
#ifdef HAVE_LINUX_AIO
    case SW_AIO_LINUX:
        ret = swAioLinux_init(SW_AIO_EVENT_NUM);
        break;
#endif
    default:
        ret = swAioBase_init(SW_AIO_EVENT_NUM);
        break;
    }
    SwooleAIO.init = 1;
    return ret;
}

void swAio_free(void)
{
    if (!SwooleAIO.init)
    {
        return;
    }
    SwooleAIO.destroy();
    SwooleAIO.init = 0;
}

/**
 * for test
 */
void swAio_callback_test(swAio_event *aio_event)
{
    printf("content=%s\n", (char *)aio_event->buf);
    printf("fd: %d, request_type: %s, offset: %ld, length: %lu\n", aio_event->fd,
            (aio_event == SW_AIO_READ) ? "READ" : "WRITE", (long)aio_event->offset,  aio_event->nbytes);
    SwooleG.running = 0;
}

#ifndef HAVE_DAEMON
int daemon(int nochdir, int noclose)
{
    pid_t pid;

    if (!nochdir && chdir("/") != 0)
    {
        swWarn("chdir() failed. Error: %s[%d]", strerror(errno), errno);
        return -1;
    }

    if (!noclose)
    {
        int fd = open("/dev/null", O_RDWR);
        if (fd < 0)
        {
            swWarn("open() failed. Error: %s[%d]", strerror(errno), errno);
            return -1;
        }

        if (dup2(fd, 0) < 0 || dup2(fd, 1) < 0 || dup2(fd, 2) < 0)
        {
            close(fd);
            swWarn("dup2() failed. Error: %s[%d]", strerror(errno), errno);
            return -1;
        }

        close(fd);
    }

    pid = fork();
    if (pid < 0)
    {
        swWarn("fork() failed. Error: %s[%d]", strerror(errno), errno);
        return -1;
    }
    if (pid > 0)
    {
        _exit(0);
    }
    if (setsid() < 0)
    {
        swWarn("setsid() failed. Error: %s[%d]", strerror(errno), errno);
        return -1;
    }
    return 0;
}
#endif

static int swAioBase_onFinish(swReactor *reactor, swEvent *event)
{
    int i;
    swAio_event *events[SW_AIO_EVENT_NUM];
    int n = read(event->fd, events, sizeof(swAio_event*) * SW_AIO_EVENT_NUM);
    if (n < 0)
    {
        swWarn("read() failed. Error: %s[%d]", strerror(errno), errno);
        return SW_ERR;
    }
    for (i = 0; i < n / sizeof(swAio_event*); i++)
    {
        if (events[i]->callback)
        {
            events[i]->callback(events[i]);
        }
        else
        {
            SwooleAIO.callback(events[i]);
        }
        SwooleAIO.task_num--;
        sw_free(events[i]);
    }
    return SW_OK;
}

int swAioBase_init(int max_aio_events)
{
    if (swPipeBase_create(&swoole_aio_pipe, 0) < 0)
    {
        return SW_ERR;
    }
    if (swMutex_create(&SwooleAIO.lock, 0) < 0)
    {
        swWarn("create mutex lock error.");
        return SW_ERR;
    }
    if (SwooleAIO.thread_num <= 0)
    {
        SwooleAIO.thread_num = SW_AIO_THREAD_NUM_DEFAULT;
    }
    if (swThreadPool_create(&swAioBase_thread_pool, SwooleAIO.thread_num) < 0)
    {
        return SW_ERR;
    }

    swAioBase_thread_pool.onTask = swAioBase_thread_onTask;

    swAioBase_pipe_read = swoole_aio_pipe.getFd(&swoole_aio_pipe, 0);
    swAioBase_pipe_write = swoole_aio_pipe.getFd(&swoole_aio_pipe, 1);

    SwooleAIO.handlers[SW_AIO_READ] = swAio_handler_read;
    SwooleAIO.handlers[SW_AIO_WRITE] = swAio_handler_write;
    SwooleAIO.handlers[SW_AIO_GETHOSTBYNAME] = swAio_handler_gethostbyname;
    SwooleAIO.handlers[SW_AIO_GETADDRINFO] = swAio_handler_getaddrinfo;
    SwooleAIO.handlers[SW_AIO_STREAM_GET_LINE] = swAio_handler_stream_get_line;
    SwooleAIO.handlers[SW_AIO_READ_FILE] = swAio_handler_read_file;
    SwooleAIO.handlers[SW_AIO_WRITE_FILE] = swAio_handler_write_file;

    SwooleG.main_reactor->setHandle(SwooleG.main_reactor, SW_FD_AIO, swAioBase_onFinish);
    SwooleG.main_reactor->add(SwooleG.main_reactor, swAioBase_pipe_read, SW_FD_AIO);

    if (swThreadPool_run(&swAioBase_thread_pool) < 0)
    {
        return SW_ERR;
    }

    SwooleAIO.destroy = swAioBase_destroy;
    SwooleAIO.read = swAioBase_read;
    SwooleAIO.write = swAioBase_write;

    return SW_OK;
}

static void swAio_handler_read(swAio_event *event)
{
    int ret = -1;
    if (flock(event->fd, LOCK_SH) < 0)
    {
        swSysError("flock(%d, LOCK_SH) failed.", event->fd);
        event->ret = -1;
        event->error = errno;
        return;
    }
    while (1)
    {
        ret = pread(event->fd, event->buf, event->nbytes, event->offset);
        if (ret < 0 && (errno == EINTR || errno == EAGAIN))
        {
            continue;
        }
        break;
    }
    if (flock(event->fd, LOCK_UN) < 0)
    {
        swSysError("flock(%d, LOCK_UN) failed.", event->fd);
    }
    event->ret = ret;
}

static inline char* find_eol(char *buf, size_t size)
{
    char *eol = memchr(buf, '\n', size);
    if (!eol)
    {
        eol = memchr(buf, '\r', size);
    }
    return eol;
}

static void swAio_handler_stream_get_line(swAio_event *event)
{
    int ret = -1;
    if (flock(event->fd, LOCK_SH) < 0)
    {
        swSysError("flock(%d, LOCK_SH) failed.", event->fd);
        event->ret = -1;
        event->error = errno;
        return;
    }

    off_t readpos = event->offset;
    off_t writepos = (long) event->req;
    size_t avail = 0;
    char *eol;
    char *tmp;

    char *read_buf = event->buf;
    int read_n = event->nbytes;

    while (1)
    {
        avail = writepos - readpos;

        swTraceLog(SW_TRACE_AIO, "readpos=%ld, writepos=%ld", readpos, writepos);

        if (avail > 0)
        {
            tmp = event->buf + readpos;
            eol = find_eol(tmp, avail);
            if (eol)
            {
                event->buf = tmp;
                event->ret = (eol - tmp) + 1;
                readpos += event->ret;
                goto _return;
            }
            else if (readpos == 0)
            {
                if (writepos == event->nbytes)
                {
                    writepos = 0;
                    event->ret = event->nbytes;
                    goto _return;
                }
                else
                {
                    event->flags = SW_AIO_EOF;
                    ((char*) event->buf)[writepos] = '\0';
                    event->ret = writepos;
                    writepos = 0;
                    goto _return;
                }
            }
            else
            {
                memmove(event->buf, event->buf + readpos, avail);
                writepos = avail;
                read_buf = event->buf + writepos;
                read_n = event->nbytes - writepos;
                readpos = 0;
                goto _readfile;
            }
        }
        else
        {
            _readfile: while (1)
            {
                ret = read(event->fd, read_buf, read_n);
                if (ret < 0 && (errno == EINTR || errno == EAGAIN))
                {
                    continue;
                }
                break;
            }
            if (ret > 0)
            {
                writepos += ret;
            }
            else if (ret == 0)
            {
                event->flags = SW_AIO_EOF;
                if (writepos > 0)
                {
                    event->ret = writepos;
                }
                else
                {
                    ((char*) event->buf)[0] = '\0';
                    event->ret = 0;
                }
                readpos = writepos = 0;
                goto _return;
            }
        }
    }

    _return:
    if (flock(event->fd, LOCK_UN) < 0)
    {
        swSysError("flock(%d, LOCK_UN) failed.", event->fd);
    }
    event->offset = readpos;
    event->req = (void *) (long) writepos;
}

static void swAio_handler_read_file(swAio_event *event)
{
    int ret = -1;
    int fd = open(event->req, O_RDONLY);
    if (fd < 0)
    {
        swSysError("open(%s, O_RDONLY) failed.", event->req);
        event->ret = ret;
        event->error = errno;
        return;
    }
    struct stat file_stat;
    if (fstat(fd, &file_stat) < 0)
    {
        swSysError("fstat(%s) failed.", event->req);
        _error: close(fd);
        event->ret = ret;
        event->error = errno;
        return;
    }
    if ((file_stat.st_mode & S_IFMT) != S_IFREG)
    {
        errno = EISDIR;
        goto _error;
    }

    long filesize = file_stat.st_size;
    if (filesize == 0)
    {
        errno = SW_ERROR_FILE_EMPTY;
        goto _error;
    }
    else if (filesize > SW_MAX_FILE_CONTENT)
    {
        errno = SW_ERROR_FILE_TOO_LARGE;
        goto _error;
    }

    if (flock(fd, LOCK_SH) < 0)
    {
        swSysError("flock(%d, LOCK_SH) failed.", event->fd);
        goto _error;
    }

    event->buf = sw_malloc(filesize);
    if (event->buf == NULL)
    {
        goto _error;
    }
    int readn = swoole_sync_readfile(fd, event->buf, (int) filesize);
    if (flock(fd, LOCK_UN) < 0)
    {
        swSysError("flock(%d, LOCK_UN) failed.", event->fd);
    }
    close(fd);
    event->ret = readn;
    event->error = 0;
}

static void swAio_handler_write_file(swAio_event *event)
{
    int ret = -1;
    int fd = open(event->req, event->flags, 0644);
    if (fd < 0)
    {
        swSysError("open(%s, %d) failed.", event->req, event->flags);
        event->ret = ret;
        event->error = errno;
        return;
    }
    if (flock(fd, LOCK_EX) < 0)
    {
        swSysError("flock(%d, LOCK_EX) failed.", event->fd);
        event->ret = ret;
        event->error = errno;
        close(fd);
        return;
    }
    int written = swoole_sync_writefile(fd, event->buf, event->nbytes);
    if (event->flags & SW_AIO_WRITE_FSYNC)
    {
        if (fsync(event->fd) < 0)
        {
            swSysError("fsync(%d) failed.", event->fd);
        }
    }
    if (flock(event->fd, LOCK_UN) < 0)
    {
        swSysError("flock(%d, LOCK_UN) failed.", event->fd);
    }
    close(fd);
    event->ret = written;
    event->error = 0;
}

static void swAio_handler_write(swAio_event *event)
{
    int ret = -1;
    if (flock(event->fd, LOCK_EX) < 0)
    {
        swSysError("flock(%d, LOCK_EX) failed.", event->fd);
        return;
    }
    if (event->offset == 0)
    {
        ret = write(event->fd, event->buf, event->nbytes);
    }
    else
    {
        ret = pwrite(event->fd, event->buf, event->nbytes, event->offset);
    }
    if (event->flags & SW_AIO_WRITE_FSYNC)
    {
        if (fsync(event->fd) < 0)
        {
            swSysError("fsync(%d) failed.", event->fd);
        }
    }
    if (flock(event->fd, LOCK_UN) < 0)
    {
        swSysError("flock(%d, LOCK_UN) failed.", event->fd);
    }
    event->ret = ret;
}

static void swAio_handler_gethostbyname(swAio_event *event)
{
    struct in_addr addr_v4;
    struct in6_addr addr_v6;
    int ret;

#ifndef HAVE_GETHOSTBYNAME2_R
    SwooleAIO.lock.lock(&SwooleAIO.lock);
#endif
    if (event->flags == AF_INET6)
    {
        ret = swoole_gethostbyname(AF_INET6, event->buf, (char *) &addr_v6);
    }
    else
    {
        ret = swoole_gethostbyname(AF_INET, event->buf, (char *) &addr_v4);
    }
    bzero(event->buf, event->nbytes);
#ifndef HAVE_GETHOSTBYNAME2_R
    SwooleAIO.lock.unlock(&SwooleAIO.lock);
#endif

    if (ret < 0)
    {
        event->error = h_errno;
    }
    else
    {
        if (inet_ntop(event->flags == AF_INET6 ? AF_INET6 : AF_INET,
                event->flags == AF_INET6 ? (void *) &addr_v6 : (void *) &addr_v4, event->buf, event->nbytes) == NULL)
        {
            ret = -1;
            event->error = SW_ERROR_BAD_IPV6_ADDRESS;
        }
        else
        {
            event->error = 0;
            ret = 0;
        }
    }
    event->ret = ret;
}

static void swAio_handler_getaddrinfo(swAio_event *event)
{
    swRequest_getaddrinfo *req = (swRequest_getaddrinfo *) event->req;
    event->ret = swoole_getaddrinfo(req);
    event->error = req->error;
}

static int swAioBase_thread_onTask(swThreadPool *pool, void *task, int task_len)
{
    swAio_event *event = task;
    if (event->type >= SW_AIO_HANDLER_MAX_SIZE || SwooleAIO.handlers[event->type] == NULL)
    {
        event->error = SW_ERROR_AIO_BAD_REQUEST;
        event->ret = -1;
        goto _error;
    }

    SwooleAIO.handlers[event->type](event);

    swTrace("aio_thread ok. ret=%d, error=%d", event->ret, event->error);

    _error: do
    {
        SwooleAIO.lock.lock(&SwooleAIO.lock);
        int ret = write(swAioBase_pipe_write, &task, sizeof(task));
        SwooleAIO.lock.unlock(&SwooleAIO.lock);
        if (ret < 0)
        {
            if (errno == EAGAIN)
            {
                swYield();
                continue;
            }
            else if (errno == EINTR)
            {
                continue;
            }
            else
            {
                swSysError("sendto swoole_aio_pipe_write failed.");
            }
        }
        break;
    } while (1);

    return SW_OK;
}

static int swAioBase_write(int fd, void *inbuf, size_t size, off_t offset)
{
    swAio_event *aio_ev = (swAio_event *) sw_malloc(sizeof(swAio_event));
    if (aio_ev == NULL)
    {
        swWarn("malloc failed.");
        return SW_ERR;
    }
    bzero(aio_ev, sizeof(swAio_event));
    aio_ev->fd = fd;
    aio_ev->buf = inbuf;
    aio_ev->type = SW_AIO_WRITE;
    aio_ev->nbytes = size;
    aio_ev->offset = offset;
    aio_ev->task_id = SwooleAIO.current_id++;

    if (swThreadPool_dispatch(&swAioBase_thread_pool, aio_ev, sizeof(aio_ev)) < 0)
    {
        return SW_ERR;
    }
    else
    {
        SwooleAIO.task_num++;
        return aio_ev->task_id;
    }
}

int swAio_dns_lookup(void *hostname, void *ip_addr, size_t size)
{
    swAio_event *aio_ev = (swAio_event *) sw_malloc(sizeof(swAio_event));
    if (aio_ev == NULL)
    {
        swWarn("malloc failed.");
        return SW_ERR;
    }

    bzero(aio_ev, sizeof(swAio_event));
    aio_ev->buf = ip_addr;
    aio_ev->req = hostname;
    aio_ev->type = SW_AIO_GETHOSTBYNAME;
    aio_ev->nbytes = size;
    aio_ev->task_id = SwooleAIO.current_id++;

    if (swThreadPool_dispatch(&swAioBase_thread_pool, aio_ev, sizeof(aio_ev)) < 0)
    {
        return SW_ERR;
    }
    else
    {
        SwooleAIO.task_num++;
        return aio_ev->task_id;
    }
}

int swAio_dispatch(swAio_event *_event)
{
    if (SwooleAIO.init == 0)
    {
        swAio_init();
    }

    _event->task_id = SwooleAIO.current_id++;

    swAio_event *event = (swAio_event *) sw_malloc(sizeof(swAio_event));
    if (event == NULL)
    {
        swWarn("malloc failed.");
        return SW_ERR;
    }
    memcpy(event, _event, sizeof(swAio_event));

    if (swThreadPool_dispatch(&swAioBase_thread_pool, event, sizeof(event)) < 0)
    {
        return SW_ERR;
    }
    else
    {
        SwooleAIO.task_num++;
        return _event->task_id;
    }
}

static int swAioBase_read(int fd, void *inbuf, size_t size, off_t offset)
{
    swAio_event *aio_ev = (swAio_event *) sw_malloc(sizeof(swAio_event));
    if (aio_ev == NULL)
    {
        swWarn("malloc failed.");
        return SW_ERR;
    }

    bzero(aio_ev, sizeof(swAio_event));
    aio_ev->fd = fd;
    aio_ev->buf = inbuf;
    aio_ev->type = SW_AIO_READ;
    aio_ev->nbytes = size;
    aio_ev->offset = offset;
    aio_ev->task_id = SwooleAIO.current_id++;

    if (swThreadPool_dispatch(&swAioBase_thread_pool, aio_ev, sizeof(aio_ev)) < 0)
    {
        return SW_ERR;
    }
    else
    {
        SwooleAIO.task_num++;
        return aio_ev->task_id;
    }
}

void swAioBase_destroy()
{
    swThreadPool_free(&swAioBase_thread_pool);
    if (SwooleG.main_reactor)
    {
        SwooleG.main_reactor->del(SwooleG.main_reactor, swAioBase_pipe_read);
    }
    swoole_aio_pipe.close(&swoole_aio_pipe);
}
