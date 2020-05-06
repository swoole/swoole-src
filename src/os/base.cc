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

#if 0
swAsyncIO SwooleAIO;

static int swAio_onTask(swThreadPool *pool, void *task, int task_len);
static int swAio_onCompleted(swReactor *reactor, swEvent *event);

static swThreadPool pool;
static swPipe _aio_pipe;
static int _pipe_read;
static int _pipe_write;

int swAio_init(void)
{
    if (SwooleAIO.init)
    {
        swWarn("AIO has already been initialized");
        return SW_ERR;
    }
    if (!SwooleTG.reactor)
    {
        swWarn("No eventloop, cannot initialized");
        return SW_ERR;
    }
    if (swPipeBase_create(&_aio_pipe, 0) < 0)
    {
        return SW_ERR;
    }
    if (swMutex_create(&SwooleAIO.lock, 0) < 0)
    {
        swWarn("create mutex lock error");
        return SW_ERR;
    }
    if (SwooleAIO.thread_num <= 0)
    {
        SwooleAIO.thread_num = SW_AIO_THREAD_NUM_DEFAULT;
    }
    if (swThreadPool_create(&pool, SwooleAIO.thread_num) < 0)
    {
        return SW_ERR;
    }

    pool.onTask = swAio_onTask;

    _pipe_read = _aio_pipe.getFd(&_aio_pipe, 0);
    _pipe_write = _aio_pipe.getFd(&_aio_pipe, 1);

    SwooleTG.reactor->setHandle(SwooleTG.reactor, SW_FD_AIO, swAio_onCompleted);
    swoole_event_add(_pipe_read, SW_FD_AIO);

    if (swThreadPool_run(&pool) < 0)
    {
        return SW_ERR;
    }

    SwooleAIO.init = 1;

    return SW_OK;
}

static int swAio_onCompleted(swReactor *reactor, swEvent *event)
{
    int i;
    swAio_event *events[SW_AIO_EVENT_NUM];
    int n = read(event->fd, events, sizeof(swAio_event*) * SW_AIO_EVENT_NUM);
    if (n < 0)
    {
        swSysWarn("read() failed");
        return SW_ERR;
    }
    for (i = 0; i < n / sizeof(swAio_event*); i++)
    {
        events[i]->callback(events[i]);
        SwooleAIO.task_num--;
        sw_free(events[i]);
    }
    return SW_OK;
}


static int swAio_onTask(swThreadPool *pool, void *task, int task_len)
{
    swAio_event *event = task;
    if (event->handler == NULL)
    {
        event->error = SW_ERROR_AIO_BAD_REQUEST;
        event->ret = -1;
        goto _error;
    }

    event->handler(event);

    swTrace("aio_thread ok. ret=%d, error=%d", event->ret, event->error);

    _error:
    do
    {
        SwooleAIO.lock.lock(&SwooleAIO.lock);
        int ret = write(_pipe_write, &task, sizeof(task));
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
                swSysWarn("sendto swoole_aio_pipe_write failed");
            }
        }
        break;
    } while (1);

    return SW_OK;
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
        swWarn("malloc failed");
        return SW_ERR;
    }
    memcpy(event, _event, sizeof(swAio_event));

    if (swThreadPool_dispatch(&pool, event, sizeof(event)) < 0)
    {
        return SW_ERR;
    }
    else
    {
        SwooleAIO.task_num++;
        return _event->task_id;
    }
}

void swAio_free(void)
{
    if (!SwooleAIO.init)
    {
        return;
    }
    swThreadPool_free(&pool);
    if (SwooleTG.reactor)
    {
        SwooleTG.reactor->del(SwooleTG.reactor, _pipe_read);
    }
    _aio_pipe.close(&_aio_pipe);
    SwooleAIO.init = 0;
}
#endif

#if __APPLE__
int swoole_daemon(int nochdir, int noclose)
{
    pid_t pid;

    if (!nochdir && chdir("/") != 0)
    {
        swSysWarn("chdir() failed");
        return -1;
    }

    if (!noclose)
    {
        int fd = open("/dev/null", O_RDWR);
        if (fd < 0)
        {
            swSysWarn("open() failed");
            return -1;
        }

        if (dup2(fd, 0) < 0 || dup2(fd, 1) < 0 || dup2(fd, 2) < 0)
        {
            close(fd);
            swSysWarn("dup2() failed");
            return -1;
        }

        close(fd);
    }

    pid = swoole_fork(SW_FORK_DAEMON);
    if (pid < 0)
    {
        swSysWarn("fork() failed");
        return -1;
    }
    if (pid > 0)
    {
        _exit(0);
    }
    if (setsid() < 0)
    {
        swSysWarn("setsid() failed");
        return -1;
    }
    return 0;
}
#else
int swoole_daemon(int nochdir, int noclose)
{
    if (swoole_fork(SW_FORK_PRECHECK) < 0) {
        return -1;
    }
    return daemon(nochdir, noclose);
}
#endif

void swAio_handler_read(swAio_event *event)
{
    int ret = -1;
    if (event->lock && flock(event->fd, LOCK_SH) < 0)
    {
        swSysWarn("flock(%d, LOCK_SH) failed", event->fd);
        event->ret = -1;
        event->error = errno;
        return;
    }
    while (1)
    {
        ret = pread(event->fd, event->buf, event->nbytes, event->offset);
        if (ret < 0 && errno == EINTR)
        {
            continue;
        }
        break;
    }
    if (event->lock && flock(event->fd, LOCK_UN) < 0)
    {
        swSysWarn("flock(%d, LOCK_UN) failed", event->fd);
    }
    if (ret < 0)
    {
        event->error = errno;
    }
    event->ret = ret;
}

void swAio_handler_fread(swAio_event *event)
{
    int ret = -1;
    if (event->lock && flock(event->fd, LOCK_SH) < 0)
    {
        swSysWarn("flock(%d, LOCK_SH) failed", event->fd);
        event->ret = -1;
        event->error = errno;
        return;
    }
    while (1)
    {
        ret = read(event->fd, event->buf, event->nbytes);
        if (ret < 0 && errno == EINTR)
        {
            continue;
        }
        break;
    }
    if (event->lock && flock(event->fd, LOCK_UN) < 0)
    {
        swSysWarn("flock(%d, LOCK_UN) failed", event->fd);
    }
    if (ret < 0)
    {
        event->error = errno;
    }
    event->ret = ret;
}

void swAio_handler_fwrite(swAio_event *event)
{
    int ret = -1;
    if (event->lock && flock(event->fd, LOCK_EX) < 0)
    {
        swSysWarn("flock(%d, LOCK_EX) failed", event->fd);
        return;
    }
    while (1)
    {
        ret = write(event->fd, event->buf, event->nbytes);
        if (ret < 0 && errno == EINTR)
        {
            continue;
        }
        break;
    }
    if (event->flags & SW_AIO_WRITE_FSYNC)
    {
        if (fsync(event->fd) < 0)
        {
            swSysWarn("fsync(%d) failed", event->fd);
        }
    }
    if (event->lock && flock(event->fd, LOCK_UN) < 0)
    {
        swSysWarn("flock(%d, LOCK_UN) failed", event->fd);
    }
    if (ret < 0)
    {
        event->error = errno;
    }
    event->ret = ret;
}

void swAio_handler_fgets(swAio_event *event)
{
    if (event->lock && flock(event->fd, LOCK_SH) < 0)
    {
        swSysWarn("flock(%d, LOCK_SH) failed", event->fd);
        event->ret = -1;
        event->error = errno;
        return;
    }

    FILE *file = (FILE *) event->req;
    char *data = fgets((char*) event->buf, event->nbytes, file);
    if (data == NULL)
    {
        event->ret = -1;
        event->error = errno;
        event->flags = SW_AIO_EOF;
    }

    if (event->lock && flock(event->fd, LOCK_UN) < 0)
    {
        swSysWarn("flock(%d, LOCK_UN) failed", event->fd);
    }
}

void swAio_handler_read_file(swAio_event *event)
{
    int ret = -1;
    int fd = open((char*) event->req, O_RDONLY);
    if (fd < 0)
    {
        swSysWarn("open(%s, O_RDONLY) failed", (char * )event->req);
        event->ret = ret;
        event->error = errno;
        return;
    }
    struct stat file_stat;
    if (fstat(fd, &file_stat) < 0)
    {
        swSysWarn("fstat(%s) failed", (char * )event->req);
        _error:
        close(fd);
        event->ret = ret;
        event->error = errno;
        return;
    }
    if ((file_stat.st_mode & S_IFMT) != S_IFREG)
    {
        errno = EISDIR;
        goto _error;
    }

    /**
     * lock
     */
    if (event->lock && flock(fd, LOCK_SH) < 0)
    {
        swSysWarn("flock(%d, LOCK_SH) failed", event->fd);
        goto _error;
    }
    /**
     * regular file
     */
    if (file_stat.st_size == 0)
    {
        swString *data = swoole_sync_readfile_eof(fd);
        if (data == NULL)
        {
            goto _error;
        }
        event->ret = data->length;
        event->buf = data->str;
        sw_free(data);
    }
    else
    {
        event->buf = sw_malloc(file_stat.st_size);
        if (event->buf == NULL)
        {
            goto _error;
        }
        size_t readn = swoole_sync_readfile(fd, event->buf, file_stat.st_size);
        event->ret = readn;
    }
    /**
     * unlock
     */
    if (event->lock && flock(fd, LOCK_UN) < 0)
    {
        swSysWarn("flock(%d, LOCK_UN) failed", event->fd);
    }
    close(fd);
    event->error = 0;
}

void swAio_handler_write_file(swAio_event *event)
{
    int ret = -1;
    int fd = open((char*) event->req, event->flags, 0644);
    if (fd < 0)
    {
        swSysWarn("open(%s, %d) failed", (char * )event->req, event->flags);
        event->ret = ret;
        event->error = errno;
        return;
    }
    if (event->lock && flock(fd, LOCK_EX) < 0)
    {
        swSysWarn("flock(%d, LOCK_EX) failed", event->fd);
        event->ret = ret;
        event->error = errno;
        close(fd);
        return;
    }
    size_t written = swoole_sync_writefile(fd, event->buf, event->nbytes);
    if (event->flags & SW_AIO_WRITE_FSYNC)
    {
        if (fsync(fd) < 0)
        {
            swSysWarn("fsync(%d) failed", event->fd);
        }
    }
    if (event->lock && flock(fd, LOCK_UN) < 0)
    {
        swSysWarn("flock(%d, LOCK_UN) failed", event->fd);
    }
    close(fd);
    event->ret = written;
    event->error = 0;
}

void swAio_handler_write(swAio_event *event)
{
    int ret = -1;
    if (event->lock && flock(event->fd, LOCK_EX) < 0)
    {
        swSysWarn("flock(%d, LOCK_EX) failed", event->fd);
        return;
    }
    while (1)
    {
        ret = pwrite(event->fd, event->buf, event->nbytes, event->offset);
        if (ret < 0 && errno == EINTR)
        {
            continue;
        }
        break;
    }
    if (event->flags & SW_AIO_WRITE_FSYNC)
    {
        if (fsync(event->fd) < 0)
        {
            swSysWarn("fsync(%d) failed", event->fd);
        }
    }
    if (event->lock && flock(event->fd, LOCK_UN) < 0)
    {
        swSysWarn("flock(%d, LOCK_UN) failed", event->fd);
    }
    if (ret < 0)
    {
        event->error = errno;
    }
    event->ret = ret;
}

void swAio_handler_gethostbyname(swAio_event *event)
{
    char addr[SW_IP_MAX_LENGTH];
    int ret;

#ifndef HAVE_GETHOSTBYNAME2_R
    SwooleG.lock.lock(&SwooleG.lock);
#endif

    ret = swoole_gethostbyname(event->flags, (char*) event->buf, addr);
    
    bzero(event->buf, event->nbytes);
#ifndef HAVE_GETHOSTBYNAME2_R
    SwooleG.lock.unlock(&SwooleG.lock);
#endif

    if (ret < 0)
    {
        event->error = SW_ERROR_DNSLOOKUP_RESOLVE_FAILED;
    }
    else
    {
        if (inet_ntop(event->flags, addr, (char *) event->buf, event->nbytes) == NULL)
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

void swAio_handler_getaddrinfo(swAio_event *event)
{
    swRequest_getaddrinfo *req = (swRequest_getaddrinfo *) event->req;
    event->ret = swoole_getaddrinfo(req);
    event->error = req->error;
}

