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
#include "async.h"
#include <sys/file.h>

swAsyncIO SwooleAIO;
swPipe swoole_aio_pipe;

static void swAioBase_destroy();
static int swAioBase_read(int fd, void *inbuf, size_t size, off_t offset);
static int swAioBase_write(int fd, void *inbuf, size_t size, off_t offset);
static int swAioBase_thread_onTask(swThreadPool *pool, void *task, int task_len);
static int swAioBase_onFinish(swReactor *reactor, swEvent *event);

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

    if (SwooleAIO.mode == SW_AIO_BASE)
    {
        swAioBase_destroy(&swAioBase_thread_pool);
    }
}

/**
 * for test
 */
void swAio_callback_test(swAio_event *aio_event)
{
    printf("content=%s\n", (char *)aio_event->buf);
    printf("fd: %d, request_type: %s, offset: %ld, length: %lu\n", aio_event->fd,
            (aio_event == SW_AIO_READ) ? "READ" : "WRITE", aio_event->offset, (uint64_t) aio_event->nbytes);
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
        SwooleAIO.callback(events[i]);
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

    SwooleG.main_reactor->setHandle(SwooleG.main_reactor, SW_FD_AIO, swAioBase_onFinish);
    SwooleG.main_reactor->add(SwooleG.main_reactor, swAioBase_pipe_read, SW_FD_AIO);

    if (swThreadPool_run(&swAioBase_thread_pool) < 0)
    {
        return SW_ERR;
    }

    SwooleAIO.callback = swAio_callback_test;
    SwooleAIO.destroy = swAioBase_destroy;
    SwooleAIO.read = swAioBase_read;
    SwooleAIO.write = swAioBase_write;

    return SW_OK;
}

static int swAioBase_thread_onTask(swThreadPool *pool, void *task, int task_len)
{
    swAio_event *event = task;
    struct in_addr addr;

    char *ip_addr;
    int ret = -1;

    start_switch:
    switch(event->type)
    {
    case SW_AIO_WRITE:
        if (flock(event->fd, LOCK_EX) < 0)
        {
            swSysError("flock(%d, LOCK_EX) failed.", event->fd);
            break;
        }
        if (event->offset == 0)
        {
            ret = write(event->fd, event->buf, event->nbytes);
        }
        else
        {
            ret = pwrite(event->fd, event->buf, event->nbytes, event->offset);
        }
        if (flock(event->fd, LOCK_UN) < 0)
        {
            swSysError("flock(%d, LOCK_UN) failed.", event->fd);
        }
        break;
    case SW_AIO_READ:
        if (flock(event->fd, LOCK_SH) < 0)
        {
            swSysError("flock(%d, LOCK_SH) failed.", event->fd);
            break;
        }
        ret = pread(event->fd, event->buf, event->nbytes, event->offset);
        if (flock(event->fd, LOCK_UN) < 0)
        {
            swSysError("flock(%d, LOCK_UN) failed.", event->fd);
        }
        break;
    case SW_AIO_DNS_LOOKUP:
        ret = swoole_gethostbyname(AF_INET, event->buf, (char *) &addr);
        if (ret < 0)
        {
            event->error = h_errno;
            switch (h_errno)
            {
            case HOST_NOT_FOUND:
                bzero(event->buf, event->nbytes);
                ret = 0;
                break;
            default:
                ret = -1;
                break;
            }
        }
        else
        {
            ip_addr = inet_ntoa(addr);
            bzero(event->buf, event->nbytes);
            memcpy(event->buf, ip_addr, strnlen(ip_addr, SW_IP_MAX_LENGTH) + 1);
            ret = 0;
        }
        break;
    default:
        swWarn("unknow aio task.");
        break;
    }

    event->ret = ret;
    if (ret < 0)
    {
        if (errno == EINTR || errno == EAGAIN)
        {
            goto start_switch;
        }
        else
        {
            event->error = errno;
        }
    }

    swTrace("aio_thread ok. ret=%d", ret);
    do
    {
        ret = write(swAioBase_pipe_write, &task, sizeof(task));
        if (ret < 0)
        {
            if (errno == EAGAIN)
            {
                swYield();
                continue;
            }
            else if(errno == EINTR)
            {
                continue;
            }
            else
            {
                swWarn("sendto swoole_aio_pipe_write failed. Error: %s[%d]", strerror(errno), errno);
            }
        }
        break;
    } while(1);

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
    aio_ev->type = SW_AIO_DNS_LOOKUP;
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
}
