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

#ifdef HAVE_LINUX_AIO

#include <sys/syscall.h>
#include <linux/aio_abi.h>

static aio_context_t swoole_aio_context;
static int swoole_aio_eventfd;

static int swAioLinux_onFinish(swReactor *reactor, swEvent *event);
static int swAioLinux_write(int fd, void *inbuf, size_t size, off_t offset);
static int swAioLinux_read(int fd, void *outbuf, size_t size, off_t offset);
static void swAioLinux_destroy();

static sw_inline int io_setup(unsigned n_request, aio_context_t *context)
{
    return syscall(__NR_io_setup, n_request, context);
}

static sw_inline int io_submit(aio_context_t ctx, long n_request,  struct iocb **iocbpp)
{
    return syscall(__NR_io_submit, ctx, n_request, iocbpp);
}

static sw_inline int io_getevents(aio_context_t ctx, long min_n_request, long max_n_request,
        struct io_event *events, struct timespec *timeout)
{
    return syscall(__NR_io_getevents, ctx, min_n_request, max_n_request, events, timeout);
}

static sw_inline int io_destroy(aio_context_t ctx)
{
    return syscall(__NR_io_destroy, ctx);
}

int swAioLinux_init(int max_aio_events)
{
    swoole_aio_context = 0;
    if (io_setup(SW_AIO_MAX_EVENTS, &swoole_aio_context) < 0)
    {
        swWarn("io_setup() failed. Error: %s[%d]", strerror(errno), errno);
        return SW_ERR;
    }

    if (swPipeNotify_auto(&swoole_aio_pipe, 0, 0) < 0)
    {
        return SW_ERR;
    }

    swoole_aio_eventfd = swoole_aio_pipe.getFd(&swoole_aio_pipe, 0);
    SwooleG.main_reactor->setHandle(SwooleG.main_reactor, SW_FD_AIO, swAioLinux_onFinish);
    SwooleG.main_reactor->add(SwooleG.main_reactor, swoole_aio_eventfd, SW_FD_AIO);

    SwooleAIO.callback = swAio_callback_test;
    SwooleAIO.destroy = swAioLinux_destroy;
    SwooleAIO.read = swAioLinux_read;
    SwooleAIO.write = swAioLinux_write;

    return SW_OK;
}

static int swAioLinux_onFinish(swReactor *reactor, swEvent *event)
{
    struct io_event events[SW_AIO_MAX_EVENTS];
    swAio_event aio_ev;
    uint64_t finished_aio;
    struct iocb *aiocb;
    struct timespec tms;
    int i, n;

    if (read(event->fd, &finished_aio, sizeof(finished_aio)) != sizeof(finished_aio))
    {
        swWarn("read() failed. Error: %s[%d]", strerror(errno), errno);
        return SW_ERR;
    }

    while (finished_aio > 0)
    {
        tms.tv_sec = 0;
        tms.tv_nsec = 0;
        n = io_getevents(swoole_aio_context, 1, SW_AIO_MAX_EVENTS, events, &tms);
        if (n > 0)
        {
            for (i = 0; i < n; i++)
            {
                aiocb = (struct iocb *) events[i].obj;
                if ((int) events[i].res < 0)
                {
                    aio_ev.error = abs((int) events[i].res);
                    aio_ev.ret = -1;
                }
                else
                {
                    aio_ev.ret = (int) events[i].res;
                }
                aio_ev.fd = aiocb->aio_fildes;
                aio_ev.type = aiocb->aio_lio_opcode == IOCB_CMD_PREAD ? SW_AIO_READ : SW_AIO_WRITE;
                aio_ev.nbytes = aio_ev.ret;
                aio_ev.offset = aiocb->aio_offset;
                aio_ev.buf = (void *) aiocb->aio_buf;
                aio_ev.task_id = aiocb->aio_reqprio;
                SwooleAIO.callback(&aio_ev);
            }
            i += n;
            finished_aio -= n;
            SwooleAIO.task_num -= n;
        }
    }
    return SW_OK;
}

static void swAioLinux_destroy()
{
    swoole_aio_pipe.close(&swoole_aio_pipe);
    io_destroy(swoole_aio_context);
}

static int swAioLinux_read(int fd, void *outbuf, size_t size, off_t offset)
{
    struct iocb *iocbps[1];
    struct iocb iocbp;
    bzero(&iocbp, sizeof(struct iocb));

    iocbp.aio_fildes = fd;
    iocbp.aio_lio_opcode = IOCB_CMD_PREAD;
    iocbp.aio_buf = (__u64 ) outbuf;
    iocbp.aio_offset = offset;
    iocbp.aio_nbytes = size;
    iocbp.aio_flags = IOCB_FLAG_RESFD;
    iocbp.aio_resfd = swoole_aio_eventfd;
    iocbp.aio_reqprio = SwooleAIO.current_id++;
    //iocbp.aio_data = (__u64) aio_callback;
    iocbps[0] = &iocbp;

    if (io_submit(swoole_aio_context, 1, iocbps) == 1)
    {
        SwooleAIO.task_num++;
        return iocbp.aio_reqprio;
    }
    swWarn("io_submit failed. Error: %s[%d]", strerror(errno), errno);
    return SW_ERR;
}

static int swAioLinux_write(int fd, void *inbuf, size_t size, off_t offset)
{
    struct iocb *iocbps[1];
    struct iocb *iocbp = sw_malloc(sizeof(struct iocb));
    if (iocbp == NULL)
    {
        swWarn("malloc failed.");
        return SW_ERR;
    }
    bzero(iocbp, sizeof(struct iocb));

    iocbp->aio_fildes = fd;
    iocbp->aio_lio_opcode = IOCB_CMD_PWRITE;
    iocbp->aio_buf = (__u64 ) inbuf;
    iocbp->aio_offset = offset;
    iocbp->aio_nbytes = size;
    iocbp->aio_flags = IOCB_FLAG_RESFD;
    iocbp->aio_resfd = swoole_aio_eventfd;
    iocbp->aio_reqprio = SwooleAIO.current_id++;
    //iocbp->aio_data = (__u64) aio_callback;
    iocbps[0] = iocbp;

    if (io_submit(swoole_aio_context, 1, iocbps) == 1)
    {
        SwooleAIO.task_num++;
        return iocbp->aio_reqprio;
    }
    swWarn("io_submit failed. Error: %s[%d]", strerror(errno), errno);
    return SW_ERR;
}

#endif
