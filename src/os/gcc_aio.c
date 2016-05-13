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

#ifdef HAVE_GCC_AIO

#include <aio.h>

typedef struct _swAio_gcc_t
{
    struct aiocb aiocb;
    struct _swAio_gcc_t *next;
} swAio_gcc_t;

static swAio_gcc_t *swAioGcc_request = NULL;

static int swAioGcc_pipe_read;
static int swAioGcc_pipe_write;

static void swAioGcc_signal_handler(int sig);
static int swAioGcc_aio_read(int fd, void *outbuf, size_t size, off_t offset);
static int swAioGcc_write(int fd, void *inbuf, size_t size, off_t offset);
static int swAioGcc_onFinish(swReactor *reactor, swEvent *event);
static void swAioGcc_destroy(void);

int swAioGcc_init(int max_aio_events)
{
    if (swPipeBase_create(&swoole_aio_pipe, 0) < 0)
    {
        return SW_ERR;
    }

    swSignal_set(SIGIO, swAioGcc_signal_handler, 1, 0);

    swAioGcc_pipe_read = swoole_aio_pipe.getFd(&swoole_aio_pipe, 0);
    swAioGcc_pipe_write = swoole_aio_pipe.getFd(&swoole_aio_pipe, 1);

    SwooleG.main_reactor->setHandle(SwooleG.main_reactor, SW_FD_AIO, swAioGcc_onFinish);
    SwooleG.main_reactor->add(SwooleG.main_reactor, swAioGcc_pipe_read, SW_FD_AIO);

    SwooleAIO.callback = swAio_callback_test;
    SwooleAIO.read = swAioGcc_aio_read;
    SwooleAIO.write = swAioGcc_write;
    SwooleAIO.destroy = swAioGcc_destroy;

    return SW_OK;
}

static int swAioGcc_onFinish(swReactor *reactor, swEvent *event)
{
    swAio_gcc_t *req = swAioGcc_request;
    swAio_event aio_ev;
    char finished_aio;
    int ret;

    if (read(event->fd, &finished_aio, sizeof(finished_aio)) != sizeof(finished_aio))
    {
        swWarn("read failed. Error: %s[%d]", strerror(errno), errno);
        return SW_ERR;
    }

    while (1)
    {
        if (aio_error(&req->aiocb) == 0)
        {
            ret = aio_return(&req->aiocb);
            aio_ev.ret = ret;
            aio_ev.fd = req->aiocb.aio_fildes;
            aio_ev.type = req->aiocb.aio_lio_opcode == LIO_READ ? SW_AIO_READ : SW_AIO_WRITE;
            aio_ev.nbytes = ret;
            aio_ev.offset = req->aiocb.aio_offset;
            aio_ev.buf = (void *) req->aiocb.aio_buf;
            SwooleAIO.callback(&aio_ev);
            SwooleAIO.task_num--;
        }

        if (req->next == NULL)
        {
            sw_free(req);
            break;
        }
        else
        {
            req = req->next;
        }
        sw_free(req);
    }
    return SW_OK;
}

static void swAioGcc_signal_handler(int sig)
{
    char flag = 0;
    if (sig == SIGIO)
    {
        if (write(swAioGcc_pipe_write, &flag, sizeof(flag)) < 0)
        {
            swWarn("sendto aio pipe failed. Error: %s[%d]", strerror(errno), errno);
        }
    }
}

static int swAioGcc_aio_read(int fd, void *outbuf, size_t size, off_t offset)
{
    swAio_gcc_t *aiocb = sw_malloc(sizeof(swAio_gcc_t));
    if (aiocb == NULL)
    {
        swWarn("malloc failed.");
        return SW_ERR;
    }
    bzero(aiocb, sizeof(swAio_gcc_t));

    aiocb->next = NULL;
    if (swAioGcc_request == NULL)
    {
        swAioGcc_request = aiocb;
    }
    else
    {
        swAioGcc_request->next = aiocb;
    }

    aiocb->aiocb.aio_fildes = fd;
    aiocb->aiocb.aio_buf = outbuf;
    aiocb->aiocb.aio_nbytes = size;
    aiocb->aiocb.aio_lio_opcode = LIO_READ;

    aiocb->aiocb.aio_sigevent.sigev_notify = SIGEV_SIGNAL;
    aiocb->aiocb.aio_sigevent.sigev_signo = SIGIO;

    if (aio_read(&aiocb->aiocb) < 0)
    {
        swWarn("aio_read failed. Error: %s[%d]", strerror(errno), errno);
        return SW_ERR;
    }
    SwooleAIO.task_num++;
    return SW_OK;
}

static int swAioGcc_write(int fd, void *inbuf, size_t size, off_t offset)
{
    swAio_gcc_t *aiocb = sw_malloc(sizeof(swAio_gcc_t));
    if (aiocb == NULL)
    {
        swWarn("malloc failed.");
        return SW_ERR;
    }

    aiocb->next = NULL;
    if (swAioGcc_request == NULL)
    {
        swAioGcc_request = aiocb;
    }
    else
    {
        swAioGcc_request->next = aiocb;
    }
    bzero(aiocb, sizeof(swAio_gcc_t));
    aiocb->aiocb.aio_fildes = fd;
    aiocb->aiocb.aio_buf = inbuf;
    aiocb->aiocb.aio_nbytes = size;
    aiocb->aiocb.aio_lio_opcode = LIO_WRITE;
    aiocb->aiocb.aio_offset = offset;

    aiocb->aiocb.aio_sigevent.sigev_notify = SIGEV_SIGNAL;
    aiocb->aiocb.aio_sigevent.sigev_signo = SIGIO;

    if (aio_write(&aiocb->aiocb) == -1)
    {
        swWarn("aio_write failed. Error: %s[%d]", strerror(errno), errno);
        return SW_ERR;
    }
    SwooleAIO.task_num++;
    return SW_OK;
}

static void swAioGcc_destroy(void)
{
    swoole_aio_pipe.close(&swoole_aio_pipe);
}

#endif