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
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
  +----------------------------------------------------------------------+
*/

#include "swoole.h"
#include "async.h"

#ifdef SW_AIO_LINUX_NATIVE

#include <sys/syscall.h>      /* for __NR_* definitions */
#include <linux/aio_abi.h>    /* for AIO types and constants */

static aio_context_t swoole_aio_context;
static int swoole_aio_eventfd;

static int swoole_aio_onFinish(swReactor *reactor, swEvent *event);

SWINLINE int io_setup(unsigned n_request, aio_context_t *context)
{
    return syscall(__NR_io_setup, n_request, context);
}

SWINLINE int io_submit(aio_context_t ctx, long n_request,  struct iocb **iocbpp)
{
    return syscall(__NR_io_submit, ctx, n_request, iocbpp);
}

SWINLINE int io_getevents(aio_context_t ctx, long min_n_request, long max_n_request,
        struct io_event *events, struct timespec *timeout)
{
    return syscall(__NR_io_getevents, ctx, min_n_request, max_n_request, events, timeout);
}

SWINLINE int io_destroy(aio_context_t ctx)
{
    return syscall(__NR_io_destroy, ctx);
}

int swoole_aio_init(swReactor *_reactor, int max_aio_events)
{
	if (swoole_aio_have_init == 0)
	{
		swoole_aio_context = 0;
		if (io_setup(SW_AIO_MAX_EVENTS, &swoole_aio_context) < 0)
		{
			swWarn("io_setup() failed. Error: %s[%d]", strerror(errno), errno);
			return SW_ERR;
		}

		if (swPipeEventfd_create(&swoole_aio_pipe, 0, 0) < 0)
		{
			return SW_ERR;
		}

		swoole_aio_complete_callback = swoole_aio_callback;

		swoole_aio_reactor = _reactor;
		swoole_aio_eventfd = swoole_aio_pipe.getFd(&swoole_aio_pipe, 0);
		swoole_aio_reactor->setHandle(swoole_aio_reactor, SW_FD_AIO, swoole_aio_onFinish);
		swoole_aio_reactor->add(swoole_aio_reactor, swoole_aio_eventfd, SW_FD_AIO);
		swoole_aio_have_init = 1;
	}
	return SW_OK;
}

static int swoole_aio_onFinish(swReactor *reactor, swEvent *event)
{
	struct io_event events[SW_AIO_MAX_EVENTS];
	swAio_event aio_ev;
	uint64_t finished_aio;
	struct iocb *aiocb;
	struct timespec tms;
	int i, n;

	if (read(event->fd, &finished_aio, sizeof(finished_aio)) != sizeof(finished_aio))
	{
		swWarn("read failed. Error: %s[%d]", strerror(errno), errno);
		return SW_ERR;
	}

	//swWarn("finished_aio=%ld", finished_aio);
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
				aio_ev.ret = (int) events[i].res;
				aio_ev.fd = aiocb->aio_fildes;
				aio_ev.type = aiocb->aio_lio_opcode == IOCB_CMD_PREAD ? SW_AIO_READ: SW_AIO_WRITE;
				aio_ev.nbytes = aio_ev.ret;
				aio_ev.offset = aiocb->aio_offset;
				aio_ev.buf = aiocb->aio_buf;
				swoole_aio_complete_callback(&aio_ev);
			}
			i += n;
			finished_aio -= n;
		}
	}
	return SW_OK;
}

void swoole_aio_destroy()
{
	swoole_aio_pipe.close(&swoole_aio_pipe);
	io_destroy(swoole_aio_context);
}

int swoole_aio_read(int fd, void *outbuf, size_t size, off_t offset)
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
	//iocbp.aio_data = (__u64) aio_callback;
	iocbps[0] = &iocbp;

    if (io_submit(swoole_aio_context, 1, iocbps) == 1)
    {
        return SW_OK;
    }
    swWarn("io_submit failed. Error: %s[%d]", strerror(errno), errno);
    return SW_ERR;
}

int swoole_aio_write(int fd, void *inbuf, size_t size, off_t offset)
{
    struct iocb *iocbps[1];
    struct iocb *iocbp = sw_malloc(sizeof(struct iocb));
    if(iocbp == NULL)
    {
    	swWarn("malloc failed.");
    	return SW_ERR;
    }
    bzero(iocbp, sizeof(struct iocb));

    iocbp->aio_fildes = fd;
    iocbp->aio_lio_opcode = IOCB_CMD_PWRITE;
    iocbp->aio_buf =  (__u64)inbuf;
    iocbp->aio_offset = offset;
    iocbp->aio_nbytes = size;
    iocbp->aio_flags = IOCB_FLAG_RESFD;
    iocbp->aio_resfd = swoole_aio_eventfd;
    //iocbp->aio_data = (__u64) aio_callback;
    iocbps[0] = iocbp;

    if (io_submit(swoole_aio_context, 1, iocbps) == 1)
    {
        return SW_OK;
    }
    swWarn("io_submit failed. Error: %s[%d]", strerror(errno), errno);
    return SW_ERR;
}

#endif
