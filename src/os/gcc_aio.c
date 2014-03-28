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

#ifdef SW_AIO_GCC
#include <aio.h>

typedef struct _swAio_gcc_t{
	struct aiocb aiocb;
	struct _swAio_gcc_t *next;
} swAio_gcc_t;

static swAio_gcc_t *swoole_aio_request = NULL;
static int swoole_aio_pipe_read;
static int swoole_aio_pipe_write;

static void swAio_signal_handler(int sig);
static int swoole_gcc_aio_onFinish(swReactor *reactor, swEvent *event);

static int swoole_gcc_aio_onFinish(swReactor *reactor, swEvent *event)
{
	swAio_gcc_t *req = swoole_aio_request;
	swAio_event aio_ev;
	char finished_aio;
	int ret;

	if (read(event->fd, &finished_aio, sizeof(finished_aio)) != sizeof(finished_aio))
	{
		swWarn("read failed. Error: %s[%d]", strerror(errno), errno);
		return SW_ERR;
	}

	while(1)
	{
		if (aio_error(&req->aiocb) == 0)
		{
			ret = aio_return(&req->aiocb);
			aio_ev.ret = ret;
			aio_ev.fd = req->aiocb.aio_fildes;
			aio_ev.type = req->aiocb.aio_lio_opcode == LIO_READ ? SW_AIO_READ: SW_AIO_WRITE;
			aio_ev.nbytes = ret;
			aio_ev.offset = req->aiocb.aio_offset;
			aio_ev.buf = req->aiocb.aio_buf;
			swoole_aio_complete_callback(&aio_ev);
		}

		if(req->next == NULL)
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

int swoole_aio_init(swReactor *_reactor, int max_aio_events)
{
	if(swoole_aio_have_init == 0)
	{
		if (swPipeBase_create(&swoole_aio_pipe, 0) < 0)
		{
			return SW_ERR;
		}

		swoole_aio_complete_callback = swoole_aio_callback;

		swSignalSet(SIGIO, swAio_signal_handler, 1, 0);

		swoole_aio_reactor = _reactor;
		swoole_aio_pipe_read = swoole_aio_pipe.getFd(&swoole_aio_pipe, 0);
		swoole_aio_pipe_write = swoole_aio_pipe.getFd(&swoole_aio_pipe, 1);
		swoole_aio_reactor->setHandle(swoole_aio_reactor, SW_FD_AIO, swoole_gcc_aio_onFinish);
		swoole_aio_reactor->add(swoole_aio_reactor, swoole_aio_pipe_read, SW_FD_AIO);

		swoole_aio_have_init = 1;
	}
	return SW_OK;
}

static void swAio_signal_handler(int sig)
{
	char flag = 0;
	if(sig == SIGIO)
	{
		if(write(swoole_aio_pipe_write, &flag, sizeof(flag)) < 0)
		{
			swWarn("sendto aio pipe failed. Error: %s[%d]", strerror(errno), errno);
		}
	}
}

int swoole_aio_read(int fd, void *outbuf, size_t size, off_t offset)
{
	swAio_gcc_t *aiocb = sw_malloc(sizeof(swAio_gcc_t));
	if(aiocb == NULL)
	{
		swWarn("malloc failed.");
		return SW_ERR;
	}
	bzero(aiocb, sizeof(swAio_gcc_t));

	aiocb->next = NULL;
	if(swoole_aio_request == NULL)
	{
		swoole_aio_request = aiocb;
	}
	else
	{
		swoole_aio_request->next = aiocb;
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
	return SW_OK;
}


int swoole_aio_write(int fd, void *inbuf, size_t size, off_t offset)
{
	swAio_gcc_t *aiocb = sw_malloc(sizeof(swAio_gcc_t));
	if(aiocb == NULL)
	{
		swWarn("malloc failed.");
		return SW_ERR;
	}

	aiocb->next = NULL;
	if(swoole_aio_request == NULL)
	{
		swoole_aio_request = aiocb;
	}
	else
	{
		swoole_aio_request->next = aiocb;
	}
	bzero(aiocb, sizeof(swAio_gcc_t));
	aiocb->aiocb.aio_fildes = fd;
	aiocb->aiocb.aio_buf = inbuf;
	aiocb->aiocb.aio_nbytes = size;
	aiocb->aiocb.aio_lio_opcode = LIO_WRITE;

	aiocb->aiocb.aio_sigevent.sigev_notify = SIGEV_SIGNAL;
	aiocb->aiocb.aio_sigevent.sigev_signo = SIGIO;

	if (aio_write(&aiocb->aiocb) == -1)
	{
		swWarn("aio_write failed. Error: %s[%d]", strerror(errno), errno);
		return SW_ERR;
	}
	return SW_OK;
}

void swoole_aio_destroy()
{
	swoole_aio_pipe.close(&swoole_aio_pipe);
}

#endif
