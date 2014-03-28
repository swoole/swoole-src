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

swPipe swoole_aio_pipe;
int swoole_aio_have_init = 0;
swReactor *swoole_aio_reactor;

void (*swoole_aio_complete_callback)(swAio_event *aio_event);

/**
 * for test
 */
void swoole_aio_callback(swAio_event *aio_event)
{
	printf("content=%s\n", (char *)aio_event->buf);
	printf("fd: %d, request_type: %s, offset: %ld, length: %lu\n", aio_event->fd,
			(aio_event == SW_AIO_READ) ? "READ" : "WRITE", aio_event->offset, (uint64_t) aio_event->nbytes);
	SwooleG.running = 0;
}

#ifdef SW_AIO_THREAD_POOL

static int swoole_aio_thread_onTask(swThreadPool *pool, void *task, int task_len);
static int swoole_aio_onFinish(swReactor *reactor, swEvent *event);
static swThreadPool swoole_aio_thread_pool;
static int swoole_aio_pipe_read;
static int swoole_aio_pipe_write;

static int swoole_aio_onFinish(swReactor *reactor, swEvent *event)
{
	swAio_event *aio_ev;
	if (read(event->fd, &aio_ev, sizeof(aio_ev)) != sizeof(aio_ev))
	{
		swWarn("read failed. Error: %s[%d]", strerror(errno), errno);
		return SW_ERR;
	}
	swoole_aio_complete_callback(aio_ev);
	sw_free(aio_ev);
	return SW_OK;
}

int swoole_aio_init(swReactor *_reactor, int max_aio_events)
{
	if (swoole_aio_have_init == 0)
	{
		if (swPipeBase_create(&swoole_aio_pipe, 0) < 0)
		{
			return SW_ERR;
		}
		if (swThreadPool_create(&swoole_aio_thread_pool, SW_AIO_THREAD_NUM) < 0)
		{
			return SW_ERR;
		}
		swoole_aio_complete_callback = swoole_aio_callback;
		swoole_aio_thread_pool.onTask = swoole_aio_thread_onTask;

		swoole_aio_pipe_read = swoole_aio_pipe.getFd(&swoole_aio_pipe, 0);
		swoole_aio_pipe_write = swoole_aio_pipe.getFd(&swoole_aio_pipe, 1);
		_reactor->setHandle(_reactor, SW_FD_AIO, swoole_aio_onFinish);
		_reactor->add(_reactor, swoole_aio_pipe_read, SW_FD_AIO);

		if (swThreadPool_run(&swoole_aio_thread_pool) < 0)
		{
			return SW_ERR;
		}
		swoole_aio_have_init = 1;
	}
	return SW_OK;
}

static int swoole_aio_thread_onTask(swThreadPool *pool, void *task, int task_len)
{
	swAio_event *event = task;
	int ret;

	switch(event->type)
	{
	case SW_AIO_WRITE:
		ret = pwrite(event->fd, event->buf, event->nbytes, event->offset);
		break;
	case SW_AIO_READ:
		ret = pread(event->fd, event->buf, event->nbytes, event->offset);
		break;
	case SW_AIO_DNS_LOOKUP:
		break;
	default:
		swWarn("unknow aio task.");
		break;
	}
	event->ret = ret;

	swTrace("aio_thread ok. ret=%d", ret);
	do
	{
		ret = write(swoole_aio_pipe_write, &task, sizeof(task));
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

int swoole_aio_write(int fd, void *inbuf, size_t size, off_t offset)
{
	swAio_event *aio_ev = sw_malloc(sizeof(swAio_event));
	bzero(aio_ev, sizeof(swAio_event));
	aio_ev->fd = fd;
	aio_ev->buf = inbuf;
	aio_ev->type = SW_AIO_WRITE;
	aio_ev->nbytes = size;
	aio_ev->offset = offset;
	return swThreadPool_dispatch(&swoole_aio_thread_pool, aio_ev, sizeof(aio_ev));
}

int swoole_aio_read(int fd, void *inbuf, size_t size, off_t offset)
{
	swAio_event *aio_ev = sw_malloc(sizeof(swAio_event));
	bzero(aio_ev, sizeof(swAio_event));
	aio_ev->fd = fd;
	aio_ev->buf = inbuf;
	aio_ev->type = SW_AIO_READ;
	aio_ev->nbytes = size;
	aio_ev->offset = offset;
	return swThreadPool_dispatch(&swoole_aio_thread_pool, aio_ev, sizeof(aio_ev));
}

void swoole_aio_destroy()
{
	swThreadPool_free(&swoole_aio_thread_pool);
}

#endif
