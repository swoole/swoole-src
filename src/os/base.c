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

#ifdef SW_AIO_THREAD_POOL

static int swoole_aio_thread_onTask(swThreadPool *pool, void *task, int task_len);
static int swoole_aio_onFinish(swReactor *reactor, swEvent *event);
static swThreadPool swoole_aio_thread_pool;
static int swoole_aio_pipe_read;
static int swoole_aio_pipe_write;

static int swoole_aio_onFinish(swReactor *reactor, swEvent *event)
{
	int i;
	swAio_event *events[SW_AIO_EVENT_NUM];
	int n = read(event->fd, events, sizeof(swAio_event*)*SW_AIO_EVENT_NUM);
	if (n < 0)
	{
		swWarn("read failed. Error: %s[%d]", strerror(errno), errno);
		return SW_ERR;
	}
	for(i = 0; i < n/sizeof(swAio_event*); i++)
	{
		swoole_aio_complete_callback(events[i]);
		sw_free(events[i]);
	}
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
	struct hostent *host_entry;
	struct in_addr addr;
	char *ip_addr;

	int ret = -1;

	start_switch:
	switch(event->type)
	{
	case SW_AIO_WRITE:
		ret = pwrite(event->fd, event->buf, event->nbytes, event->offset);
		break;
	case SW_AIO_READ:
		ret = pread(event->fd, event->buf, event->nbytes, event->offset);
		break;
	case SW_AIO_DNS_LOOKUP:
		if (!(host_entry = gethostbyname(event->buf)))
		{
			event->error = errno;
		}
		else
		{
			memcpy(&addr, host_entry->h_addr_list[0], host_entry->h_length);
			ip_addr = inet_ntoa(addr);
			memcpy(event->buf, ip_addr, strnlen(ip_addr, SW_IP_MAX_LENGTH));
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
	return swThreadPool_dispatch(&swoole_aio_thread_pool, aio_ev, sizeof(aio_ev));
}

int swoole_aio_dns_lookup(void *hostname, void *ip_addr, size_t size)
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
	return swThreadPool_dispatch(&swoole_aio_thread_pool, aio_ev, sizeof(aio_ev));
}

int swoole_aio_read(int fd, void *inbuf, size_t size, off_t offset)
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
	return swThreadPool_dispatch(&swoole_aio_thread_pool, aio_ev, sizeof(aio_ev));
}

void swoole_aio_destroy()
{
	swThreadPool_free(&swoole_aio_thread_pool);
}

#endif
