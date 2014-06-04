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
#include <sys/poll.h>

static int swReactorPoll_add(swReactor *reactor, int fd, int fdtype);
static int swReactorPoll_set(swReactor *reactor, int fd, int fdtype);
static int swReactorPoll_del(swReactor *reactor, int fd);
static int swReactorPoll_wait(swReactor *reactor, struct timeval *timeo);
static void swReactorPoll_free(swReactor *reactor);

typedef struct _swPollFdInfo
{
	int fdtype;
} swPollFdInfo;

typedef struct _swReactorPoll
{
	int max_fd_num;
	swPollFdInfo *fds;
	struct pollfd *events;
} swReactorPoll;

int swReactorPoll_create(swReactor *reactor, int max_fd_num)
{
	//create reactor object
	swReactorPoll *object = sw_malloc(sizeof(swReactorPoll));
	if (object == NULL)
	{
		swError("malloc[0] failed");
		return SW_ERR;
	}
	bzero(object, sizeof(swReactorPoll));

	object->fds = sw_calloc(max_fd_num, sizeof(swPollFdInfo));
	if (object->fds == NULL)
	{
		swError("malloc[1] failed");
		return SW_ERR;
	}
	object->events = sw_calloc(max_fd_num, sizeof(struct pollfd));
	if (object->events == NULL)
	{
		swError("malloc[2] failed");
		return SW_ERR;
	}
	object->max_fd_num = max_fd_num;
	reactor->max_event_num = max_fd_num;
	bzero(reactor->handle, sizeof(reactor->handle));
	reactor->object = object;
	//binding method
	reactor->add = swReactorPoll_add;
	reactor->del = swReactorPoll_del;
	reactor->set = swReactorPoll_set;
	reactor->wait = swReactorPoll_wait;
	reactor->free = swReactorPoll_free;
	reactor->setHandle = swReactor_setHandle;
	reactor->onFinish = NULL;
	reactor->onTimeout = NULL;
	return SW_OK;
}

static void swReactorPoll_free(swReactor *reactor)
{
	swReactorPoll *object = reactor->object;
	sw_free(object->fds);
	sw_free(reactor->object);
}

static int swReactorPoll_add(swReactor *reactor, int fd, int fdtype)
{
	swReactorPoll *object = reactor->object;
	int cur = reactor->event_num;
	if (reactor->event_num == object->max_fd_num)
	{
		swError("too many connection, more than %d", object->max_fd_num);
		return SW_ERR;
	}
	object->fds[cur].fdtype = swReactor_fdtype(fdtype);
	object->events[cur].fd = fd;
	//object->events[cur].events = POLLRDHUP;
	object->events[cur].events = 0;

	if (swReactor_event_read(fdtype))
	{
		object->events[cur].events |= POLLIN;
	}
	if (swReactor_event_write(fdtype))
	{
		object->events[cur].events |= POLLOUT;
	}
	if (swReactor_event_error(fdtype))
	{
		object->events[cur].events |= POLLHUP;
	}
	reactor->event_num++;
	return SW_OK;
}

static int swReactorPoll_set(swReactor *reactor, int fd, int fdtype)
{
	uint32_t i;
	swReactorPoll *object = reactor->object;

	for (i = 0; i < reactor->event_num; i++)
	{
		//found
		if (object->events[i].fd == fd)
		{
			object->fds[i].fdtype = swReactor_fdtype(fdtype);
			//object->events[i].events = POLLRDHUP;
			object->events[i].events = 0;
			if (swReactor_event_read(fdtype))
			{
				object->events[i].events |= POLLIN;
			}
			if (swReactor_event_write(fdtype))
			{
				object->events[i].events |= POLLOUT;
			}
			return SW_OK;
		}
	}
	return SW_ERR;
}

static int swReactorPoll_del(swReactor *reactor, int fd)
{
	uint32_t i;
	swReactorPoll *object = reactor->object;

	for (i = 0; i < reactor->event_num; i++)
	{
		//找到了
		if (object->events[i].fd == fd)
		{
			uint32_t old_num = reactor->event_num;
			reactor->event_num--;;
			for (; i < old_num; i++)
			{
				if (i == old_num)
				{
					object->fds[i].fdtype = 0;
					object->events[i].fd = 0;
					object->events[i].events = 0;
				}
				else
				{
					object->fds[i] = object->fds[i + 1];
					object->events[i] = object->events[i + 1];
				}
			}
			close(fd);
			return SW_OK;
		}
	}
	return SW_ERR;
}

static int swReactorPoll_wait(swReactor *reactor, struct timeval *_timeo)
{
	swReactorPoll *object = reactor->object;
	swDataHead event;
	swReactor_handle handle;

	struct timeval timeo = *_timeo;
	int ret;
	int i;

	while (SwooleG.running > 0)
	{
		ret = poll(object->events, reactor->event_num, timeo.tv_sec * 1000 + timeo.tv_usec / 1000);
		if (ret < 0)
		{
			if (swReactor_error(reactor) < 0)
			{
				swWarn("poll error. Error: %s[%d]", strerror(errno), errno);
			}
			continue;
		}
		else if (ret == 0)
		{
			if(reactor->onTimeout != NULL)
			{
				reactor->onTimeout(reactor);
			}
			continue;
		}
		else
		{
			for (i = 0; i < reactor->event_num; i++)
			{
				event.fd = object->events[i].fd;
				event.from_id = reactor->id;
				event.type = object->fds[i].fdtype;
				swTrace("Event: fd=%d|from_id=%d|type=%d", event.fd, reactor->id, object->fds[i].fdtype);
				//in
				if (object->events[i].revents & POLLIN)
				{
					handle = swReactor_getHandle(reactor, SW_EVENT_READ, event.type);
					ret = handle(reactor, &event);
					if (ret < 0)
					{
						swWarn("poll[POLLIN] handler failed. fd=%d|errno=%d.Error: %s[%d]", event.fd, errno, strerror(errno), errno);
					}
				}
				//error
				if (object->events[i].revents & (POLLHUP | POLLERR))
				{
					handle = swReactor_getHandle(reactor, SW_EVENT_READ, event.type);
					ret = handle(reactor, &event);
					if (ret < 0)
					{
						swWarn("poll[POLLERR] handler failed. fd=%d|errno=%d.Error: %s[%d]", event.fd, errno, strerror(errno), errno);
					}
				}
				//out
				if (object->events[i].revents & POLLOUT)
				{
					handle = swReactor_getHandle(reactor, SW_EVENT_WRITE, event.type);
					ret = handle(reactor, &event);
					if (ret < 0)
					{
						swWarn("poll[POLLOUT] handler failed. fd=%d|errno=%d.Error: %s[%d]", event.fd, errno, strerror(errno), errno);
					}
				}
			}
			if (reactor->onFinish != NULL)
			{
				reactor->onFinish(reactor);
			}
		}
	}
	return SW_OK;
}
