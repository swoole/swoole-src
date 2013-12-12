#include "swoole.h"
#include <sys/poll.h>

#ifndef POLLRDHUP
# define POLLRDHUP	0x2000
#endif

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
	int fd_num;
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
		swError("malloc[0] fail\n");
		return SW_ERR;
	}
	object->fds = sw_calloc(max_fd_num, sizeof(swPollFdInfo));
	if (object->fds == NULL)
	{
		swError("malloc[1] fail\n");
		return SW_ERR;
	}
	object->events = sw_calloc(max_fd_num, sizeof(struct pollfd));
	if (object->events == NULL)
	{
		swError("malloc[2] fail\n");
		return SW_ERR;
	}
	object->fd_num = 0;
	object->max_fd_num = max_fd_num;
	bzero(reactor->handle, sizeof(reactor->handle));
	reactor->object = object;
	//binding method
	reactor->add = swReactorPoll_add;
	reactor->del = swReactorPoll_del;
	reactor->set = swReactorPoll_set;
	reactor->wait = swReactorPoll_wait;
	reactor->free = swReactorPoll_free;
	reactor->setHandle = swReactor_setHandle;
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
	int cur = object->fd_num;
	if (object->fd_num == object->max_fd_num)
	{
		swError("too many connection, more than %d\n", object->max_fd_num);
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
	object->fd_num++;
	return SW_OK;
}

static int swReactorPoll_set(swReactor *reactor, int fd, int fdtype)
{
	uint32_t i;
	swReactorPoll *object = reactor->object;

	for (i = 0; i < object->fd_num; i++)
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

	for (i = 0; i < object->fd_num; i++)
	{
		//找到了
		if (object->events[i].fd == fd)
		{
			uint32_t old_num = object->fd_num;
			object->fd_num--;
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

static int swReactorPoll_wait(swReactor *reactor, struct timeval *timeo)
{
	swReactorPoll *object = reactor->object;
	swDataHead event;
	swReactor_handle handle;
	int ret;
	int i;

	while (swoole_running > 0)
	{
		ret = poll(object->events, object->fd_num, timeo->tv_sec * 1000 + timeo->tv_usec / 1000);
		if (ret < 0)
		{
			if (swReactor_error(reactor) < 0)
			{
				swWarn("poll error. Errno=%d\n", errno);
			}
			continue;
		}
		else if (ret == 0)
		{
			reactor->timeout = 1;
			continue;
		}
		else
		{
			for (i = 0; i < object->fd_num; i++)
			{
				//in
				if (object->events[i].revents & POLLIN)
				{
					event.fd = object->events[i].fd;
					event.from_id = reactor->id;
					event.type = object->fds[i].fdtype;

					//error
					if ((object->events[i].events & POLLRDHUP))
					{
						handle = swReactor_getHandle(reactor, SW_EVENT_ERROR, event.type);
					}
					//read
					else
					{
						handle = swReactor_getHandle(reactor, SW_EVENT_READ, event.type);
					}
					swTrace("Event:Handle=%p|fd=%d|from_id=%d|type=%d\n",
							reactor->handle[event.type], event.fd, reactor->id, object->fds[i].fdtype);
					ret = handle(reactor, &event);
					if (ret < 0)
					{
						swWarn("poll[POLLIN] handler fail. fd=%d|errno=%d.Error: %s[%d]", event.fd, errno, strerror(errno), errno);
					}
				}
				//out
				if (object->events[i].revents & POLLOUT)
				{
					event.fd = object->events[i].fd;
					event.from_id = reactor->id;
					event.type = object->fds[i].fdtype;

					handle = swReactor_getHandle(reactor, SW_EVENT_WRITE, event.type);
					swTrace("Event:Handle=%p|fd=%d|from_id=%d|type=%d\n",
							handle, event.fd, reactor->id, object->fds[i].fdtype);
					ret = handle(reactor, &event);
					if (ret < 0)
					{
						swWarn("poll[POLLOUT] handler fail. fd=%d|errno=%d.Error: %s[%d]", event.fd, errno, strerror(errno), errno);
					}
				}
			}
			if (object->fd_num < 1)
			{
				swWarn("poll exception");
			}
			reactor->timeout = 0;
		}
	}
	return SW_OK;
}
