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
	int fd_num;
	int max_fd_num;
	swPollFdInfo *fds;
	struct pollfd *events;
} swReactorPoll;

int swReactorPoll_create(swReactor *reactor, int max_fd_num)
{
	//create reactor object
	swReactorPoll *this = sw_malloc(sizeof(swReactorPoll));
	if (this == NULL)
	{
		swError("malloc[0] fail\n");
		return SW_ERR;
	}
	this->fds = sw_calloc(max_fd_num, sizeof(swPollFdInfo));
	if (this->fds == NULL)
	{
		swError("malloc[1] fail\n");
		return SW_ERR;
	}
	this->events = sw_calloc(max_fd_num, sizeof(struct pollfd));
	if (this->events == NULL)
	{
		swError("malloc[2] fail\n");
		return SW_ERR;
	}
	this->fd_num = 0;
	this->max_fd_num = max_fd_num;
	bzero(reactor->handle, sizeof(reactor->handle));
	reactor->object = this;
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
	swReactorPoll *this = reactor->object;
	sw_free(this->fds);
	sw_free(reactor->object);
}

static int swReactorPoll_add(swReactor *reactor, int fd, int fdtype)
{
	swReactorPoll *this = reactor->object;
	int cur = this->fd_num;
	if(this->fd_num == this->max_fd_num)
	{
		swError("too many connection, more than %d\n", this->max_fd_num);
		return SW_ERR;
	}
	this->fds[cur].fdtype = swReactor_fdtype(fdtype);
	this->events[cur].fd = fd;
	this->events[cur].events = 0;

	if(swReactor_event_read(fdtype))
	{
		this->events[cur].events |= POLLIN;
	}
	if(swReactor_event_write(fdtype))
	{
		this->events[cur].events |= POLLOUT;
	}
	this->fd_num++;
	return SW_OK;
}


static int swReactorPoll_set(swReactor *reactor, int fd, int fdtype)
{
	uint32_t i;
	swReactorPoll *this = reactor->object;

	for (i = 0; i < this->fd_num; i++)
	{
		//found
		if (this->events[i].fd == fd)
		{
			this->fds[i].fdtype = swReactor_fdtype(fdtype);
			this->events[i].events = 0;
			if(swReactor_event_read(fdtype))
			{
				this->events[i].events |= POLLIN;
			}
			if(swReactor_event_write(fdtype))
			{
				this->events[i].events |= POLLOUT;
			}
			return SW_OK;
		}
	}
	return SW_ERR;
}

static int swReactorPoll_del(swReactor *reactor, int fd)
{
	uint32_t i;
	swReactorPoll *this = reactor->object;

	for (i = 0; i < this->fd_num; i++)
	{
		//找到了
		if (this->events[i].fd == fd)
		{
			uint32_t old_num = this->fd_num;
			this->fd_num--;
			for (; i < old_num; i++)
			{
				if (i == old_num)
				{
					this->fds[i].fdtype = 0;
					this->events[i].fd = 0;
					this->events[i].events = 0;
				}
				else
				{
					this->fds[i] = this->fds[i + 1];
					this->events[i] = this->events[i + 1];
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
	swReactorPoll *this = reactor->object;
	swDataHead event;
	int ret;
	int i;

	while (swoole_running > 0)
	{
		reactor->timeout = 0;
		ret = poll(this->events, this->fd_num, timeo->tv_sec * 1000 + timeo->tv_usec / 1000);
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
			for (i = 0; i < this->fd_num; i++)
			{
				if (this->events[i].revents & POLLIN)
				{
					event.fd = this->events[i].fd;
					event.from_id = reactor->id;
					event.type = this->fds[i].fdtype;
					swTrace("Event:Handle=%p|fd=%d|from_id=%d|type=%d\n",
							reactor->handle[event.type], event.fd, reactor->id, this->fds[i].fdtype);
					ret = reactor->handle[event.type](reactor, &event);
					if(ret < 0)
					{
						swWarn("poll event handler fail. fd=%d|errno=%d", event.fd, errno);
					}
				}
			}
			if(this->fd_num < 2)
			{
				swWarn("poll exception");
			}
		}
	}
	return SW_OK;
}
