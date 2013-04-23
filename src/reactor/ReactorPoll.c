#include "swoole.h"
#include <sys/poll.h>

int swReactorPoll_add(swReactor *reactor, int fd, int fdtype);
int swReactorPoll_del(swReactor *reactor, int fd);
int swReactorPoll_wait(swReactor *reactor, struct timeval *timeo);
void swReactorPoll_free(swReactor *reactor);

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

int swReactorPoll_add(swReactor *reactor, int fd, int fdtype);
int swReactorPoll_wait(swReactor *reactor, struct timeval *timeo);
void swReactorPoll_free(swReactor *reactor);
int swReactorPoll_del(swReactor *reactor, int fd);

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
	reactor->wait = swReactorPoll_wait;
	reactor->free = swReactorPoll_free;
	reactor->setHandle = swReactor_setHandle;
	return SW_OK;
}

void swReactorPoll_free(swReactor *reactor)
{
	swReactorPoll *this = reactor->object;
	sw_free(this->fds);
	sw_free(reactor->object);
}

int swReactorPoll_add(swReactor *reactor, int fd, int fdtype)
{
	swReactorPoll *this = reactor->object;
	int cur = this->fd_num;
	if(this->fd_num == this->max_fd_num)
	{
		swError("too many connection, more than %d\n", this->max_fd_num);
		return SW_ERR;
	}
	this->fds[cur].fdtype = fdtype;
	this->events[cur].fd = fd;
	this->events[cur].events = POLLIN;
	this->fd_num++;
	return SW_OK;
}

int swReactorPoll_del(swReactor *reactor, int fd)
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
			return SW_OK;
		}
	}
	return SW_ERR;
}

int swReactorPoll_wait(swReactor *reactor, struct timeval *timeo)
{
	swReactorPoll *this = reactor->object;
	swEvent event;
	struct timeval timeout;
	int ret;
	int i;
	int msec = (timeout.tv_sec * 1000) + (timeout.tv_usec / 1000);

	while (swoole_running > 0)
	{
		timeout.tv_sec = timeo->tv_sec;
		timeout.tv_usec = timeo->tv_usec;
		ret = poll(this->events, this->fd_num, msec);
		if (ret < 0)
		{
			swTrace("select error. Errno=%d\n", errno);
			if (swReactor_error(reactor) < 0)
			{
				return SW_ERR;
			}
			else
			{
				continue;
			}
		}
		else if (ret == 0)
		{
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
					reactor->handle[event.type](reactor, &event);
				}
			}
		}
	}
	return SW_OK;
}
