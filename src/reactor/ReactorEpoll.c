#include "swoole.h"
#include <string.h>

typedef struct swReactorEpoll_s swReactorEpoll;
typedef struct _swFd
{
	uint32_t fd;
	uint32_t fdtype;
} swFd;

int swReactorEpoll_add(swReactor *reactor, int fd, int fdtype);
int swReactorEpoll_del(swReactor *reactor, int fd);
int swReactorEpoll_wait(swReactor *reactor, struct timeval *timeo);
void swReactorEpoll_free(swReactor *reactor);

struct swReactorEpoll_s
{
	int epfd;
	int event_max;
	struct epoll_event *events;
};

int swReactorEpoll_create(swReactor *reactor, int max_event_num)
{
	//create reactor object
	swReactorEpoll *reactor_object = sw_malloc(sizeof(swReactorEpoll));
	if (reactor_object == NULL)
	{
		swTrace("[swReactorEpollCreate] malloc[0] fail\n");
		return SW_ERR;
	}
	reactor->object = reactor_object;
	reactor_object->events = sw_calloc(max_event_num, sizeof(struct epoll_event));

	if (reactor_object->events == NULL)
	{
		swTrace("[swReactorEpollCreate] malloc[1] fail\n");
		return SW_ERR;
	}
	//epoll create
	reactor_object->event_max = 0;
	reactor_object->epfd = epoll_create(512);
	if (reactor_object->epfd < 0)
	{
		swTrace("[swReactorEpollCreate] epoll_create[0] fail\n");
		return SW_ERR;
	}
	//binding method
	reactor->add = swReactorEpoll_add;
	reactor->del = swReactorEpoll_del;
	reactor->wait = swReactorEpoll_wait;
	reactor->free = swReactorEpoll_free;
	reactor->setHandle = swReactor_setHandle;
	return SW_OK;
}

void swReactorEpoll_free(swReactor *reactor)
{
	swReactorEpoll *this = reactor->object;
	close(this->epfd);
	sw_free(this->events);
	sw_free(this);
}

int swReactorEpoll_add(swReactor *reactor, int fd, int fdtype)
{
	swReactorEpoll *this = reactor->object;
	struct epoll_event e;
	swFd fd_;
	int ret;
	bzero(&e, sizeof(struct epoll_event));

	fd_.fd = fd;
	fd_.fdtype = fdtype;
	//e.data.u64 = 0;
	//e.events = EPOLLIN | EPOLLOUT;
	e.events = EPOLLIN | EPOLLET;
	memcpy(&(e.data.u64), &fd_, sizeof(fd_));

	swTrace("[THREAD #%ld]EP=%d|FD=%d\n", pthread_self(), this->epfd, fd);
	ret = epoll_ctl(this->epfd, EPOLL_CTL_ADD, fd, &e);
	if (ret < 0)
	{
		swTrace("[THREAD #%ld]add event fail.Ep=%d|fd=%d\n", pthread_self(), this->epfd, fd);
		return SW_ERR;
	}
	this->event_max++;
	return SW_OK;
}

int swReactorEpoll_del(swReactor *reactor, int fd)
{
	swReactorEpoll *this = reactor->object;
	struct epoll_event e;
	int ret;
	e.data.fd = fd;
	//e.data.u64 = 0;
	//e.events = EPOLLIN | EPOLLOUT;
	e.events = EPOLLIN | EPOLLET;
	ret = epoll_ctl(this->epfd, EPOLL_CTL_DEL, fd, &e);
	if (ret < 0)
	{
		return -1;
	}
	this->event_max--;
	return SW_OK;
}

int swReactorEpoll_wait(swReactor *reactor, struct timeval *timeo)
{
	swEvent ev;
	swFd fd_;
	swReactorEpoll *this = reactor->object;
	int i, n, ret;

	while (swoole_running > 0)
	{
		n = epoll_wait(this->epfd, this->events, this->event_max + 1, timeo->tv_sec * 1000 + timeo->tv_usec / 1000);

		if (n < 0)
		{
			//swTrace("epoll error.EP=%d | Errno=%d\n", this->epfd, errno);
			if(swReactor_error(reactor) < 0)
			{
				return SW_ERR;
			}
			else
			{
				continue;
			}
		}
		else if (n == 0)
		{
			continue;
		}
		for (i = 0; i < n; i++)
		{
			if (this->events[i].events & EPOLLIN)
			{
				swTrace("event coming.Ep=%d|fd=%d\n", this->epfd, this->events[i].data.fd);
				memcpy(&fd_, &(this->events[i].data.u64), sizeof(fd_));
				ev.fd = fd_.fd;
				ev.from_id = reactor->id;
				ev.type = fd_.fdtype;
				ret = reactor->handle[ev.type](reactor, &ev);
				swTrace("[THREAD #%ld]event finish.Ep=%d|ret=%d\n", pthread_self(), this->epfd, ret);
			}
		}
	}
	return 0;
}
