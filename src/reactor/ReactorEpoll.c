#include "swoole.h"

#ifdef HAVE_EPOLL
#include <sys/epoll.h>
#ifndef EPOLLRDHUP
#define EPOLLRDHUP   0x2000
#define NO_EPOLLRDHUP
#endif

#ifndef EPOLLONESHOT
#define EPOLLONESHOT (1u << 30)
#endif

typedef struct swReactorEpoll_s swReactorEpoll;

#pragma pack(4)
typedef struct _swFd
{
	uint32_t fd;
	uint32_t fdtype;
} swFd;
#pragma pack()

static int swReactorEpoll_add(swReactor *reactor, int fd, int fdtype);
static int swReactorEpoll_set(swReactor *reactor, int fd, int fdtype);
static int swReactorEpoll_del(swReactor *reactor, int fd);
static int swReactorEpoll_wait(swReactor *reactor, struct timeval *timeo);
static void swReactorEpoll_free(swReactor *reactor);
SWINLINE static int swReactorEpoll_event_set(int fdtype);

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
		swWarn("malloc[0] fail\n");
		return SW_ERR;
	}
	bzero(reactor, sizeof(swReactor));
	bzero(reactor_object, sizeof(swReactorEpoll));

	reactor->object = reactor_object;
	reactor_object->events = sw_calloc(max_event_num, sizeof(struct epoll_event));

	if (reactor_object->events == NULL)
	{
		swWarn("malloc[1] fail\n");
		return SW_ERR;
	}
	//epoll create
	reactor_object->event_max = 0;
	reactor_object->epfd = epoll_create(512);
	if (reactor_object->epfd < 0)
	{
		swWarn("epoll_create fail.Error: %s[%d]", strerror(errno), errno);
		return SW_ERR;
	}
	//binding method
	reactor->add = swReactorEpoll_add;
	reactor->set = swReactorEpoll_set;
	reactor->del = swReactorEpoll_del;
	reactor->wait = swReactorEpoll_wait;
	reactor->free = swReactorEpoll_free;
	reactor->setHandle = swReactor_setHandle;
	return SW_OK;
}

void swReactorEpoll_free(swReactor *reactor)
{
	swReactorEpoll *object = reactor->object;
	close(object->epfd);
	sw_free(object->events);
	sw_free(object);
}

int swReactorEpoll_add(swReactor *reactor, int fd, int fdtype)
{
	swReactorEpoll *object = reactor->object;
	struct epoll_event e;
	swFd fd_;
	int ret;
	bzero(&e, sizeof(struct epoll_event));

	fd_.fd = fd;
	fd_.fdtype = swReactor_fdtype(fdtype);
	e.events = swReactorEpoll_event_set(fdtype);

	memcpy(&(e.data.u64), &fd_, sizeof(fd_));
	ret = epoll_ctl(object->epfd, EPOLL_CTL_ADD, fd, &e);
	if (ret < 0)
	{
		swWarn("add event fail. Error: %s[%d]", strerror(errno), errno);
		return SW_ERR;
	}
	object->event_max++;
	return SW_OK;
}

int swReactorEpoll_del(swReactor *reactor, int fd)
{
	swReactorEpoll *object = reactor->object;
	struct epoll_event e;
	int ret;
	e.data.fd = fd;

	if (fd <= 0)
	{
		return SW_ERR;
	}
	//	e.events = EPOLLIN | EPOLLET | EPOLLOUT;
	ret = epoll_ctl(object->epfd, EPOLL_CTL_DEL, fd, &e);
	if (ret < 0)
	{
		swWarn("epoll remove fd[=%d] fail. Error: %s[%d]", fd, strerror(errno), errno);
		return SW_ERR;
	}
	//close时会自动从epoll事件中移除
	//swoole中未使用dup
	ret = close(fd);
	(object->event_max <= 0) ? object->event_max = 0 : object->event_max--;
	return SW_OK;
}

SWINLINE static int swReactorEpoll_event_set(int fdtype)
{
	uint32_t flag = 0;
#ifdef SW_USE_EPOLLET
	flag = EPOLLET;
#endif

	if (swReactor_event_read(fdtype))
	{
		flag |= EPOLLIN;
	}
	if (swReactor_event_write(fdtype))
	{
		flag |= EPOLLOUT;
	}
	if (swReactor_event_error(fdtype))
	{
		flag |= (EPOLLRDHUP);
		//flag |= (EPOLLRDHUP | EPOLLHUP | EPOLLERR);
	}
	return flag;
}

int swReactorEpoll_set(swReactor *reactor, int fd, int fdtype)
{
	swReactorEpoll *object = reactor->object;
	swFd fd_;
	struct epoll_event e;
	int ret;
	bzero(&e, sizeof(struct epoll_event));
	e.events = swReactorEpoll_event_set(fdtype);
	fd_.fd = fd;
	fd_.fdtype = swReactor_fdtype(fdtype);
	memcpy(&(e.data.u64), &fd_, sizeof(fd_));

	ret = epoll_ctl(object->epfd, EPOLL_CTL_MOD, fd, &e);
	if (ret < 0)
	{
		swWarn("set event fail. Error: %s[%d]", strerror(errno), errno);
		return SW_ERR;
	}
	return SW_OK;
}

int swReactorEpoll_wait(swReactor *reactor, struct timeval *timeo)
{
	swEvent ev;
	swFd fd_;
	swReactorEpoll *object = reactor->object;
	swReactor_handle handle;
	int i, n, ret, usec;

	if (timeo == NULL)
	{
		usec = SW_MAX_UINT;
	}
	else
	{
		usec = timeo->tv_sec * 1000 + timeo->tv_usec / 1000;
	}

	while (SwooleG.running > 0)
	{
		n = epoll_wait(object->epfd, object->events, object->event_max + 1, usec);
		if (n < 0)
		{
			if (swReactor_error(reactor) < 0)
			{
				swWarn("Epoll[#%d] Error: %s[%d]", reactor->id, strerror(errno), errno);
				return SW_ERR;
			}
			else
			{
				continue;
			}
		}
		else if (n == 0)
		{
			if(reactor->onTimeout != NULL)
			{
				reactor->onTimeout(reactor);
			}
			continue;
		}
		for (i = 0; i < n; i++)
		{
			//取出事件
			memcpy(&fd_, &(object->events[i].data.u64), sizeof(fd_));
			ev.fd = fd_.fd;
			ev.from_id = reactor->id;
			ev.type = fd_.fdtype;

			//read
			if (object->events[i].events & EPOLLIN)
			{
				//read
				handle = swReactor_getHandle(reactor, SW_EVENT_READ, ev.type);
				ret = handle(reactor, &ev);
				if (ret < 0)
				{
					swWarn("[Reactor#%d] epoll handle fail. fd=%d|type=%d", reactor->id, ev.fd, ev.type);
				}
			}
			//write
			if ((object->events[i].events & EPOLLOUT))
			{
				handle = swReactor_getHandle(reactor, SW_EVENT_WRITE, ev.type);
				ret = handle(reactor, &ev);
				if (ret < 0)
				{
					swWarn("[Reactor#%d] epoll event[type=SW_EVENT_WRITE] handler fail. fd=%d|errno=%d", reactor->id,
							ev.fd, errno);
				}
			}
			//error
#ifndef NO_EPOLLRDHUP
			//if ((object->events[i].events & (EPOLLRDHUP | EPOLLERR | EPOLLHUP)))
			if ((object->events[i].events & (EPOLLRDHUP)))
			{
				handle = swReactor_getHandle(reactor, SW_EVENT_ERROR, ev.type);
				ret = handle(reactor, &ev);
				if (ret < 0)
				{
					swWarn("[Reactor#%d] epoll handle fail. fd=%d|type=%d", reactor->id, ev.fd, ev.type);
				}
			}
#endif
		}
		if(reactor->onFinish != NULL)
		{
			reactor->onFinish(reactor);
		}
	}
	return 0;
}

#endif
