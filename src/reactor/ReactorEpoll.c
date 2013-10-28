#include "swoole.h"

#ifdef HAVE_EPOLL

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
	swReactorEpoll *reactor_object = sw_memory_pool->alloc(sw_memory_pool, sizeof(swReactorEpoll));
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
	swReactorEpoll *object = reactor->object;
	close(object->epfd);
	sw_free(object->events);
}

int swReactorEpoll_add(swReactor *reactor, int fd, int fdtype)
{
	swReactorEpoll *object = reactor->object;
	struct epoll_event e;
	swFd fd_;
	int ret;
	bzero(&e, sizeof(struct epoll_event));

	fd_.fd = fd;
	fd_.fdtype = fdtype;
	//e.data.u64 = 0;
	e.events = EPOLLIN | EPOLLET;
#ifdef EPOLLRDHUP
	e.events |= EPOLLRDHUP;
#endif
	memcpy(&(e.data.u64), &fd_, sizeof(fd_));

	swTrace("[THREAD #%ld]EP=%d|FD=%d\n", pthread_self(), object->epfd, fd);
	ret = epoll_ctl(object->epfd, EPOLL_CTL_ADD, fd, &e);
	if (ret < 0)
	{
		swTrace("[THREAD #%ld]add event fail.Ep=%d|fd=%d\n", pthread_self(), object->epfd, fd);
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
	//e.data.u64 = 0;
	//e.events = EPOLLIN | EPOLLOUT;
	e.events = EPOLLIN | EPOLLET;
	ret = epoll_ctl(object->epfd, EPOLL_CTL_DEL, fd, &e);
	if (ret < 0)
	{
		swWarn("epoll remove fd fail.errno=%d|fd=%d", errno, fd);
		return -1;
	}
	close(fd);
	(object->event_max <= 0) ? object->event_max = 0 : object->event_max--;
	return SW_OK;
}

int swReactorEpoll_wait(swReactor *reactor, struct timeval *timeo)
{
	swDataHead ev;
	swFd fd_;
	swReactorEpoll *object = reactor->object;
	swEventClose_queue close_queue;
	close_queue.num = 0;
	int i, n, ret;

	while (swoole_running > 0)
	{
		n = epoll_wait(object->epfd, object->events, object->event_max + 1, timeo->tv_sec * 1000 + timeo->tv_usec / 1000);

		if (n < 0)
		{
			if(swReactor_error(reactor) < 0)
			{
				swTrace("epoll error.EP=%d | Errno=%d\n", object->epfd, errno);
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
			if (object->events[i].events & EPOLLIN)
			{
				swTrace("event coming.Ep=%d|fd=%d\n", object->epfd, object->events[i].data.fd);

				//取出事件
				memcpy(&fd_, &(object->events[i].data.u64), sizeof(fd_));
				ev.fd = fd_.fd;
				ev.from_id = reactor->id;
				ev.type = fd_.fdtype;

#ifdef EPOLLRDHUP
				//close事件
				if(object->events[i].events & EPOLLRDHUP)
				{
#ifdef SW_CLOSE_AGAIN
					close_queue.events[close_queue.num].fd = ev.fd;
					//-1表示直接在reactor内关闭
					close_queue.events[close_queue.num].from_id = -1;
					//关闭连接
					reactor->del(reactor, ev.fd);
					//增加计数
					close_queue.num++;

					//close队列已满，如果写main_pipe失败，进程会阻塞
					if (close_queue.num == SW_CLOSE_QLEN)
					{
						ret = reactor->handle[SW_FD_CLOSE_QUEUE](reactor, &close_queue);
						if (ret >= 0)
						{
							bzero(&close_queue, sizeof(close_queue));
						}
						//写失败了，继续写
					}
#else
					ret = reactor->handle[SW_FD_CLOSE](reactor, &ev);
#endif
				}
				else
#endif
				{
					ret = reactor->handle[ev.type](reactor, &ev);
					if(ret < 0)
					{
						swWarn("[Reactor#%d] epoll handle fail. fd=%d|type=%d|errno=%d|sw_errno=%d", ev.fd, reactor->id, ev.type, errno, sw_errno);
					}
				}
				swTrace("[THREAD #%ld]event finish.Ep=%d|ret=%d", pthread_self(), object->epfd, ret);
			}
		}
		if(close_queue.num > 0)
		{
			ret = reactor->handle[SW_FD_CLOSE_QUEUE](reactor, &close_queue);
			if(ret >= SW_OK)
			{
				bzero(&close_queue, sizeof(close_queue));
			}
			//写失败了，继续写
		}
	}
	return 0;
}

#endif
