#include "swoole.h"
#include <string.h>

#ifdef HAVE_KQUEUE

typedef struct swReactorKqueue_s swReactorKqueue;
typedef struct _swFd
{
	uint32_t fd;
	uint32_t fdtype;
} swFd;



int swReactorKqueue_add(swReactor *reactor, int fd, int fdtype);
int swReactorKqueue_del(swReactor *reactor, int fd);
int swReactorKqueue_wait(swReactor *reactor, struct timeval *timeo);
void swReactorKqueue_free(swReactor *reactor);

struct swReactorKqueue_s
{
	int epfd;
	int event_max;
	struct kevent *events;
};

int swReactorKqueue_create(swReactor *reactor, int max_event_num)
{
	//create reactor object
	swReactorKqueue *reactor_object = sw_malloc(sizeof(swReactorKqueue));
	if (reactor_object == NULL)
	{
		swTrace("[swReactorKqueueCreate] malloc[0] fail\n");
		return SW_ERR;
	}
	reactor->object = reactor_object;
	reactor_object->events = sw_calloc(max_event_num, sizeof(struct kevent));

	if (reactor_object->events == NULL)
	{
		swTrace("[swReactorKqueueCreate] malloc[1] fail\n");
		return SW_ERR;
	}
	//kqueue create
	reactor_object->event_max = max_event_num;
	reactor_object->epfd = kqueue();
	if (reactor_object->epfd < 0)
	{
		swTrace("[swReactorKqueueCreate] kqueue_create[0] fail\n");
		return SW_ERR;
	}

	//binding method
	reactor->add = swReactorKqueue_add;
	reactor->del = swReactorKqueue_del;
	reactor->wait = swReactorKqueue_wait;
	reactor->free = swReactorKqueue_free;
	reactor->setHandle = swReactor_setHandle;
	return SW_OK;
}

void swReactorKqueue_free(swReactor *reactor)
{
	swReactorKqueue *this = reactor->object;
	close(this->epfd);
	sw_free(this->events);
	sw_free(this);
}

int swReactorKqueue_add(swReactor *reactor, int fd, int fdtype)
{
	swReactorKqueue *this = reactor->object;
	struct kevent e;
	swFd fd_;
	int ret;

	fd_.fd = fd;
	fd_.fdtype = swReactor_fdtype(fdtype);
	//e.data.u64 = 0;
	//e.events = kqueueIN | kqueueOUT;

    EV_SET(&e, fd, EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0 , NULL);

    memcpy(&e.udata, &fd_, sizeof(swFd));

	swTrace("[THREAD #%ld]EP=%d|FD=%d\n", pthread_self(), this->epfd, fd);
	ret = kevent(this->epfd, &e, 1, NULL, 0, NULL);
	if (ret < 0)
	{
		swTrace("[THREAD #%ld]add event fail.Ep=%d|fd=%d\n", pthread_self(), this->epfd, fd);
		return SW_ERR;
	}
	return SW_OK;
}

int swReactorKqueue_del(swReactor *reactor, int fd)
{
	swReactorKqueue *this = reactor->object;
	struct kevent e;
	int ret;

    EV_SET(&e, fd, EVFILT_READ, EV_DELETE | EV_CLEAR, 0, 0, NULL);

	ret = kevent(this->epfd, &e, 1, NULL, 0, NULL);
	if (ret < 0)
	{
		return -1;
	}
	close(fd);
	return SW_OK;
}

int swReactorKqueue_wait(swReactor *reactor, struct timeval *timeo)
{
	swEvent ev;
	swFd fd_;
	swReactorKqueue *this = reactor->object;
	int i, n, ret;
    struct timespec t;

    t.tv_sec = timeo->tv_sec;
    t.tv_nsec = timeo->tv_usec;

	while (swoole_running > 0)
	{
		n = kevent(this->epfd, NULL, 0, this->events, this->event_max, &t);

		if (n < 0)
		{
			//swTrace("kqueue error.EP=%d | Errno=%d\n", this->epfd, errno);
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
			if (this->events[i].udata)
			{
				swTrace("event coming.Ep=%d|fd=%d\n", this->epfd, this->events[i].udata);
				memcpy(&fd_, &(this->events[i].udata), sizeof(fd_));
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
#endif
