#include "swoole.h"
#include "list.h"
#include <sys/select.h>

typedef struct _swList_node
{
	struct _swList_node *next, *prev;
	int fd;
	int fdtype;
} swList_node;

typedef struct _swReactorSelect
{
	fd_set rfds;
	//fd_set wfds;
	//fd_set efds;
	swList_node *fds;
	int maxfd;
	int fd_num;
} swReactorSelect;

int swReactorSelect_add(swReactor *reactor, int fd, int fdtype);
int swReactorSelect_wait(swReactor *reactor, struct timeval *timeo);
void swReactorSelect_free(swReactor *reactor);
int swReactorSelect_del(swReactor *reactor, int fd);

int swReactorSelect_create(swReactor *reactor)
{
	//create reactor object
	swReactorSelect *this = sw_malloc(sizeof(swReactorSelect));
	if (this == NULL)
	{
		swTrace("[swReactorSelect_create] malloc[0] fail\n");
		return SW_ERR;
	}
	this->fds = NULL;
	this->maxfd = 0;
	this->fd_num = 0;
	bzero(reactor->handle, sizeof(reactor->handle));
	reactor->object = this;
	//binding method
	reactor->add = swReactorSelect_add;
	reactor->del = swReactorSelect_del;
	reactor->wait = swReactorSelect_wait;
	reactor->free = swReactorSelect_free;
	reactor->setHandle = swReactor_setHandle;
	return SW_OK;
}

void swReactorSelect_free(swReactor *reactor)
{
	swList_node *ev;
	swReactorSelect *this = reactor->object;
	LL_FOREACH(this->fds, ev)
	{
		LL_DELETE(this->fds, ev);
		sw_free(ev);
	}
	sw_free(reactor->object);
}

int swReactorSelect_add(swReactor *reactor, int fd, int fdtype)
{
	swReactorSelect *this = reactor->object;
	swList_node *ev = sw_malloc(sizeof(swList_node));
	ev->fd = fd;
	ev->fdtype = fdtype;
	LL_APPEND(this->fds, ev);
	this->fd_num++;
	if (fd > this->maxfd)
	{
		this->maxfd = fd;
	}
	return 0;
}

int swReactorSelect_cmp(swList_node *a, swList_node *b)
{
	return a->fd == b->fd ? 0 : (a->fd > b->fd ? -1 : 1);
}

int swReactorSelect_del(swReactor *reactor, int fd)
{
	swReactorSelect *this = reactor->object;
	swList_node ev, *s_ev;
	ev.fd = fd;

	LL_SEARCH(this->fds, s_ev, &ev, swReactorSelect_cmp);
	LL_DELETE(this->fds, s_ev);
	this->fd_num--;
	sw_free(s_ev);
	return SW_OK;
}

int swReactorSelect_wait(swReactor *reactor, struct timeval *timeo)
{
	swReactorSelect *this = reactor->object;
	swList_node *ev;
	swEvent event;
	struct timeval timeout;
	int ret;

	while (swoole_running > 0)
	{
		FD_ZERO(&(this->rfds));
		timeout.tv_sec = timeo->tv_sec;
		timeout.tv_usec = timeo->tv_usec;
		LL_FOREACH(this->fds, ev)
		{
			FD_SET(ev->fd, &(this->rfds));
		}
		ret = select(this->maxfd + 1, &(this->rfds), NULL, NULL, &timeout);
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
			LL_FOREACH(this->fds, ev)
			{
				if (FD_ISSET(ev->fd, &(this->rfds)))
				{
					event.fd = ev->fd;
					event.from_id = reactor->id;
					event.type = ev->fdtype;
					swTrace("Event:Handle=%p|fd=%d|from_id=%d|type=%d\n",
							reactor->handle[event.type], ev->fd, reactor->id, ev->fdtype);
					reactor->handle[event.type](reactor, &event);
				}
			}
		}
	}
	return SW_OK;
}
