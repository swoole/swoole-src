#include "swoole.h"
#include "list.h"
#include <sys/select.h>

typedef struct _swFdList_node
{
	struct _swFdList_node *next, *prev;
	int fd;
	int fdtype;
} swFdList_node;

typedef struct _swReactorSelect
{
	fd_set rfds;
	fd_set wfds;
	fd_set efds;
	swFdList_node *fds;
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
	swReactorSelect *object = sw_malloc(sizeof(swReactorSelect));
	if (object == NULL)
	{
		swTrace("[swReactorSelect_create] malloc[0] fail\n");
		return SW_ERR;
	}
	object->fds = NULL;
	object->maxfd = 0;
	object->fd_num = 0;
	bzero(reactor->handle, sizeof(reactor->handle));
	reactor->object = object;
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
	swFdList_node *ev;
	swReactorSelect *object = reactor->object;
	LL_FOREACH(object->fds, ev)
	{
		LL_DELETE(object->fds, ev);
		sw_free(ev);
	}
	sw_free(reactor->object);
}

int swReactorSelect_add(swReactor *reactor, int fd, int fdtype)
{
	if(fd > FD_SETSIZE)
	{
		swWarn("max fd value is FD_SETSIZE(%d).\n", FD_SETSIZE);
		return SW_ERR;
	}
	swReactorSelect *object = reactor->object;
	swFdList_node *ev = sw_malloc(sizeof(swFdList_node));
	ev->fd = fd;
	ev->fdtype = fdtype;
	LL_APPEND(object->fds, ev);
	object->fd_num++;
	if (fd > object->maxfd)
	{
		object->maxfd = fd;
	}
	return SW_OK;
}

int swReactorSelect_cmp(swFdList_node *a, swFdList_node *b)
{
	return a->fd == b->fd ? 0 : (a->fd > b->fd ? -1 : 1);
}

int swReactorSelect_del(swReactor *reactor, int fd)
{
	swReactorSelect *object = reactor->object;
	swFdList_node ev, *s_ev;
	ev.fd = fd;

	LL_SEARCH(object->fds, s_ev, &ev, swReactorSelect_cmp);
	LL_DELETE(object->fds, s_ev);
	object->fd_num--;
	sw_free(s_ev);
	return SW_OK;
}

int swReactorSelect_wait(swReactor *reactor, struct timeval *timeo)
{
	swReactorSelect *object = reactor->object;
	swFdList_node *ev;
	swDataHead event;
	struct timeval timeout;
	int ret;

	while (swoole_running > 0)
	{
		FD_ZERO(&(object->rfds));
		timeout.tv_sec = timeo->tv_sec;
		timeout.tv_usec = timeo->tv_usec;
		LL_FOREACH(object->fds, ev)
		{
			FD_SET(ev->fd, &(object->rfds));
		}
		ret = select(object->maxfd + 1, &(object->rfds), NULL, NULL, &timeout);
		if (ret < 0)
		{
			if (swReactor_error(reactor) < 0)
			{
				swWarn("select error. Errno=%d", errno);
			}
			continue;
		}
		else if (ret == 0)
		{
			continue;
		}
		else
		{
			LL_FOREACH(object->fds, ev)
			{
				if (FD_ISSET(ev->fd, &(object->rfds)))
				{
					event.fd = ev->fd;
					event.from_id = reactor->id;
					event.type = ev->fdtype;
					swTrace("Event:Handle=%p|fd=%d|from_id=%d|type=%d\n",
							reactor->handle[event.type], ev->fd, reactor->id, ev->fdtype);
					ret = reactor->handle[event.type](reactor, &event);
					if(ret < 0)
					{
						swWarn("[Reactor#%d] select event[type=%d] handler fail. fd=%d|errno=%d", reactor->id, event.type, ev->fd, errno);
					}
				}
			}
		}
	}
	return SW_OK;
}
