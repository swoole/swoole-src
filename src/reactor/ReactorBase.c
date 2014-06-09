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

int swReactor_accept(swReactor *reactor, swDataHead *event)
{
	swEventConnect conn_ev;
	conn_ev.from_id = event->from_id;
	conn_ev.serv_fd = event->fd;
	conn_ev.addrlen = sizeof(conn_ev.addr);
	bzero(&conn_ev.addr, conn_ev.addrlen);

	conn_ev.conn_fd = accept(conn_ev.serv_fd, (struct sockaddr *) &conn_ev.addr, &conn_ev.addrlen);
	if (conn_ev.conn_fd < 0)
	{
		swTrace("[swReactorEpollWait]accept fail\n");
		return -1;
	}
	swSetNonBlock(conn_ev.conn_fd);
	reactor->add(reactor, conn_ev.conn_fd, SW_FD_TCP);
	return conn_ev.conn_fd;
}

SWINLINE int swReactor_error(swReactor *reactor)
{
	uint64_t flag = 1;
	switch (errno)
	{
	case EINTR:
		if (SwooleG.signal_alarm && SwooleG.timer.use_pipe)
		{
			SwooleG.timer.pipe.write(&SwooleG.timer.pipe, &flag, sizeof(flag));
		}
		return SW_OK;
	}
	return SW_ERR;
}

SWINLINE int swReactor_fdtype(int fdtype)
{
	return fdtype & (~SW_EVENT_READ) & (~SW_EVENT_WRITE) & (~SW_EVENT_ERROR);
}

SWINLINE int swReactor_event_read(int fdtype)
{
	return (fdtype < SW_EVENT_DEAULT) || (fdtype & SW_EVENT_READ);
}

SWINLINE int swReactor_event_write(int fdtype)
{
	return fdtype & SW_EVENT_WRITE;
}

SWINLINE int swReactor_event_error(int fdtype)
{
	return fdtype & SW_EVENT_ERROR;
}

swReactor_handle swReactor_getHandle(swReactor *reactor, int event_type, int fdtype)
{
	if (event_type == SW_EVENT_WRITE)
	{
		//默认可写回调函数SW_FD_WRITE
		return (reactor->write_handle[fdtype] != NULL) ? reactor->write_handle[fdtype] : reactor->handle[SW_FD_WRITE];
	}
	if (event_type == SW_EVENT_ERROR)
	{
		//默认关闭回调函数SW_FD_CLOSE
		return (reactor->error_handle[fdtype] != NULL) ? reactor->error_handle[fdtype] : reactor->handle[SW_FD_CLOSE];
	}
	return reactor->handle[fdtype];
}

/**
 * 自动适配reactor
 */
int swReactor_auto(swReactor *reactor, int max_event)
{
	int ret;
#ifdef HAVE_EPOLL
	ret = swReactorEpoll_create(reactor, max_event);
#elif defined(HAVE_KQUEUE)
	ret = swReactorKqueue_create(reactor, max_event);
#elif defined(SW_MAINREACTOR_USE_POLL)
	ret = swReactorPoll_create(reactor, max_event);
#else
	ret = swReactorSelect_create(SwooleG.main_reactor)
#endif
	return ret;
}

int swReactor_setHandle(swReactor *reactor, int _fdtype, swReactor_handle handle)
{
	int fdtype = swReactor_fdtype(_fdtype);

	if (fdtype >= SW_MAX_FDTYPE)
	{
		swWarn("fdtype > SW_MAX_FDTYPE[%d]", SW_MAX_FDTYPE);
		return SW_ERR;
	}
	else
	{
		if (swReactor_event_read(_fdtype))
		{
			reactor->handle[fdtype] = handle;
		}
		else if (swReactor_event_write(_fdtype))
		{
			reactor->write_handle[fdtype] = handle;
		}
		else if (swReactor_event_error(_fdtype))
		{
			reactor->error_handle[fdtype] = handle;
		}
		else
		{
			swWarn("unknow fdtype");
			return SW_ERR;
		}
	}
	return SW_OK;
}

int swReactor_receive(swReactor *reactor, swEvent *event)
{
	swEventData data;
	return swRead(event->fd, data.data, SW_BUFFER_SIZE);
}
