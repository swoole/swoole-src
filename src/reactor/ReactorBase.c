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
	switch (errno)
	{
	case EINTR:
		return SW_OK;
	}
	return SW_ERR;
}

SWINLINE int swReactor_fdtype(int fdtype)
{
	return fdtype  & (~SW_EVENT_READ) & (~SW_EVENT_WRITE) & (~SW_EVENT_ERROR);
}

SWINLINE int swReactor_event_read(int fdtype)
{
	return fdtype & SW_EVENT_READ;
}

SWINLINE int swReactor_event_write(int fdtype)
{
	return fdtype & SW_EVENT_WRITE;
}

SWINLINE int swReactor_event_error(int fdtype)
{
	return fdtype & SW_EVENT_ERROR;
}

int swReactor_close(swReactor *reactor, swDataHead *event)
{
	//swEventClose close_ev;
	//close_ev.fd = event->fd;
	//close_ev.from_id = event->fd;

	close(event->fd);
	reactor->del(reactor, event->fd);
	return 0;
}

int swReactor_setHandle(swReactor *reactor, int fdtype, swReactor_handle handle)
{
	if (fdtype >= SW_MAX_FDTYPE)
	{
		return -1;
	}
	else
	{
		reactor->handle[fdtype] = handle;
		return 0;
	}
}

int swReactor_receive(swReactor *reactor, swEvent *event)
{
	swEventData data;
	return swRead(event->fd, data.data, SW_BUFFER_SIZE);
}
