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
#include "Server.h"

/**
 * close connection
 */
SWINLINE void swConnection_close(swServer *serv, int fd, int notify)
{
	swConnection *conn = swServer_get_connection(serv, fd);
	swReactor *reactor;
	swEvent notify_ev;
	if(conn == NULL)
	{
		swWarn("[Master]connection not found. fd=%d|max_fd=%d", fd, swServer_get_maxfd(serv));
		return;
	}
	//关闭此连接，必须放在最前面，以保证线程安全
	conn->active = 0;
	int reactor_id = conn->from_id;

	swCloseQueue *queue = &serv->reactor_threads[reactor_id].close_queue;

	//将关闭的fd放入队列
	queue->events[queue->num] = fd;
	//增加计数
	queue->num ++;

	reactor = &(serv->reactor_threads[reactor_id].reactor);
	if(reactor->del(reactor, fd) < 0)
	{
		return;
	}
	swTrace("Close Event.fd=%d|from=%d", fd, reactor_id);

	//释放缓存区占用的内存
	if (serv->open_eof_check == 1)
	{
		if (conn->in_buffer != NULL)
		{
			swBuffer_free(conn->in_buffer);
			conn->in_buffer = NULL;
		}
	}
	else if (serv->open_length_check == 1)
	{
		if (conn->string_buffer != NULL)
		{
			swString_free(conn->string_buffer);
		}
	}

	if (conn->out_buffer != NULL)
	{
		swBuffer_free(conn->out_buffer);
		conn->out_buffer = NULL;
	}

	//通知到worker进程
	if (serv->onClose != NULL && notify == 1)
	{
		//通知worker进程
		notify_ev.from_id = reactor_id;
		notify_ev.fd = fd;
		notify_ev.type = SW_EVENT_CLOSE;
		SwooleG.factory->notify(SwooleG.factory, &notify_ev);
	}
	//通知主进程
	if (queue->num == SW_CLOSE_QLEN)
	{
		swReactorThread_close_queue(reactor, queue);
	}
}

/**
 * new connection
 */
SWINLINE int swServer_new_connection(swServer *serv, swEvent *ev)
{
	int conn_fd = ev->fd;
	swConnection* connection = NULL;

	if(conn_fd > swServer_get_maxfd(serv))
	{
		swServer_set_maxfd(serv, conn_fd);
#ifdef SW_CONNECTION_LIST_EXPAND
	//新的fd超过了最大fd

		//需要扩容
		if(conn_fd == serv->connection_list_capacity - 1)
		{
			void *new_ptr = sw_shm_realloc(serv->connection_list, sizeof(swConnection)*(serv->connection_list_capacity + SW_CONNECTION_LIST_EXPAND));
			if(new_ptr == NULL)
			{
				swWarn("connection_list realloc fail");
				return SW_ERR;
			}
			else
			{
				serv->connection_list_capacity += SW_CONNECTION_LIST_EXPAND;
				serv->connection_list = (swConnection *)new_ptr;
			}
		}
#endif
	}

	connection = &(serv->connection_list[conn_fd]);
	bzero(connection, sizeof(swConnection));

	connection->fd = conn_fd;
	connection->from_id = ev->from_id;
	connection->from_fd = ev->from_fd;
	connection->connect_time = SwooleGS->now;
	connection->last_time = SwooleGS->now;
	connection->active = 1; //使此连接激活,必须在最后，保证线程安全

	return SW_OK;
}
