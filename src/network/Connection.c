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

#ifndef EOK
#define EOK      0
#endif

SWINLINE int swConnection_error(int fd, int err)
{
	switch(err)
	{
	case ECONNRESET:
	case EPIPE:
	case ENOTCONN:
	case ETIMEDOUT:
	case ECONNREFUSED:
	case ENETDOWN:
	case ENETUNREACH:
	case EHOSTDOWN:
	case EHOSTUNREACH:
		return SW_ERR;
	case EAGAIN:
	case EOK:
		return SW_OK;
	default:
		swWarn("recv from connection[fd=%d] failed. Error: %s[%d]", fd, strerror(err), err);
		return SW_OK;
	}
}

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

	conn->active = 0;

	int reactor_id = conn->from_id;

	swCloseQueue *queue = &serv->reactor_threads[reactor_id].close_queue;

	//将关闭的fd放入队列
	queue->events[queue->num] = fd;
	//增加计数
	queue->num ++;

	reactor = &(serv->reactor_threads[reactor_id].reactor);
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

	if (conn->in_buffer != NULL)
	{
		swBuffer_free(conn->in_buffer);
		conn->in_buffer = NULL;
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
	//关闭此连接，必须放在最前面，以保证线程安全
	reactor->del(reactor, fd);
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

SWINLINE swString* swConnection_get_string_buffer(swConnection *conn)
{
	swString *buffer = conn->string_buffer;
	if (buffer == NULL)
	{
		return swString_new(SW_BUFFER_SIZE);
	}
	else
	{
		return buffer;
	}
}

SWINLINE void swConnection_clear_string_buffer(swConnection *conn)
{
	swString *buffer = conn->string_buffer;
	if (buffer != NULL)
	{
		swString_free(buffer);
		conn->string_buffer = NULL;
	}
}

int swConnection_send_in_buffer(swConnection *conn)
{
	int ret;
#ifdef SW_DEBUG
    int i;
#endif

	swFactory *factory = SwooleG.factory;
	swEventData _send;
	swBuffer *buffer = conn->in_buffer;
	swBuffer_trunk *trunk = swBuffer_get_trunk(buffer);

	_send.info.fd = conn->fd;
	_send.info.type = (buffer->trunk_num == 1) ? SW_EVENT_TCP : SW_EVENT_PACKAGE_START;
	_send.info.from_id = conn->from_id;

	while (trunk != NULL)
	{
		_send.info.len = trunk->length;
		memcpy(_send.data, trunk->data, _send.info.len);
		ret = factory->dispatch(factory, &_send);

		//TODO: 处理数据失败，数据将丢失
		if (ret < 0)
		{
			swWarn("factory->dispatch failed.");
		}

		swBuffer_pop_trunk(buffer, trunk);
		trunk = swBuffer_get_trunk(buffer);

		swTrace("send2worker[i=%d][trunk_num=%d][type=%d]\n", i++, buffer->trunk_num, _send.info.type);

		if (_send.info.type == SW_EVENT_PACKAGE_START)
		{
			_send.info.type = SW_EVENT_PACKAGE_TRUNK;
		}
		//package end
		if (trunk == NULL || trunk->next == NULL)
		{
			_send.info.type = SW_EVENT_PACKAGE_END;
		}
	}
	return SW_OK;
}

SWINLINE swBuffer_trunk* swConnection_get_in_buffer(swConnection *conn)
{
	swBuffer_trunk *trunk = NULL;
	swBuffer *buffer;

	if (conn->in_buffer == NULL)
	{
		buffer = swBuffer_new(SW_BUFFER_SIZE);
		//buffer create failed
		if (buffer == NULL)
		{
			return NULL;
		}
		//new trunk
		trunk = swBuffer_new_trunk(buffer, SW_TRUNK_DATA, buffer->trunk_size);
		if (trunk == NULL)
		{
			sw_free(buffer);
			return NULL;
		}
		conn->in_buffer = buffer;
	}
	else
	{
		buffer = conn->in_buffer;
		trunk = swBuffer_get_trunk(buffer);
		if (trunk == NULL || trunk->length == buffer->trunk_size)
		{
			trunk = swBuffer_new_trunk(buffer, SW_TRUNK_DATA, buffer->trunk_size);
		}
	}
	return trunk;
}

SWINLINE swBuffer_trunk* swConnection_get_out_buffer(swConnection *conn, uint32_t type)
{
	swBuffer_trunk *trunk;
	if (conn->out_buffer == NULL)
	{
		conn->out_buffer = swBuffer_new(SW_BUFFER_SIZE);
		if (conn->out_buffer == NULL)
		{
			return NULL;
		}
	}
	if (type == SW_TRUNK_SENDFILE)
	{
		trunk = swBuffer_new_trunk(conn->out_buffer, SW_TRUNK_SENDFILE, 0);
	}
	else
	{
		trunk = swBuffer_get_trunk(conn->out_buffer);
		if (trunk == NULL)
		{
			trunk = swBuffer_new_trunk(conn->out_buffer, SW_TRUNK_DATA, conn->out_buffer->trunk_size);
		}
	}
	return trunk;
}
