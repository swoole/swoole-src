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

#include <sys/poll.h>
#include <sys/stat.h>

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
		return SW_CLOSE;
	case EAGAIN:
	case EOK:
		return SW_WAIT;
	default:
		return SW_ERROR;
	}
}

SWINLINE int swConnection_send_blocking(int fd, void *data, int length, int timeout)
{
	int ret, n, writen = length;
	struct pollfd event;
	event.fd = fd;
	event.events = POLLOUT;

	while(writen > 0)
	{
		ret = poll(&event, 1, timeout);
		if (ret == 0)
		{
			return SW_ERR;
		}
		else if (ret > 0)
		{
			n = send(fd, data, writen, MSG_NOSIGNAL | MSG_DONTWAIT);
			if (n < 0)
			{
				swWarn("send() failed. Error: %s[%d]", strerror(errno), errno);
				return SW_ERR;
			}
			else
			{
				writen -= n;
				continue;
			}
		}
		else
		{
			swWarn("poll() failed. Error: %s[%d]", strerror(errno), errno);
			return SW_ERR;
		}
	}
	return 0;
}

SWINLINE int swConnection_sendfile_blocking(int fd, char *filename, int timeout)
{
	int file_fd = open(filename, O_RDONLY);
	if (file_fd < 0)
	{
		swWarn("open file[%s] failed. Error: %s[%d]", filename, strerror(errno), errno);
		return SW_ERR;
	}

	struct stat file_stat;
	if (fstat(file_fd, &file_stat) < 0)
	{
		swWarn("fstat() failed. Error: %s[%d]", strerror(errno), errno);
		return SW_ERR;
	}

	int n, ret, sendn;
	off_t offset;
	struct pollfd event;
	event.fd = fd;
	event.events = POLLOUT;
	size_t file_size = file_stat.st_size;

	while (offset < file_size)
	{
		ret = poll(&event, 1, timeout);
		if (ret == 0)
		{
			return SW_ERR;
		}
		else if (ret > 0)
		{
			sendn = (file_size - offset > SW_SENDFILE_TRUNK) ? SW_SENDFILE_TRUNK : file_size - offset;
			n = swoole_sendfile(fd, file_fd, &offset, sendn);
			if (n <= 0)
			{
				return SW_ERR;
			}
			else
			{
				continue;
			}
		}
		else
		{
			swWarn("poll() failed. Error: %s[%d]", strerror(errno), errno);
			return SW_ERR;
		}
	}
	return 0;
}

/**
 * close connection
 */
SWINLINE void swConnection_close(swServer *serv, int fd, int notify)
{
	swConnection *conn = swServer_get_connection(serv, fd);
	swReactor *reactor;
	swEvent notify_ev;

	if (conn == NULL)
	{
		swWarn("[Reactor]connection not found. fd=%d|max_fd=%d", fd, swServer_get_maxfd(serv));
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
		if (conn->object != NULL)
		{
			swString_free(conn->object);
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

	//立即关闭socket，清理缓存区
	if (serv->tcp_socket_linger > 0)
	{
		struct linger linger;
		linger.l_onoff = 1;
		linger.l_linger = 0;

		if (setsockopt(fd, SOL_SOCKET, SO_LINGER, &linger, sizeof(struct linger)) == -1)
		{
			swWarn("setsockopt(SO_LINGER) failed. Error: %s[%d]", strerror(errno), errno);
		}
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
		if (conn_fd == serv->connection_list_capacity - 1)
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
	swString *buffer = conn->object;
	if (buffer == NULL)
	{
		return swString_new(SW_BUFFER_SIZE);
	}
	else
	{
		return buffer;
	}
}

SWINLINE int swConnection_send_string_buffer(swConnection *conn)
{
	int ret;
	swString *buffer = conn->object;
	swFactory *factory = SwooleG.factory;
	swEventData _send;

	_send.info.fd = conn->fd;
	_send.info.from_id = conn->from_id;

#ifdef SW_USE_RINGBUFFER
	swServer *serv = SwooleG.serv;
	swMemoryPool *pool = serv->reactor_threads[conn->from_id].pool;
	swPackage package;

	package.length = buffer->length;
	while (1)
	{
		package.data = pool->alloc(pool, buffer->length);
		if (package.data == NULL)
		{
			swYield();
			swWarn("reactor memory pool full.");
			continue;
		}
		break;
	}
	_send.info.type = SW_EVENT_PACKAGE;
	_send.info.len = sizeof(package);
	memcpy(package.data, buffer->str, buffer->length);
	memcpy(_send.data, &package, sizeof(package));

	//swoole_dump_bin(package.data, 's', buffer->length);

	ret = factory->dispatch(factory, &_send);
#else
	int send_n = buffer->length;
	_send.info.type = SW_EVENT_PACKAGE_START;

	/**
	 * lock target
	 */
	SwooleTG.factory_lock_target = 1;

	void *send_ptr = buffer->str;
	do
	{
		if (send_n > SW_BUFFER_SIZE)
		{
			_send.info.len = SW_BUFFER_SIZE;
			memcpy(_send.data, send_ptr, SW_BUFFER_SIZE);
		}
		else
		{
			_send.info.type = SW_EVENT_PACKAGE_END;
			_send.info.len = send_n;
			memcpy(_send.data, send_ptr, send_n);
		}

		swTrace("dispatch, type=%d|len=%d\n", _send.info.type, _send.info.len);

		ret = factory->dispatch(factory, &_send);
		//TODO: 处理数据失败，数据将丢失
		if (ret < 0)
		{
			swWarn("factory->dispatch failed.");
		}
		send_n -= _send.info.len;
		send_ptr += _send.info.len;
	}
	while (send_n > 0);

	/**
	 * unlock
	 */
	SwooleTG.factory_target_worker = -1;
	SwooleTG.factory_lock_target = 0;

#endif
	return ret;
}

SWINLINE void swConnection_clear_string_buffer(swConnection *conn)
{
	swString *buffer = conn->object;
	if (buffer != NULL)
	{
		swString_free(buffer);
		conn->object = NULL;
	}
}

int swConnection_send_in_buffer(swConnection *conn)
{
	swFactory *factory = SwooleG.factory;
	swEventData _send;

	_send.info.fd = conn->fd;
	_send.info.from_id = conn->from_id;

	swBuffer *buffer = conn->in_buffer;
	volatile swBuffer_trunk *trunk = swBuffer_get_trunk(buffer);

#ifdef SW_USE_RINGBUFFER

	swServer *serv = SwooleG.serv;
	swMemoryPool *pool = serv->reactor_threads[conn->from_id].pool;
	swPackage package;

	package.length = 0;
	while (1)
	{
		package.data = pool->alloc(pool, buffer->length);
		if (package.data == NULL)
		{
			swYield();
			swWarn("reactor memory pool full.");
			continue;
		}
		break;
	}
	_send.info.type = SW_EVENT_PACKAGE;

	while (trunk != NULL)
	{
		_send.info.len = trunk->length;
		memcpy(package.data + package.length , trunk->store.ptr, trunk->length);
		package.length += trunk->length;

		swBuffer_pop_trunk(buffer, trunk);
		trunk = swBuffer_get_trunk(buffer);
	}
	_send.info.len = sizeof(package);
	memcpy(_send.data, &package, sizeof(package));
	//swWarn("[ReactorThread] copy_n=%d", package.length);
	return factory->dispatch(factory, &_send);

#else

	int ret;
	_send.info.type = SW_EVENT_PACKAGE_START;

	/**
	 * lock target
	 */
	SwooleTG.factory_lock_target = 1;

	while (trunk != NULL)
	{
		_send.info.len = trunk->length;
		memcpy(_send.data, trunk->store.ptr, _send.info.len);
		//package end
		if (trunk->next == NULL)
		{
			_send.info.type = SW_EVENT_PACKAGE_END;
		}
		ret = factory->dispatch(factory, &_send);
		//TODO: 处理数据失败，数据将丢失
		if (ret < 0)
		{
			swWarn("factory->dispatch failed.");
		}
		swBuffer_pop_trunk(buffer, trunk);
		trunk = swBuffer_get_trunk(buffer);

		swTrace("send2worker[trunk_num=%d][type=%d]\n", buffer->trunk_num, _send.info.type);
	}
	/**
	 * unlock
	 */
	SwooleTG.factory_target_worker = -1;
	SwooleTG.factory_lock_target = 0;

#endif
	return SW_OK;
}

SWINLINE volatile swBuffer_trunk* swConnection_get_in_buffer(swConnection *conn)
{
	volatile swBuffer_trunk *trunk = NULL;
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
		trunk = buffer->tail;
		if (trunk == NULL || trunk->length == buffer->trunk_size)
		{
			trunk = swBuffer_new_trunk(buffer, SW_TRUNK_DATA, buffer->trunk_size);
		}
	}
	return trunk;
}

SWINLINE volatile swBuffer_trunk* swConnection_get_out_buffer(swConnection *conn, uint32_t type)
{
	volatile swBuffer_trunk *trunk;
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
