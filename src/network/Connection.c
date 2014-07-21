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
#include "Connection.h"

#include <sys/stat.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL        0
#endif

int swConnection_send_blocking(int fd, void *data, int length, int timeout)
{
	int ret, n, writen = length;

	while(writen > 0)
	{
	    if (swSocket_wait(fd, timeout, SW_EVENT_WRITE) < 0)
		{
			return SW_ERR;
		}
		else
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
	}
	return 0;
}

int swConnection_sendfile_blocking(int fd, char *filename, int timeout)
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
	off_t offset = 0;
	size_t file_size = file_stat.st_size;

	while (offset < file_size)
	{
	    if (swSocket_wait(fd, timeout, SW_EVENT_WRITE) < 0)
	    {
			return SW_ERR;
		}
		else
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
	}
	return 0;
}

/**
 * send buffer to client
 */
int swConnection_buffer_send(swConnection *conn)
{
	int ret, sendn;
	swBuffer *buffer = conn->out_buffer;
	swBuffer_trunk *trunk = swBuffer_get_trunk(buffer);
	sendn = trunk->length - trunk->offset;

	if (sendn == 0)
	{
		swBuffer_pop_trunk(buffer, trunk);
		return SW_CONTINUE;
	}
	ret = swConnection_send(conn, trunk->store.ptr + trunk->offset, sendn, 0);
	//printf("BufferOut: reactor=%d|sendn=%d|ret=%d|trunk->offset=%d|trunk_len=%d\n", reactor->id, sendn, ret, trunk->offset, trunk->length);
	if (ret < 0)
	{
		switch (swConnection_error(errno))
		{
		case SW_ERROR:
			swWarn("send to fd[%d] failed. Error: %s[%d]", conn->fd, strerror(errno), errno);
			return SW_OK;
		case SW_CLOSE:
			return SW_CLOSE;
		case SW_WAIT:
			return SW_WAIT;
		default:
			return SW_CONTINUE;
		}
	}
	//trunk full send
	else if(ret == sendn || sendn == 0)
	{
		swBuffer_pop_trunk(buffer, trunk);
	}
	else
	{
		trunk->offset += ret;
	}
	return SW_CONTINUE;
}

swString* swConnection_get_string_buffer(swConnection *conn)
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

int swConnection_send_string_buffer(swConnection *conn)
{
	int ret;
	swString *buffer = conn->object;
	swEventData _send;

	_send.info.fd = conn->fd;
	_send.info.from_id = conn->from_id;

#ifdef SW_USE_RINGBUFFER

	swServer *serv = SwooleG.serv;
	uint16_t target_worker_id = swServer_worker_schedule(serv, conn->fd);
	swWorker *worker = swServer_get_worker(serv, target_worker_id);
	swMemoryPool *pool = worker->pool_input;
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
	//swoole_dump_bin(package.data, 's', buffer->length);
	memcpy(package.data, buffer->str, buffer->length);
	memcpy(_send.data, &package, sizeof(package));
	ret = swServer_send2worker(serv, &_send, target_worker_id);

#else
	int send_n = buffer->length;
	swFactory *factory = SwooleG.factory;
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

void swConnection_clear_string_buffer(swConnection *conn)
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
	swEventData _send;

	_send.info.fd = conn->fd;
	_send.info.from_id = conn->from_id;

	swBuffer *buffer = conn->in_buffer;
	swBuffer_trunk *trunk = swBuffer_get_trunk(buffer);

#ifdef SW_USE_RINGBUFFER

	swServer *serv = SwooleG.serv;
    uint16_t target_worker_id = swServer_worker_schedule(serv, conn->fd);
    swWorker *worker = swServer_get_worker(serv, target_worker_id);
    swMemoryPool *pool = worker->pool_input;
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
	return swServer_send2worker(serv, &_send, target_worker_id);

#else

	swFactory *factory = SwooleG.factory;
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

volatile swBuffer_trunk* swConnection_get_in_buffer(swConnection *conn)
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

volatile swBuffer_trunk* swConnection_get_out_buffer(swConnection *conn, uint32_t type)
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
