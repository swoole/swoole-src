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

#include <sys/stat.h>

/**
 * close the connection
 */
int swReactorThread_onClose(swReactor *reactor, swEvent *event)
{
	swServer *serv = reactor->ptr;
	swConnection *conn = swServer_get_connection(serv, event->fd);
	if (conn != NULL && conn->active == 1)
	{
		swConnection_close(serv, event->fd, event->type == SW_EVENT_CLOSE ? 0 : 1);
	}
	return SW_OK;
}

/**
 * send to client or append to out_buffer
 */
int swReactorThread_send(swEventData *resp)
{
	int buf_size, copy_n;
	swServer *serv = SwooleG.serv;
	swSendData send_data;
	swEvent closeFd;
	swBuffer_trunk *trunk;
	swTask_sendfile *task;

	swConnection *conn = swServer_get_connection(serv, resp->info.fd);
	swReactor *reactor = &(serv->reactor_threads[conn->from_id].reactor);

	//recv length=0, will close connection
	if (resp->info.len == 0)
	{
#ifdef SW_REACTOR_DIRECT_SEND
		close_fd:
#endif
		{
			closeFd.fd = resp->info.fd;
			closeFd.from_id = resp->info.from_id;
			closeFd.type = SW_EVENT_CLOSE;
			//printf("closeFd.fd=%d|from_id=%d\n", closeFd.fd, closeFd.from_id);
			swReactorThread_onClose(reactor, &closeFd);
		}
		return SW_OK;
	}
	//sendfile to client
	else if(resp->info.type == SW_EVENT_SENDFILE)
	{
		trunk = swConnection_get_out_buffer(conn, SW_TRUNK_SENDFILE);
		if (trunk == NULL)
		{
			swWarn("get out_buffer trunk failed.");
			return SW_ERR;
		}
		task = sw_malloc(sizeof(swTask_sendfile));
		if (task == NULL)
		{
			swWarn("malloc for swTask_sendfile failed.");
			//TODO: 回收这里的内存
			return SW_ERR;
		}
		bzero(task, sizeof(swTask_sendfile));
		int file_fd = open(resp->data, O_RDONLY);
		if (file_fd < 0)
		{
			swWarn("open file[%s] failed. Error: %s[%d]", task->filename, strerror(errno), errno);
			return SW_ERR;
		}
		struct stat file_stat;
		if (fstat(file_fd, &file_stat) < 0)
		{
			swWarn("swoole_async_readfile: fstat failed. Error: %s[%d]", strerror(errno), errno);
			return SW_ERR;
		}
		task->filesize = file_stat.st_size;
		task->fd = file_fd;
		trunk->data = (void *)task;
		reactor->set(reactor, resp->info.fd, SW_EVENT_TCP | SW_EVENT_WRITE | SW_EVENT_READ);
	}
	//send data
	else
	{
		send_data.data = resp->data;
		send_data.info.len = resp->info.len;
		send_data.info.from_id = resp->info.from_id;
		send_data.info.fd = resp->info.fd;

#ifdef SW_REACTOR_DIRECT_SEND
		if(!swBuffer_empty(conn->out_buffer))
		{
			trunk = swBuffer_get_trunk(conn->out_buffer);
#else
		{
			trunk = swConnection_get_out_buffer(conn, SW_TRUNK_DATA);
#endif
			buf_size = conn->out_buffer->trunk_size - trunk->length;

#ifdef SW_REACTOR_DIRECT_SEND
			append_out_buffer:
#else
			//listen EPOLLOUT event
			reactor->set(reactor, resp->info.fd, SW_EVENT_TCP | SW_EVENT_WRITE | SW_EVENT_READ);
#endif
			do
			{
				copy_n =  (buf_size >= send_data.info.len) ? send_data.info.len : buf_size;
				memcpy(trunk->data, send_data.data, copy_n);
				send_data.data += copy_n;
				send_data.info.len -= copy_n;
				trunk->length += copy_n;
				buf_size += copy_n;

				//trunk is full, create new trunk
				if (trunk->length == conn->out_buffer->trunk_size)
				{
					//trunk no enough space, creating a new trunk
					trunk = swBuffer_new_trunk(conn->out_buffer, SW_TRUNK_DATA);
					if (trunk == NULL)
					{
						swWarn("append to out_buffer failed.");
						return SW_ERR;
					}
					buf_size = conn->out_buffer->trunk_size;
				}
			} while(send_data.info.len > 0);
		}
#ifdef SW_REACTOR_DIRECT_SEND
		else
		{
			//try send
			int ret = swWrite(send_data.info.fd, send_data.data, send_data.info.len);
			if (ret < 0)
			{
				//连接已被关闭
				if (errno == ECONNRESET || errno == EBADF)
				{
					goto close_fd;
				}
				swWarn("factory->onFinish failed.fd=%d|from_id=%d. Error: %s[%d]", resp->info.fd, resp->info.from_id, strerror(errno), errno);
			}
			//Did not finish, add to writable event callback
			else if(ret < resp->info.len)
			{
				trunk = swConnection_get_out_buffer(conn, SW_TRUNK_DATA);
				send_data.data += ret;
				send_data.info.len -= ret;
				buf_size = conn->out_buffer->trunk_size;
				goto append_out_buffer;
			}
			//printf("[writer]pop.fd=%d|from_id=%d|data=%s\n", resp->info.fd, resp->info.from_id, resp->data);
		}
#endif
	}
	return SW_OK;
}

int swReactorThread_onWrite(swReactor *reactor, swEvent *ev)
{
	int ret, sendn;
	swServer *serv = SwooleG.serv;
	swConnection *conn = swServer_get_connection(serv, ev->fd);
	swBuffer *out_buffer = conn->out_buffer;
	swBuffer_trunk *trunk;
	swEvent closeFd;
	swTask_sendfile *task = NULL;

	do
	{
		trunk = swBuffer_get_trunk(out_buffer);
		if (trunk->type == SW_TRUNK_SENDFILE)
		{
			task = (swTask_sendfile *) trunk->data;
			sendn = (task->filesize - task->offset > SW_SENDFILE_TRUNK) ? SW_SENDFILE_TRUNK : task->filesize - task->offset;
			ret = swoole_sendfile(ev->fd, task->fd, &task->offset, sendn);
			swTrace("ret=%d|task->offset=%ld|sendn=%d|filesize=%ld", ret, task->offset, sendn, task->filesize);

			if (ret <= 0)
			{
				swWarn("sendfile failed. Error: %s[%d]", strerror(errno), errno);
				if (errno == EAGAIN)
				{
					return SW_OK;
				}
				else if (swConnection_error(conn, errno) < 0)
				{
					close_fd:
					closeFd.fd = ev->fd;
					closeFd.from_id = ev->from_id;
					closeFd.type = SW_EVENT_CLOSE;
					swReactorThread_onClose(reactor, &closeFd);
				}
				else
				{
					swBuffer_pop_trunk(out_buffer, trunk);
					return SW_ERR;
				}
			}
			//sendfile finish
			if (task->offset >= task->filesize)
			{
				reactor->set(reactor, ev->fd, SW_EVENT_TCP | SW_EVENT_READ);
				swBuffer_pop_trunk(out_buffer, trunk);
				close(task->fd);
				sw_free(task);
			}
			return SW_OK;
		}
		else
		{
			sendn = trunk->length - trunk->offset;
			ret = swWrite(ev->fd, trunk->data + trunk->offset, sendn);
			//printf("sendn=%d|ret=%d|trunk->offset=%d\n", sendn, ret, trunk->offset);
			if (ret <= 0)
			{
				if (swConnection_error(conn, errno) < 0)
				{
					goto close_fd;
				}
				swWarn("send failed. fd=%d|from_id=%d. Error: %s[%d]", ev->fd, reactor->id, strerror(errno), errno);
			}
			else if(ret == trunk->length)
			{
				swBuffer_pop_trunk(out_buffer, trunk);
			}
			else
			{
				trunk->offset += ret;
			}
		}
	} while(!swBuffer_empty(out_buffer));
	//remove EPOLLOUT event
	reactor->set(reactor, ev->fd, SW_EVENT_TCP | SW_EVENT_READ);
	return SW_OK;
}

int swReactorThread_onReceive_buffer_check_eof(swReactor *reactor, swEvent *event)
{
	int ret, n, recv_again = SW_FALSE;
	int isEOF = -1;

	swServer *serv = SwooleG.serv;
	swFactory *factory =  SwooleG.factory;
	swConnection *conn = swServer_get_connection(serv, event->fd);
	if (conn->active == 0)
	{
		return SW_OK;
	}

	//swDispatchData send_data;
	swEventData send_data;
	swBuffer *buffer;
	swBuffer_trunk *trunk;
	int buf_size;

	if (conn->in_buffer == NULL)
	{
		buffer = swBuffer_new(SW_BUFFER_SIZE);
		//buffer create failed
		if (buffer == NULL)
		{
			recv_data_nobuffer:
			return swReactorThread_onReceive_no_buffer(reactor, event);
		}
		//new trunk
		trunk = swBuffer_new_trunk(buffer, SW_TRUNK_DATA);
		if (trunk == NULL)
		{
			sw_free(buffer);
			goto recv_data_nobuffer;
		}
		conn->in_buffer = buffer;
		buf_size = buffer->trunk_size;
	}
	else
	{
		buffer = conn->in_buffer;
		trunk = swBuffer_get_trunk(buffer);
		//trunk
		buf_size =  buffer->trunk_size - trunk->length;
	}

	recv_data:

#ifdef SW_USE_EPOLLET
	n = swRead(event->fd,  trunk->data, SW_BUFFER_SIZE);
#else
	//非ET模式会持续通知
	n = recv(event->fd,  trunk->data + trunk->length, buf_size, 0);
#endif

	//printf("recv[len=%d]-----------------\n", n);
	if (n < 0)
	{
		if (swConnection_error(conn, errno) < 0)
		{
			goto close_fd;
		}
		return SW_OK;
	}
	else if (n == 0)
	{
		close_fd:
		swTrace("Close Event.FD=%d|From=%d", event->fd, event->from_id);
		swConnection_close(serv, event->fd, 1);
		return SW_OK;
	}
	else
	{
		//更新时间
		conn->last_time =  SwooleGS->now;

		//读满buffer了,可能还有数据
		if ((buffer->trunk_size - trunk->length) == n)
		{
			recv_again = SW_TRUE;
		}
		trunk->length += n;
		buffer->length += n;

		//超过最大尺寸,将会被丢弃
		if (buffer->length > serv->buffer_input_size)
		{
			swWarn("Package is too big. package_length=%d", buffer->length);
			goto close_fd;
		}

		//printf("buffer[len=%d][n=%d]-----------------\n", trunk->len, n);

		//trunk->data[trunk->len] = 0; //这里是为了printf
		//printf("buffer-----------------: %s|fd=%d|len=%d\n", trunk->data, event->fd, trunk->len);

		//EOF_Check----------------------------------------------------------------------------------
		isEOF = memcmp(trunk->data + trunk->length - serv->package_eof_len, serv->package_eof, serv->package_eof_len);
		//printf("buffer ok. EOF=%s|Len=%d|RecvEOF=%s|isEOF=%d\n", serv->package_eof, serv->package_eof_len, trunk->data + trunk->len - serv->package_eof_len, isEOF);

		//收到EOF,发送数据到worker进程
		if (isEOF == 0)
		{
			//printf("EOF------------------------------------\n");
			send_data.info.fd = event->fd;
			send_data.info.type = (buffer->trunk_num == 1) ? SW_EVENT_TCP : SW_EVENT_PACKAGE_START;
			send_data.info.from_id = event->from_id;
			swBuffer_trunk *send_trunk = buffer->head;

			int i = 1;
			while (send_trunk != NULL && send_trunk->length != 0)
			{
				send_data.info.len = send_trunk->length;
				memcpy(send_data.data, send_trunk->data, send_data.info.len);
				send_trunk = send_trunk->next;
				ret = factory->dispatch(factory, &send_data);
				//处理数据失败，数据将丢失
				if (ret < 0)
				{
					swWarn("factory->dispatch failed.");
				}
				//printf("send2worker[i=%d][trunk_num=%d][type=%d]------------------------------------\n", i, buffer_item->trunk_num, send_data.info.type);
				i++;
				if (send_data.info.type == SW_EVENT_PACKAGE_START)
				{
					send_data.info.type = (i == buffer->trunk_num) ? SW_EVENT_PACKAGE_END : SW_EVENT_PACKAGE_TRUNK;
				}
				else if(i == buffer->trunk_num && send_data.info.type == SW_EVENT_PACKAGE_TRUNK)
				{
					send_data.info.type = SW_EVENT_PACKAGE_END;
				}
			}
			swBuffer_flush(buffer);
			return SW_OK;
		}
		else if(recv_again)
		{
			swBuffer_new_trunk(buffer, SW_TRUNK_DATA);
			buf_size = buffer->trunk_size;
			goto recv_data;
		}
	}
	return SW_OK;
}

int swReactorThread_onReceive_no_buffer(swReactor *reactor, swEvent *event)
{
	int ret, n;
	swServer *serv = reactor->ptr;
	swFactory *factory = &(serv->factory);

	swConnection *conn = swServer_get_connection(serv, event->fd);
	if (conn->active == 0)
	{
		return SW_OK;
	}

	struct
	{
		/**
		 * For Message Queue
		 * 这里多一个long int 就可以直接插入到队列中，不需要内存拷贝
		 */
		long queue_type;
		swEventData buf;
	} rdata;

#ifdef SW_USE_EPOLLET
	n = swRead(event->fd, rdata.buf.data, SW_BUFFER_SIZE);
#else
	//非ET模式会持续通知
	n = recv(event->fd, rdata.buf.data, SW_BUFFER_SIZE, 0);
#endif
	if (n < 0)
	{
		if (swConnection_error(conn, errno) < 0)
		{
			goto close_fd;
		}
		return SW_OK;
	}
	//需要检测errno来区分是EAGAIN还是ECONNRESET
	else if (n == 0)
	{
		close_fd:
		swTrace("Close Event.FD=%d|From=%d|errno=%d", event->fd, event->from_id, errno);
		swConnection_close(serv, event->fd, 1);
		return SW_OK;
	}
	else
	{
		swTrace("recv: %s|fd=%d|len=%d\n", rdata.buf.data, event->fd, n);
		//更新最近收包时间
		conn->last_time =  SwooleGS->now;

		//heartbeat ping package
		if (serv->heartbeat_ping_length == n)
		{
			if(serv->heartbeat_pong_length > 0)
			{
				send(event->fd, serv->heartbeat_pong, serv->heartbeat_pong_length, 0);
			}
			return SW_OK;
		}

		rdata.buf.info.fd = event->fd;
		rdata.buf.info.len = n;
		rdata.buf.info.type = SW_EVENT_TCP;
		rdata.buf.info.from_id = event->from_id;

		ret = factory->dispatch(factory, &rdata.buf);
		//处理数据失败，数据将丢失
		if (ret < 0)
		{
			swWarn("factory->dispatch fail.errno=%d|sw_errno=%d", errno, sw_errno);
		}
		if (sw_errno == SW_OK)
		{
			return ret;
		}
		//缓存区还有数据没读完，继续读，EPOLL的ET模式
//		else if (sw_errno == EAGAIN)
//		{
//			swWarn("sw_errno == EAGAIN");
//			ret = swReactorThread_onReceive_no_buffer(reactor, event);
//		}
		return ret;
	}
	return SW_OK;
}

int swReactorThread_onReceive_buffer_check_length(swReactor *reactor, swEvent *event)
{
	int ret, n, buf_size;
	swServer *serv = reactor->ptr;
	swFactory *factory = &(serv->factory);
	swConnection *conn = swServer_get_connection(serv, event->fd);
	if (conn->active == 0)
	{
		return SW_OK;
	}
	swString *buffer = swConnection_get_string_buffer(conn);
	swEventData send_data;

	buf_size = buffer->size - swString_length(buffer);

#ifdef SW_USE_EPOLLET
	n = swRead(event->fd, swString_ptr(buffer), buf_size);
#else
	//非ET模式会持续通知
	n = recv(event->fd, swString_ptr(buffer), buf_size, 0);
#endif

	if (n < 0)
	{
		if (swConnection_error(conn, errno) < 0)
		{
			goto close_fd;
		}
		return SW_OK;
	}
	else if (n == 0)
	{
		close_fd:
		swTrace("Close Event.FD=%d|From=%d", event->fd, event->from_id);
		swConnection_close(serv, event->fd, 1);
		return SW_OK;
	}
	else
	{
		conn->last_time = SwooleGS->now;
		int package_length_offset = serv->package_length_offset;
		uint8_t package_length_size = (serv->package_length_type & SW_NUM_INT) ? 4 : 2;
		int64_t package_body_length;
		buffer->length += n;

		send_data.info.fd = event->fd;
		send_data.info.from_id = event->from_id;

		char *tmp_ptr = buffer->str;
		int tmp_len = buffer->length;

		do
		{
			/*---------------------包头不足---------------------*/
			if (tmp_len < package_length_offset + package_length_size)
			{
				//wait more data
				return SW_OK;
			}
			/*--------------------计算包体长度---------------------*/
			//sign int
			if (serv->package_length_type & SW_NUM_SIGN)
			{
				int *length_sign = (int *) (tmp_ptr + package_length_offset);
				package_body_length = *length_sign;
			}
			//unsigned
			else
			{
				uint32_t *length_unsign = (uint32_t *)(tmp_ptr + package_length_offset);
				package_body_length = *length_unsign;
			}
			//network byte order convert to host byte order
			//字节序转换
			if (serv->package_length_type & SW_NUM_NET)
			{
				package_body_length = ntohl((uint32_t) package_body_length);
			}
			//Length error
			//协议长度不合法，越界或超过配置长度
			if (package_body_length < 1 || package_body_length > serv->buffer_input_size)
			{
				goto close_fd;
			}
			/*-------------------包完整性检测---------------------*/
			//A complete package
			//一个完整的数据包

			int package_length = serv->package_body_start + package_body_length;  //包的总长度

			printf("package_length=%d|body_len=%ld|tmp_len=%d|tmp_ptr=%p\n", package_length, package_body_length, tmp_len, tmp_ptr);

			if (package_length <= tmp_len)
			{
				//超过SW_BUFFER_SIZE
				if(package_length > SW_BUFFER_SIZE)
				{
					int send_n = package_length;
					send_data.info.type = SW_EVENT_PACKAGE_START;
					void *send_ptr = tmp_ptr;
					do
					{
						if (send_n > SW_BUFFER_SIZE)
						{
							send_data.info.len = SW_BUFFER_SIZE;
							memcpy(send_data.data, send_ptr, SW_BUFFER_SIZE);
						}
						else
						{
							send_data.info.type = SW_EVENT_PACKAGE_END;
							send_data.info.len = send_n;
							memcpy(send_data.data, send_ptr, send_n);
						}
						ret = factory->dispatch(factory, &send_data);
						//处理数据失败，数据将丢失
						if (ret < 0)
						{
							swWarn("factory->dispatch failed.");
						}
						send_n -= SW_BUFFER_SIZE;
						send_ptr += send_data.info.len;
						//转为trunk
						if (send_data.info.type == SW_EVENT_PACKAGE_START)
						{
							send_data.info.type = SW_EVENT_PACKAGE_TRUNK;
						}
					}
					while (send_n > 0);
				}
				else
				{
					memcpy(send_data.data, tmp_ptr, package_length);
					send_data.info.len = package_length;
					send_data.info.type = SW_EVENT_TCP;
					ret = factory->dispatch(factory, &send_data);
					if (ret < 0)
					{
						swWarn("factory->dispatch failed.");
					}
				}
				tmp_len -= package_length;
				tmp_ptr += package_length;
			}
			//wait more data
			//继续等待数据
			else
			{
				//包的长度超过buffer区,需要扩容
				if(package_length > buffer->size + package_length_offset)
				{
					swString_extend(buffer, package_length + package_length_offset);
				}
				return SW_OK;
			}
		}
		while (tmp_len > 0);
	}
	return SW_OK;
}

int swReactorThread_close_queue(swReactor *reactor, swCloseQueue *close_queue)
{
	swServer *serv = reactor->ptr;
	int ret;
	while (1)
	{
		ret = serv->main_pipe.write(&(serv->main_pipe), close_queue->events, sizeof(int) * close_queue->num);
		if (ret < 0)
		{
			//close事件缓存区满了，必须阻塞写入
			if (errno == EAGAIN && close_queue->num == SW_CLOSE_QLEN)
			{
				//切换一次进程
				swYield();
				continue;
			}
			else if (errno == EINTR)
			{
				continue;
			}
		}
		break;
	}
	if (ret < 0)
	{
		swWarn("write to main_pipe failed. Error: %s[%d]", strerror(errno), errno);
		return SW_ERR;
	}
	bzero(close_queue, sizeof(swCloseQueue));
	return SW_OK;
}

void swReactorThread_onFinish(swReactor *reactor)
{
	swServer *serv = reactor->ptr;
	swCloseQueue *queue = &serv->reactor_threads[reactor->id].close_queue;
	//打开关闭队列
	if (queue->num > 0)
	{
		swReactorThread_close_queue(reactor, queue);
	}
}

void swReactorThread_onTimeout(swReactor *reactor)
{
	swReactorThread_onFinish(reactor);
}
