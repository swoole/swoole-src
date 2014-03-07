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

#include <sys/sendfile.h>
#include <sys/stat.h>

int swReactorThread_response(swEventData *resp)
{
	int ret;
	swServer *serv = SwooleG.serv;
	swFactory *factory = SwooleG.factory;
	swReactor *reactor;
	swSendData send_data;
	swDataHead closeFd;

	//表示关闭
	if (resp->info.len == 0)
	{
		close_fd:
		{
			closeFd.fd = resp->info.fd;
			closeFd.from_id = resp->info.from_id;
			closeFd.type = SW_EVENT_CLOSE;
			reactor = &(serv->reactor_threads[closeFd.from_id].reactor);
			//printf("closeFd.fd=%d|from_id=%d\n", closeFd.fd, closeFd.from_id);
			swServer_reactor_thread_onClose(reactor, &closeFd);
		}
		return SW_OK;
	}
	//发送文件
	else if(resp->info.type == SW_EVENT_SENDFILE)
	{
		swConnection *conn = swServer_get_connection(serv, resp->info.fd);
		conn->output.send_file = sw_malloc(sizeof(swTask_sendfile));
		if (conn->output.send_file == NULL)
		{
			swWarn("malloc for swTask_sendfile failed.");
			return SW_ERR;
		}
		bzero(conn->output.send_file, sizeof(swTask_sendfile));
		int file_fd = open(resp->data, O_RDONLY);
		if (file_fd < 0)
		{
			swWarn("open file[%s] failed. Error: %s[%d]", send_data.data, strerror(errno), errno);
			return SW_ERR;
		}
		struct stat file_stat;
		if (fstat(file_fd, &file_stat) < 0)
		{
			swWarn("swoole_async_readfile: fstat failed. Error: %s[%d]", strerror(errno), errno);
			return SW_ERR;
		}
		conn->output.send_file->filesize = file_stat.st_size;
		conn->output.send_file->fd = file_fd;
		reactor = &(serv->reactor_threads[closeFd.from_id].reactor);
		reactor->set(reactor, resp->info.fd, SW_EVENT_TCP | SW_EVENT_WRITE | SW_EVENT_READ);
	}
	else
	{
		send_data.data = resp->data;
		send_data.info.len = resp->info.len;
		send_data.info.from_id = resp->info.from_id;
		send_data.info.fd = resp->info.fd;
		ret = factory->onFinish(factory, &send_data);
		if (ret < 0)
		{
			//连接已被关闭
			if (errno == ECONNRESET || errno == EBADF)
			{
				goto close_fd;
			}
			swWarn("factory->onFinish failed.fd=%d|from_id=%d. Error: %s[%d]", resp->info.fd, resp->info.from_id, strerror(errno), errno);
		}
		//printf("[writer]pop.fd=%d|from_id=%d|data=%s\n", resp->info.fd, resp->info.from_id, resp->data);
	}
	return SW_OK;
}

int swServer_reactor_thread_onWrite(swReactor *reactor, swDataHead *ev)
{
	swServer *serv = SwooleG.serv;
	swConnection *conn = swServer_get_connection(serv, ev->fd);
	int ret, sendn;
	if (conn->output.send_file != NULL)
	{
		swTask_sendfile *task = conn->output.send_file;
		sendn = (task->filesize - task->offset > SW_SENDFILE_TRUNK) ? SW_SENDFILE_TRUNK : task->filesize - task->offset;
		ret = sendfile(ev->fd, task->fd, &task->offset, sendn);

		//swWarn("ret=%d|task->offset=%ld|sendn=%d|filesize=%ld", ret, task->offset, sendn, task->filesize);
		if (ret < 0)
		{
			swWarn("sendfile failed. Error: %s[%d]", strerror(errno), errno);
			return SW_ERR;
		}
		if (task->offset >= task->filesize)
		{
			reactor->set(reactor, ev->fd, SW_EVENT_TCP | SW_EVENT_READ);
			conn->output.send_file = NULL;
			close(task->fd);
			sw_free(task);
		}
	}
	return SW_OK;
}
