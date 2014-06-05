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
 * in worker process
 */
int swTaskWorker_onFinish(swReactor *reactor, swEvent *event)
{
	swServer *serv = reactor->ptr;
	swEventData task;
	int n;
	do
	{
		n = read(event->fd, &task, sizeof(task));
	}
	while(n < 0 && errno == EINTR);
	return serv->onFinish(serv, &task);
}

int swTaskWorker_onTask(swProcessPool *pool, swEventData *task)
{
	swServer *serv = pool->ptr;
	return serv->onTask(serv, task);
}

int swTaskWorker_large_pack(swEventData *task, void *data, int data_len)
{
	swPackage_task pkg;
	memcpy(pkg.tmpfile, SW_TASK_TMP_FILE, sizeof(SW_TASK_TMP_FILE));
#ifdef HAVE_MKOSTEMP
	int tpm_fd  = mkostemp(pkg.tmpfile, O_WRONLY);
#else
	int tpm_fd  = mkstemp(pkg.tmpfile);
#endif
	if (tpm_fd < 0)
	{
		swWarn("mkdtemp() failed. Error: %s[%d]", strerror(errno), errno);
		return SW_ERR;
	}
	if (swoole_sync_writefile(tpm_fd, data, data_len) <=0)
	{
		swWarn("write to tmp file failed.");
		return SW_ERR;
	}
	/**
	 * from_fd == 1, read from file
	 */
	task->info.from_fd = 1;
	task->info.len = sizeof(swPackage_task);
	pkg.length = data_len;
	memcpy(task->data, &pkg, sizeof(swPackage_task));
	return SW_OK;
}

void swTaskWorker_onWorkerStart(swProcessPool *pool, int worker_id)
{
	swServer *serv = pool->ptr;
	serv->onWorkerStart(serv, worker_id + serv->worker_num);

	char *tmp_dir = swoole_dirname(SW_TASK_TMP_FILE);
	//create tmp dir
	if (access(tmp_dir, R_OK) < 0 && swoole_mkdir_recursive(tmp_dir) < 0)
	{
		swWarn("create task tmp dir failed.");
	}
	free(tmp_dir);
}
