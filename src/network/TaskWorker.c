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

static swEventData *current_task;

static void swTaskWorker_signal_init(void);

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
	current_task = task;
	return serv->onTask(serv, task);
}

int swTaskWorker_large_pack(swEventData *task, void *data, int data_len)
{
	swPackage_task pkg;
	memcpy(pkg.tmpfile, SwooleG.task_tmpdir, SwooleG.task_tmpdir_len);

#ifdef HAVE_MKOSTEMP
	int tpm_fd  = mkostemp(pkg.tmpfile, O_WRONLY);
#else
	int tpm_fd  = mkstemp(pkg.tmpfile);
#endif

	if (tpm_fd < 0)
	{
		swWarn("mkdtemp(%s) failed. Error: %s[%d]", pkg.tmpfile, strerror(errno), errno);
		return SW_ERR;
	}

	if (swoole_sync_writefile(tpm_fd, data, data_len) <=0)
	{
		swWarn("write to tmpfile failed.");
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

static void swTaskWorker_signal_init(void)
{
	swSignal_set(SIGHUP, NULL, 1, 0);
	swSignal_set(SIGPIPE, NULL, 1, 0);
	swSignal_set(SIGUSR1, NULL, 1, 0);
	swSignal_set(SIGUSR2, NULL, 1, 0);
	swSignal_set(SIGTERM, swWorker_signal_handler, 1, 0);
	swSignal_set(SIGALRM, swTimer_signal_handler, 1, 0);
}

void swTaskWorker_onStart(swProcessPool *pool, int worker_id)
{
    swServer *serv = pool->ptr;
    SwooleWG.id = worker_id + serv->worker_num;

    SwooleG.use_timer_pipe = 0;
    SwooleG.use_timerfd = 0;

    swTaskWorker_signal_init();
    swWorker_onStart(serv);

    SwooleG.process_type = SW_PROCESS_TASKWORKER;

    char *tmp_dir = swoole_dirname(SwooleG.task_tmpdir);
    //create tmp dir
    if (access(tmp_dir, R_OK) < 0 && swoole_mkdir_recursive(tmp_dir) < 0)
    {
        swWarn("create task tmp dir failed.");
    }
    free(tmp_dir);
}

void swTaskWorker_onStop(swProcessPool *pool, int worker_id)
{
	swServer *serv = pool->ptr;
	swWorker_onStop(serv);
}

int swTaskWorker_finish(swServer *serv, char *data, int data_len)
{
    swEventData buf;
    if (SwooleG.task_worker_num < 1)
    {
        swWarn("cannot use task/finish, because no set serv->task_worker_num.");
        return SW_ERR;
    }

    int ret;
    //for swoole_server_task
    if (current_task->info.type == SW_TASK_NONBLOCK)
    {
        buf.info.type = SW_EVENT_FINISH;
        buf.info.fd = current_task->info.fd;

        //write to file
        if (data_len >= sizeof(buf.data))
        {
            if (swTaskWorker_large_pack(&buf, data, data_len) < 0 )
            {
                swWarn("large task pack failed()");
                return SW_ERR;
            }
        }
        else
        {
            memcpy(buf.data, data, data_len);
            buf.info.len = data_len;
            buf.info.from_fd = 0;
        }

        /**
         * TODO: 这里需要重构，改成统一的模式
         */
        if (serv->factory_mode == SW_MODE_PROCESS)
        {
            ret = swServer_send2worker_blocking(serv, &buf, sizeof(buf.info) + buf.info.len, current_task->info.from_id);
        }
        else
        {
            ret = swWrite(SwooleG.event_workers->workers[current_task->info.from_id].pipe_worker, &buf, sizeof(buf.info) + data_len);
        }
    }
    else
    {
        uint64_t flag = 1;
        uint16_t worker_id = current_task->info.from_id;

        /**
         * Use worker shm store the result
         */
        swEventData *result = &(SwooleG.task_result[worker_id]);
        swPipe *task_notify_pipe = &(SwooleG.task_notify[worker_id]);

        result->info.type = SW_EVENT_FINISH;
        result->info.fd = current_task->info.fd;

        if (data_len >= sizeof(buf.data))
        {
            if (swTaskWorker_large_pack(result, data, data_len) < 0)
            {
                swWarn("large task pack failed()");
                return SW_ERR;
            }
        }
        else
        {
            memcpy(result->data, data, data_len);
            result->info.len = data_len;
            result->info.from_fd = 0;
        }

        while (1)
        {
            ret = task_notify_pipe->write(task_notify_pipe, &flag, sizeof(flag));
            if (ret < 0 && errno == EAGAIN)
            {
                if (swSocket_wait(task_notify_pipe->getFd(task_notify_pipe, 1), -1, SW_EVENT_WRITE) == 0)
                {
                    continue;
                }
            }
            break;
        }
    }
    if (ret < 0)
    {
        swWarn("TaskWorker: send result to worker failed. Error: %s[%d]", strerror(errno), errno);
    }
    return ret;
}
