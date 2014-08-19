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

static int swProcessPool_worker_start(swProcessPool *pool, swWorker *worker);
static void swProcessPool_free(swProcessPool *pool);

/**
 * Process manager
 */
int swProcessPool_create(swProcessPool *pool, int worker_num, int max_request, key_t msgqueue_key)
{
	bzero(pool, sizeof(swProcessPool));
	pool->workers = sw_calloc(worker_num, sizeof(swWorker));
	pool->worker_num = worker_num;
	pool->max_request = max_request;

	if (pool->workers == NULL)
	{
		swWarn("malloc[1] failed.");
		return SW_ERR;
	}
	pool->pipes = sw_calloc(worker_num, sizeof(swPipe));
	if (pool->pipes == NULL)
	{
		swWarn("malloc[2] failed.");
		sw_free(pool->workers);
		return SW_ERR;
	}

	pool->map = swHashMap_new(SW_HASHMAP_INIT_BUCKET_N, free);
	if (pool->map == NULL)
	{
	    return SW_ERR;
	}

	int i;
	if (msgqueue_key > 0)
	{
		if (swQueueMsg_create(&pool->queue, 1, msgqueue_key, 1) < 0)
		{
			return SW_ERR;
		}
		pool->use_msgqueue = 1;
		pool->msgqueue_key = msgqueue_key;
	}
	else
	{
		swPipe *pipe;
		for (i = 0; i < worker_num; i++)
		{
			pipe = &pool->pipes[i];
			if (swPipeUnsock_create(pipe, 1, SOCK_DGRAM) < 0)
			{
				return SW_ERR;
			}
			swProcessPool_worker(pool, i).pipe_master = pipe->getFd(pipe, 1);
			swProcessPool_worker(pool, i).pipe_worker = pipe->getFd(pipe, 0);
		}
	}

	for (i = 0; i < worker_num; i++)
	{
		swProcessPool_worker(pool, i).id = i;
		swProcessPool_worker(pool, i).pool = pool;
	}
	pool->main_loop = swProcessPool_worker_start;
	return SW_OK;
}

/**
 * start workers
 */
int swProcessPool_start(swProcessPool *pool)
{
	int i;
	for (i = 0; i < pool->worker_num; i++)
	{
		if(swProcessPool_spawn(&(pool->workers[i])) < 0)
		{
			swWarn("swProcessPool_spawn fail");
			return SW_ERR;
		}
	}
	return SW_OK;
}

/**
 * dispatch data to worker
 */
int swProcessPool_dispatch(swProcessPool *pool, swEventData *data, int worker_id)
{
	int ret;
	//no worker_id, will round
	if (worker_id < 0)
	{
		worker_id = (pool->round_id++)%pool->worker_num;
	}

	struct
	{
		long mtype;
		swEventData buf;
	} in;

	if (pool->use_msgqueue)
	{
		in.mtype = worker_id + 1;
		memcpy(&in.buf, data, sizeof(data->info) + data->info.len);
		ret = pool->queue.in(&pool->queue, (swQueue_data *) &in, sizeof(data->info) + data->info.len);
		if (ret < 0)
		{
			swWarn("msgsnd failed. Error: %s[%d]", strerror(errno), errno);
		}
	}
	else
	{
		swWorker *worker = &swProcessPool_worker(pool, worker_id);

		while(1)
		{
			ret = write(worker->pipe_master, data, sizeof(data->info) + data->info.len);
			if (ret < 0)
			{
				/**
				 * Wait pipe can be written.
				 */
				if (errno == EAGAIN && swSocket_wait(worker->pipe_master, SW_WORKER_WAIT_TIMEOUT, SW_EVENT_WRITE) == SW_OK)
				{
					continue;
				}
				else if (errno == EINTR)
				{
					continue;
				}
				else
				{
					break;
				}
			}
			break;
		}
		if (ret < 0)
		{
			swWarn("sendto unix socket failed. Error: %s[%d]", strerror(errno), errno);
		}
	}
	return ret;
}

void swProcessPool_shutdown(swProcessPool *pool)
{
	int i, ret;
	SwooleG.running = 0;
	for (i = 0; i < pool->worker_num; i++)
	{
		ret = kill(pool->workers[i].pid, SIGTERM);
		if (ret < 0)
		{
			swWarn("[Manager]kill fail.pid=%d. Error: %s [%d]", pool->workers[i].pid, strerror(errno), errno);
			continue;
		}
	}
	swProcessPool_free(pool);
}

pid_t swProcessPool_spawn(swWorker *worker)
{
	pid_t pid = fork();
	swProcessPool *pool = worker->pool;

	switch (pid)
	{
	//child
	case 0:
		/**
		 * Process start
		 */
		if (pool->onWorkerStart != NULL)
		{
			pool->onWorkerStart(pool, worker->id);
		}
		/**
		 * Process main loop
		 */
		int ret_code = pool->main_loop(pool, worker);
		/**
		 * Process stop
		 */
		if (pool->onWorkerStop != NULL)
		{
			pool->onWorkerStop(pool, worker->id);
		}
		exit(ret_code);
		break;
	case -1:
		swWarn("[swProcessPool_run] fork failed. Error: %s [%d]", strerror(errno), errno);
		break;
		//parent
	default:
		worker->pid = pid;
		swHashMap_add_int(pool->map, pid, worker);
		break;
	}
	return pid;
}

static int swProcessPool_worker_start(swProcessPool *pool, swWorker *worker)
{
	struct
	{
		long mtype;
		swEventData buf;
	} out;

	int n, ret;
	int task_n, worker_task_always = 0;

	if (pool->max_request < 1)
	{
		task_n = 1;
		worker_task_always = 1;
	}
	else
	{
		task_n = pool->max_request;
	}

	/**
	 * Use from_fd save the task_worker->id
	 */
	out.buf.info.from_fd = worker->id;

	if (SwooleG.task_ipc_mode > 1)
	{
		out.mtype = worker->id + 1;
	}
	else
	{
		out.mtype = 0;
	}

	while (SwooleG.running > 0 && task_n > 0)
	{
		if (pool->use_msgqueue)
		{
			n = pool->queue.out(&pool->queue, (swQueue_data *) &out, sizeof(out.buf));
		}
		else
		{
			n = read(worker->pipe_worker, &out.buf, sizeof(out.buf));
		}

		if (n < 0)
		{
			if (errno != EINTR)
			{
				swWarn("[Worker#%d]read() or msgrcv() failed. Error: %s [%d]", worker->id, strerror(errno), errno);
			}
			else if (SwooleG.signal_alarm)
			{
				swTimer_select(&SwooleG.timer);
			}
			continue;
		}

		ret = pool->onTask(pool, &out.buf);
		if (ret > 0 && !worker_task_always)
		{
			task_n--;
		}
	}
	return SW_OK;
}

/**
 * add a worker to pool
 */
int swProcessPool_add_worker(swProcessPool *pool, swWorker *worker)
{
	swHashMap_add_int(pool->map, worker->pid, worker);
	return SW_OK;
}

int swProcessPool_wait(swProcessPool *pool)
{
	int pid, new_pid;
	int reload_worker_i = 0;
	int ret;

	swWorker *reload_workers;
	reload_workers = sw_calloc(pool->worker_num, sizeof(swWorker));
	if (reload_workers == NULL)
	{
		swError("[manager] malloc[reload_workers] fail.\n");
		return SW_ERR;
	}

	while (1)
	{
		pid = wait(NULL);
		swTrace("[manager] worker stop.pid=%d\n", pid);
		if (pid < 0)
		{
			if (pool->reloading == 0)
			{
				swTrace("[Manager] wait fail. Error: %s [%d]", strerror(errno), errno);
			}
			else if (pool->reload_flag == 0)
			{
				memcpy(reload_workers, pool->workers, sizeof(swWorker) * pool->worker_num);
				pool->reload_flag = 1;
				goto reload_worker;
			}
		}
		if (SwooleG.running == 1)
		{
			swWorker *exit_worker = swHashMap_find_int(pool->map, pid);
			if (exit_worker == NULL)
			{
				swWarn("[Manager]unknow worker[pid=%d]", pid);
				continue;
			}
			new_pid = swProcessPool_spawn(exit_worker);
			if (new_pid < 0)
			{
				swWarn("Fork worker process fail. Error: %s [%d]", strerror(errno), errno);
				return SW_ERR;
			}
			swHashMap_del_int(pool->map, pid);
		}
		//reload worker
		reload_worker: if (pool->reloading == 1)
		{
			//reload finish
			if (reload_worker_i >= pool->worker_num)
			{
				pool->reloading = 0;
				reload_worker_i = 0;
				continue;
			}
			ret = kill(reload_workers[reload_worker_i].pid, SIGTERM);
			if (ret < 0)
			{
				swWarn("[Manager]kill fail.pid=%d. Error: %s [%d]", reload_workers[reload_worker_i].pid,
						strerror(errno), errno);
				continue;
			}
			reload_worker_i++;
		}
	}
	return SW_OK;
}

static void swProcessPool_free(swProcessPool *pool)
{
	int i;
	swPipe *pipe;

	if (!pool->use_msgqueue)
	{
		for (i = 0; i < pool->worker_num; i++)
		{
			pipe = &pool->pipes[i];
			pipe->close(pipe);
		}
	}

	sw_free(pool->workers);
	sw_free(pool->pipes);
	swHashMap_free(pool->map);
}
