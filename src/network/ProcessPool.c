#include "swoole.h"

static int swProcessPool_worker_loop(swProcessPool *pool, swWorker *worker);
static void swProcessPool_free(swProcessPool *pool);

/**
 * Process manager
 */
int swProcessPool_create(swProcessPool *pool, int worker_num, int max_request)
{
	bzero(pool, sizeof(swProcessPool));
	pool->workers = sw_calloc(worker_num, sizeof(swWorker));
	pool->worker_num = worker_num;
	pool->max_request = max_request;

	if (pool->workers == NULL)
	{
		swWarn("[swProcessPool_create] malloc fail.");
		return SW_ERR;
	}
	int i;
	swPipe pipe;
	for (i = 0; i < worker_num; i++)
	{
		if (swPipeUnsock_create(&pipe, 1, SOCK_STREAM) < 0)
		{
			return SW_ERR;
		}
		swProcessPool_worker(pool, i).pipe_master = pipe.getFd(&pipe, 1);
		swProcessPool_worker(pool, i).pipe_worker = pipe.getFd(&pipe, 0);
		swProcessPool_worker(pool, i).id = i;
	}
	return SW_OK;
}

/**
 * start
 */
int swProcessPool_start(swProcessPool *pool)
{
	int i;
	for (i = 0; i < pool->worker_num; i++)
	{
		if(swProcessPool_spawn(pool, &(pool->workers[i])) < 0)
		{
			swWarn("swProcessPool_spawn fail");
			return SW_ERR;
		}
	}
	return SW_OK;
}

/**
 * dispatch
 */
int swProcessPool_dispatch(swProcessPool *pool, swEventData *data)
{
	int id = (pool->round_id++)%pool->worker_num;
	swWorker *worker = &swProcessPool_worker(pool, id);
	return swWrite(worker->pipe_master, data, sizeof(data->info) + data->info.len);
}

void swProcessPool_shutdown(swProcessPool *pool)
{
	int i, ret;
	swoole_running = 0;
	for (i = 0; i < pool->worker_num; i++)
	{
		kill(pool->workers[i].pid, SIGTERM);
		if (ret < 0)
		{
			swWarn("[Manager]kill fail.pid=%d. Error: %s [%d]", pool->workers[i].pid, strerror(errno), errno);
			continue;
		}
	}
	swProcessPool_free(pool);
}

pid_t swProcessPool_spawn(swProcessPool *pool, swWorker *worker)
{
	pid_t pid = fork();

	switch (pid)
	{
	//child
	case 0:
		exit(swProcessPool_worker_loop(pool, worker));
		break;
	case -1:
		swWarn("[swProcessPool_run] fork fail. Error: %s [%d]", strerror(errno), errno)
		;
		break;
		//parent
	default:
		worker->pid = pid;
		swHashMap_add_int(&pool->map, pid, worker);
		break;
	}
	return pid;
}

static int swProcessPool_worker_loop(swProcessPool *pool, swWorker *worker)
{
	swEventData buf;
	int n, ret;
	int task_n = pool->max_request;
	//使用from_fd保存task_worker的id
	buf.info.from_fd = worker->id;

	while (swoole_running > 0 && task_n > 0)
	{
		n = read(worker->pipe_worker, &buf, sizeof(buf));
		if (n < 0)
		{
			swWarn("[Worker#%d]read pipe fail. Error: %s [%d]", worker->id, strerror(errno), errno);
			continue;
		}
		ret = pool->onTask(pool, &buf);
		if (ret > 0)
		{
			task_n--;
		}
	}
	return SW_OK;
}

int swProcessPool_wait(swProcessPool *pool)
{
	int pid, new_pid;
	int i, writer_pti;
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
		if (swoole_running == 1)
		{
			swWorker *exit_worker = swHashMap_find_int(&pool->map, pid);
			if (exit_worker == NULL)
			{
				swWarn("[Manager]unknow worker[pid=%d]", pid);
			}
			new_pid = swProcessPool_spawn(pool, exit_worker);
			if (new_pid < 0)
			{
				swWarn("Fork worker process fail. Error: %s [%d]", strerror(errno), errno);
				return SW_ERR;
			}
			swHashMap_del_int(&pool->map, pid);
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
	swProcessPool_shutdown(pool);
	sw_free(pool->workers);
	swHashMap_free(&pool->map);
}
