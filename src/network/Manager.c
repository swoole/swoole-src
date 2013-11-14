#include "swoole.h"

static int swManager_main_loop(swManager *ma);
static pid_t swManager_spawn(swManager *ma, swWorker *worker);
static void swManager_free(swManager *ma);

/**
 * Process manager
 */
int swManager_create(swManager *ma, int max_num)
{
	bzero(ma, sizeof(swManager));
	ma->workers = sw_calloc(max_num, sizeof(swWorker));
	ma->max_num = max_num;
	if (ma->workers == NULL)
	{
		swWarn("[swManager_create] malloc fail.");
		return SW_ERR;
	}
	return SW_OK;
}

int swManager_add_worker(swManager *ma, swWorkerCall cb)
{
	swPipe pipe;
	if (ma->worker_num >= ma->max_num)
	{
		swWarn("[swManager_create] too many worker[max_num=%d]", ma->max_num);
		return SW_ERR;
	}
	int cur_id = ma->worker_num++;

	swManager_worker(ma, cur_id).call = cb;
	if (swPipeUnsock_create(&pipe, 1, SOCK_STREAM) < 0)
	{
		return SW_ERR;
	}
	swManager_worker(ma, cur_id).pipe_master = pipe.getFd(&pipe, 1);
	swManager_worker(ma, cur_id).pipe_worker = pipe.getFd(&pipe, 0);
	swManager_worker(ma, cur_id).id = cur_id;
	return cur_id;
}

int swManager_run(swManager *ma)
{
	int i;
	for (i = 0; i < ma->worker_num; i++)
	{
		swManager_spawn(ma, &(ma->workers[i]));
	}
	return swManager_main_loop(ma);
}

void swManager_shutdown(swManager *ma)
{
	int i, ret;
	swoole_running = 0;
	for (i = 0; i < ma->worker_num; i++)
	{
		kill(ma->workers[i].pid, SIGTERM);
		if (ret < 0)
		{
			swWarn("[Manager]kill fail.pid=%d. Error: %s [%d]", ma->workers[i].pid, strerror(errno), errno);
			continue;
		}
	}
	swManager_free(ma);
}

static pid_t swManager_spawn(swManager *ma, swWorker *worker)
{
	pid_t pid = fork();
	switch (pid)
	{
	//child
	case 0:
		worker->call(worker);
		exit(0);
		break;
	case -1:
		swWarn("[swManager_run] fork fail. Error: %s [%d]", strerror(errno), errno)
		;
		break;
		//parent
	default:
		worker->pid = pid;
		swHashMap_add_int(&ma->map, pid, worker);
		break;
	}
	return pid;
}

static int swManager_main_loop(swManager *ma)
{
	int pid, new_pid;
	int i, writer_pti;
	int reload_worker_i = 0;
	int ret;

	swWorker *reload_workers;
	reload_workers = sw_calloc(ma->worker_num, sizeof(swWorker));
	if (reload_workers == NULL)
	{
		swError("[manager] malloc[reload_workers] fail.\n");
		return SW_ERR;
	}

	while (1)
	{
		pid = wait(NULL);exit(0);
		swTrace("[manager] worker stop.pid=%d\n", pid);
		if (pid < 0)
		{
			if (ma->reloading == 0)
			{
				swTrace("[Manager] wait fail. Error: %s [%d]", strerror(errno), errno);
			}
			else if (ma->reload_flag == 0)
			{
				memcpy(reload_workers, ma->workers, sizeof(swWorker) * ma->worker_num);
				ma->reload_flag = 1;
				goto reload_worker;
			}
		}
		if (swoole_running == 1)
		{
			swWorker *exit_worker = swHashMap_find_int(&ma->map, pid);
			if (exit_worker == NULL)
			{
				swWarn("[Manager]unknow worker[pid=%d]", pid);
			}
			new_pid = swManager_spawn(ma, exit_worker);
			if (new_pid < 0)
			{
				swWarn("Fork worker process fail. Error: %s [%d]", strerror(errno), errno);
				return SW_ERR;
			}
			swHashMap_del_int(&ma->map, pid);
		}
		//reload worker
		reload_worker: if (ma->reloading == 1)
		{
			//reload finish
			if (reload_worker_i >= ma->worker_num)
			{
				ma->reloading = 0;
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

static void swManager_free(swManager *ma)
{
	swManager_shutdown(ma);
	sw_free(ma->workers);
	swHashMap_free(&ma->map);
}
