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

static int swProcessPool_worker_start(swProcessPool *pool, swWorker *worker);
static void swProcessPool_free(swProcessPool *pool);

/**
 * Process manager
 */
int swProcessPool_create(swProcessPool *pool, int worker_num, int max_request, key_t msgqueue_key, int create_pipe)
{
    bzero(pool, sizeof(swProcessPool));

    pool->worker_num = worker_num;
    pool->max_request = max_request;

    if (msgqueue_key > 0)
    {
        pool->use_msgqueue = 1;
        pool->msgqueue_key = msgqueue_key;
    }
    
    pool->workers = SwooleG.memory_pool->alloc(SwooleG.memory_pool, worker_num * sizeof(swWorker));
    if (pool->workers == NULL)
    {
        swWarn("malloc[1] failed.");
        return SW_ERR;
    }

    pool->map = swHashMap_new(SW_HASHMAP_INIT_BUCKET_N, NULL);
    if (pool->map == NULL)
    {
        return SW_ERR;
    }

    int i;
    if (pool->use_msgqueue)
    {
        if (swQueueMsg_create(&pool->queue, 1, pool->msgqueue_key, 1) < 0)
        {
            return SW_ERR;
        }
    }
    else if (create_pipe)
    {
        pool->pipes = sw_calloc(worker_num, sizeof(swPipe));
        if (pool->pipes == NULL)
        {
            swWarn("malloc[2] failed.");
            sw_free(pool->workers);
            return SW_ERR;
        }

        swPipe *pipe;
        for (i = 0; i < worker_num; i++)
        {
            pipe = &pool->pipes[i];
            if (swPipeUnsock_create(pipe, 1, SOCK_DGRAM) < 0)
            {
                return SW_ERR;
            }

            pool->workers[i].pipe_master = pipe->getFd(pipe, SW_PIPE_MASTER);
            pool->workers[i].pipe_worker = pipe->getFd(pipe, SW_PIPE_WORKER);
            pool->workers[i].pipe_object = pipe;
            
        }
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
        pool->workers[i].pool = pool;
        pool->workers[i].id = pool->start_id + i;

        if (swProcessPool_spawn(&(pool->workers[i])) < 0)
        {
            return SW_ERR;
        }
    }
    return SW_OK;
}

/**
 * dispatch data to worker
 */
int swProcessPool_dispatch(swProcessPool *pool, swEventData *data, int *dst_worker_id)
{
    int ret = 0;

    if (*dst_worker_id < 0)
    {
        int i, target_worker_id = pool->round_id;
        swWorker *worker;
        int task_worker_num = SwooleGS->task_num;  //TODO: pool->worker_num

        for (i = 0; i < task_worker_num; i++)
        {
            pool->round_id++;
            target_worker_id = pool->round_id % task_worker_num;

            worker = swProcessPool_get_worker(pool, *dst_worker_id);

            if (worker->status == SW_WORKER_IDLE)
            {
                break;
            }
        }
        *dst_worker_id = target_worker_id;
    }

    *dst_worker_id += pool->start_id;

    struct
    {
        long mtype;
        swEventData buf;
    } in;

    if (pool->use_msgqueue)
    {
        in.mtype = *dst_worker_id + 1;
        memcpy(&in.buf, data, sizeof(data->info) + data->info.len);
        ret = pool->queue.in(&pool->queue, (swQueue_data *) &in, sizeof(data->info) + data->info.len);
        if (ret < 0)
        {
            swSysError("msgsnd() failed.");
        }
    }
    else
    {
        swWorker *worker = swProcessPool_get_worker(pool, *dst_worker_id);
        if (SwooleG.main_reactor)
        {
            ret = SwooleG.main_reactor->write(SwooleG.main_reactor, worker->pipe_master, data,
                    sizeof(data->info) + data->info.len);
        }
        else
        {
            ret = swSocket_write_blocking(worker->pipe_master, data, sizeof(data->info) + data->info.len);
        }

        if (ret < 0)
        {
            swSysError("sendto unix socket failed.");
        }
        else
        {
            sw_atomic_fetch_add(&worker->tasking_num, 1);
        }
    }
    return ret;
}

void swProcessPool_shutdown(swProcessPool *pool)
{
    int i, status;
    swWorker *worker;
    SwooleG.running = 0;

    for (i = 0; i < SwooleGS->task_num; i++)
    {
        worker = &pool->workers[i];
        if (kill(worker->pid, SIGTERM) < 0)
        {
            swSysError("kill(%d) failed.", worker->pid);
            continue;
        }
        if (swWaitpid(worker->pid, &status, 0) < 0)
        {
            swSysError("waitpid(%d) failed.", worker->pid);
        }
    }
    swProcessPool_free(pool);
}

pid_t swProcessPool_spawn(swWorker *worker)
{
    pid_t pid = fork();
    swProcessPool *pool = worker->pool;

    struct passwd *passwd;
    struct group *group;
    int is_root = !geteuid();

    switch (pid)
    {
    //child
    case 0:
        /**
         * Process start
         */
        if(is_root) 
        {
            passwd = getpwnam(SwooleG.user);
            group  = getgrnam(SwooleG.group);

            if(passwd != NULL) 
            {
                if (0 > setuid(passwd->pw_uid)) 
                {
                    swWarn("setuid to %s fail \r\n", SwooleG.user);
                }
            }
            else
            {
                swWarn("get user %s info fail \r\n", SwooleG.user);
            }

            if(group != NULL) 
            {
                if(0 > setgid(group->gr_gid)) 
                {
                    swWarn("setgid to %s fail \r\n", SwooleG.group);
                }
            }
            else
            {
                swWarn("get group %s info fail \r\n", SwooleG.group);
            }
        }

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
        swWarn("fork() failed. Error: %s [%d]", strerror(errno), errno);
        break;
        //parent
    default:
        //remove old process
        if (worker->pid)
        {
            swHashMap_del_int(pool->map, worker->pid);
        }
        worker->del = 0;
        worker->pid = pid;
        //insert new process
        swHashMap_add_int(pool->map, pid, worker, NULL);
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

    if (SwooleG.task_dispatch_mode)
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
            if (n < 0 && errno != EINTR)
            {
                swSysError("[Worker#%d] msgrcv() failed.", worker->id);
            }
        }
        else
        {
            n = read(worker->pipe_worker, &out.buf, sizeof(out.buf));
            if (n < 0 && errno != EINTR)
            {
                swSysError("[Worker#%d] read(%d) failed.", worker->id, worker->pipe_worker);
            }
        }

        if (n < 0)
        {
            if (errno == EINTR && SwooleG.signal_alarm)
            {
                SwooleG.timer.select(&SwooleG.timer);
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
    worker->pool = pool;
    swHashMap_add_int(pool->map, worker->pid, worker, NULL);
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

    while (SwooleG.running)
    {
        pid = wait(NULL);
        if (pid < 0)
        {
            if (pool->reloading == 0)
            {
                swTrace("[Manager] wait failed. Error: %s [%d]", strerror(errno), errno);
            }
            else if (pool->reload_flag == 0)
            {
                swTrace("[Manager] reload workers.");
                memcpy(reload_workers, pool->workers, sizeof(swWorker) * pool->worker_num);
                pool->reload_flag = 1;
                goto reload_worker;
            }
            else if (SwooleG.running == 0)
            {
                break;
            }
        }
        swTrace("[Manager] worker stop.pid=%d", pid);
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
                swWarn("Fork worker process failed. Error: %s [%d]", strerror(errno), errno);
                return SW_ERR;
            }
            swHashMap_del_int(pool->map, pid);
        }
        //reload worker
        reload_worker:
        if (pool->reloading == 1)
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
                swSysError("[Manager]kill(%d) failed.", reload_workers[reload_worker_i].pid);
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
    swPipe *_pipe;

    if (!pool->use_msgqueue)
    {
        for (i = 0; i < pool->worker_num; i++)
        {
            _pipe = &pool->pipes[i];
            _pipe->close(_pipe);
        }
        sw_free(pool->pipes);
    }
    swHashMap_free(pool->map);
}
