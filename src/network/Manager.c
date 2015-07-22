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
  | license@swoole.com so we can mail you a copy immediately.            |
  +----------------------------------------------------------------------+
  | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
  +----------------------------------------------------------------------+
*/

#include "swoole.h"
#include "Server.h"

#include <sys/wait.h>

typedef struct
{
    uint8_t reloading;
    uint8_t reload_event_worker;
    uint8_t reload_task_worker;

} swManagerProcess;

static int swManager_loop(swFactory *factory);
static void swManager_signal_handle(int sig);
static pid_t swManager_spawn_user_worker(swServer *serv, swWorker* worker);
static pid_t swManager_spawn_worker(swFactory *factory, int worker_id);
static void swManager_check_exit_status(swServer *serv, int worker_id, pid_t pid, int status);

static swManagerProcess ManagerProcess;

//create worker child proccess
int swManager_start(swFactory *factory)
{
    swFactoryProcess *object = factory->object;
    int i, ret;
    pid_t pid;
    swServer *serv = factory->ptr;

    object->pipes = sw_calloc(serv->worker_num, sizeof(swPipe));
    if (object->pipes == NULL)
    {
        swError("malloc[worker_pipes] failed. Error: %s [%d]", strerror(errno), errno);
        return SW_ERR;
    }

    //worker进程的pipes
    for (i = 0; i < serv->worker_num; i++)
    {
        if (swPipeUnsock_create(&object->pipes[i], 1, SOCK_DGRAM) < 0)
        {
            return SW_ERR;
        }
        serv->workers[i].pipe_master = object->pipes[i].getFd(&object->pipes[i], SW_PIPE_MASTER);
        serv->workers[i].pipe_worker = object->pipes[i].getFd(&object->pipes[i], SW_PIPE_WORKER);
        serv->workers[i].pipe_object = &object->pipes[i];
        swServer_pipe_set(serv, serv->workers[i].pipe_object);
    }

    if (SwooleG.task_worker_num > 0)
    {
        key_t key = 0;
        int create_pipe = 1;

        if (SwooleG.task_ipc_mode > SW_TASK_IPC_UNIXSOCK)
        {
            key = serv->message_queue_key + 2;
            create_pipe = 0;
        }

        //启动min个.此时的pool->worker_num相当于max
        int task_num = SwooleG.task_worker_max > 0 ? SwooleG.task_worker_max : SwooleG.task_worker_num;

        if (swProcessPool_create(&SwooleGS->task_workers, task_num, SwooleG.task_max_request, key, create_pipe) < 0)
        {
            swWarn("[Master] create task_workers failed.");
            return SW_ERR;
        }

        swProcessPool *pool = &SwooleGS->task_workers;
        swTaskWorker_init(pool);

        int i;
        swWorker *worker;
        for (i = 0; i < task_num; i++)
        {
            worker = &pool->workers[i];
            if (swWorker_create(worker) < 0)
            {
                return SW_ERR;
            }
            if (SwooleG.task_ipc_mode == SW_IPC_UNSOCK)
            {
                swServer_pipe_set(SwooleG.serv, worker->pipe_object);
            }
        }
    }

    pid = fork();
    switch (pid)
    {
    //创建manager进程
    case 0:
        //wait master process
        SW_START_SLEEP;
        if (SwooleGS->start == 0)
        {
            return SW_OK;
        }
        /**
         * create worker process
         */
        for (i = 0; i < serv->worker_num; i++)
        {
            //close(worker_pipes[i].pipes[0]);
            pid = swManager_spawn_worker(factory, i);
            if (pid < 0)
            {
                swError("fork() failed.");
                return SW_ERR;
            }
            else
            {
                serv->workers[i].pid = pid;
            }
        }

        /**
         * create task worker process
         */
        if (SwooleG.task_worker_num > 0)
        {
            swProcessPool_start(&SwooleGS->task_workers);
        }

        /**
         * create user worker process
         */
        if (serv->user_worker_list)
        {
            swUserWorker_node *user_worker;
            LL_FOREACH(serv->user_worker_list, user_worker)
            {
                /**
                 * store the pipe object
                 */
                if (user_worker->worker->pipe_object)
                {
                    swServer_pipe_set(serv, user_worker->worker->pipe_object);
                }
                swManager_spawn_user_worker(serv, user_worker->worker);
            }
        }

        //标识为管理进程
        SwooleG.process_type = SW_PROCESS_MANAGER;
        SwooleG.pid = getpid();

        ret = swManager_loop(factory);
        exit(ret);
        break;

        //master process
    default:
        SwooleGS->manager_pid = pid;
        break;
    case -1:
        swError("fork() failed.");
        return SW_ERR;
    }
    return SW_OK;
}

static void swManager_check_exit_status(swServer *serv, int worker_id, pid_t pid, int status)
{
    if (!WIFEXITED(status))
    {
        swWarn("worker#%d abnormal exit, status=%d, signal=%d", worker_id, WEXITSTATUS(status), WTERMSIG(status));

        if (serv->onWorkerError != NULL)
        {
            serv->onWorkerError(serv, worker_id, pid, WEXITSTATUS(status));
        }
    }
}

static int swManager_loop(swFactory *factory)
{
    int pid, new_pid;
    int i;
    int reload_worker_i = 0;
    int reload_worker_num;
    int ret;
    int status;

    SwooleG.use_signalfd = 0;
    SwooleG.use_timerfd = 0;

    memset(&ManagerProcess, 0, sizeof(ManagerProcess));

    swServer *serv = factory->ptr;
    swWorker *reload_workers;

    if (serv->onManagerStart)
    {
        serv->onManagerStart(serv);
    }

    reload_worker_num = serv->worker_num + SwooleG.task_worker_num;
    reload_workers = sw_calloc(reload_worker_num, sizeof(swWorker));
    if (reload_workers == NULL)
    {
        swError("malloc[reload_workers] failed");
        return SW_ERR;
    }

    //for reload
    swSignal_add(SIGHUP, NULL);
    swSignal_add(SIGTERM, swManager_signal_handle);
    swSignal_add(SIGUSR1, swManager_signal_handle);
    swSignal_add(SIGUSR2, swManager_signal_handle);
    //swSignal_add(SIGINT, swManager_signal_handle);

    //for add/recycle task process
    if (SwooleG.task_worker_max > 0)
    {
        swSignal_add(SIGALRM, swManager_signal_handle);
        alarm(1);
    }

    while (SwooleG.running > 0)
    {
        pid = wait(&status);

        if (pid < 0)
        {
            if (ManagerProcess.reloading == 0)
            {
                swTrace("wait() failed. Error: %s [%d]", strerror(errno), errno);
            }
            else if (ManagerProcess.reload_event_worker == 1)
            {
                memcpy(reload_workers, serv->workers, sizeof(swWorker) * serv->worker_num);
                reload_worker_num = serv->worker_num;
                if (SwooleG.task_worker_num > 0)
                {
                    memcpy(reload_workers + serv->worker_num, SwooleGS->task_workers.workers,
                            sizeof(swWorker) * SwooleG.task_worker_num);
                    reload_worker_num += SwooleG.task_worker_num;
                }
                reload_worker_i = 0;
                ManagerProcess.reload_event_worker = 0;
                goto kill_worker;
            }
            else if (ManagerProcess.reload_task_worker == 1)
            {
                if (SwooleG.task_worker_num == 0)
                {
                    swWarn("cannot reload workers, because server no have task workers.");
                    continue;
                }
                memcpy(reload_workers, SwooleGS->task_workers.workers, sizeof(swWorker) * SwooleG.task_worker_num);
                reload_worker_num = SwooleG.task_worker_num;
                reload_worker_i = 0;
                ManagerProcess.reload_task_worker = 0;
                goto kill_worker;
            }
        }
        if (SwooleG.running == 1)
        {
            for (i = 0; i < serv->worker_num; i++)
            {
                //compare PID
                if (pid != serv->workers[i].pid)
                {
                    continue;
                }
                else
                {
                    swManager_check_exit_status(serv, i, pid, status);
                    pid = 0;
                    while (1)
                    {
                        new_pid = swManager_spawn_worker(factory, i);
                        if (new_pid < 0)
                        {
                            usleep(100000);
                            continue;
                        }
                        else
                        {
                            serv->workers[i].pid = new_pid;
                            break;
                        }
                    }
                }
            }

            if (pid > 0)
            {
                swWorker *exit_worker;
                //task worker
                if (SwooleGS->task_workers.map)
                {
                    exit_worker = swHashMap_find_int(SwooleGS->task_workers.map, pid);
                    if (exit_worker != NULL)
                    {
                        swManager_check_exit_status(serv, exit_worker->id, pid, status);
                        if (exit_worker->deleted == 1)  //主动回收不重启
                        {
                            exit_worker->deleted = 0;
                        }
                        else
                        {
                            swProcessPool_spawn(exit_worker);
                            goto kill_worker;
                        }
                    }
                }
                //user process
                if (serv->user_worker_map != NULL)
                {
                    exit_worker = swHashMap_find_int(serv->user_worker_map, pid);
                    if (exit_worker != NULL)
                    {
                        swManager_spawn_user_worker(serv, exit_worker);
                        goto kill_worker;
                    }
                }
            }
        }
        //reload worker
        kill_worker: if (ManagerProcess.reloading == 1)
        {
            //reload finish
            if (reload_worker_i >= reload_worker_num)
            {
                ManagerProcess.reloading = 0;
                reload_worker_i = 0;
                continue;
            }
            ret = kill(reload_workers[reload_worker_i].pid, SIGTERM);
            if (ret < 0)
            {
                swSysError("kill(%d, SIGTERM) failed.", reload_workers[reload_worker_i].pid);
            }
            reload_worker_i++;
        }
    }

    sw_free(reload_workers);

    //kill all child process
    for (i = 0; i < serv->worker_num; i++)
    {
        swTrace("[Manager]kill worker processor");
        kill(serv->workers[i].pid, SIGTERM);
    }

    //wait child process
    for (i = 0; i < serv->worker_num; i++)
    {
        if (swWaitpid(serv->workers[i].pid, &status, 0) < 0)
        {
            swSysError("waitpid(%d) failed.", serv->workers[i].pid);
        }
    }

    //kill and wait task process
    if (SwooleG.task_worker_num > 0)
    {
        swProcessPool_shutdown(&SwooleGS->task_workers);
    }

    if (serv->user_worker_map)
    {
        swWorker* user_worker;
        uint64_t key;

        //kill user process
        while (1)
        {
            user_worker = swHashMap_each_int(serv->user_worker_map, &key);
            //hashmap empty
            if (user_worker == NULL)
            {
                break;
            }
            kill(user_worker->pid, SIGTERM);
        }

        //wait user process
        while (1)
        {
            user_worker = swHashMap_each_int(serv->user_worker_map, &key);
            //hashmap empty
            if (user_worker == NULL)
            {
                break;
            }
            if (swWaitpid(user_worker->pid, &status, 0) < 0)
            {
                swSysError("waitpid(%d) failed.", serv->workers[i].pid);
            }
        }
    }

    if (serv->onManagerStop)
    {
        serv->onManagerStop(serv);
    }

    return SW_OK;
}

static pid_t swManager_spawn_worker(swFactory *factory, int worker_id)
{
    pid_t pid;
    int ret;

    pid = fork();

    //fork() failed
    if (pid < 0)
    {
        swWarn("Fork Worker failed. Error: %s [%d]", strerror(errno), errno);
        return SW_ERR;
    }
    //worker child processor
    else if (pid == 0)
    {
        ret = swWorker_loop(factory, worker_id);
        exit(ret);
    }
    //parent,add to writer
    else
    {
        return pid;
    }
}

static void swManager_signal_handle(int sig)
{
    swProcessPool *pool = &(SwooleGS->task_workers);
    swWorker *worker = NULL;
    int i = 0, ret, over_load_num = 0, zero_load_num = 0;

    switch (sig)
    {
    case SIGTERM:
        SwooleG.running = 0;
        break;
    case SIGALRM:
        worker = &(pool->workers[pool->run_worker_num]);
        if (worker->deleted == 1 && worker->tasking_num == 0)
        {
            ret = kill(worker->pid, SIGTERM);
            if (ret < 0)
            {
                swWarn("[Manager]kill fail.pid=%d. Error: %s [%d]", worker->pid, strerror(errno), errno);
            }
            alarm(1);
            break;
        }

        for (i = 0; i < pool->run_worker_num; i++)
        {
            worker = &(pool->workers[i]);

            if (worker->tasking_num >= 1)  //todo support config
            {
                over_load_num++;
            }
            else  // == 0
            {
                zero_load_num++;
            }
        }

        if (over_load_num > pool->run_worker_num / 2 && pool->run_worker_num < SwooleG.task_worker_max)
        {
            if (swProcessPool_spawn(&(pool->workers[pool->run_worker_num])) < 0)
            {
                swWarn("swProcessPool_spawn fail");
            }
            else
            {
                pool->run_worker_num++;
            }
        }
        else if (zero_load_num >= SwooleG.task_worker_num && pool->run_worker_num > SwooleG.task_worker_num)
        {
            SwooleG.task_recycle_num++;
            if (SwooleG.task_recycle_num > 3)
            {
                pool->run_worker_num--;
                worker = &(pool->workers[pool->run_worker_num]);
                worker->deleted = 1;
                SwooleG.task_recycle_num = 0;
            }
        }
        alarm(1);
        break;
        /**
         * reload all workers
         */
    case SIGUSR1:
        if (ManagerProcess.reloading == 0)
        {
            ManagerProcess.reloading = 1;
            ManagerProcess.reload_event_worker = 1;
        }
        break;
        /**
         * only reload task workers
         */
    case SIGUSR2:
        if (ManagerProcess.reloading == 0)
        {
            ManagerProcess.reloading = 1;
            ManagerProcess.reload_task_worker = 1;
        }
        break;
    default:
        break;
    }
}

static pid_t swManager_spawn_user_worker(swServer *serv, swWorker* worker)
{
    pid_t pid = fork();

    if (pid < 0)
    {
        swWarn("Fork Worker failed. Error: %s [%d]", strerror(errno), errno);
        return SW_ERR;
    }
    //child
    else if (pid == 0)
    {
        SwooleWG.id = serv->worker_num + SwooleG.task_worker_num + worker->id;
        serv->onUserWorkerStart(serv, worker);
        exit(0);
    }
    //parent
    else
    {
        if (worker->pid)
        {
            swHashMap_del_int(serv->user_worker_map, worker->pid);
        }
        worker->pid = pid;
        swHashMap_add_int(serv->user_worker_map, pid, worker, NULL);
        return pid;
    }
}
