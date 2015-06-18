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
#include <signal.h>
#include <sys/wait.h>
#include <sys/time.h>

typedef struct
{
    uint8_t reloading;
    uint8_t reload_event_worker;
    uint8_t reload_task_worker;

} swManagerProcess;

static int swFactoryProcess_start(swFactory *factory);
static int swFactoryProcess_notify(swFactory *factory, swDataHead *event);
static int swFactoryProcess_dispatch(swFactory *factory, swDispatchData *buf);
static int swFactoryProcess_finish(swFactory *factory, swSendData *data);
static int swFactoryProcess_shutdown(swFactory *factory);
static int swFactoryProcess_end(swFactory *factory, int fd);

static int swManager_loop(swFactory *factory);
static int swManager_start(swFactory *factory);
static void swManager_signal_handle(int sig);
static pid_t swManager_spawn_user_worker(swServer *serv, swWorker* worker);
static pid_t swManager_spawn_worker(swFactory *factory, int worker_id);
static void swManager_check_exit_status(swServer *serv, int worker_id, pid_t pid, int status);

static swManagerProcess ManagerProcess;

int swFactoryProcess_create(swFactory *factory, int worker_num)
{
    swFactoryProcess *object;
    object = SwooleG.memory_pool->alloc(SwooleG.memory_pool, sizeof(swFactoryProcess));
    if (object == NULL)
    {
        swWarn("[Master] malloc[object] failed");
        return SW_ERR;
    }

    factory->object = object;
    factory->dispatch = swFactoryProcess_dispatch;
    factory->finish = swFactoryProcess_finish;
    factory->start = swFactoryProcess_start;
    factory->notify = swFactoryProcess_notify;
    factory->shutdown = swFactoryProcess_shutdown;
    factory->end = swFactoryProcess_end;

    return SW_OK;
}

static int swFactoryProcess_shutdown(swFactory *factory)
{
    int status;

    if (kill(SwooleGS->manager_pid, SIGTERM) < 0)
    {
        swSysError("kill(%d) failed.", SwooleGS->manager_pid);
    }

    if (swWaitpid(SwooleGS->manager_pid, &status, 0) < 0)
    {
        swSysError("waitpid(%d) failed.", SwooleGS->manager_pid);
    }

    return SW_OK;
}

static int swFactoryProcess_start(swFactory *factory)
{
    int i;
    swServer *serv = factory->ptr;
    swWorker *worker;

    for (i = 0; i < serv->worker_num; i++)
    {
        worker = swServer_get_worker(serv, i);
        if (swWorker_create(worker) < 0)
        {
            return SW_ERR;
        }
    }

    serv->reactor_pipe_num = serv->worker_num / serv->reactor_num;

    //必须先启动manager进程组，否则会带线程fork
    if (swManager_start(factory) < 0)
    {
        swWarn("swFactoryProcess_manager_start failed.");
        return SW_ERR;
    }
    //主进程需要设置为直写模式
    factory->finish = swFactory_finish;
    return SW_OK;
}

//create worker child proccess
static int swManager_start(swFactory *factory)
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

/**
 * worker: send to client
 */
static int swFactoryProcess_finish(swFactory *factory, swSendData *resp)
{
    int ret, sendn;
    swServer *serv = factory->ptr;
    int fd = resp->info.fd;

    swConnection *conn = swServer_connection_verify(serv, fd);
    if (!conn)
    {
        swWarn("session#%d does not exist.", fd);
        return SW_ERR;
    }
    else if ((conn->closed || conn->removed) && resp->info.type != SW_EVENT_CLOSE)
    {
        int _len = resp->length > 0 ? resp->length : resp->info.len;
        swWarn("send %d byte failed, because session#%d is closed.", _len, fd);
        return SW_ERR;
    }
    else if (conn->overflow)
    {
        swWarn("send failed, session#%d output buffer has been overflowed.", fd);
        return SW_ERR;
    }

    swEventData ev_data;
    ev_data.info.fd = fd;
    ev_data.info.type = resp->info.type;
    swWorker *worker = swServer_get_worker(serv, SwooleWG.id);

    /**
     * Big response, use shared memory
     */
    if (resp->length > 0)
    {
        if (worker->send_shm == NULL)
        {
            swWarn("send failed, data is too big.");
            return SW_ERR;
        }

        swPackage_response response;

        worker->lock.lock(&worker->lock);

        response.length = resp->length;
        response.worker_id = SwooleWG.id;

        //swWarn("BigPackage, length=%d|worker_id=%d", response.length, response.worker_id);

        ev_data.info.from_fd = SW_RESPONSE_BIG;
        ev_data.info.len = sizeof(response);

        memcpy(ev_data.data, &response, sizeof(response));
        memcpy(worker->send_shm, resp->data, resp->length);
    }
    else
    {
        //copy data
        memcpy(ev_data.data, resp->data, resp->info.len);

        ev_data.info.len = resp->info.len;
        ev_data.info.from_fd = SW_RESPONSE_SMALL;
    }

    ev_data.info.from_id = conn->from_id;

    sendn = ev_data.info.len + sizeof(resp->info);
    swTrace("[Worker] send: sendn=%d|type=%d|content=%s", sendn, resp->info.type, resp->data);
    ret = swWorker_send2reactor(&ev_data, sendn, fd);
    if (ret < 0)
    {
        swWarn("sendto to reactor failed. Error: %s [%d]", strerror(errno), errno);
    }
    return ret;
}

static __thread struct
{
    long target_worker_id;
    swDataHead _send;
} sw_notify_data;

/**
 * [ReactorThread] notify info to worker process
 */
static int swFactoryProcess_notify(swFactory *factory, swDataHead *ev)
{
    memcpy(&sw_notify_data._send, ev, sizeof(swDataHead));
    sw_notify_data._send.len = 0;
    sw_notify_data.target_worker_id = -1;
    return factory->dispatch(factory, (swDispatchData *) &sw_notify_data);
}

/**
 * [ReactorThread] dispatch request to worker
 */
static int swFactoryProcess_dispatch(swFactory *factory, swDispatchData *task)
{
    uint32_t schedule_key;
    uint32_t send_len = sizeof(task->data.info) + task->data.info.len;
    uint16_t target_worker_id;
    swServer *serv = SwooleG.serv;

    if (task->target_worker_id < 0)
    {
        //udp use remote port
        if (swEventData_is_dgram(task->data.info.type))
        {
            if (serv->dispatch_mode == SW_DISPATCH_IPMOD || serv->dispatch_mode == SW_DISPATCH_UIDMOD)
            {
                schedule_key = task->data.info.fd;
            }
            else
            {
                schedule_key = task->data.info.from_id;
            }
        }
        else
        {
            schedule_key = task->data.info.fd;
        }

#ifndef SW_USE_RINGBUFFER
        if (SwooleTG.factory_lock_target)
        {
            if (SwooleTG.factory_target_worker < 0)
            {
                target_worker_id = swServer_worker_schedule(serv, schedule_key);
                SwooleTG.factory_target_worker = target_worker_id;
            }
            else
            {
                target_worker_id = SwooleTG.factory_target_worker;
            }
        }
        else
#endif
        {
            target_worker_id = swServer_worker_schedule(serv, schedule_key);
        }
    }
    else
    {
        target_worker_id = task->target_worker_id;
    }

    if (swEventData_is_stream(task->data.info.type))
    {
        swConnection *conn = swServer_connection_get(serv, task->data.info.fd);
        if (conn == NULL || conn->active == 0)
        {
            swWarn("dispatch[type=%d] failed, connection#%d is not active.", task->data.info.type, task->data.info.fd);
            return SW_ERR;
        }
        //server active close, discard data.
        if (conn->closed)
        {
            if (!(task->data.info.type == SW_EVENT_CLOSE && conn->close_force))
            {
                swWarn("dispatch[type=%d] failed, connection#%d[session_id=%d] is closed by server.",
                        task->data.info.type, task->data.info.fd, conn->session_id);
                return SW_OK;
            }
        }
        //converted fd to session_id
        task->data.info.fd = conn->session_id;
    }

    return swReactorThread_send2worker((void *) &(task->data), send_len, target_worker_id);
}

static int swFactoryProcess_end(swFactory *factory, int fd)
{
    swServer *serv = factory->ptr;
    swSendData _send;

    bzero(&_send, sizeof(_send));
    _send.info.fd = fd;
    _send.info.len = 0;
    _send.info.type = SW_EVENT_CLOSE;

    swConnection *conn = swWorker_get_connection(serv, fd);
    if (conn == NULL || conn->active == 0)
    {
        //swWarn("can not close. Connection[%d] not found.", _send.info.fd);
        return SW_ERR;
    }
    else if (conn->close_force)
    {
        goto do_close;
    }
    else if (conn->closing)
    {
        swWarn("The connection[%d] is closing.", fd);
        return SW_ERR;
    }
    else if (conn->closed)
    {
        return SW_ERR;
    }
    else
    {
        do_close:
        conn->closing = 1;
        if (serv->onClose != NULL)
        {
            serv->onClose(serv, fd, conn->from_id);
        }
        conn->closing = 0;
        conn->closed = 1;
        return factory->finish(factory, &_send);
    }
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
