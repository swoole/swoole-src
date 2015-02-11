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

static int swFactoryProcess_manager_loop(swFactory *factory);
static int swFactoryProcess_manager_start(swFactory *factory);

static int swFactoryProcess_worker_spawn(swFactory *factory, int worker_pti);

static int swFactoryProcess_notify(swFactory *factory, swDataHead *event);
static int swFactoryProcess_dispatch(swFactory *factory, swDispatchData *buf);
static int swFactoryProcess_finish(swFactory *factory, swSendData *data);

static void swManager_signal_handle(int sig);
static pid_t swManager_create_user_worker(swServer *serv, swWorker* worker);

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
    factory->onTask = NULL;
    factory->onFinish = NULL;

    return SW_OK;
}

int swFactoryProcess_shutdown(swFactory *factory)
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

int swFactoryProcess_start(swFactory *factory)
{
    if (swFactory_check_callback(factory) < 0)
    {
        swWarn("swFactory_check_callback failed");
        return SW_ERR;
    }

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
    if (swFactoryProcess_manager_start(factory) < 0)
    {
        swWarn("swFactoryProcess_manager_start failed.");
        return SW_ERR;
    }
    //主进程需要设置为直写模式
    factory->finish = swFactory_finish;
    return SW_OK;
}

//create worker child proccess
static int swFactoryProcess_manager_start(swFactory *factory)
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
        if (SwooleG.task_ipc_mode == SW_IPC_MSGQUEUE)
        {
            key = serv->message_queue_key + 2;
        }

        int task_num = SwooleG.task_worker_max > 0 ? SwooleG.task_worker_max : SwooleG.task_worker_num;
        //启动min个.此时的pool->worker_num相当于max
        if (swProcessPool_create(&SwooleGS->task_workers, task_num, serv->task_max_request, key, 1) < 0)
        {
            swWarn("[Master] create task_workers failed.");
            return SW_ERR;
        }
        SwooleGS->task_workers.run_worker_num = SwooleG.task_worker_num;

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
            pid = swFactoryProcess_worker_spawn(factory, i);
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
                swManager_create_user_worker(serv, user_worker->worker);
            }
        }

        //标识为管理进程
        SwooleG.process_type = SW_PROCESS_MANAGER;
        SwooleG.pid = getpid();

        ret = swFactoryProcess_manager_loop(factory);
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

static pid_t swManager_create_user_worker(swServer *serv, swWorker* worker)
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

static int swFactoryProcess_manager_loop(swFactory *factory)
{
    int pid, new_pid;
    int i;
    int reload_worker_i = 0;
    int reload_worker_num;
    int ret;
    int worker_exit_code;

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
        pid = wait(&worker_exit_code);

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
                    swWarn("Cannot reload workers, because server no have task workers.");
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
                    if (serv->onWorkerError != NULL && WEXITSTATUS(worker_exit_code) > 0)
                    {
                        serv->onWorkerError(serv, i, pid, WEXITSTATUS(worker_exit_code));
                    }
                    pid = 0;
                    while (1)
                    {
                        new_pid = swFactoryProcess_worker_spawn(factory, i);
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

            //task worker
            if (pid > 0)
            {
                swWorker *exit_worker = swHashMap_find_int(SwooleGS->task_workers.map, pid);

                if (exit_worker != NULL)
                {
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

                if (serv->user_worker_map != NULL)
                {
                    exit_worker = swHashMap_find_int(serv->user_worker_map, pid);
                    if (exit_worker != NULL)
                    {
                        swManager_create_user_worker(serv, exit_worker);
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
                swSysError("[Manager]kill(%d) failed.", reload_workers[reload_worker_i].pid);
                continue;
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

    if (SwooleG.task_worker_num > 0)
    {
        swProcessPool_shutdown(&SwooleGS->task_workers);
    }

    if (serv->onManagerStop)
    {
        serv->onManagerStop(serv);
    }
    return SW_OK;
}

static int swFactoryProcess_worker_spawn(swFactory *factory, int worker_pti)
{
    int pid, ret;
    struct passwd *passwd = NULL;
    struct group *group = NULL;
    int is_root = !geteuid();

    pid = fork();
    if (pid < 0)
    {
        swWarn("Fork Worker failed. Error: %s [%d]", strerror(errno), errno);
        return SW_ERR;
    }
    //worker child processor
    else if (pid == 0)
    {
        if (is_root)
        {

            if (SwooleG.chroot)
            {
                if(0 > chroot(SwooleG.chroot)) 
                {
                    swSysError("chroot to [%s] failed.", SwooleG.chroot);
                }
            }

            if (SwooleG.group)
            {
                group = getgrnam(SwooleG.group);
                if (group != NULL)
                {
                    if (setgid(group->gr_gid) < 0)
                    {
                        swSysError("setgid to [%s] failed.", SwooleG.group);
                    }
                }
                else
                {
                    swSysError("get group [%s] info failed.", SwooleG.group);
                }
            }

            if (SwooleG.user)
            {
                passwd = getpwnam(SwooleG.user);
                if (passwd != NULL)
                {
                    if (setuid(passwd->pw_uid) < 0)
                    {
                        swSysError("setuid to [%s] failed.", SwooleG.user);
                    }
                }
                else
                {
                    swSysError("get user [%s] info failed.", SwooleG.user);
                }
            }
        }
        ret = swWorker_loop(factory, worker_pti);
        exit(ret);
    }
    //parent,add to writer
    else
    {
        return pid;
    }
}

/**
 * Close the connection
 */
int swFactoryProcess_end(swFactory *factory, int fd)
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
        conn->closing = 1;
        if (serv->onClose != NULL)
        {
            serv->onClose(serv, fd, conn->from_id);
        }
        conn->closing = 0;

        do_close:
        conn->closed = 1;
        return swFactoryProcess_finish(factory, &_send);
    }
}

/**
 * worker: send to client
 */
int swFactoryProcess_finish(swFactory *factory, swSendData *resp)
{
    int ret, sendn;
    swServer *serv = factory->ptr;
    int fd = resp->info.fd;

    //unix dgram
    if (resp->info.type == SW_EVENT_UNIX_DGRAM)
    {
        socklen_t len;
        struct sockaddr_un addr_un;
        int from_sock = resp->info.from_fd;

        addr_un.sun_family = AF_UNIX;
        memcpy(addr_un.sun_path, resp->sun_path, resp->sun_path_len);
        addr_un.sun_path[resp->sun_path_len] = 0;
        len = sizeof(addr_un);
        return swSocket_sendto_blocking(from_sock, resp->data, resp->info.len, 0, (struct sockaddr *) &addr_un, len);
    }
    //UDP pacakge
    else if (resp->info.type == SW_EVENT_UDP || resp->info.type == SW_EVENT_UDP6)
    {
        return swServer_udp_send(serv, resp);
    }

    swConnection *conn = swWorker_get_connection(serv, fd);
    if (conn == NULL || conn->active == 0 || ((conn->closed || conn->removed) && resp->info.type != SW_EVENT_CLOSE))
    {
        swWarn("send failed, because connection[%d] has been closed.", fd);
        return SW_ERR;
    }
    else if (conn->overflow)
    {
        swWarn("send failed, connection[%d] output buffer has been overflowed.", fd);
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

#if SW_REACTOR_SCHEDULE == 2
    ev_data.info.from_id = fd % serv->reactor_num;
#else
    ev_data.info.from_id = conn->from_id;
#endif

    sendn = ev_data.info.len + sizeof(resp->info);
    //swWarn("send: sendn=%d|type=%d|content=%s", sendn, resp->info.type, resp->data);
    swTrace("[Worker]input_queue[%ld]->in| fd=%d", sdata.pti, fd);
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
 * 主进程通知worker进程
 */
int swFactoryProcess_notify(swFactory *factory, swDataHead *ev)
{
    memcpy(&sw_notify_data._send, ev, sizeof(swDataHead));
    sw_notify_data._send.len = 0;
    sw_notify_data.target_worker_id = -1;
    return factory->dispatch(factory, (swDispatchData *) &sw_notify_data);
}

/**
 * [ReactorThread] dispatch request to worker
 */
int swFactoryProcess_dispatch(swFactory *factory, swDispatchData *task)
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
            if (serv->dispatch_mode == SW_DISPATCH_IPMOD)
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

    if (!swEventData_is_dgram(task->data.info.type))
    {
        swConnection *conn = swServer_connection_get(serv, task->data.info.fd);
        if (conn == NULL || conn->active == 0)
        {
            swWarn("connection#%d is not active.", task->data.info.fd);
            return SW_ERR;
        }
        if (conn->closed)
        {
            swWarn("connection#%d is closed by server.", task->data.info.fd);
            return SW_OK;
        }
#ifdef SW_REACTOR_USE_SESSION
        task->data.info.fd = conn->session_id;
#endif
    }

    return swReactorThread_send2worker((void *) &(task->data), send_len, target_worker_id);
}

