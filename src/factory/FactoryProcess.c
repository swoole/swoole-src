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

static int swFactoryProcess_writer_start(swFactory *factory);
static int swFactoryProcess_writer_loop_queue(swThreadParam *param);

static int swFactoryProcess_notify(swFactory *factory, swDataHead *event);
static int swFactoryProcess_dispatch(swFactory *factory, swDispatchData *buf);
static int swFactoryProcess_finish(swFactory *factory, swSendData *data);

static void swManager_signal_handle(int sig);
static pid_t swManager_create_user_worker(swServer *serv, swWorker* worker);

static swManagerProcess ManagerProcess;

int swFactoryProcess_create(swFactory *factory, int writer_num, int worker_num)
{
    swFactoryProcess *object;
    swServer *serv = SwooleG.serv;
    object = SwooleG.memory_pool->alloc(SwooleG.memory_pool, sizeof(swFactoryProcess));
    if (object == NULL)
    {
        swWarn("[Master] malloc[object] failed");
        return SW_ERR;
    }
    serv->writer_threads = SwooleG.memory_pool->alloc(SwooleG.memory_pool, serv->reactor_num * sizeof(swWorkerThread));
    if (serv->writer_threads == NULL)
    {
        swWarn("[Master] malloc[object->writers] failed");
        return SW_ERR;
    }
    object->writer_pti = 0;

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
    swServer *serv = SwooleG.serv;
    int status;

    if (kill(SwooleGS->manager_pid, SIGTERM) < 0)
    {
        swSysError("kill(%d) failed.", SwooleGS->manager_pid);
    }

    if (swWaitpid(SwooleGS->manager_pid, &status, 0) < 0)
    {
        swSysError("waitpid(%d) failed.", SwooleGS->manager_pid);
    }

    if (serv->ipc_mode == SW_IPC_MSGQUEUE)
    {
        swQueueMsg_set_destory(&serv->read_queue, 1);
        serv->read_queue.free(&serv->read_queue);

        swQueueMsg_set_destory(&serv->read_queue, 1);
        serv->write_queue.free(&serv->write_queue);
    }

    //close pipes
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

    if (serv->ipc_mode == SW_IPC_MSGQUEUE)
    {
        swQueueMsg_set_blocking(&serv->read_queue, 1);
        //tcp & message queue require writer pthread
        if (serv->have_tcp_sock == 1)
        {
            int ret = swFactoryProcess_writer_start(factory);
            if (ret < 0)
            {
                return SW_ERR;
            }
        }
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
    int reactor_pti;
    swServer *serv = factory->ptr;

    if (serv->ipc_mode == SW_IPC_MSGQUEUE)
    {
        //读数据队列
        if (swQueueMsg_create(&serv->read_queue, 1, serv->message_queue_key, 1) < 0)
        {
            swError("[Master] swPipeMsg_create[In] fail. Error: %s [%d]", strerror(errno), errno);
            return SW_ERR;
        }
        //为TCP创建写队列
        if (serv->have_tcp_sock == 1)
        {
            //写数据队列
            if (swQueueMsg_create(&serv->write_queue, 1, serv->message_queue_key + 1, 1) < 0)
            {
                swError("[Master] swPipeMsg_create[out] fail. Error: %s [%d]", strerror(errno), errno);
                return SW_ERR;
            }
        }
    }
    else
    {
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
            serv->workers[i].pipe_master = object->pipes[i].getFd(&object->pipes[i], 1);
            serv->workers[i].pipe_worker = object->pipes[i].getFd(&object->pipes[i], 0);
            serv->workers[i].pipe_object = &object->pipes[i];
            swServer_pipe_set(serv, i, serv->workers[i].pipe_object);
        }
    }

    if (SwooleG.task_worker_num > 0)
    {
        key_t key = 0;
        if (SwooleG.task_ipc_mode == SW_IPC_MSGQUEUE)
        {
            key = serv->message_queue_key + 2;
        }

        if (swProcessPool_create(&SwooleG.task_workers, SwooleG.task_worker_num, serv->task_max_request, key, 1) < 0)
        {
            swWarn("[Master] create task_workers failed.");
            return SW_ERR;
        }

        swTaskWorker_init(&SwooleG.task_workers);

        int worker_id;
        swWorker *worker;
        for (i = 0; i < SwooleG.task_worker_num; i++)
        {
            worker_id = serv->worker_num + i;
            worker = swServer_get_worker(serv, worker_id);
            if (swWorker_create(worker) < 0)
            {
                return SW_ERR;
            }
            swServer_pipe_set(serv, worker_id, worker->pipe_object);
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
            reactor_pti = (i % serv->writer_num);
            serv->workers[i].reactor_id = reactor_pti;
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
            swProcessPool_start(&SwooleG.task_workers);
        }

        /**
         * create user workers
         */
        if (serv->user_worker_list)
        {
            swUserWorker_node *user_worker;
            LL_FOREACH(serv->user_worker_list, user_worker)
            {
                swManager_create_user_worker(serv, user_worker->worker);
            }
        }

        //标识为管理进程
        SwooleG.process_type = SW_PROCESS_MANAGER;
        ret = swFactoryProcess_manager_loop(factory);
        exit(ret);
        break;
        //主进程
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
    switch (sig)
    {
    case SIGTERM:
        SwooleG.running = 0;
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
                    memcpy(reload_workers + serv->worker_num, SwooleG.task_workers.workers,
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
                memcpy(reload_workers, SwooleG.task_workers.workers, sizeof(swWorker) * SwooleG.task_worker_num);
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
                swWorker *exit_worker = swHashMap_find_int(SwooleG.task_workers.map, pid);
                if (exit_worker != NULL)
                {
                    swProcessPool_spawn(exit_worker);
                    goto kill_worker;
                }

                exit_worker = swHashMap_find_int(serv->user_worker_map, pid);
                if (exit_worker != NULL)
                {
                    swManager_create_user_worker(serv, exit_worker);
                    goto kill_worker;
                }
            }
        }
        //reload worker
        kill_worker:
        if (ManagerProcess.reloading == 1)
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
        swProcessPool_shutdown(&SwooleG.task_workers);
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

    pid = fork();
    if (pid < 0)
    {
        swWarn("Fork Worker failed. Error: %s [%d]", strerror(errno), errno);
        return SW_ERR;
    }
    //worker child processor
    else if (pid == 0)
    {
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

    swConnection *conn = swServer_connection_get(serv, _send.info.fd);
    if (conn == NULL || conn->active == 0)
    {
        //swWarn("can not close. Connection[%d] not found.", _send.info.fd);
        return SW_ERR;
    }
    else if (conn->active & SW_STATE_CLOSEING)
    {
        swWarn("The connection[%d] is closeing.", fd);
        return SW_ERR;
    }
    else if (conn->active & SW_STATE_CLOSED)
    {
        return SW_ERR;
    }
    else
    {
        if (serv->onClose != NULL)
        {
            serv->onClose(serv, fd, conn->from_id);
        }
        conn->active |= SW_STATE_CLOSED;
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
        len = sizeof(addr_un);
        ret = swSendto(from_sock, resp->data, resp->info.len, 0, (struct sockaddr *) &addr_un, len);
        goto finish;
    }
    //UDP pacakge
    else if (resp->info.type == SW_EVENT_UDP || resp->info.type == SW_EVENT_UDP6)
    {
        return swServer_udp_send(serv, resp);
    }

    //for message queue
    swEventData_overflow sdata;
    sdata.pti = (SwooleWG.id % serv->writer_num) + 1;

    swConnection *conn = swServer_connection_get(serv, fd);
    if (conn == NULL || conn->active == 0)
    {
        swWarn("connection[%d] not found.", fd);
        return SW_ERR;
    }

    sdata._send.info.fd = fd;
    sdata._send.info.type = resp->info.type;
    swWorker *worker = swServer_get_worker(serv, SwooleWG.id);

	/**
     * Big response, use shared memory
     */
    if (resp->length > 0)
    {
        swPackage_response response;

        worker->lock.lock(&worker->lock);

        response.length = resp->length;
        response.worker_id = SwooleWG.id;

        //swWarn("BigPackage, length=%d|worker_id=%d", response.length, response.worker_id);

        sdata._send.info.from_fd = SW_RESPONSE_BIG;
        sdata._send.info.len = sizeof(response);

        memcpy(sdata._send.data, &response, sizeof(response));
        memcpy(worker->send_shm, resp->data, resp->length);
    }
    else
    {
        //copy data
        memcpy(sdata._send.data, resp->data, resp->info.len);

        sdata._send.info.len = resp->info.len;
        sdata._send.info.from_fd = SW_RESPONSE_SMALL;
    }

#if SW_REACTOR_SCHEDULE == 2
    sdata._send.info.from_id = fd % serv->reactor_num;
#else
    sdata._send.info.from_id = conn->from_id;
#endif

    sendn = sdata._send.info.len + sizeof(resp->info);
    //swWarn("send: sendn=%d|type=%d|content=%s", sendn, resp->info.type, resp->data);
    swTrace("[Worker]input_queue[%ld]->in| fd=%d", sdata.pti, fd);

    ret = swWorker_send2reactor(&sdata, sendn, fd);

    finish:
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
        if (task->data.info.type == SW_EVENT_UDP || task->data.info.type == SW_EVENT_UDP6
                || task->data.info.type == SW_EVENT_UNIX_DGRAM)
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

    if (SwooleTG.type == SW_THREAD_REACTOR)
    {
        return swReactorThread_send2worker((void *) &(task->data), send_len, target_worker_id);
    }
    else
    {
        return swServer_send2worker_blocking(serv, (void *) &(task->data), send_len, target_worker_id);
    }
}

/**
 * for message queue
 */
static int swFactoryProcess_writer_start(swFactory *factory)
{
    swServer *serv = SwooleG.serv;
    swThreadParam *param;
    int i;
    pthread_t pidt;

    for (i = 0; i < serv->writer_num; i++)
    {
        param = sw_malloc(sizeof(swPipe));
        if (param == NULL)
        {
            swSysError("malloc failed.");
            return SW_ERR;
        }
        param->object = factory;
        param->pti = i;
        if (pthread_create(&pidt, NULL, (swThreadStartFunc) swFactoryProcess_writer_loop_queue, (void *) param) < 0)
        {
            swSysError("pthread_create() failed.");
            return SW_ERR;
        }
        pthread_detach(pidt);
        serv->writer_threads[i].ptid = pidt;
        SW_START_SLEEP;
    }
    return SW_OK;
}

/**
 * Use message queue ipc
 */
int swFactoryProcess_writer_loop_queue(swThreadParam *param)
{
    swEventData *resp;
    swServer *serv = SwooleG.serv;

    int pti = param->pti;
    swQueue_data sdata;
    //必须加1,msg_type必须不能为0
    sdata.mtype = pti + 1;

    swSignal_none();
    while (SwooleG.running > 0)
    {
        swTrace("[Writer]wt_queue[%ld]->out wait", sdata.mtype);
        if (serv->write_queue.out(&serv->write_queue, &sdata, sizeof(sdata.mdata)) < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            swSysError("[writer#%d]wt_queue->out() failed.", pti);
        }
        else
        {
            int ret;
            resp = (swEventData *) sdata.mdata;

            //close connection
            //TODO: thread safe, should close in reactor thread.
            if (resp->info.type == SW_EVENT_CLOSE)
            {
                close_fd:
                swServer_connection_close(SwooleG.serv, resp->info.fd);
                continue;
            }
            //sendfile
            else if (resp->info.type == SW_EVENT_SENDFILE)
            {
                ret = swSocket_sendfile_sync(resp->info.fd, resp->data, SW_WRITER_TIMEOUT);
            }
            //send data
            else
            {
                ret = swConnection_send_blocking(resp->info.fd, resp->data, resp->info.len, 1000 * SW_WRITER_TIMEOUT);
            }

            if (ret < 0)
            {
                switch (swConnection_error(errno))
                {
                case SW_ERROR:
                    swSysError("send to client[%d] failed.", resp->info.fd);
                    break;
                case SW_CLOSE:
                    goto close_fd;
                default:
                    break;
                }
            }
        }
    }
    pthread_exit((void *) param);
    return SW_OK;
}

