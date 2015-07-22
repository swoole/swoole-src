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
#include <sys/time.h>

static int swFactoryProcess_start(swFactory *factory);
static int swFactoryProcess_notify(swFactory *factory, swDataHead *event);
static int swFactoryProcess_dispatch(swFactory *factory, swDispatchData *buf);
static int swFactoryProcess_finish(swFactory *factory, swSendData *data);
static int swFactoryProcess_shutdown(swFactory *factory);
static int swFactoryProcess_end(swFactory *factory, int fd);

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

    if (swKill(SwooleGS->manager_pid, SIGTERM) < 0)
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
