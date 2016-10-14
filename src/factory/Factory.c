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

int swFactory_create(swFactory *factory)
{
    factory->dispatch = swFactory_dispatch;
    factory->finish = swFactory_finish;
    factory->start = swFactory_start;
    factory->shutdown = swFactory_shutdown;
    factory->end = swFactory_end;
    factory->notify = swFactory_notify;
    return SW_OK;
}

int swFactory_start(swFactory *factory)
{
    SwooleWG.run_always = 1;
    return SW_OK;
}

int swFactory_shutdown(swFactory *factory)
{
    return SW_OK;
}

int swFactory_dispatch(swFactory *factory, swDispatchData *task)
{
    swServer *serv = SwooleG.serv;
    factory->last_from_id = task->data.info.from_id;

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
            swWarn("dispatch[type=%d] failed, connection#%d is closed by server.", task->data.info.type,
                    task->data.info.fd);
            return SW_OK;
        }
        //converted fd to session_id
        task->data.info.fd = conn->session_id;
        task->data.info.from_fd = conn->from_fd;
    }
    return swWorker_onTask(factory, &task->data);
}

int swFactory_notify(swFactory *factory, swDataHead *info)
{
    swServer *serv = factory->ptr;
    swConnection *conn = swServer_connection_get(serv, info->fd);
    if (conn == NULL || conn->active == 0)
    {
        swWarn("dispatch[type=%d] failed, connection#%d is not active.", info->type, info->fd);
        return SW_ERR;
    }
    //server active close, discard data.
    if (conn->closed)
    {
        swWarn("dispatch[type=%d] failed, connection#%d is closed by server.", info->type, info->fd);
        return SW_OK;
    }
    //converted fd to session_id
    info->fd = conn->session_id;
    info->from_fd = conn->from_fd;
    return swWorker_onTask(factory, (swEventData *) info);
}

int swFactory_end(swFactory *factory, int fd)
{
    swServer *serv = factory->ptr;
    swSendData _send;
    swDataHead info;

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
            info.fd = fd;
            info.from_id =  conn->from_id;
            info.from_fd =  conn->from_fd;
            serv->onClose(serv, &info);
        }
        conn->closing = 0;
        conn->closed = 1;
        conn->close_errno = 0;

        if (swBuffer_empty(conn->out_buffer) || conn->removed)
        {
            swReactor *reactor = &serv->reactor_threads[SwooleTG.id].reactor;
            return swReactorThread_close(reactor, conn->fd);
        }
        else
        {
            swBuffer_trunk *trunk = swBuffer_new_trunk(conn->out_buffer, SW_CHUNK_CLOSE, 0);
            trunk->store.data.val1 = _send.info.type;
            return SW_OK;
        }
    }
}

int swFactory_finish(swFactory *factory, swSendData *resp)
{
    if (resp->length == 0)
    {
        resp->length = resp->info.len;
    }
    if (swReactorThread_send(resp) < 0)
    {
        swSysError("sendto to connection#%d failed.", resp->info.fd);
        return SW_ERR;
    }
    else
    {
        return SW_OK;
    }
}

