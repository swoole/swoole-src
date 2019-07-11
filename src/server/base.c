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
#include "server.h"

static int swFactory_start(swFactory *factory);
static int swFactory_shutdown(swFactory *factory);
static int swFactory_dispatch(swFactory *factory, swSendData *req);
static int swFactory_notify(swFactory *factory, swDataHead *event);
static int swFactory_end(swFactory *factory, int fd);
static void swFactory_free(swFactory *factory);

int swFactory_create(swFactory *factory)
{
    factory->dispatch = swFactory_dispatch;
    factory->finish = swFactory_finish;
    factory->start = swFactory_start;
    factory->shutdown = swFactory_shutdown;
    factory->end = swFactory_end;
    factory->notify = swFactory_notify;
    factory->free = swFactory_free;

    return SW_OK;
}

static int swFactory_start(swFactory *factory)
{
    SwooleWG.run_always = 1;
    return SW_OK;
}

static int swFactory_shutdown(swFactory *factory)
{
    return SW_OK;
}

static int swFactory_dispatch(swFactory *factory, swSendData *task)
{
    swServer *serv = factory->ptr;
    swPacket_ptr pkg;

    if (swEventData_is_stream(task->info.type))
    {
        swConnection *conn = swServer_connection_get(serv, task->info.fd);
        if (conn == NULL || conn->active == 0)
        {
            swWarn("dispatch[type=%d] failed, connection#%d is not active", task->info.type, task->info.fd);
            return SW_ERR;
        }
        //server active close, discard data.
        if (conn->closed)
        {
            swWarn("dispatch[type=%d] failed, connection#%d is closed by server", task->info.type,
                    task->info.fd);
            return SW_OK;
        }
        //converted fd to session_id
        task->info.fd = conn->session_id;
        task->info.server_fd = conn->server_fd;
    }
    //with data
    if (task->info.len > 0)
    {
        memcpy(&pkg.info, &task->info, sizeof(pkg.info));
        pkg.info.flags = SW_EVENT_DATA_PTR;
        bzero(&pkg.data, sizeof(pkg.data));
        pkg.data.length = task->info.len;
        pkg.data.str = task->data;

        return swWorker_onTask(factory, (swEventData*) &pkg);
    }
    //no data
    else
    {
        return swWorker_onTask(factory, (swEventData*) &task->info);
    }
}

/**
 * only stream fd
 */
static int swFactory_notify(swFactory *factory, swDataHead *info)
{
    swServer *serv = factory->ptr;
    swConnection *conn = swServer_connection_get(serv, info->fd);
    if (conn == NULL || conn->active == 0)
    {
        swWarn("dispatch[type=%d] failed, connection#%d is not active", info->type, info->fd);
        return SW_ERR;
    }
    //server active close, discard data.
    if (conn->closed)
    {
        swWarn("dispatch[type=%d] failed, connection#%d is closed by server", info->type, info->fd);
        return SW_OK;
    }
    //converted fd to session_id
    info->fd = conn->session_id;
    info->server_fd = conn->server_fd;
    info->flags = SW_EVENT_DATA_NORMAL;
    return swWorker_onTask(factory, (swEventData *) info);
}

static int swFactory_end(swFactory *factory, int fd)
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
        //swWarn("can not close. Connection[%d] not found", _send.info.fd);
        return SW_ERR;
    }
    else if (conn->close_force)
    {
        goto _do_close;
    }
    else if (conn->closing)
    {
        swWarn("The connection[%d] is closing", fd);
        return SW_ERR;
    }
    else if (conn->closed)
    {
        return SW_ERR;
    }
    else
    {
        _do_close:
        conn->closing = 1;
        if (serv->onClose != NULL)
        {
            info.fd = fd;
            if (conn->close_actively)
            {
                info.reactor_id = -1;
            }
            else
            {
                info.reactor_id = conn->reactor_id;
            }
            info.server_fd = conn->server_fd;
            serv->onClose(serv, &info);
        }
        conn->closing = 0;
        conn->closed = 1;
        conn->close_errno = 0;

        if (swBuffer_empty(conn->out_buffer) || conn->removed)
        {
            swReactor *reactor = SwooleG.main_reactor;
            return swReactorThread_close(reactor, conn->fd);
        }
        else
        {
            swBuffer_chunk *chunk = swBuffer_new_chunk(conn->out_buffer, SW_CHUNK_CLOSE, 0);
            chunk->store.data.val1 = _send.info.type;
            conn->close_queued = 1;
            return SW_OK;
        }
    }
}

int swFactory_finish(swFactory *factory, swSendData *resp)
{
    if (swServer_master_send(factory->ptr, resp) < 0)
    {
        return SW_ERR;
    }
    else
    {
        return SW_OK;
    }
}

static void swFactory_free(swFactory *factory)
{

}
