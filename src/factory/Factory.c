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

int swFactory_create(swFactory *factory)
{
    factory->dispatch = swFactory_dispatch;
    factory->finish = swFactory_finish;
    factory->start = swFactory_start;
    factory->shutdown = swFactory_shutdown;
    factory->end = swFactory_end;
    factory->notify = swFactory_notify;

    factory->onTask = NULL;
    factory->onFinish = NULL;

    return SW_OK;
}

int swFactory_start(swFactory *factory)
{
    return SW_OK;
}

int swFactory_shutdown(swFactory *factory)
{
    return SW_OK;
}

int swFactory_dispatch(swFactory *factory, swDispatchData *task)
{
    swTrace("New Task:%s\n", task->data);
    factory->last_from_id = task->data.info.from_id;
    return factory->onTask(factory, &(task->data));
}

int swFactory_notify(swFactory *factory, swEvent *req)
{
    swServer *serv = factory->ptr;
    switch (req->type)
    {
    case SW_EVENT_CLOSE:
        serv->onClose(serv, req->fd, req->from_id);
        break;
    case SW_EVENT_CONNECT:
        serv->onConnect(serv, req->fd, req->from_id);
        break;
    default:
        swWarn("Error event[type=%d]", (int)req->type);
        break;
    }
    return SW_OK;
}

int swFactory_end(swFactory *factory, swEvent *event)
{
    swServer *serv = factory->ptr;
    if (serv->onClose != NULL)
    {
        serv->onClose(serv, event->fd, event->from_id);
    }
    return swServer_close(serv, event);
}

int swFactory_finish(swFactory *factory, swSendData *resp)
{
    int ret;
    swServer *serv = SwooleG.serv;

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
        ret = swServer_udp_send(serv, resp);
        goto finish;
    }
    else
    {
        resp->length = resp->info.len;
        swReactorThread_send(resp);
    }

    finish:
    if (ret < 0)
    {
        swWarn("sendto to reactor failed. Error: %s [%d]", strerror(errno), errno);
    }
    return ret;
}

int swFactory_check_callback(swFactory *factory)
{
    if (factory->onTask == NULL)
    {
        return SW_ERR;
    }
    if (factory->onFinish == NULL)
    {
        return SW_ERR;
    }
    return SW_OK;
}
