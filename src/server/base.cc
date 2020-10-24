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

#include "swoole_server.h"

using namespace swoole;

static int swFactory_start(Factory *factory);
static int swFactory_shutdown(Factory *factory);
static bool swFactory_dispatch(Factory *factory, SendData *req);
static bool swFactory_notify(Factory *factory, DataHead *event);
static bool swFactory_end(Factory *factory, SessionId session_id);
static void swFactory_free(Factory *factory);

int swFactory_create(Factory *factory) {
    factory->dispatch = swFactory_dispatch;
    factory->finish = swFactory_finish;
    factory->start = swFactory_start;
    factory->shutdown = swFactory_shutdown;
    factory->end = swFactory_end;
    factory->notify = swFactory_notify;
    factory->free = swFactory_free;

    return SW_OK;
}

static int swFactory_start(Factory *factory) {
    SwooleWG.run_always = true;
    return SW_OK;
}

static int swFactory_shutdown(Factory *factory) {
    return SW_OK;
}

static bool swFactory_dispatch(Factory *factory, SendData *task) {
    Server *serv = (Server *) factory->ptr;
    PacketPtr pkg;
    Connection *conn = nullptr;

    if (Server::is_stream_event(task->info.type)) {
        conn = serv->get_connection(task->info.fd);
        if (conn == nullptr || conn->active == 0) {
            swWarn("dispatch[type=%d] failed, socket#%ld is not active", task->info.type, task->info.fd);
            return false;
        }
        // server active close, discard data.
        if (conn->closed) {
            swWarn("dispatch[type=%d] failed, socket#%ld is closed by server", task->info.type, task->info.fd);
            return false;
        }
        // converted fd to session_id
        task->info.fd = conn->session_id;
        task->info.server_fd = conn->server_fd;
    }
    // with data
    if (task->info.len > 0) {
        memcpy(&pkg.info, &task->info, sizeof(pkg.info));
        pkg.info.flags = SW_EVENT_DATA_PTR;
        swString_clear(&pkg.data);
        pkg.data.length = task->info.len;
        pkg.data.str = (char *) task->data;

        if (conn && conn->socket->recv_buffer && task->data == conn->socket->recv_buffer->str &&
            conn->socket->recv_buffer->offset > 0 &&
            conn->socket->recv_buffer->length == (size_t) conn->socket->recv_buffer->offset) {
            pkg.info.flags |= SW_EVENT_DATA_POP_PTR;
        }

        return serv->accept_task((EventData *) &pkg) == SW_OK;
    }
    // no data
    else {
        return serv->accept_task((EventData *) &task->info) == SW_OK;
    }
}

/**
 * only stream fd
 */
static bool swFactory_notify(Factory *factory, DataHead *info) {
    Server *serv = (Server *) factory->ptr;
    Connection *conn = serv->get_connection(info->fd);
    if (conn == nullptr || conn->active == 0) {
        swWarn("dispatch[type=%d] failed, socket#%ld is not active", info->type, info->fd);
        return false;
    }
    // server active close, discard data.
    if (conn->closed) {
        swWarn("dispatch[type=%d] failed, session#%ld is closed by server", info->type, conn->session_id);
        return false;
    }
    // converted fd to session_id
    info->fd = conn->session_id;
    info->server_fd = conn->server_fd;
    info->flags = SW_EVENT_DATA_NORMAL;

    return serv->accept_task((EventData *) info) == SW_OK;
}

static bool swFactory_end(Factory *factory, SessionId session_id) {
    Server *serv = (Server *) factory->ptr;
    SendData _send{};
    DataHead info;

    _send.info.fd = session_id;
    _send.info.len = 0;
    _send.info.type = SW_SERVER_EVENT_CLOSE;

    Connection *conn = serv->get_connection_by_session_id(session_id);
    if (conn == nullptr || conn->active == 0) {
        swoole_set_last_error(SW_ERROR_SESSION_NOT_EXIST);
        return false;
    } else if (conn->close_force) {
        goto _do_close;
    } else if (conn->closing) {
        swWarn("session#%ld is closing", session_id);
        return false;
    } else if (conn->closed) {
        return false;
    } else {
    _do_close:
        conn->closing = 1;
        if (serv->onClose != nullptr) {
            info.fd = session_id;
            if (conn->close_actively) {
                info.reactor_id = -1;
            } else {
                info.reactor_id = conn->reactor_id;
            }
            info.server_fd = conn->server_fd;
            serv->onClose(serv, &info);
        }
        conn->closing = 0;
        conn->closed = 1;
        conn->close_errno = 0;

        if (conn->socket == nullptr) {
            swWarn("session#%ld->socket is nullptr", session_id);
            return false;
        }

        if (Buffer::empty(conn->socket->out_buffer) || conn->peer_closed || conn->close_force) {
            Reactor *reactor = SwooleTG.reactor;
            return Server::close_connection(reactor, conn->socket) == SW_OK;
        } else {
            BufferChunk *chunk = conn->socket->out_buffer->alloc(BufferChunk::TYPE_CLOSE, 0);
            chunk->value.data.val1 = _send.info.type;
            conn->close_queued = 1;
            return true;
        }
    }
}

/**
 * @return: success returns SW_OK, failure returns SW_ERR.
 */
bool swFactory_finish(Factory *factory, SendData *resp) {
    return ((Server *) factory->ptr)->send_to_connection(resp) == SW_OK;
}

static void swFactory_free(Factory *factory) {}
