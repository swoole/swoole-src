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

namespace swoole {

bool BaseFactory::start() {
    SwooleWG.run_always = true;
    return true;
}

bool BaseFactory::shutdown() {
    return true;
}

bool BaseFactory::dispatch(SendData *task) {
    PacketPtr pkg{};
    Connection *conn = nullptr;

    if (Server::is_stream_event(task->info.type)) {
        conn = server_->get_connection(task->info.fd);
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
        pkg.data.length = task->info.len;
        pkg.data.str = (char *) task->data;

        if (conn && conn->socket->recv_buffer && task->data == conn->socket->recv_buffer->str &&
            conn->socket->recv_buffer->offset > 0 &&
            conn->socket->recv_buffer->length == (size_t) conn->socket->recv_buffer->offset) {
            pkg.info.flags |= SW_EVENT_DATA_POP_PTR;
        }

        return server_->accept_task((EventData *) &pkg) == SW_OK;
    }
    // no data
    else {
        return server_->accept_task((EventData *) &task->info) == SW_OK;
    }
}

/**
 * only stream fd
 */
bool BaseFactory::notify(DataHead *info) {
    Connection *conn = server_->get_connection(info->fd);
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

    return server_->accept_task((EventData *) info) == SW_OK;
}

bool BaseFactory::end(SessionId session_id) {
    SendData _send{};
    DataHead info;

    _send.info.fd = session_id;
    _send.info.len = 0;
    _send.info.type = SW_SERVER_EVENT_CLOSE;

    Connection *conn = server_->get_connection_by_session_id(session_id);
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
        if (server_->onClose != nullptr) {
            info.fd = session_id;
            if (conn->close_actively) {
                info.reactor_id = -1;
            } else {
                info.reactor_id = conn->reactor_id;
            }
            info.server_fd = conn->server_fd;
            server_->onClose(server_, &info);
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

static int send_func(network::Socket *socket, const void *data, size_t length) {
    if (!swoole_event_is_available()) {
        return socket->send_blocking(data, length);
    } else {
        return swoole_event_write(socket, data, length);
    }
}

bool BaseFactory::finish(SendData *data) {
    SessionId session_id = data->info.fd;

    Session *session = server_->get_session(session_id);
    if (session->reactor_id != SwooleG.process_id) {
        swTrace("session->reactor_id=%d, SwooleG.process_id=%d", session->reactor_id, SwooleG.process_id);
        Worker *worker = server_->gs->event_workers.get_worker(session->reactor_id);
        EventData proxy_msg{};

        if (data->info.type == SW_SERVER_EVENT_RECV_DATA) {
            proxy_msg.info.fd = session_id;
            proxy_msg.info.reactor_id = SwooleG.process_id;
            proxy_msg.info.type = SW_SERVER_EVENT_PROXY_START;

            size_t send_n = data->info.len;
            size_t offset = 0;

            while (send_n > 0) {
                if (send_n > SW_IPC_BUFFER_SIZE) {
                    proxy_msg.info.len = SW_IPC_BUFFER_SIZE;
                } else {
                    proxy_msg.info.type = SW_SERVER_EVENT_PROXY_END;
                    proxy_msg.info.len = send_n;
                }
                memcpy(proxy_msg.data, data->data + offset, proxy_msg.info.len);
                send_n -= proxy_msg.info.len;
                offset += proxy_msg.info.len;
                send_func(worker->pipe_master, (const char *) &proxy_msg, sizeof(proxy_msg.info) + proxy_msg.info.len);
            }

            swTrace("proxy message, fd=%d, len=%ld", worker->pipe_master, sizeof(proxy_msg.info) + proxy_msg.info.len);
        } else if (data->info.type == SW_SERVER_EVENT_SEND_FILE) {
            memcpy(&proxy_msg.info, &data->info, sizeof(proxy_msg.info));
            memcpy(proxy_msg.data, data->data, data->info.len);
            return send_func(
                worker->pipe_master, (const char *) &proxy_msg, sizeof(proxy_msg.info) + proxy_msg.info.len);
        } else {
            swWarn("unkown event type[%d]", data->info.type);
            return false;
        }
        return true;
    } else {
        return server_->send_to_connection(data) == SW_OK;
    }
}

BaseFactory::~BaseFactory() {}

}  // namespace swoole
