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
 | Author: Tianfeng Han  <rango@swoole.com>                             |
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
    Connection *conn = nullptr;

    if (Server::is_stream_event(task->info.type)) {
        conn = server_->get_connection(task->info.fd);
        if (conn == nullptr || conn->active == 0) {
            swoole_warning("dispatch[type=%d] failed, socket#%ld is not active", task->info.type, task->info.fd);
            return false;
        }
        // server active close, discard data.
        if (conn->closed) {
            swoole_warning("dispatch[type=%d] failed, socket#%ld is closed by server", task->info.type, task->info.fd);
            return false;
        }
        // converted fd to session_id
        task->info.fd = conn->session_id;
        task->info.server_fd = conn->server_fd;
    }

    if (task->info.len > 0) {
        if (conn && conn->socket->recv_buffer && task->data == conn->socket->recv_buffer->str &&
            conn->socket->recv_buffer->offset > 0 &&
            conn->socket->recv_buffer->length == (size_t) conn->socket->recv_buffer->offset) {
            task->info.flags |= SW_EVENT_DATA_POP_PTR;
        }
    }

    server_->message_bus.pass(task);
    server_->worker_accept_event(&server_->message_bus.get_buffer()->info);

    return true;
}

/**
 * only stream fd
 */
bool BaseFactory::notify(DataHead *info) {
    Connection *conn = server_->get_connection(info->fd);
    if (conn == nullptr || conn->active == 0) {
        swoole_warning("dispatch[type=%d] failed, socket#%ld is not active", info->type, info->fd);
        return false;
    }
    // server active close, discard data.
    if (conn->closed) {
        swoole_warning("dispatch[type=%d] failed, session#%ld is closed by server", info->type, conn->session_id);
        return false;
    }
    // converted fd to session_id
    info->fd = conn->session_id;
    info->server_fd = conn->server_fd;
    info->flags = SW_EVENT_DATA_NORMAL;

    server_->worker_accept_event(info);

    return true;
}

bool BaseFactory::end(SessionId session_id, int flags) {
    SendData _send{};
    _send.info.fd = session_id;
    _send.info.len = 0;
    _send.info.type = SW_SERVER_EVENT_CLOSE;
    _send.info.reactor_id = SwooleG.process_id;

    Session *session = server_->get_session(session_id);
    if (!session->fd) {
        swoole_error_log(SW_LOG_NOTICE,
                         SW_ERROR_SESSION_NOT_EXIST,
                         "failed to close connection, session#%ld does not exist",
                         session_id);
        return false;
    }

    if (session->reactor_id != SwooleG.process_id) {
        Worker *worker = server_->get_worker(session->reactor_id);
        if (worker->pipe_master->send_async((const char *) &_send.info, sizeof(_send.info)) < 0) {
            swoole_sys_warning("failed to send %lu bytes to pipe_master", sizeof(_send.info));
            return false;
        }
        return true;
    }

    Connection *conn = server_->get_connection_verify_no_ssl(session_id);
    if (conn == nullptr) {
        swoole_set_last_error(SW_ERROR_SESSION_NOT_EXIST);
        return false;
    }
    // Reset send buffer, Immediately close the connection.
    if (flags & Server::CLOSE_RESET) {
        conn->close_reset = 1;
    }
    // Server is initiative to close the connection
    if (flags & Server::CLOSE_ACTIVELY) {
        conn->close_actively = 1;
    }

    if (conn->closing) {
        swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SESSION_CLOSING, "session#%ld is closing", session_id);
        return false;
    } else if (!(conn->close_force || conn->close_reset) && conn->closed) {
        swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SESSION_CLOSED, "session#%ld is closed", session_id);
        return false;
    }

    conn->closing = 1;
    if (server_->onClose != nullptr && !conn->closed) {
        DataHead info{};
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
        swoole_warning("session#%ld->socket is nullptr", session_id);
        return false;
    }

    if (Buffer::empty(conn->socket->out_buffer) || (conn->close_reset || conn->peer_closed || conn->close_force)) {
        Reactor *reactor = SwooleTG.reactor;
        return Server::close_connection(reactor, conn->socket) == SW_OK;
    } else {
        BufferChunk *chunk = conn->socket->out_buffer->alloc(BufferChunk::TYPE_CLOSE, 0);
        chunk->value.data.val1 = _send.info.type;
        conn->close_queued = 1;
        return true;
    }
}

bool BaseFactory::finish(SendData *data) {
    SessionId session_id = data->info.fd;

    Session *session = server_->get_session(session_id);
    if (session->reactor_id != SwooleG.process_id) {
        swoole_trace("session->reactor_id=%d, SwooleG.process_id=%d", session->reactor_id, SwooleG.process_id);
        Worker *worker = server_->gs->event_workers.get_worker(session->reactor_id);
        EventData proxy_msg{};

        if (data->info.type == SW_SERVER_EVENT_SEND_DATA) {
            if (!server_->message_bus.write(worker->pipe_master, data)) {
                swoole_sys_warning("failed to send %u bytes to pipe_master", data->info.len);
                return false;
            }
            swoole_trace(
                "proxy message, fd=%d, len=%ld", worker->pipe_master->fd, sizeof(proxy_msg.info) + proxy_msg.info.len);
        } else if (data->info.type == SW_SERVER_EVENT_SEND_FILE) {
            memcpy(&proxy_msg.info, &data->info, sizeof(proxy_msg.info));
            memcpy(proxy_msg.data, data->data, data->info.len);
            size_t __len = sizeof(proxy_msg.info) + proxy_msg.info.len;
            return worker->pipe_master->send_async((const char *) &proxy_msg, __len);
        } else {
            swoole_warning("unkown event type[%d]", data->info.type);
            return false;
        }
        return true;
    } else {
        return server_->send_to_connection(data) == SW_OK;
    }
}

BaseFactory::~BaseFactory() {}

}  // namespace swoole
