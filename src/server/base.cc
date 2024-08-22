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

Factory *Server::create_base_factory() {
    reactor_num = worker_num;
    connection_list = (Connection *) sw_calloc(max_connection, sizeof(Connection));
    if (connection_list == nullptr) {
        swoole_sys_warning("calloc[2](%d) failed", (int) (max_connection * sizeof(Connection)));
        return nullptr;
    }
    gs->connection_nums = (sw_atomic_t *) sw_shm_calloc(worker_num, sizeof(sw_atomic_t));
    if (gs->connection_nums == nullptr) {
        swoole_error("sw_shm_calloc(%ld) for gs->connection_nums failed", worker_num * sizeof(sw_atomic_t));
        return nullptr;
    }

    for (auto port : ports) {
        port->gs->connection_nums = (sw_atomic_t *) sw_shm_calloc(worker_num, sizeof(sw_atomic_t));
        if (port->gs->connection_nums == nullptr) {
            swoole_error("sw_shm_calloc(%ld) for port->connection_nums failed", worker_num * sizeof(sw_atomic_t));
            return nullptr;
        }
    }

    return new BaseFactory(this);
}

void Server::destroy_base_factory() {
    sw_free(connection_list);
    sw_shm_free((void *) gs->connection_nums);
    for (auto port : ports) {
        sw_shm_free((void *) port->gs->connection_nums);
    }
    gs->connection_nums = nullptr;
}

BaseFactory::BaseFactory(Server *server) : Factory(server) {}

BaseFactory::~BaseFactory() {}

bool BaseFactory::start() {
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

    auto bus = server_->get_worker_message_bus();
    bus->pass(task);
    server_->worker_accept_event(&bus->get_buffer()->info);

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
    _send.info.reactor_id = swoole_get_process_id();

    Session *session = server_->get_session(session_id);
    if (!session->fd) {
        swoole_error_log(SW_LOG_TRACE,
                         SW_ERROR_SESSION_NOT_EXIST,
                         "failed to close connection, session#%ld does not exist",
                         session_id);
        return false;
    }

    if (server_->if_forward_message(session)) {
        swoole_trace_log(SW_TRACE_SERVER,
                         "session_id=%ld, fd=%d, session->reactor_id=%d",
                         session_id,
                         session->fd,
                         session->reactor_id);
        return forward_message(session, &_send);
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
        swoole_error_log(SW_LOG_TRACE, SW_ERROR_SESSION_CLOSED, "session#%ld is closed", session_id);
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
    network::Socket *_socket = conn->socket;

    if (_socket == nullptr) {
        swoole_warning("session#%ld->socket is nullptr", session_id);
        return false;
    }

    if (Buffer::empty(_socket->out_buffer) || (conn->close_reset || conn->peer_closed || conn->close_force)) {
        Reactor *reactor = SwooleTG.reactor;
        return Server::close_connection(reactor, _socket) == SW_OK;
    } else {
        _socket->out_buffer->alloc(BufferChunk::TYPE_CLOSE, 0);
        conn->close_queued = 1;
        return true;
    }
}

bool BaseFactory::finish(SendData *data) {
    SessionId session_id = data->info.fd;

    Session *session = server_->get_session(session_id);
    if (server_->if_forward_message(session)) {
        swoole_trace_log(SW_TRACE_SERVER,
                         "session_id=%ld, fd=%d, session->reactor_id=%d",
                         session_id,
                         session->fd,
                         session->reactor_id);

        if (data->info.type == SW_SERVER_EVENT_SEND_DATA || data->info.type == SW_SERVER_EVENT_SEND_FILE) {
            return forward_message(session, data);
        } else {
            swoole_warning("unknown event type[%d]", data->info.type);
            return false;
        }
    } else {
        return server_->send_to_connection(data) == SW_OK;
    }
}

bool BaseFactory::forward_message(Session *session, SendData *data) {
    Worker *worker = server_->gs->event_workers.get_worker(session->reactor_id);
    swoole_trace_log(SW_TRACE_SERVER,
                     "fd=%d, worker_id=%d, type=%d, len=%ld",
                     worker->pipe_master->get_fd(),
                     session->reactor_id,
                     data->info.type,
                     data->info.len);

    auto mb = server_->get_worker_message_bus();
    auto sock = server_->is_thread_mode() ? mb->get_pipe_socket(worker->pipe_master) : worker->pipe_master;
    if (!mb->write(sock, data)) {
        swoole_sys_warning("failed to send %u bytes to pipe_master", data->info.len);
        return false;
    }
    return true;
}

}  // namespace swoole
