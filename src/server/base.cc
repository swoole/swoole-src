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
    connection_list = static_cast<Connection *>(sw_calloc(max_connection, sizeof(Connection)));
    if (connection_list == nullptr) {
        swoole_sys_warning("calloc[2](%zu) failed", max_connection * sizeof(Connection));
        return nullptr;
    }
    gs->connection_nums = static_cast<sw_atomic_t *>(sw_shm_calloc(worker_num, sizeof(sw_atomic_t)));
    if (gs->connection_nums == nullptr) {
        swoole_sys_warning("sw_shm_calloc(%ld) for gs->connection_nums failed", worker_num * sizeof(sw_atomic_t));
        destroy_base_factory();
        return nullptr;
    }

    for (const auto port : ports) {
        port->gs->connection_nums = static_cast<sw_atomic_t *>(sw_shm_calloc(worker_num, sizeof(sw_atomic_t)));
        if (port->gs->connection_nums == nullptr) {
            swoole_sys_warning("sw_shm_calloc(%ld) for port->connection_nums failed", worker_num * sizeof(sw_atomic_t));
            destroy_base_factory();
            return nullptr;
        }
    }

    return new BaseFactory(this);
}

void Server::destroy_base_factory() {
    if (connection_list) {
        sw_free(connection_list);
        connection_list = nullptr;
    }
    if (gs->connection_nums) {
        sw_shm_free((void *) gs->connection_nums);
        gs->connection_nums = nullptr;
    }
    for (auto port : ports) {
        if (port->gs->connection_nums) {
            sw_shm_free((void *) port->gs->connection_nums);
            port->gs->connection_nums = nullptr;
        }
    }
}

BaseFactory::BaseFactory(Server *server) : Factory(server) {}

BaseFactory::~BaseFactory() = default;

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
        if (conn->is_close_requested()) {
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
    if (task->info.type == SW_SERVER_EVENT_RECV_DATA && task->info.len > 0) {
        // BASE/THREAD consume this event synchronously on the same owner reactor.
        conn->add_recv_queued_bytes<Connection::ReceiveQueueMode::OWNER_REACTOR>(task->info.len);
        swoole_trace_log(SW_TRACE_SERVER,
                         "session_id=%ld, len=%d, qb=%d",
                         conn->session_id,
                         task->info.len,
                         conn->get_recv_queued_bytes());
    }
    server_->worker_accept_event(&bus->get_buffer()->info);

    return true;
}

/**
 * only stream fd
 */
bool BaseFactory::notify(DataHead *info) {
    const auto conn = server_->get_connection(info->fd);
    if (conn == nullptr || conn->active == 0) {
        swoole_warning("dispatch[type=%d] failed, socket#%ld is not active", info->type, info->fd);
        return false;
    }
    // server active close, discard data.
    if (conn->is_close_requested() && info->type != SW_SERVER_EVENT_CLOSE) {
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

/**
 * Worker-side close processing, after Factory::end routes active closes to the assigned worker.
 * PROCESS runs in an event worker; BASE/THREAD run on the owner event reactor. Only callback claims
 * and command ownership touch shared Connection state under its slot lock. Release it before PHP,
 * coroutine cancellation, or IPC; callbacks can reenter close and the fd may be retired/reused.
 * Output abort/RST are command flags for the owning reactor, not fields written by this worker.
 */
bool Server::finish_close(SessionId session_id, int flags) const {
    Connection *conn = get_connection_verify_no_ssl(session_id);
    if (!conn) {
        swoole_set_last_error(SW_ERROR_SESSION_NOT_EXIST);
        return false;
    }
    SendData close_event{};
    close_event.info.fd = session_id;
    close_event.info.type = SW_SERVER_EVENT_CLOSE;
    close_event.info.ext_flags = flags & (CLOSE_RESET | CLOSE_ABORT);

    DataHead info{};
    bool call_close = false;
    bool claimed = false;
    int duplicate_error = SW_ERROR_SESSION_CLOSED;
    String *certificate = nullptr;
    // Claim the session generation and callback together, before releasing the slot for user code.
    sw_spinlock(&conn->lock);
    if (!conn->active || conn->session_id != session_id) {
        sw_spinlock_release(&conn->lock);
        swoole_set_last_error(SW_ERROR_SESSION_NOT_EXIST);
        return false;
    }
    if (flags & CLOSE_RESET) {
        conn->begin_close(ConnectionCloseReason::APPLICATION);
    }
    claimed = !conn->close_worker_claimed;
    if (claimed) {
        conn->close_worker_claimed = true;
        conn->close_worker_started = true;
        if (flags & CLOSE_ACTIVELY) {
            conn->close_actively = true;
        }
        conn->begin_close(flags & CLOSE_ACTIVELY ? ConnectionCloseReason::APPLICATION
                                                 : ConnectionCloseReason::SERVER_ERROR);
        call_close = claim_close_callback(conn);
        info.fd = session_id;
        info.reactor_id = conn->is_close_active() ? -1 : conn->reactor_id;
        info.server_fd = conn->server_fd;
        info.ext_flags = (conn->is_websocket_active() ? CLOSE_CALLBACK_WEBSOCKET : 0) |
                         (conn->http2_stream ? CLOSE_CALLBACK_HTTP2 : 0);
        if (conn->ssl_client_cert && conn->ssl_client_cert_pid == swoole_get_worker_pid()) {
            certificate = conn->ssl_client_cert;
            conn->ssl_client_cert = nullptr;
        }
    }
    if (!claimed && conn->is_close_callback_dispatching()) {
        duplicate_error = SW_ERROR_SESSION_CLOSING;
    }
    sw_spinlock_release(&conn->lock);
    delete certificate;
    if (!claimed) {
        if (flags & (CLOSE_RESET | CLOSE_ABORT)) {
            return factory_->finish(&close_event);
        }
        swoole_set_last_error(duplicate_error);
        return false;
    }

    try {
        if (call_close) {
            onClose(const_cast<Server *>(this), &info);
            conn->finish_close_callback(session_id);
        }
    } catch (...) {
        // The owner reactor applies the abort policy; workers never mutate its output state.
        close_event.info.ext_flags |= CLOSE_ABORT;
        conn = get_connection_verify_no_ssl(session_id);
        if (conn) {
            conn->finish_close_callback(session_id);
            try {
                if (!factory_->finish(&close_event)) {
                    conn = get_connection_verify_no_ssl(session_id);
                    if (conn) {
                        conn->release_close_worker(session_id);
                    }
                }
            } catch (...) {
                // Preserve the callback's original exception; allow another close attempt.
                conn = get_connection_verify_no_ssl(session_id);
                if (conn) {
                    conn->release_close_worker(session_id);
                }
            }
        }
        throw;
    }

    // onClose cancels send-yield coroutines and can reenter server code. Never keep an old slot pointer across it.
    conn = get_connection_verify_no_ssl(session_id);
    if (!conn) {
        return true;
    }
    if (!factory_->finish(&close_event)) {
        conn = get_connection_verify_no_ssl(session_id);
        if (conn) {
            conn->release_close_worker(session_id);
        }
        return false;
    }
    return true;
}

bool BaseFactory::end(SessionId session_id, int flags) {
    SendData _send{};
    _send.info.fd = session_id;
    _send.info.len = 0;
    _send.info.type = SW_SERVER_EVENT_CLOSE;
    _send.info.reactor_id = swoole_get_worker_id();

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
        _send.info.type = SW_SERVER_EVENT_CLOSE_FORWARD;
        _send.info.ext_flags = flags;
        return forward_message(session, &_send);
    }

    return server_->finish_close(session_id, flags);
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

bool BaseFactory::forward_message(const Session *session, SendData *data) const {
    const Worker *worker = server_->get_event_worker_pool()->get_worker(session->reactor_id);
    swoole_trace_log(SW_TRACE_SERVER,
                     "fd=%d, worker_id=%d, type=%d, len=%u",
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
