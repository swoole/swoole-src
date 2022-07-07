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

#include <signal.h>

#include "swoole_server.h"

namespace swoole {

using network::Socket;

ProcessFactory::ProcessFactory(Server *server) : Factory(server) {}

bool ProcessFactory::shutdown() {
    int status;

    if (swoole_kill(server_->gs->manager_pid, SIGTERM) < 0) {
        swoole_sys_warning("kill(%d) failed", server_->gs->manager_pid);
    }

    if (swoole_waitpid(server_->gs->manager_pid, &status, 0) < 0) {
        swoole_sys_warning("waitpid(%d) failed", server_->gs->manager_pid);
    }

    SW_LOOP_N(server_->worker_num) {
        Worker *worker = &server_->workers[i];
        server_->destroy_worker(worker);
    }

    return SW_OK;
}

ProcessFactory::~ProcessFactory() {
    if (server_->stream_socket_file) {
        unlink(server_->stream_socket_file);
        sw_free(server_->stream_socket_file);
        server_->stream_socket->free();
    }
}

bool ProcessFactory::start() {
    if (server_->dispatch_mode == Server::DISPATCH_STREAM) {
        server_->stream_socket_file = swoole_string_format(64, "/tmp/swoole.%d.sock", server_->gs->master_pid);
        if (server_->stream_socket_file == nullptr) {
            return false;
        }
        Socket *sock = swoole::make_server_socket(SW_SOCK_UNIX_STREAM, server_->stream_socket_file);
        if (sock == nullptr) {
            return false;
        }
        sock->set_fd_option(1, 1);
        server_->stream_socket = sock;
    }

    SW_LOOP_N(server_->worker_num) {
        server_->create_worker(server_->get_worker(i));
    }

    SW_LOOP_N(server_->worker_num) {
        auto _sock = new UnixSocket(true, SOCK_DGRAM);
        if (!_sock->ready()) {
            delete _sock;
            return false;
        }

        pipes.emplace_back(_sock);
        server_->workers[i].pipe_master = _sock->get_socket(true);
        server_->workers[i].pipe_worker = _sock->get_socket(false);
        server_->workers[i].pipe_object = _sock;
        server_->store_pipe_fd(server_->workers[i].pipe_object);
    }

    server_->init_ipc_max_size();
    if (server_->create_pipe_buffers() < 0) {
        return false;
    }

    /**
     * The manager process must be started first, otherwise it will have a thread fork
     */
    if (server_->start_manager_process() < 0) {
        swoole_warning("failed to start");
        return false;
    }
    return true;
}

/**
 * [ReactorThread] notify info to worker process
 */
bool ProcessFactory::notify(DataHead *ev) {
    SendData task;
    task.info = *ev;
    task.data = nullptr;
    return dispatch(&task);
}

/**
 * [ReactorThread] dispatch request to worker
 */
bool ProcessFactory::dispatch(SendData *task) {
    int fd = task->info.fd;

    int target_worker_id = server_->schedule_worker(fd, task);
    if (target_worker_id < 0) {
        switch (target_worker_id) {
        case Server::DISPATCH_RESULT_DISCARD_PACKET:
            return false;
        case Server::DISPATCH_RESULT_CLOSE_CONNECTION:
            // TODO: close connection
            return false;
        default:
            swoole_warning("invalid target worker id[%d]", target_worker_id);
            return false;
        }
    }

    if (Server::is_stream_event(task->info.type)) {
        Connection *conn = server_->get_connection(fd);
        if (conn == nullptr || conn->active == 0) {
            swoole_warning("dispatch[type=%d] failed, connection#%d is not active", task->info.type, fd);
            return false;
        }
        // server active close, discard data.
        if (conn->closed) {
            // Connection has been clsoed by server
            if (!(task->info.type == SW_SERVER_EVENT_CLOSE && conn->close_force)) {
                return true;
            }
        }
        // converted fd to session_id
        task->info.fd = conn->session_id;
        task->info.server_fd = conn->server_fd;
    }

    Worker *worker = server_->get_worker(target_worker_id);

    if (task->info.type == SW_SERVER_EVENT_RECV_DATA) {
        sw_atomic_fetch_add(&worker->dispatch_count, 1);
    }

    SendData _task;
    memcpy(&_task, task, sizeof(SendData));

    network::Socket *pipe_socket =
        server_->is_reactor_thread() ? server_->get_worker_pipe_socket(worker) : worker->pipe_master;
    return server_->message_bus.write(pipe_socket, &_task);
}

static bool inline process_is_supported_send_yield(Server *serv, Connection *conn) {
    if (!serv->is_hash_dispatch_mode()) {
        return false;
    } else {
        return serv->schedule_worker(conn->fd, nullptr) == (int) SwooleG.process_id;
    }
}

/**
 * [Worker] send to client, proxy by reactor
 */
bool ProcessFactory::finish(SendData *resp) {
    /**
     * More than the output buffer
     */
    if (resp->info.len > server_->output_buffer_size) {
        swoole_error_log(SW_LOG_WARNING,
                         SW_ERROR_DATA_LENGTH_TOO_LARGE,
                         "The length of data [%u] exceeds the output buffer size[%u], "
                         "please use the sendfile, chunked transfer mode or adjust the output_buffer_size",
                         resp->info.len,
                         server_->output_buffer_size);
        return false;
    }

    SessionId session_id = resp->info.fd;
    Connection *conn;
    if (resp->info.type != SW_SERVER_EVENT_CLOSE) {
        conn = server_->get_connection_verify(session_id);
    } else {
        conn = server_->get_connection_verify_no_ssl(session_id);
    }
    if (!conn) {
        if (resp->info.type != SW_SERVER_EVENT_CLOSE) {
            swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SESSION_NOT_EXIST, "session#%ld does not exists", session_id);
        }
        return false;
    } else if ((conn->closed || conn->peer_closed) && resp->info.type != SW_SERVER_EVENT_CLOSE) {
        swoole_error_log(SW_LOG_NOTICE,
                         SW_ERROR_SESSION_CLOSED,
                         "send %d bytes failed, because session#%ld is closed",
                         resp->info.len,
                         session_id);
        return false;
    } else if (conn->overflow &&
               (resp->info.type == SW_SERVER_EVENT_SEND_DATA || resp->info.type == SW_SERVER_EVENT_SEND_FILE)) {
        if (server_->send_yield && process_is_supported_send_yield(server_, conn)) {
            swoole_set_last_error(SW_ERROR_OUTPUT_SEND_YIELD);
        } else {
            swoole_error_log(SW_LOG_WARNING,
                             SW_ERROR_OUTPUT_BUFFER_OVERFLOW,
                             "send failed, session=%ld output buffer overflow",
                             session_id);
        }
        return false;
    }

    if (server_->last_stream_socket) {
        uint32_t _len = resp->info.len;
        uint32_t _header = htonl(_len + sizeof(resp->info));
        if (swoole_event_write(server_->last_stream_socket, (char *) &_header, sizeof(_header)) < 0) {
            return false;
        }
        if (swoole_event_write(server_->last_stream_socket, &resp->info, sizeof(resp->info)) < 0) {
            return false;
        }
        if (_len > 0 && swoole_event_write(server_->last_stream_socket, resp->data, _len) < 0) {
            return false;
        }
        return true;
    }

    SendData task;
    memcpy(&task, resp, sizeof(SendData));
    task.info.fd = session_id;
    task.info.reactor_id = conn->reactor_id;
    task.info.server_fd = SwooleG.process_id;

    swoole_trace("worker_id=%d, type=%d", SwooleG.process_id, task.info.type);

    return server_->message_bus.write(server_->get_reactor_pipe_socket(session_id, task.info.reactor_id), &task);
}

bool ProcessFactory::end(SessionId session_id, int flags) {
    SendData _send{};
    DataHead info{};

    _send.info.fd = session_id;
    _send.info.len = 0;
    _send.info.type = SW_SERVER_EVENT_CLOSE;

    Connection *conn = server_->get_connection_verify_no_ssl(session_id);
    if (!conn) {
        swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SESSION_NOT_EXIST, "session#%ld does not exists", session_id);
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

    swoole_trace_log(SW_TRACE_CLOSE, "session_id=%ld, fd=%d", session_id, conn->fd);

    Worker *worker;
    DataHead ev = {};

    /**
     * Only close actively needs to determine whether it is in the process of connection binding.
     * If the worker process is not currently bound to this connection,
     * MUST forward to the correct worker process
     */
    if (conn->close_actively) {
        if (server_->last_stream_socket) {
            goto _close;
        }
        bool hash = server_->is_hash_dispatch_mode();
        int worker_id = hash ? server_->schedule_worker(conn->fd, nullptr) : conn->fd % server_->worker_num;
        if (server_->is_worker() && (!hash || worker_id == (int) SwooleG.process_id)) {
            goto _close;
        }
        worker = server_->get_worker(worker_id);
        ev.type = SW_SERVER_EVENT_CLOSE;
        ev.fd = session_id;
        ev.reactor_id = conn->reactor_id;
        return server_->send_to_worker_from_worker(worker, &ev, sizeof(ev), SW_PIPE_MASTER) > 0;
    }

_close:
    if (conn->closing) {
        swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SESSION_CLOSING, "session#%ld is closing", session_id);
        return false;
    } else if (!(conn->close_force || conn->close_reset) && conn->closed) {
        swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SESSION_CLOSED, "session#%ld is closed", session_id);
        return false;
    }

    if (server_->onClose != nullptr && !conn->closed) {
        info.fd = session_id;
        if (conn->close_actively) {
            info.reactor_id = -1;
        } else {
            info.reactor_id = conn->reactor_id;
        }
        info.server_fd = conn->server_fd;
        conn->closing = 1;
        server_->onClose(server_, &info);
        conn->closing = 0;
    }
    conn->closed = 1;
    conn->close_errno = 0;
    return finish(&_send);
}
}  // namespace swoole
