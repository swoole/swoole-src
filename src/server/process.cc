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

#include <signal.h>

#include "swoole_server.h"

namespace swoole {

using network::Socket;

ProcessFactory::ProcessFactory(Server *server) : Factory(server) {

}

bool ProcessFactory::shutdown() {
    int status;

    if (swoole_kill(server_->gs->manager_pid, SIGTERM) < 0) {
        swoole_sys_warning("swKill(%d) failed", server_->gs->manager_pid);
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
    server_->release_pipe_buffers();

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
        int kernel_buffer_size = SW_UNIXSOCK_MAX_BUF_SIZE;
        auto _sock = new UnixSocket(true, SOCK_DGRAM);
        if (!_sock->ready()) {
            delete _sock;
            return false;
        }

        pipes.emplace_back(_sock);
        server_->workers[i].pipe_master = _sock->get_socket(true);
        server_->workers[i].pipe_worker = _sock->get_socket(false);

        server_->workers[i].pipe_master->set_send_buffer_size(kernel_buffer_size);
        server_->workers[i].pipe_worker->set_send_buffer_size(kernel_buffer_size);

        server_->workers[i].pipe_object = _sock;
        server_->store_pipe_fd(server_->workers[i].pipe_object);
    }

    server_->set_ipc_max_size();
    if (server_->create_pipe_buffers() < 0) {
        return false;
    }

    /**
     * The manager process must be started first, otherwise it will have a thread fork
     */
    if (server_->start_manager_process() < 0) {
        swoole_warning("FactoryProcess_manager_start failed");
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
        worker->dispatch_count++;
        server_->gs->dispatch_count++;
    }

    SendData _task;
    memcpy(&_task, task, sizeof(SendData));

    return server_->send_pipe_packet(&server_->get_thread(SwooleTG.id)->pipe_sockets[worker->pipe_master->fd], &_task);
}

bool Server::send_pipe_packet(Socket *sock, SendData *resp) {
    const char *data = resp->data;
    uint32_t l_payload = resp->info.len;
    off_t offset = 0;
    uint32_t copy_n;

    struct iovec iov[2];

    uint64_t msg_id = pipe_packet_msg_id.fetch_add(1);
    uint32_t max_length = ipc_max_size - sizeof(resp->info);
    resp->info.msg_id = msg_id;

    auto send_fn = [](Socket *sock, const iovec *iov, size_t iovcnt) {
        if (swoole_event_is_available()) {
            return swoole_event_writev(sock, iov, iovcnt);
        } else {
            return sock->writev_blocking(iov, iovcnt);
        }
    };

    if (l_payload <= max_length) {
        resp->info.flags = 0;
        resp->info.len = l_payload;

        size_t iovcnt;
        iov[0].iov_base = &resp->info;
        iov[0].iov_len = sizeof(resp->info);

        if (resp->data && l_payload > 0) {
            iov[1].iov_base = (void *) resp->data;
            iov[1].iov_len = l_payload;
            iovcnt = 2;
        } else {
            iovcnt = 1;
        }

        ssize_t retval = send_fn(sock, iov, iovcnt);
#ifdef __linux__
        if (retval < 0 && errno == ENOBUFS) {
            max_length = SW_IPC_BUFFER_SIZE;
            goto _ipc_use_chunk;
        }
#endif
        return retval >= 0;
    }

#ifdef __linux__
_ipc_use_chunk:
#endif
    resp->info.flags = SW_EVENT_DATA_CHUNK | SW_EVENT_DATA_BEGIN;
    resp->info.len = l_payload;

    while (l_payload > 0) {
        if (l_payload > max_length) {
            copy_n = max_length;
        } else {
            resp->info.flags |= SW_EVENT_DATA_END;
            copy_n = l_payload;
        }

        iov[0].iov_base = &resp->info;
        iov[0].iov_len = sizeof(resp->info);
        iov[1].iov_base = (void *) (data + offset);
        iov[1].iov_len = copy_n;

        swoole_trace("finish, type=%d|len=%u", resp->info.type, copy_n);

        if (send_fn(sock, iov, 2) < 0) {
#ifdef __linux__
            if (errno == ENOBUFS && max_length > SW_BUFFER_SIZE_STD) {
                max_length = SW_IPC_BUFFER_SIZE;
                continue;
            }
#endif
            return false;
        }

        if (resp->info.flags & SW_EVENT_DATA_BEGIN) {
            resp->info.flags &= ~SW_EVENT_DATA_BEGIN;
        }

        l_payload -= copy_n;
        offset += copy_n;
    }

    return true;
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
        swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SESSION_NOT_EXIST, "session#%ld does not exists", session_id);
        return false;
    } else if ((conn->closed || conn->peer_closed) && resp->info.type != SW_SERVER_EVENT_CLOSE) {
        swoole_error_log(SW_LOG_NOTICE,
                         SW_ERROR_SESSION_CLOSED,
                         "send %d bytes failed, because session#%ld is closed",
                         resp->info.len,
                         session_id);
        return false;
    } else if (conn->overflow) {
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

    /**
     * stream
     */
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

    return server_->send_pipe_packet(server_->get_reactor_thread_pipe(session_id, task.info.reactor_id), &task);
}

bool ProcessFactory::end(SessionId session_id, int flags) {
    SendData _send{};
    DataHead info{};

    _send.info.fd = session_id;
    _send.info.len = 0;
    _send.info.type = SW_SERVER_EVENT_CLOSE;

    Connection *conn = server_->get_connection_verify_no_ssl(session_id);
    if (!conn) {
        swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SESSION_NOT_EXIST, "session[%ld] is closed", session_id);
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
     * Only active shutdown needs to determine whether it is in the process of connection binding
     */
    if (conn->close_actively) {
        /**
         * The worker process is not currently bound to this connection,
         * and needs to be forwarded to the correct worker process
         */
        if (server_->is_hash_dispatch_mode()) {
            int worker_id = server_->schedule_worker(conn->fd, nullptr);
            if (worker_id != (int) SwooleG.process_id) {
                worker = server_->get_worker(worker_id);
                goto _notify;
            } else {
                goto _close;
            }
        } else if (!server_->is_worker()) {
            worker = server_->get_worker(conn->fd % server_->worker_num);
        _notify:
            ev.type = SW_SERVER_EVENT_CLOSE;
            ev.fd = session_id;
            ev.reactor_id = conn->reactor_id;
            return server_->send_to_worker_from_worker(worker, &ev, sizeof(ev), SW_PIPE_MASTER) > 0;
        }
    }

_close:
    if (conn == nullptr || conn->active == 0) {
        swoole_set_last_error(SW_ERROR_SESSION_NOT_EXIST);
        return false;
    } else if (conn->close_force) {
        goto _do_close;
    } else if (conn->closing) {
        swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SESSION_CLOSING, "session#%ld is closing", session_id);
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
        return finish(&_send);
    }
}

ssize_t Server::recv_pipe_packet(Event *event, PipeBuffer *pipe_buffer) {
    ssize_t recv_n = 0;
    int recv_chunk_count = 0;
    DataHead *info = &pipe_buffer->info;
    struct iovec buffers[2];

_read_from_pipe:
    recv_n = recv(event->fd, info, sizeof(pipe_buffer->info), MSG_PEEK);
    if (recv_n < 0) {
        if (event->socket->catch_error(errno) == SW_WAIT) {
            return SW_OK;
        }
        return SW_ERR;
    } else if (recv_n == 0) {
        swoole_warning("receive pipeline data error, pipe_fd=%d, reactor_id=%d", event->fd, info->reactor_id);
        return SW_ERR;
    }

    if (!pipe_buffer->is_chunked()) {
        return event->socket->read(pipe_buffer, ipc_max_size);
    }

    String *packet_buffer = nullptr;

    SW_LOOP {
        auto iter = pipe_packet_buffers.find(info->msg_id);
        if (iter == pipe_packet_buffers.end()) {
            if (pipe_buffer->is_begin()) {
                packet_buffer = make_string(info->len, pipe_buffer_allocator);
                pipe_packet_buffers.emplace(info->msg_id, std::shared_ptr<String>(packet_buffer));
            }
            break;
        }
        packet_buffer = iter->second.get();
        break;
    }

    if (packet_buffer == nullptr) {
        swoole_error_log(SW_LOG_WARNING,
                         SW_ERROR_SERVER_WORKER_ABNORMAL_PIPE_DATA,
                         "abnormal pipeline data, msg_id=%ld, pipe_fd=%d, reactor_id=%d",
                         info->msg_id,
                         event->fd,
                         info->reactor_id);
        return SW_OK;
    }
    size_t remain_len = pipe_buffer->info.len - packet_buffer->length;

    buffers[0].iov_base = info;
    buffers[0].iov_len = sizeof(pipe_buffer->info);
    buffers[1].iov_base = packet_buffer->str + packet_buffer->length;
    buffers[1].iov_len = SW_MIN(ipc_max_size - sizeof(pipe_buffer->info), remain_len);

    recv_n = readv(event->fd, buffers, 2);
    if (recv_n == 0) {
        swoole_warning("receive pipeline data error, pipe_fd=%d, reactor_id=%d", event->fd, info->reactor_id);
        return SW_ERR;
    }
    if (recv_n < 0 && event->socket->catch_error(errno) == SW_WAIT) {
        return SW_OK;
    }
    if (recv_n > 0) {
        packet_buffer->length += (recv_n - sizeof(pipe_buffer->info));
        swoole_trace("append msgid=%ld, buffer=%p, n=%ld", pipe_buffer->info.msg_id, worker_buffer, recv_n);
    }

    recv_chunk_count++;

    if (!pipe_buffer->is_end()) {
        /**
         * if the reactor thread sends too many chunks to the worker process,
         * the worker process may receive chunks all the time,
         * resulting in the worker process being unable to handle other tasks.
         * in order to make the worker process handle tasks fairly,
         * the maximum number of consecutive chunks received by the worker is limited.
         */
        if (recv_chunk_count >= SW_WORKER_MAX_RECV_CHUNK_COUNT) {
            swoole_trace_log(SW_TRACE_WORKER,
                             "worker process[%u] receives the chunk data to the maximum[%d], return to event loop",
                             SwooleG.process_id,
                             recv_chunk_count);
            return SW_OK;
        }
        goto _read_from_pipe;
    } else {
        /**
         * Because we don't want to split the EventData parameters into DataHead and data,
         * we store the value of the worker_buffer pointer in EventData.data.
         * The value of this pointer will be fetched in the Server::get_pipe_packet() function.
         */
        pipe_buffer->info.flags |= SW_EVENT_DATA_OBJ_PTR;
        memcpy(pipe_buffer->data, &packet_buffer, sizeof(packet_buffer));
        swoole_trace("msg_id=%ld, len=%u", pipe_buffer->info.msg_id, pipe_buffer->info.len);
    }

    return recv_n;
}

}  // namespace swoole
