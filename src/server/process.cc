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

using namespace swoole;
using swoole::network::Socket;

struct FactoryProcess {
    Pipe *pipes;
    PipeBuffer *send_buffer;
};

typedef int (*send_func_t)(Server *, PipeBuffer *, size_t, void *);

static int swFactoryProcess_start(Factory *factory);
static int swFactoryProcess_shutdown(Factory *factory);
static void swFactoryProcess_free(Factory *factory);
static int swFactoryProcess_create_pipes(Factory *factory);

static bool swFactoryProcess_notify(Factory *factory, DataHead *event);
static bool swFactoryProcess_dispatch(Factory *factory, SendData *data);
static bool swFactoryProcess_finish(Factory *factory, SendData *data);
static bool swFactoryProcess_end(Factory *factory, SessionId fd);

static bool process_send_packet(Server *serv, PipeBuffer *buf, SendData *resp, send_func_t _send, void *private_data);
static int process_sendto_worker(Server *serv, PipeBuffer *buf, size_t n, void *private_data);
static int process_sendto_reactor(Server *serv, PipeBuffer *buf, size_t n, void *private_data);

int swFactoryProcess_create(Factory *factory, uint32_t worker_num) {
    factory->object = new FactoryProcess;
    factory->dispatch = swFactoryProcess_dispatch;
    factory->finish = swFactoryProcess_finish;
    factory->start = swFactoryProcess_start;
    factory->notify = swFactoryProcess_notify;
    factory->shutdown = swFactoryProcess_shutdown;
    factory->end = swFactoryProcess_end;
    factory->free = swFactoryProcess_free;

    return SW_OK;
}

static int swFactoryProcess_shutdown(Factory *factory) {
    int status;
    Server *serv = (Server *) factory->ptr;

    if (swoole_kill(serv->gs->manager_pid, SIGTERM) < 0) {
        swSysWarn("swKill(%d) failed", serv->gs->manager_pid);
    }

    if (swoole_waitpid(serv->gs->manager_pid, &status, 0) < 0) {
        swSysWarn("waitpid(%d) failed", serv->gs->manager_pid);
    }

    return SW_OK;
}

static void swFactoryProcess_free(Factory *factory) {
    Server *serv = (Server *) factory->ptr;
    FactoryProcess *object = (FactoryProcess *) serv->factory.object;

    uint32_t i;

    for (i = 0; i < serv->reactor_num; i++) {
        sw_free(serv->pipe_buffers[i]);
    }
    sw_free(serv->pipe_buffers);

    if (serv->stream_socket_file) {
        unlink(serv->stream_socket_file);
        sw_free(serv->stream_socket_file);
        serv->stream_socket->free();
    }

    for (i = 0; i < serv->worker_num; i++) {
        object->pipes[i].close(&object->pipes[i]);
    }

    sw_free(object->send_buffer);
    delete[] object->pipes;
    delete object;
}

static int swFactoryProcess_create_pipes(Factory *factory) {
    Server *serv = (Server *) factory->ptr;
    FactoryProcess *object = (FactoryProcess *) serv->factory.object;

    object->pipes = new Pipe[serv->worker_num]();

    for (uint32_t i = 0; i < serv->worker_num; i++) {
        int kernel_buffer_size = SW_UNIXSOCK_MAX_BUF_SIZE;

        if (swPipeUnsock_create(&object->pipes[i], 1, SOCK_DGRAM) < 0) {
            delete[] object->pipes;
            object->pipes = nullptr;
            return SW_ERR;
        }

        serv->workers[i].pipe_master = object->pipes[i].get_socket(true);
        serv->workers[i].pipe_worker = object->pipes[i].get_socket(false);

        serv->workers[i].pipe_master->set_send_buffer_size(kernel_buffer_size);
        serv->workers[i].pipe_worker->set_send_buffer_size(kernel_buffer_size);

        serv->workers[i].pipe_object = &object->pipes[i];
        serv->store_pipe_fd(serv->workers[i].pipe_object);
    }

    return SW_OK;
}

static int swFactoryProcess_start(Factory *factory) {
    Server *serv = (Server *) factory->ptr;
    FactoryProcess *object = (FactoryProcess *) serv->factory.object;

    if (serv->dispatch_mode == SW_DISPATCH_STREAM) {
        serv->stream_socket_file = swoole_string_format(64, "/tmp/swoole.%d.sock", serv->gs->master_pid);
        if (serv->stream_socket_file == nullptr) {
            return SW_ERR;
        }
        Socket *sock = swoole::make_server_socket(SW_SOCK_UNIX_STREAM, serv->stream_socket_file);
        if (sock == nullptr) {
            return SW_ERR;
        }
        sock->set_fd_option(1, 1);
        serv->stream_socket = sock;
    }

    for (uint32_t i = 0; i < serv->worker_num; i++) {
        if (serv->create_worker(serv->get_worker(i)) < 0) {
            return SW_ERR;
        }
    }

    if (swFactoryProcess_create_pipes(factory) < 0) {
        return SW_ERR;
    }

    serv->set_ipc_max_size();
    if (serv->create_pipe_buffers() < 0) {
        return SW_ERR;
    }

    object->send_buffer = (PipeBuffer *) sw_malloc(serv->ipc_max_size);
    if (object->send_buffer == nullptr) {
        swSysError("malloc[send_buffer] failed");
        return SW_ERR;
    }
    sw_memset_zero(object->send_buffer, sizeof(DataHead));

    /**
     * The manager process must be started first, otherwise it will have a thread fork
     */
    if (serv->start_manager_process() < 0) {
        swWarn("FactoryProcess_manager_start failed");
        return SW_ERR;
    }
    factory->finish = swFactory_finish;
    return SW_OK;
}

/**
 * [ReactorThread] notify info to worker process
 */
static bool swFactoryProcess_notify(Factory *factory, DataHead *ev) {
    SendData task;
    task.info = *ev;
    task.data = nullptr;
    return swFactoryProcess_dispatch(factory, &task);
}

static inline int process_sendto_worker(Server *serv, PipeBuffer *buf, size_t n, void *private_data) {
    return serv->send_to_worker_from_master((Worker *) private_data, buf, n);
}

static inline int process_sendto_reactor(Server *serv, PipeBuffer *buf, size_t n, void *private_data) {
    return serv->send_to_reactor_thread((EventData *) buf, n, ((Connection *) private_data)->session_id);
}

/**
 * [ReactorThread] dispatch request to worker
 */
static bool swFactoryProcess_dispatch(Factory *factory, SendData *task) {
    Server *serv = (Server *) factory->ptr;
    int fd = task->info.fd;

    int target_worker_id = serv->schedule_worker(fd, task);
    if (target_worker_id < 0) {
        switch (target_worker_id) {
        case SW_DISPATCH_RESULT_DISCARD_PACKET:
            return false;
        case SW_DISPATCH_RESULT_CLOSE_CONNECTION:
            // TODO: close connection
            return false;
        default:
            swWarn("invalid target worker id[%d]", target_worker_id);
            return false;
        }
    }

    if (Server::is_stream_event(task->info.type)) {
        Connection *conn = serv->get_connection(fd);
        if (conn == nullptr || conn->active == 0) {
            swWarn("dispatch[type=%d] failed, connection#%d is not active", task->info.type, fd);
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

    Worker *worker = serv->get_worker(target_worker_id);

    // without data
    if (task->data == nullptr) {
        task->info.flags = 0;
        return serv->send_to_worker_from_master(worker, &task->info, sizeof(task->info));
    }

    if (task->info.type == SW_SERVER_EVENT_RECV_DATA) {
        worker->dispatch_count++;
    }

    /**
     * Multi-Threads
     */
    PipeBuffer *buf = serv->pipe_buffers[SwooleTG.id];
    buf->info = task->info;

    return process_send_packet(serv, buf, task, process_sendto_worker, worker);
}

/**
 * @description: master process send data to worker process.
 *  If the data sent is larger than Server::ipc_max_size, then it is sent in chunks. Otherwise send it directly。
 * @return: send success returns SW_OK, send failure returns SW_ERR.
 */
static bool process_send_packet(
    Server *serv, PipeBuffer *buf, SendData *resp, send_func_t _send, void *private_data) {
    const char *data = resp->data;
    uint32_t send_n = resp->info.len;
    off_t offset = 0;
    uint32_t copy_n;

    uint32_t max_length = serv->ipc_max_size - sizeof(buf->info);

    if (send_n <= max_length) {
        buf->info.flags = 0;
        buf->info.len = send_n;
        memcpy(buf->data, data, send_n);

        int retval = _send(serv, buf, sizeof(buf->info) + send_n, private_data);
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
    buf->info.flags = SW_EVENT_DATA_CHUNK;
    buf->info.len = send_n;

    while (send_n > 0) {
        if (send_n > max_length) {
            copy_n = max_length;
        } else {
            buf->info.flags |= SW_EVENT_DATA_END;
            copy_n = send_n;
        }

        memcpy(buf->data, data + offset, copy_n);

        swTrace("finish, type=%d|len=%d", buf->info.type, copy_n);

        if (_send(serv, buf, sizeof(buf->info) + copy_n, private_data) < 0) {
#ifdef __linux__
            if (errno == ENOBUFS && max_length > SW_BUFFER_SIZE_STD) {
                max_length = SW_IPC_BUFFER_SIZE;
                continue;
            }
#endif
            return false;
        }

        send_n -= copy_n;
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
static bool swFactoryProcess_finish(Factory *factory, SendData *resp) {
    Server *serv = (Server *) factory->ptr;
    FactoryProcess *object = (FactoryProcess *) serv->factory.object;

    /**
     * More than the output buffer
     */
    if (resp->info.len > serv->output_buffer_size) {
        swoole_error_log(SW_LOG_WARNING,
                         SW_ERROR_DATA_LENGTH_TOO_LARGE,
                         "The length of data [%u] exceeds the output buffer size[%u], "
                         "please use the sendfile, chunked transfer mode or adjust the output_buffer_size",
                         resp->info.len,
                         serv->output_buffer_size);
        return false;
    }

    SessionId session_id = resp->info.fd;
    Connection *conn;
    if (resp->info.type != SW_SERVER_EVENT_CLOSE) {
        conn = serv->get_connection_verify(session_id);
    } else {
        conn = serv->get_connection_verify_no_ssl(session_id);
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
        if (serv->send_yield && process_is_supported_send_yield(serv, conn)) {
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
    if (serv->last_stream_socket) {
        uint32_t _len = resp->info.len;
        uint32_t _header = htonl(_len + sizeof(resp->info));
        if (swoole_event_write(serv->last_stream_socket, (char *) &_header, sizeof(_header)) < 0) {
            return false;
        }
        if (swoole_event_write(serv->last_stream_socket, &resp->info, sizeof(resp->info)) < 0) {
            return false;
        }
        if (swoole_event_write(serv->last_stream_socket, resp->data, _len) < 0) {
            return false;
        }
        return true;
    }

    PipeBuffer *buf = object->send_buffer;

    buf->info.fd = session_id;
    buf->info.type = resp->info.type;
    buf->info.reactor_id = conn->reactor_id;
    buf->info.server_fd = SwooleG.process_id;

    swTrace("worker_id=%d, type=%d", SwooleG.process_id, buf->info.type);

    return process_send_packet(serv, buf, resp, process_sendto_reactor, conn);
}

static bool swFactoryProcess_end(Factory *factory, SessionId session_id) {
    Server *serv = (Server *) factory->ptr;
    SendData _send{};
    DataHead info{};

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
        swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SESSION_CLOSING, "session#%ld is closing", session_id);
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
        return factory->finish(factory, &_send);
    }
}
