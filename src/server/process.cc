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

#include "server.h"

struct swFactoryProcess {
    swPipe *pipes;
    swPipeBuffer *send_buffer;
};

typedef int (*send_func_t)(swServer *, swPipeBuffer *, size_t, void *);

static int swFactoryProcess_start(swFactory *factory);
static int swFactoryProcess_notify(swFactory *factory, swDataHead *event);
static int swFactoryProcess_dispatch(swFactory *factory, swSendData *data);
static int swFactoryProcess_finish(swFactory *factory, swSendData *data);
static int swFactoryProcess_shutdown(swFactory *factory);
static int swFactoryProcess_end(swFactory *factory, int fd);
static void swFactoryProcess_free(swFactory *factory);
static int swFactoryProcess_create_pipes(swFactory *factory);

static int process_send_packet(
    swServer *serv, swPipeBuffer *buf, swSendData *resp, send_func_t _send, void *private_data);
static int process_sendto_worker(swServer *serv, swPipeBuffer *buf, size_t n, void *private_data);
static int process_sendto_reactor(swServer *serv, swPipeBuffer *buf, size_t n, void *private_data);

int swFactoryProcess_create(swFactory *factory, uint32_t worker_num) {
    swFactoryProcess *object = (swFactoryProcess *) sw_malloc(sizeof(swFactoryProcess));
    if (object == nullptr) {
        swWarn("[Master] malloc[object] failed");
        return SW_ERR;
    }

    factory->object = object;
    factory->dispatch = swFactoryProcess_dispatch;
    factory->finish = swFactoryProcess_finish;
    factory->start = swFactoryProcess_start;
    factory->notify = swFactoryProcess_notify;
    factory->shutdown = swFactoryProcess_shutdown;
    factory->end = swFactoryProcess_end;
    factory->free = swFactoryProcess_free;

    return SW_OK;
}

static int swFactoryProcess_shutdown(swFactory *factory) {
    int status;
    swServer *serv = (swServer *) factory->ptr;

    if (swoole_kill(serv->gs->manager_pid, SIGTERM) < 0) {
        swSysWarn("swKill(%d) failed", serv->gs->manager_pid);
    }

    if (swoole_waitpid(serv->gs->manager_pid, &status, 0) < 0) {
        swSysWarn("waitpid(%d) failed", serv->gs->manager_pid);
    }

    return SW_OK;
}

static void swFactoryProcess_free(swFactory *factory) {
    swServer *serv = (swServer *) factory->ptr;
    swFactoryProcess *object = (swFactoryProcess *) serv->factory.object;

    uint32_t i;

    for (i = 0; i < serv->reactor_num; i++) {
        sw_free(serv->pipe_buffers[i]);
    }
    sw_free(serv->pipe_buffers);

    if (serv->stream_socket_file) {
        unlink(serv->stream_socket_file);
        sw_free(serv->stream_socket_file);
        swSocket_free(serv->stream_socket);
    }

    for (i = 0; i < serv->worker_num; i++) {
        object->pipes[i].close(&object->pipes[i]);
    }

    sw_free(object->send_buffer);
    sw_free(object->pipes);
    sw_free(object);
}

static int swFactoryProcess_create_pipes(swFactory *factory) {
    swServer *serv = (swServer *) factory->ptr;
    swFactoryProcess *object = (swFactoryProcess *) serv->factory.object;

    object->pipes = (swPipe *) sw_calloc(serv->worker_num, sizeof(swPipe));
    if (object->pipes == nullptr) {
        swSysError("malloc[pipes] failed");
        return SW_ERR;
    }

    for (uint32_t i = 0; i < serv->worker_num; i++) {
        int kernel_buffer_size = SW_UNIXSOCK_MAX_BUF_SIZE;

        if (swPipeUnsock_create(&object->pipes[i], 1, SOCK_DGRAM) < 0) {
            sw_free(object->pipes);
            object->pipes = nullptr;
            return SW_ERR;
        }

        serv->workers[i].pipe_master = object->pipes[i].getSocket(&object->pipes[i], SW_PIPE_MASTER);
        serv->workers[i].pipe_worker = object->pipes[i].getSocket(&object->pipes[i], SW_PIPE_WORKER);

        setsockopt(
            serv->workers[i].pipe_master->fd, SOL_SOCKET, SO_SNDBUF, &kernel_buffer_size, sizeof(kernel_buffer_size));
        setsockopt(
            serv->workers[i].pipe_worker->fd, SOL_SOCKET, SO_SNDBUF, &kernel_buffer_size, sizeof(kernel_buffer_size));

        serv->workers[i].pipe_object = &object->pipes[i];
        swServer_store_pipe_fd(serv, serv->workers[i].pipe_object);
    }

    return SW_OK;
}

static int swFactoryProcess_start(swFactory *factory) {
    swServer *serv = (swServer *) factory->ptr;
    swFactoryProcess *object = (swFactoryProcess *) serv->factory.object;

    if (serv->dispatch_mode == SW_DISPATCH_STREAM) {
        serv->stream_socket_file = swoole_string_format(64, "/tmp/swoole.%d.sock", serv->gs->master_pid);
        if (serv->stream_socket_file == nullptr) {
            return SW_ERR;
        }
        swSocket *sock = swSocket_create_server(SW_SOCK_UNIX_STREAM, serv->stream_socket_file, 0, 2048);
        if (sock == nullptr) {
            return SW_ERR;
        }
        serv->stream_socket = sock;
        swoole_fcntl_set_option(sock->fd, 1, 1);
        serv->stream_socket->nonblock = 1;
        serv->stream_socket->cloexec = 1;
    }

    for (uint32_t i = 0; i < serv->worker_num; i++) {
        if (serv->create_worker(serv->get_worker(i)) < 0) {
            return SW_ERR;
        }
    }

    serv->reactor_pipe_num = serv->worker_num / serv->reactor_num;

    if (swFactoryProcess_create_pipes(factory) < 0) {
        return SW_ERR;
    }

    serv->set_ipc_max_size();
    if (serv->create_pipe_buffers() < 0) {
        return SW_ERR;
    }

    object->send_buffer = (swPipeBuffer *) sw_malloc(serv->ipc_max_size);
    if (object->send_buffer == nullptr) {
        swSysError("malloc[send_buffer] failed");
        return SW_ERR;
    }
    sw_memset_zero(object->send_buffer, sizeof(swDataHead));

    /**
     * The manager process must be started first, otherwise it will have a thread fork
     */
    if (serv->start_manager_process() < 0) {
        swWarn("swFactoryProcess_manager_start failed");
        return SW_ERR;
    }
    factory->finish = swFactory_finish;
    return SW_OK;
}

/**
 * [ReactorThread] notify info to worker process
 */
static int swFactoryProcess_notify(swFactory *factory, swDataHead *ev) {
    swSendData task;
    task.info = *ev;
    task.data = nullptr;
    return swFactoryProcess_dispatch(factory, &task);
}

static inline int process_sendto_worker(swServer *serv, swPipeBuffer *buf, size_t n, void *private_data) {
    return serv->send_to_worker_from_master((swWorker *) private_data, buf, n);
}

static inline int process_sendto_reactor(swServer *serv, swPipeBuffer *buf, size_t n, void *private_data) {
    return serv->send_to_reactor_thread((swEventData *) buf, n, ((swConnection *) private_data)->session_id);
}

/**
 * [ReactorThread] dispatch request to worker
 */
static int swFactoryProcess_dispatch(swFactory *factory, swSendData *task) {
    swServer *serv = (swServer *) factory->ptr;
    int fd = task->info.fd;

    int target_worker_id = swServer_worker_schedule(serv, fd, task);
    if (target_worker_id < 0) {
        switch (target_worker_id) {
        case SW_DISPATCH_RESULT_DISCARD_PACKET:
            return SW_ERR;
        case SW_DISPATCH_RESULT_CLOSE_CONNECTION:
            // TODO: close connection
            return SW_ERR;
        default:
            swWarn("invalid target worker id[%d]", target_worker_id);
            return SW_ERR;
        }
    }

    if (swEventData_is_stream(task->info.type)) {
        swConnection *conn = serv->get_connection(fd);
        if (conn == nullptr || conn->active == 0) {
            swWarn("dispatch[type=%d] failed, connection#%d is not active", task->info.type, fd);
            return SW_ERR;
        }
        // server active close, discard data.
        if (conn->closed) {
            // Connection has been clsoed by server
            if (!(task->info.type == SW_SERVER_EVENT_CLOSE && conn->close_force)) {
                return SW_OK;
            }
        }
        // converted fd to session_id
        task->info.fd = conn->session_id;
        task->info.server_fd = conn->server_fd;
    }

    swWorker *worker = serv->get_worker(target_worker_id);

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
    swPipeBuffer *buf = serv->pipe_buffers[SwooleTG.id];
    buf->info = task->info;

    return process_send_packet(serv, buf, task, process_sendto_worker, worker);
}

/**
 * @description: master process send data to worker process.
 *  If the data sent is larger than swServer::ipc_max_size, then it is sent in chunks. Otherwise send it directly。
 * @return: send success returns SW_OK, send failure returns SW_ERR.
 */
static int process_send_packet(
    swServer *serv, swPipeBuffer *buf, swSendData *resp, send_func_t _send, void *private_data) {
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
        return retval < 0 ? SW_ERR : SW_OK;
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
            return SW_ERR;
        }

        send_n -= copy_n;
        offset += copy_n;
    }

    return SW_OK;
}

static bool inline process_is_supported_send_yield(swServer *serv, swConnection *conn) {
    if (!swServer_dispatch_mode_is_mod(serv)) {
        return false;
    } else {
        return swServer_worker_schedule(serv, conn->fd, nullptr) == (int) SwooleG.process_id;
    }
}

/**
 * [Worker] send to client, proxy by reactor
 */
static int swFactoryProcess_finish(swFactory *factory, swSendData *resp) {
    swServer *serv = (swServer *) factory->ptr;
    swFactoryProcess *object = (swFactoryProcess *) serv->factory.object;

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
        return SW_ERR;
    }

    int session_id = resp->info.fd;
    swConnection *conn;
    if (resp->info.type != SW_SERVER_EVENT_CLOSE) {
        conn = serv->get_connection_verify(session_id);
    } else {
        conn = serv->get_connection_verify_no_ssl(session_id);
    }
    if (!conn) {
        swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SESSION_NOT_EXIST, "connection[fd=%d] does not exists", session_id);
        return SW_ERR;
    } else if ((conn->closed || conn->peer_closed) && resp->info.type != SW_SERVER_EVENT_CLOSE) {
        swoole_error_log(SW_LOG_NOTICE,
                         SW_ERROR_SESSION_CLOSED,
                         "send %d byte failed, because connection[fd=%d] is closed",
                         resp->info.len,
                         session_id);
        return SW_ERR;
    } else if (conn->overflow) {
        if (serv->send_yield && process_is_supported_send_yield(serv, conn)) {
            swoole_set_last_error(SW_ERROR_OUTPUT_SEND_YIELD);
        } else {
            swoole_error_log(SW_LOG_WARNING,
                             SW_ERROR_OUTPUT_BUFFER_OVERFLOW,
                             "send failed, connection[fd=%d] output buffer has been overflowed",
                             session_id);
        }
        return SW_ERR;
    }

    /**
     * stream
     */
    if (serv->last_stream_socket) {
        int _len = resp->info.len;
        int _header = htonl(_len + sizeof(resp->info));
        if (SwooleTG.reactor->write(SwooleTG.reactor, serv->last_stream_socket, (char *) &_header, sizeof(_header)) <
            0) {
            return SW_ERR;
        }
        if (SwooleTG.reactor->write(SwooleTG.reactor, serv->last_stream_socket, &resp->info, sizeof(resp->info)) < 0) {
            return SW_ERR;
        }
        if (SwooleTG.reactor->write(SwooleTG.reactor, serv->last_stream_socket, resp->data, _len) < 0) {
            return SW_ERR;
        }
        return SW_OK;
    }

    swPipeBuffer *buf = object->send_buffer;

    buf->info.fd = session_id;
    buf->info.type = resp->info.type;
    buf->info.reactor_id = conn->reactor_id;
    buf->info.server_fd = SwooleG.process_id;

    swTrace("worker_id=%d, type=%d", SwooleG.process_id, buf->info.type);

    return process_send_packet(serv, buf, resp, process_sendto_reactor, conn);
}

static int swFactoryProcess_end(swFactory *factory, int fd) {
    swServer *serv = (swServer *) factory->ptr;
    swSendData _send = {};
    swDataHead info = {};

    _send.info.fd = fd;
    _send.info.len = 0;
    _send.info.type = SW_SERVER_EVENT_CLOSE;

    swConnection *conn = serv->get_connection_by_session_id(fd);
    if (conn == nullptr || conn->active == 0) {
        swoole_set_last_error(SW_ERROR_SESSION_NOT_EXIST);
        return SW_ERR;
    } else if (conn->close_force) {
        goto _do_close;
    } else if (conn->closing) {
        swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SESSION_CLOSING, "The connection[%d] is closing", fd);
        return SW_ERR;
    } else if (conn->closed) {
        return SW_ERR;
    } else {
    _do_close:
        conn->closing = 1;
        if (serv->onClose != nullptr) {
            info.fd = fd;
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
