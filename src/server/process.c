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

#include "swoole.h"
#include "server.h"

#include <signal.h>

static int swFactoryProcess_start(swFactory *factory);
static int swFactoryProcess_notify(swFactory *factory, swDataHead *event);
static int swFactoryProcess_dispatch(swFactory *factory, swSendData *data);
static int swFactoryProcess_finish(swFactory *factory, swSendData *data);
static int swFactoryProcess_shutdown(swFactory *factory);
static int swFactoryProcess_end(swFactory *factory, int fd);

int swFactoryProcess_create(swFactory *factory, int worker_num)
{
    swFactoryProcess *object;
    object = SwooleG.memory_pool->alloc(SwooleG.memory_pool, sizeof(swFactoryProcess));
    if (object == NULL)
    {
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

    return SW_OK;
}

static int swFactoryProcess_shutdown(swFactory *factory)
{
    int status;
    swServer *serv = factory->ptr;

    if (swKill(serv->gs->manager_pid, SIGTERM) < 0)
    {
        swSysError("swKill(%d) failed.", serv->gs->manager_pid);
    }

    if (swWaitpid(serv->gs->manager_pid, &status, 0) < 0)
    {
        swSysError("waitpid(%d) failed.", serv->gs->manager_pid);
    }

    return SW_OK;
}

static int swFactoryProcess_start(swFactory *factory)
{
    int i;
    swServer *serv = factory->ptr;

    if (serv->dispatch_mode == SW_DISPATCH_STREAM)
    {
        serv->stream_socket = swoole_string_format(64, "/tmp/swoole.%d.sock", serv->gs->master_pid);
        if (serv->stream_socket == NULL)
        {
            return SW_ERR;
        }
        int _reuse_port = SwooleG.reuse_port;
        SwooleG.reuse_port = 0;
        serv->stream_fd = swSocket_create_server(SW_SOCK_UNIX_STREAM, serv->stream_socket, 0, 2048);
        if (serv->stream_fd < 0)
        {
            return SW_ERR;
        }
        swoole_fcntl_set_option(serv->stream_fd, 1, 1);
        SwooleG.reuse_port = _reuse_port;
    }

    for (i = 0; i < serv->worker_num; i++)
    {
        if (swServer_worker_create(serv, swServer_get_worker(serv, i)) < 0)
        {
            return SW_ERR;
        }
    }

    serv->reactor_pipe_num = serv->worker_num / serv->reactor_num;

    /**
     * The manager process must be started first, otherwise it will have a thread fork
     */
    if (swManager_start(factory) < 0)
    {
        swWarn("swFactoryProcess_manager_start failed.");
        return SW_ERR;
    }
    factory->finish = swFactory_finish;
    return SW_OK;
}

/**
 * [ReactorThread] notify info to worker process
 */
static int swFactoryProcess_notify(swFactory *factory, swDataHead *ev)
{
    swSendData task;
    task.info = *ev;
    task.length = 0;
    task.data = NULL;
    return swFactoryProcess_dispatch(factory, &task);
}

/**
 * [ReactorThread] dispatch request to worker
 */
static int swFactoryProcess_dispatch(swFactory *factory, swSendData *task)
{
    swServer *serv = (swServer *) factory->ptr;
    int fd = task->info.fd;

    int target_worker_id = swServer_worker_schedule(serv, fd, task);
    if (target_worker_id < 0)
    {
        switch (target_worker_id)
        {
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

    if (swEventData_is_stream(task->info.type))
    {
        swConnection *conn = swServer_connection_get(serv, fd);
        if (conn == NULL || conn->active == 0)
        {
            swWarn("dispatch[type=%d] failed, connection#%d is not active.", task->info.type, fd);
            return SW_ERR;
        }
        //server active close, discard data.
        if (conn->closed)
        {
            //Connection has been clsoed by server
            if (!(task->info.type == SW_EVENT_CLOSE && conn->close_force))
            {
                return SW_OK;
            }
        }
        //converted fd to session_id
        task->info.fd = conn->session_id;
        task->info.from_fd = conn->from_fd;
    }

    swWorker *worker = swServer_get_worker(serv, target_worker_id);

    //without data
    if (task->data == NULL)
    {
        task->info.flags = 0;
        return swReactorThread_send2worker(serv, worker, &task->info, sizeof(task->info));
    }

    switch (task->info.type)
    {
    case SW_EVENT_TCP6:
    case SW_EVENT_TCP:
    case SW_EVENT_UNIX_STREAM:
    case SW_EVENT_UDP:
    case SW_EVENT_UDP6:
    case SW_EVENT_UNIX_DGRAM:
        worker->dispatch_count++;
        break;
    }

    uint32_t send_n = task->length;
    uint32_t offset = 0;
    swEventData buf;
    char *data = task->data;

    buf.info = task->info;

    if (send_n <= SW_IPC_BUFFER_SIZE)
    {
        buf.info.flags = 0;
        buf.info.len = send_n;
        memcpy(buf.data, data, buf.info.len);
        return swReactorThread_send2worker(serv, worker, &buf, sizeof(buf.info) + buf.info.len);
    }

    buf.info.flags = SW_EVENT_DATA_CHUNK;

    while (send_n > 0)
    {
        if (send_n > SW_IPC_BUFFER_SIZE)
        {
            buf.info.len = SW_IPC_BUFFER_SIZE;
        }
        else
        {
            buf.info.flags |= SW_EVENT_DATA_END;
            buf.info.len = send_n;
        }

        memcpy(buf.data, data + offset, buf.info.len);

        send_n -= buf.info.len;
        offset += buf.info.len;

        swTrace("dispatch, type=%d|len=%d", buf.info.type, buf.info.len);

        if (swReactorThread_send2worker(serv, worker, &buf, sizeof(buf.info) + buf.info.len) < 0)
        {
            return SW_ERR;
        }
    }

    return SW_OK;
}

/**
 * worker: send to client
 */
static int swFactoryProcess_finish(swFactory *factory, swSendData *resp)
{
    int ret, sendn;
    swServer *serv = factory->ptr;

    /**
     * More than the output buffer
     */
    if (resp->length > serv->buffer_output_size)
    {
        swoole_error_log(
            SW_LOG_WARNING, SW_ERROR_DATA_LENGTH_TOO_LARGE,
            "The length of data [%u] exceeds the output buffer size[%u], "
            "please use the sendfile, chunked transfer mode or adjust the buffer_output_size.",
            resp->length, serv->buffer_output_size
        );
        return SW_ERR;
    }

    int session_id = resp->info.fd;
    swConnection *conn;
    if (resp->info.type != SW_EVENT_CLOSE)
    {
        conn = swServer_connection_verify(serv, session_id);
    }
    else
    {
        conn = swServer_connection_verify_no_ssl(serv, session_id);
    }
    if (!conn)
    {
        swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SESSION_NOT_EXIST, "connection[fd=%d] does not exists.", session_id);
        return SW_ERR;
    }
    else if ((conn->closed || conn->removed) && resp->info.type != SW_EVENT_CLOSE)
    {
        int _len = resp->length > 0 ? resp->length : resp->info.len;
        swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SESSION_CLOSED, "send %d byte failed, because connection[fd=%d] is closed.", _len, session_id);
        return SW_ERR;
    }
    else if (conn->overflow)
    {
        if (serv->send_yield)
        {
            SwooleG.error = SW_ERROR_OUTPUT_BUFFER_OVERFLOW;
        }
        else
        {
            swoole_error_log(SW_LOG_WARNING, SW_ERROR_OUTPUT_BUFFER_OVERFLOW, "send failed, connection[fd=%d] output buffer has been overflowed.", session_id);
        }
        return SW_ERR;
    }

    swEventData ev_data = {{0}};
    ev_data.info.fd = session_id;
    ev_data.info.type = resp->info.type;
    swWorker *worker = swServer_get_worker(serv, SwooleWG.id);

    /**
     * stream
     */
    if (serv->last_stream_fd > 0)
    {
        int _len = resp->length > 0 ? resp->length : resp->info.len;
        int _header = htonl(_len + sizeof(resp->info));
        if (SwooleG.main_reactor->write(SwooleG.main_reactor, serv->last_stream_fd, (char*) &_header, sizeof(_header)) < 0)
        {
            return SW_ERR;
        }
        if (SwooleG.main_reactor->write(SwooleG.main_reactor, serv->last_stream_fd, &resp->info, sizeof(resp->info)) < 0)
        {
            return SW_ERR;
        }
        if (SwooleG.main_reactor->write(SwooleG.main_reactor, serv->last_stream_fd, resp->data, _len) < 0)
        {
            return SW_ERR;
        }
        return SW_OK;
    }

    /**
     * Big response, use shared memory
     */
    if (resp->length > SW_IPC_BUFFER_SIZE)
    {
        if (worker == NULL || worker->send_shm == NULL)
        {
            goto pack_data;
        }

        //worker process
        if (SwooleG.main_reactor)
        {
            int _pipe_fd = swWorker_get_send_pipe(serv, session_id, conn->from_id);
            swConnection *_pipe_socket = swReactor_get(SwooleG.main_reactor, _pipe_fd);

            //cannot use send_shm
            if (!swBuffer_empty(_pipe_socket->out_buffer))
            {
                pack_data:
                if (swTaskWorker_large_pack(&ev_data, resp->data, resp->length) < 0)
                {
                    return SW_ERR;
                }
                ev_data.info.from_fd = SW_RESPONSE_TMPFILE;
                goto send_to_reactor_thread;
            }
        }

        swPackage_response response;
        response.length = resp->length;
        response.worker_id = SwooleWG.id;
        ev_data.info.from_fd = SW_RESPONSE_SHM;
        ev_data.info.len = sizeof(response);
        memcpy(ev_data.data, &response, sizeof(response));

        swTrace("[Worker] big response, length=%d|worker_id=%d", response.length, response.worker_id);

        worker->lock.lock(&worker->lock);
        memcpy(worker->send_shm, resp->data, resp->length);
    }
    else
    {
        //copy data
        memcpy(ev_data.data, resp->data, resp->length);
        ev_data.info.len = resp->length;
        ev_data.info.from_fd = SW_RESPONSE_SMALL;
    }

    send_to_reactor_thread: ev_data.info.from_id = conn->from_id;
    sendn = ev_data.info.len + sizeof(resp->info);

    swTrace("[Worker] send: sendn=%d|type=%d|content=<<EOF\n%.*s\nEOF", sendn, resp->info.type, resp->length > 0 ? resp->length : resp->info.len, resp->data);
    ret = swWorker_send2reactor(serv, &ev_data, sendn, session_id);
    if (ret < 0)
    {
        swWarn("sendto to reactor failed. Error: %s [%d]", strerror(errno), errno);
    }
    return ret;
}

static int swFactoryProcess_end(swFactory *factory, int fd)
{
    swServer *serv = factory->ptr;
    swSendData _send;
    swDataHead info;

    bzero(&_send, sizeof(_send));
    _send.info.fd = fd;
    _send.info.len = 0;
    _send.info.type = SW_EVENT_CLOSE;

    swConnection *conn = swWorker_get_connection(serv, fd);
    if (conn == NULL || conn->active == 0)
    {
        SwooleG.error = SW_ERROR_SESSION_NOT_EXIST;
        return SW_ERR;
    }
    else if (conn->close_force)
    {
        goto do_close;
    }
    else if (conn->closing)
    {
        swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SESSION_CLOSING, "The connection[%d] is closing.", fd);
        return SW_ERR;
    }
    else if (conn->closed)
    {
        return SW_ERR;
    }
    else
    {
        do_close:
        conn->closing = 1;
        if (serv->onClose != NULL)
        {
            info.fd = fd;
            if (conn->close_actively)
            {
                info.from_id = -1;
            }
            else
            {
                info.from_id = conn->from_id;
            }
            info.from_fd = conn->from_fd;
            serv->onClose(serv, &info);
        }
        conn->closing = 0;
        conn->closed = 1;
        conn->close_errno = 0;
        return factory->finish(factory, &_send);
    }
}
