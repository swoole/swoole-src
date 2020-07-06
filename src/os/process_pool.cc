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

#include "server.h"
#include "client.h"

/**
 * call onTask
 */
static int swProcessPool_worker_loop(swProcessPool *pool, swWorker *worker);
/**
 * call onMessage
 */
static int swProcessPool_worker_loop_ex(swProcessPool *pool, swWorker *worker);

static void swProcessPool_kill_timeout_worker(swTimer *timer, swTimer_node *tnode)
{
    uint32_t i;
    pid_t reload_worker_pid = 0;
    swProcessPool *pool = (swProcessPool *)tnode->data;
    pool->reloading = 0;

    for (i = 0; i < pool->worker_num; i++)
    {
        if (i >= pool->reload_worker_i)
        {
            reload_worker_pid = pool->reload_workers[i].pid;
            if (swoole_kill(reload_worker_pid, 0) == -1)
            {
                continue;
            }
            if (swoole_kill(reload_worker_pid, SIGKILL) < 0)
            {
                swSysWarn("swKill(%d, SIGKILL) [%d] failed", pool->reload_workers[i].pid, i);
            }
            else
            {
                swWarn("swKill(%d, SIGKILL) [%d]", pool->reload_workers[i].pid, i);
            }
        }
    }
    errno = 0;
    pool->reload_worker_i = 0;
    pool->reload_init = 0;
}
/**
 * Process manager
 */
int swProcessPool_create(swProcessPool *pool, uint32_t worker_num, key_t msgqueue_key, int ipc_mode)
{
    sw_memset_zero(pool, sizeof(swProcessPool));

    uint32_t i;

    pool->worker_num = worker_num;

    /**
     * Shared memory is used here
     */
    pool->workers = (swWorker *) SwooleG.memory_pool->alloc(SwooleG.memory_pool, worker_num * sizeof(swWorker));
    if (pool->workers == nullptr)
    {
        swSysWarn("malloc[1] failed");
        return SW_ERR;
    }

    if (ipc_mode == SW_IPC_MSGQUEUE)
    {
        pool->use_msgqueue = 1;
        pool->msgqueue_key = msgqueue_key;

        pool->queue = (swMsgQueue *) sw_malloc(sizeof(swMsgQueue));
        if (pool->queue == nullptr)
        {
            swSysWarn("malloc[2] failed");
            return SW_ERR;
        }

        if (swMsgQueue_create(pool->queue, 1, pool->msgqueue_key, 0) < 0)
        {
            return SW_ERR;
        }
    }
    else if (ipc_mode == SW_IPC_UNIXSOCK)
    {
        pool->pipes = (swPipe *) sw_calloc(worker_num, sizeof(swPipe));
        if (pool->pipes == nullptr)
        {
            swWarn("malloc[2] failed");
            return SW_ERR;
        }

        swPipe *pipe;
        for (i = 0; i < worker_num; i++)
        {
            pipe = &pool->pipes[i];
            if (swPipeUnsock_create(pipe, 1, SOCK_DGRAM) < 0)
            {
                return SW_ERR;
            }          
            pool->workers[i].pipe_master = pipe->getSocket(pipe, SW_PIPE_MASTER);
            pool->workers[i].pipe_worker = pipe->getSocket(pipe, SW_PIPE_WORKER);
            pool->workers[i].pipe_object = pipe;
        }
    }
    else if (ipc_mode == SW_IPC_SOCKET)
    {
        pool->use_socket = 1;
        pool->stream = (swStreamInfo *) sw_malloc(sizeof(swStreamInfo));
        if (pool->stream == nullptr)
        {
            swWarn("malloc[2] failed");
            return SW_ERR;
        }
        sw_memset_zero(pool->stream, sizeof(swStreamInfo));
    }
    else
    {
        ipc_mode = SW_IPC_NONE;
    }

    pool->map = swHashMap_new(SW_HASHMAP_INIT_BUCKET_N, nullptr);
    if (pool->map == nullptr)
    {
        swProcessPool_free(pool);
        return SW_ERR;
    }

    pool->ipc_mode = ipc_mode;
    if (ipc_mode > SW_IPC_NONE)
    {
        pool->main_loop = swProcessPool_worker_loop;
    }

    for (i = 0; i < worker_num; i++)
    {
        pool->workers[i].pool = pool;
    }

    return SW_OK;
}

int swProcessPool_create_unix_socket(swProcessPool *pool, const char *socket_file, int blacklog)
{
    if (pool->ipc_mode != SW_IPC_SOCKET)
    {
        swWarn("ipc_mode is not SW_IPC_SOCKET");
        return SW_ERR;
    }
    pool->stream->socket_file = sw_strdup(socket_file);
    if (pool->stream->socket_file == nullptr)
    {
        return SW_ERR;
    }
    pool->stream->socket = swSocket_create_server(SW_SOCK_UNIX_STREAM, pool->stream->socket_file, 0, blacklog);
    if (!pool->stream->socket)
    {
        return SW_ERR;
    }
    return SW_OK;
}

int swProcessPool_create_tcp_socket(swProcessPool *pool, const char *host, int port, int blacklog)
{
    if (pool->ipc_mode != SW_IPC_SOCKET)
    {
        swWarn("ipc_mode is not SW_IPC_SOCKET");
        return SW_ERR;
    }
    pool->stream->socket_file = sw_strdup(host);
    if (pool->stream->socket_file == nullptr)
    {
        return SW_ERR;
    }
    pool->stream->socket = swSocket_create_server(SW_SOCK_TCP, host, port, blacklog);
    if (!pool->stream->socket)
    {
        return SW_ERR;
    }
    return SW_OK;
}

/**
 * start workers
 */
int swProcessPool_start(swProcessPool *pool)
{
    if (pool->ipc_mode == SW_IPC_SOCKET && (pool->stream == nullptr || pool->stream->socket == 0))
    {
        swWarn("must first listen to an tcp port");
        return SW_ERR;
    }

    uint32_t i;
    pool->started = 1;
    pool->running = 1;

    for (i = 0; i < pool->worker_num; i++)
    {
        pool->workers[i].pool = pool;
        pool->workers[i].id = pool->start_id + i;
        pool->workers[i].type = pool->type;
    }

    for (i = 0; i < pool->worker_num; i++)
    {
        if (swProcessPool_spawn(pool, &(pool->workers[i])) < 0)
        {
            return SW_ERR;
        }
    }

    return SW_OK;
}

static sw_inline int swProcessPool_schedule(swProcessPool *pool)
{
    if (pool->dispatch_mode == SW_DISPATCH_QUEUE)
    {
        return 0;
    }

    uint32_t i, target_worker_id = 0;
    uint8_t found = 0;

    for (i = 0; i < pool->worker_num + 1; i++)
    {
        target_worker_id = sw_atomic_fetch_add(&pool->round_id, 1) % pool->worker_num;
        if (pool->workers[target_worker_id].status == SW_WORKER_IDLE)
        {
            found = 1;
            break;
        }
    }
    if (found == 0)
    {
        pool->scheduler_warning = 1;
    }
    return target_worker_id;
}

int swProcessPool_response(swProcessPool *pool, const char *data, int length)
{
    if (pool->stream == nullptr || pool->stream->last_connection == nullptr || pool->stream->response_buffer == nullptr)
    {
        swoole_set_last_error(SW_ERROR_INVALID_PARAMS);
        return SW_ERR;
    }
    return swString_append_ptr(pool->stream->response_buffer, data, length);
}

/**
 * dispatch data to worker
 */
int swProcessPool_dispatch(swProcessPool *pool, swEventData *data, int *dst_worker_id)
{
    int ret = 0;
    swWorker *worker;

    if (pool->use_socket)
    {
        swStream *stream = swStream_new(pool->stream->socket_file, 0, SW_SOCK_UNIX_STREAM);
        if (stream == nullptr)
        {
            return SW_ERR;
        }
        stream->response = nullptr;
        if (swStream_send(stream, (char*) data, sizeof(data->info) + data->info.len) < 0)
        {
            stream->cancel = 1;
            return SW_ERR;
        }
        return SW_OK;
    }

    if (*dst_worker_id < 0)
    {
        *dst_worker_id = swProcessPool_schedule(pool);
    }

    *dst_worker_id += pool->start_id;
    worker = swProcessPool_get_worker(pool, *dst_worker_id);

    int sendn = sizeof(data->info) + data->info.len;
    ret = swWorker_send_pipe_message(worker, data, sendn, SW_PIPE_MASTER | SW_PIPE_NONBLOCK);

    if (ret >= 0)
    {
        sw_atomic_fetch_add(&worker->tasking_num, 1);
    }
    else
    {
        swWarn("send %d bytes to worker#%d failed", sendn, *dst_worker_id);
    }

    return ret;
}

/**
 * dispatch data to worker
 */
int swProcessPool_dispatch_blocking(swProcessPool *pool, swEventData *data, int *dst_worker_id)
{
    int ret = 0;
    int sendn = sizeof(data->info) + data->info.len;

    if (pool->use_socket)
    {
        swClient _socket;
        if (swClient_create(&_socket, SW_SOCK_UNIX_STREAM, SW_SOCK_SYNC) < 0)
        {
            return SW_ERR;
        }
        if (_socket.connect(&_socket, pool->stream->socket_file, 0, -1, 0) < 0)
        {
            return SW_ERR;
        }
        if (_socket.send(&_socket, (char*) data, sendn, 0) < 0)
        {
            return SW_ERR;
        }
        _socket.close(&_socket);
        return SW_OK;
    }

    if (*dst_worker_id < 0)
    {
        *dst_worker_id = swProcessPool_schedule(pool);
    }

    *dst_worker_id += pool->start_id;
    swWorker *worker = swProcessPool_get_worker(pool, *dst_worker_id);

    ret = swWorker_send_pipe_message(worker, data, sendn, SW_PIPE_MASTER);
    if (ret < 0)
    {
        swWarn("send %d bytes to worker#%d failed", sendn, *dst_worker_id);
    }
    else
    {
        sw_atomic_fetch_add(&worker->tasking_num, 1);
    }

    return ret;
}

void swProcessPool_shutdown(swProcessPool *pool)
{
    uint32_t i;
    int status;
    swWorker *worker;
    pool->running = 0;

    swSignal_none();
    //concurrent kill
    for (i = 0; i < pool->worker_num; i++)
    {
        worker = &pool->workers[i];
        if (swoole_kill(worker->pid, SIGTERM) < 0)
        {
            swSysWarn("swKill(%d) failed", worker->pid);
            continue;
        }
    }
    for (i = 0; i < pool->worker_num; i++)
    {
        worker = &pool->workers[i];
        if (swoole_waitpid(worker->pid, &status, 0) < 0)
        {
            swSysWarn("waitpid(%d) failed", worker->pid);
        }
    }
    swProcessPool_free(pool);
    pool->started = 0;
}

pid_t swProcessPool_spawn(swProcessPool *pool, swWorker *worker)
{
    pid_t pid = swoole_fork(0);
    int ret_code = 0;

    switch (pid)
    {
    //child
    case 0:
        /**
         * Process start
         */
        if (pool->onWorkerStart != nullptr)
        {
            pool->onWorkerStart(pool, worker->id);
        }
        /**
         * Process main loop
         */
        if (pool->main_loop)
        {
            ret_code = pool->main_loop(pool, worker);
        }
        /**
         * Process stop
         */
        if (pool->onWorkerStop != nullptr)
        {
            pool->onWorkerStop(pool, worker->id);
        }
        exit(ret_code);
        break;
    case -1:
        swSysWarn("fork() failed");
        break;
        //parent
    default:
        //remove old process
        if (worker->pid)
        {
            swHashMap_del_int(pool->map, worker->pid);
        }
        worker->pid = pid;
        //insert new process
        swHashMap_add_int(pool->map, pid, worker);
        break;
    }
    return pid;
}

int swProcessPool_get_max_request(swProcessPool *pool)
{
    int task_n;
    if (pool->max_request < 1)
    {
        return -1;
    }
    else
    {
        task_n = pool->max_request;
        if (pool->max_request_grace > 0)
        {
            task_n += swoole_system_random(1, pool->max_request_grace);
        }
    }
    return task_n;
}

void swProcessPool_set_max_request(swProcessPool *pool, uint32_t max_request, uint32_t max_request_grace)
{
    pool->max_request = max_request;
    pool->max_request_grace = max_request_grace;
}

static int swProcessPool_worker_loop(swProcessPool *pool, swWorker *worker)
{
    struct
    {
        long mtype;
        swEventData buf;
    } out;

    int n = 0, ret, worker_task_always = 0;
    int task_n = swProcessPool_get_max_request(pool);
    if (task_n <= 0)
    {
        worker_task_always = 1;
        task_n = 1;
    }

    /**
     * Use from_fd save the task_worker->id
     */
    out.buf.info.server_fd = worker->id;

    if (pool->dispatch_mode == SW_DISPATCH_QUEUE)
    {
        out.mtype = 0;
    }
    else
    {
        out.mtype = worker->id + 1;
    }

    while (pool->running && !SwooleWG.shutdown && task_n > 0)
    {
        /**
         * fetch task
         */
        if (pool->use_msgqueue)
        {
            n = swMsgQueue_pop(pool->queue, (swQueue_data *) &out, sizeof(out.buf));
            if (n < 0 && errno != EINTR)
            {
                swSysWarn("[Worker#%d] msgrcv() failed", worker->id);
                break;
            }
        }
        else if (pool->use_socket)
        {
            swSocketAddress sa;
            swSocket *conn = swSocket_accept(pool->stream->socket, &sa);
            if (conn == nullptr)
            {
                if (errno == EAGAIN || errno == EINTR)
                {
                    continue;
                }
                else
                {
                    swSysWarn("accept(%d) failed", pool->stream->socket);
                    break;
                }
            }

            n = swStream_recv_blocking(conn, (void*) &out.buf, sizeof(out.buf));
            if (n == SW_CLOSE)
            {
                swSocket_free(conn);
                continue;
            }
            pool->stream->last_connection = conn;
        }
        else
        {
            n = read(worker->pipe_worker->fd, &out.buf, sizeof(out.buf));
            if (n < 0 && errno != EINTR)
            {
                swSysWarn("[Worker#%d] read(%d) failed", worker->id, worker->pipe_worker->fd);
            }
        }

        /**
         * timer
         */
        if (n < 0)
        {
            if (errno == EINTR && SwooleWG.signal_alarm && SwooleTG.timer)
            {
                _alarm_handler:
                SwooleWG.signal_alarm = 0;
                swTimer_select(SwooleTG.timer);
            }
            continue;
        }

        /**
         * do task
         */
        worker->status = SW_WORKER_BUSY;
        ret = pool->onTask(pool, &out.buf);
        worker->status = SW_WORKER_IDLE;

        if (pool->use_socket && pool->stream->last_connection)
        {
            int _end = 0;
            swSocket_write_blocking(pool->stream->last_connection, (void *) &_end, sizeof(_end));
            swSocket_free(pool->stream->last_connection);
            pool->stream->last_connection = nullptr;
        }

        /**
         * timer
         */
        if (SwooleWG.signal_alarm)
        {
            goto _alarm_handler;
        }

        if (ret >= 0 && !worker_task_always)
        {
            task_n--;
        }
    }
    return SW_OK;
}

int swProcessPool_set_protocol(swProcessPool *pool, int task_protocol, uint32_t max_packet_size)
{
    if (task_protocol)
    {
        pool->main_loop = swProcessPool_worker_loop;
    }
    else
    {
        pool->packet_buffer = (char *) sw_malloc(max_packet_size);
        if (pool->packet_buffer == nullptr)
        {
            swSysWarn("malloc(%d) failed", max_packet_size);
            return SW_ERR;
        }
        if (pool->stream)
        {
            pool->stream->response_buffer = swString_new(SW_BUFFER_SIZE_STD);
            if (pool->stream->response_buffer == nullptr)
            {
                sw_free(pool->packet_buffer);
                return SW_ERR;
            }
        }
        pool->max_packet_size = max_packet_size;
        pool->main_loop = swProcessPool_worker_loop_ex;
    }

    return SW_OK;
}

static int swProcessPool_worker_loop_ex(swProcessPool *pool, swWorker *worker)
{
    uint32_t n;
    char *data;

    swQueue_data *outbuf = (swQueue_data *) pool->packet_buffer;
    outbuf->mtype = 0;

    while (pool->running)
    {
        /**
         * fetch task
         */
        if (pool->use_msgqueue)
        {
            n = swMsgQueue_pop(pool->queue, outbuf, SW_MSGMAX);
            if (n < 0 && errno != EINTR)
            {
                swSysWarn("[Worker#%d] msgrcv() failed", worker->id);
                break;
            }
            data = outbuf->mdata;
            outbuf->mtype = 0;
        }
        else if (pool->use_socket)
        {
            swSocketAddress sa;
            swSocket *conn = swSocket_accept(pool->stream->socket, &sa);
            if (conn == nullptr)
            {
                if (errno == EAGAIN || errno == EINTR)
                {
                    continue;
                }
                else
                {
                    swSysWarn("accept(%d) failed", pool->stream->socket);
                    break;
                }
            }
            int tmp = 0;
            if (swSocket_recv_blocking(conn, &tmp, sizeof(tmp), MSG_WAITALL) <= 0)
            {
                goto _close;
            }
            n = ntohl(tmp);
            if (n <= 0)
            {
                goto _close;
            }
            else if (n > pool->max_packet_size)
            {
                goto _close;
            }
            if (swSocket_recv_blocking(conn, pool->packet_buffer, n, MSG_WAITALL) <= 0)
            {
                _close:
                swSocket_free(conn);
                continue;
            }
            data = pool->packet_buffer;
            pool->stream->last_connection = conn;
        }
        else
        {
            n = read(worker->pipe_worker->fd, pool->packet_buffer, pool->max_packet_size);
            if (n < 0 && errno != EINTR)
            {
                swSysWarn("[Worker#%d] read(%d) failed", worker->id, worker->pipe_worker->fd);
            }
            data = pool->packet_buffer;
        }

        /**
         * timer
         */
        if (n < 0)
        {
            if (errno == EINTR && SwooleWG.signal_alarm && SwooleTG.timer)
            {
                _alarm_handler:
                SwooleWG.signal_alarm = 0;
                swTimer_select(SwooleTG.timer);
            }
            continue;
        }

        pool->onMessage(pool, data, n);

        if (pool->use_socket && pool->stream->last_connection)
        {
            swString *resp_buf = pool->stream->response_buffer;
            if (resp_buf && resp_buf->length > 0)
            {
                int _l = htonl(resp_buf->length);
                swSocket_write_blocking(pool->stream->last_connection, &_l, sizeof(_l));
                swSocket_write_blocking(pool->stream->last_connection, resp_buf->str, resp_buf->length);
                swString_clear(resp_buf);
            }
            swSocket_free(pool->stream->last_connection);
            pool->stream->last_connection = nullptr;
        }

        /**
         * timer
         */
        if (SwooleWG.signal_alarm)
        {
            goto _alarm_handler;
        }
    }
    return SW_OK;
}

/**
 * add a worker to pool
 */
int swProcessPool_add_worker(swProcessPool *pool, swWorker *worker)
{
    swHashMap_add_int(pool->map, worker->pid, worker);
    return SW_OK;
}

int swProcessPool_wait(swProcessPool *pool)
{
    int pid, new_pid;
    pid_t reload_worker_pid = 0;
    int ret;
    int status;

    pool->reload_workers = (swWorker *) sw_calloc(pool->worker_num, sizeof(swWorker));
    if (pool->reload_workers == nullptr)
    {
        swError("malloc[reload_workers] failed");
        return SW_ERR;
    }

    while (pool->running)
    {
        pid = wait(&status);
        if (SwooleWG.signal_alarm && SwooleTG.timer)
        {
            SwooleWG.signal_alarm = 0;
            swTimer_select(SwooleTG.timer);
        }
        if (pid < 0)
        {
            if (pool->running == 0)
            {
                break;
            }
            if (pool->reloading == 0)
            {
                if (errno > 0 && errno != EINTR)
                {
                    swSysWarn("[Manager] wait failed");
                }
                continue;
            }
            else
            {
                if (pool->reload_init == 0)
                {
                    swInfo("reload workers");
                    pool->reload_init = 1;
                    memcpy(pool->reload_workers, pool->workers, sizeof(swWorker) * pool->worker_num);
                    if (pool->max_wait_time)
                    {
                        swoole_timer_add((long) (pool->max_wait_time * 1000), SW_FALSE, swProcessPool_kill_timeout_worker, pool);
                    }
                }
                goto _kill_worker;
            }
        }

        if (pool->running == 1)
        {
            swWorker *exit_worker = (swWorker *) swHashMap_find_int(pool->map, pid);
            if (exit_worker == nullptr)
            {
                if (pool->onWorkerNotFound)
                {
                    pool->onWorkerNotFound(pool, pid, status);
                }
                else
                {
                    swWarn("[Manager]unknow worker[pid=%d]", pid);
                }
                continue;
            }
            if (!WIFEXITED(status))
            {
                swWarn(
                    "worker#%d abnormal exit, status=%d, signal=%d" "%s",
                    exit_worker->id, WEXITSTATUS(status),  WTERMSIG(status),
                    WTERMSIG(status) == SIGSEGV ? "\n" SWOOLE_BUG_REPORT : ""
                );
            }
            new_pid = swProcessPool_spawn(pool, exit_worker);
            if (new_pid < 0)
            {
                swSysWarn("Fork worker process failed");
                sw_free(pool->reload_workers);
                return SW_ERR;
            }
            swHashMap_del_int(pool->map, pid);
            if (pid == reload_worker_pid)
            {
                pool->reload_worker_i++;
            }
        }
        //reload worker
        _kill_worker:
        if (pool->reloading == 1)
        {
            //reload finish
            if (pool->reload_worker_i >= pool->worker_num)
            {
                pool->reloading = pool->reload_init = reload_worker_pid = pool->reload_worker_i = 0;
                continue;
            }
            reload_worker_pid = pool->reload_workers[pool->reload_worker_i].pid;
            ret = swoole_kill(reload_worker_pid, SIGTERM);
            if (ret < 0)
            {
                if (errno == ECHILD)
                {
                    pool->reload_worker_i++;
                    goto _kill_worker;
                }
                swSysWarn("[Manager]swKill(%d) failed", pool->reload_workers[pool->reload_worker_i].pid);
                continue;
            }
        }
    }
    sw_free(pool->reload_workers);
    pool->reload_workers = nullptr;
    return SW_OK;
}

void swProcessPool_free(swProcessPool *pool)
{
    uint32_t i;
    swPipe *_pipe;

    if (pool->pipes)
    {
        for (i = 0; i < pool->worker_num; i++)
        {
            _pipe = &pool->pipes[i];
            _pipe->close(_pipe);
        }
        sw_free(pool->pipes);
    }

    if (pool->use_msgqueue == 1 && pool->msgqueue_key == 0)
    {
        swMsgQueue_free(pool->queue);
    }

    if (pool->stream)
    {
        if (pool->stream->socket)
        {
            unlink(pool->stream->socket_file);
            sw_free((void*) pool->stream->socket_file);
        }
        if (pool->stream->socket)
        {
            swSocket_free(pool->stream->socket);
            pool->stream->socket = nullptr;
        }
        if (pool->stream->response_buffer)
        {
            swString_free(pool->stream->response_buffer);
        }
        sw_free(pool->stream);
    }

    if (pool->packet_buffer)
    {
        sw_free(pool->packet_buffer);
    }

    if (pool->map)
    {
        swHashMap_free(pool->map);
    }
}
