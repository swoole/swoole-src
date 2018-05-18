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
#include "Server.h"
#include "Client.h"

/**
 * call onTask
 */
static int swProcessPool_worker_loop(swProcessPool *pool, swWorker *worker);
/**
 * call onMessage
 */
static int swProcessPool_worker_loop_ex(swProcessPool *pool, swWorker *worker);

static void swProcessPool_free(swProcessPool *pool);

/**
 * Process manager
 */
int swProcessPool_create(swProcessPool *pool, int worker_num, int max_request, key_t msgqueue_key, int ipc_mode)
{
    bzero(pool, sizeof(swProcessPool));

    pool->worker_num = worker_num;
    pool->max_request = max_request;

    pool->workers = SwooleG.memory_pool->alloc(SwooleG.memory_pool, worker_num * sizeof(swWorker));
    if (pool->workers == NULL)
    {
        swSysError("malloc[1] failed.");
        return SW_ERR;
    }

    if (ipc_mode == SW_IPC_MSGQUEUE)
    {
        pool->use_msgqueue = 1;
        pool->msgqueue_key = msgqueue_key;

        pool->queue = sw_malloc(sizeof(swMsgQueue));
        if (pool->queue == NULL)
        {
            swSysError("malloc[2] failed.");
            return SW_ERR;
        }

        if (swMsgQueue_create(pool->queue, 1, pool->msgqueue_key, 0) < 0)
        {
            return SW_ERR;
        }
    }
    else if (ipc_mode == SW_IPC_SOCKET)
    {
        pool->use_socket = 1;
        pool->stream = sw_malloc(sizeof(swStreamInfo));
        if (pool->stream == NULL)
        {
            swWarn("malloc[2] failed.");
            return SW_ERR;
        }
        bzero(pool->stream, sizeof(swStreamInfo));
    }
    else if (ipc_mode == SW_IPC_UNIXSOCK)
    {
        pool->pipes = sw_calloc(worker_num, sizeof(swPipe));
        if (pool->pipes == NULL)
        {
            swWarn("malloc[2] failed.");
            return SW_ERR;
        }

        swPipe *pipe;
        int i;
        for (i = 0; i < worker_num; i++)
        {
            pipe = &pool->pipes[i];
            if (swPipeUnsock_create(pipe, 1, SOCK_DGRAM) < 0)
            {
                return SW_ERR;
            }
            pool->workers[i].pipe_master = pipe->getFd(pipe, SW_PIPE_MASTER);
            pool->workers[i].pipe_worker = pipe->getFd(pipe, SW_PIPE_WORKER);
            pool->workers[i].pipe_object = pipe;
        }
    }
    else
    {
        ipc_mode = SW_IPC_NONE;
    }

    pool->map = swHashMap_new(SW_HASHMAP_INIT_BUCKET_N, NULL);
    if (pool->map == NULL)
    {
        swProcessPool_free(pool);
        return SW_ERR;
    }

    pool->ipc_mode = ipc_mode;
    if (ipc_mode > SW_IPC_NONE)
    {
        pool->main_loop = swProcessPool_worker_loop;
    }

    return SW_OK;
}

int swProcessPool_create_unix_socket(swProcessPool *pool, char *socket_file, int blacklog)
{
    if (pool->ipc_mode != SW_IPC_SOCKET)
    {
        swWarn("ipc_mode is not SW_IPC_SOCKET.");
        return SW_ERR;
    }
    pool->stream->socket_file = sw_strdup(socket_file);
    if (pool->stream->socket_file == NULL)
    {
        return SW_ERR;
    }
    pool->stream->socket = swSocket_create_server(SW_SOCK_UNIX_STREAM, pool->stream->socket_file, 0, blacklog);
    if (pool->stream->socket < 0)
    {
        return SW_ERR;
    }
    return SW_OK;
}

int swProcessPool_create_tcp_socket(swProcessPool *pool, char *host, int port, int blacklog)
{
    if (pool->ipc_mode != SW_IPC_SOCKET)
    {
        swWarn("ipc_mode is not SW_IPC_SOCKET.");
        return SW_ERR;
    }
    pool->stream->socket_file = sw_strdup(host);
    if (pool->stream->socket_file == NULL)
    {
        return SW_ERR;
    }
    pool->stream->socket = swSocket_create_server(SW_SOCK_TCP, host, port, blacklog);
    if (pool->stream->socket < 0)
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
    if (pool->ipc_mode == SW_IPC_SOCKET && (pool->stream == NULL || pool->stream->socket == 0))
    {
        swWarn("must first listen to an tcp port.");
        return SW_ERR;
    }

    int i;
    pool->started = 1;
    pool->run_worker_num = pool->worker_num;

    for (i = 0; i < pool->worker_num; i++)
    {
        pool->workers[i].pool = pool;
        pool->workers[i].id = pool->start_id + i;
        pool->workers[i].type = pool->type;

        if (swProcessPool_spawn(&(pool->workers[i])) < 0)
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

    int i, target_worker_id = 0;
    int run_worker_num = pool->run_worker_num;

    for (i = 0; i < run_worker_num + 1; i++)
    {
        target_worker_id = sw_atomic_fetch_add(&pool->round_id, 1) % run_worker_num;
        if (pool->workers[target_worker_id].status == SW_WORKER_IDLE)
        {
            break;
        }
    }
    return target_worker_id;
}

int swProcessPool_response(swProcessPool *pool, char *data, int length)
{
    if (pool->stream == NULL || pool->stream->last_connection == 0 || pool->stream->response_buffer == NULL)
    {
        SwooleG.error = SW_ERROR_INVALID_PARAMS;
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
        if (stream == NULL)
        {
            return SW_ERR;
        }
        stream->response = NULL;
        stream->session_id = 0;
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
    ret = swWorker_send2worker(worker, data, sendn, SW_PIPE_MASTER | SW_PIPE_NONBLOCK);

    if (ret >= 0)
    {
        sw_atomic_fetch_add(&worker->tasking_num, 1);
    }
    else
    {
        swWarn("send %d bytes to worker#%d failed.", sendn, *dst_worker_id);
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
        if (_socket.send(&_socket, (void*) data, sendn, 0) < 0)
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

    ret = swWorker_send2worker(worker, data, sendn, SW_PIPE_MASTER);
    if (ret < 0)
    {
        swWarn("send %d bytes to worker#%d failed.", sendn, *dst_worker_id);
    }
    else
    {
        sw_atomic_fetch_add(&worker->tasking_num, 1);
    }

    return ret;
}

void swProcessPool_shutdown(swProcessPool *pool)
{
    int i, status;
    swWorker *worker;
    SwooleG.running = 0;

	swSignal_none();
    //concurrent kill
    for (i = 0; i < pool->run_worker_num; i++)
    {
        worker = &pool->workers[i];
        if (swKill(worker->pid, SIGTERM) < 0)
        {
            swSysError("kill(%d) failed.", worker->pid);
            continue;
        }
    }
    for (i = 0; i < pool->run_worker_num; i++)
    {
        worker = &pool->workers[i];
        if (swWaitpid(worker->pid, &status, 0) < 0)
        {
            swSysError("waitpid(%d) failed.", worker->pid);
        }
    }
    swProcessPool_free(pool);
    pool->started = 0;
}

pid_t swProcessPool_spawn(swWorker *worker)
{
    pid_t pid = fork();
    int ret_code = 0;
    swProcessPool *pool = worker->pool;

    switch (pid)
    {
    //child
    case 0:
        /**
         * Process start
         */
        if (pool->onWorkerStart != NULL)
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
        if (pool->onWorkerStop != NULL)
        {
            pool->onWorkerStop(pool, worker->id);
        }
        exit(ret_code);
        break;
    case -1:
        swWarn("fork() failed. Error: %s [%d]", strerror(errno), errno);
        break;
        //parent
    default:
        //remove old process
        if (worker->pid)
        {
            swHashMap_del_int(pool->map, worker->pid);
        }
        worker->deleted = 0;
        worker->pid = pid;
        //insert new process
        swHashMap_add_int(pool->map, pid, worker);
        break;
    }
    return pid;
}

static int swProcessPool_worker_loop(swProcessPool *pool, swWorker *worker)
{
    struct
    {
        long mtype;
        swEventData buf;
    } out;

    int n = 0, ret;
    int task_n, worker_task_always = 0;

    if (pool->max_request < 1)
    {
        task_n = 1;
        worker_task_always = 1;
    }
    else
    {
        task_n = pool->max_request;
        if (pool->max_request > 10)
        {
            n = swoole_system_random(1, pool->max_request / 2);
            if (n > 0)
            {
                task_n += n;
            }
        }
    }

    /**
     * Use from_fd save the task_worker->id
     */
    out.buf.info.from_fd = worker->id;

    if (pool->dispatch_mode == SW_DISPATCH_QUEUE)
    {
        out.mtype = 0;
    }
    else
    {
        out.mtype = worker->id + 1;
    }

    while (SwooleG.running > 0 && task_n > 0)
    {
        /**
         * fetch task
         */
        if (pool->use_msgqueue)
        {
            n = swMsgQueue_pop(pool->queue, (swQueue_data *) &out, sizeof(out.buf));
            if (n < 0 && errno != EINTR)
            {
                swSysError("[Worker#%d] msgrcv() failed.", worker->id);
                break;
            }
        }
        else if (pool->use_socket)
        {
            int fd = accept(pool->stream->socket, NULL, NULL);
            if (fd < 0)
            {
                if (errno == EAGAIN || errno == EINTR)
                {
                    continue;
                }
                else
                {
                    swSysError("accept(%d) failed.", pool->stream->socket);
                    break;
                }
            }

            n = swStream_recv_blocking(fd, (void*) &out.buf, sizeof(out.buf));
            if (n == SW_CLOSE)
            {
                close(fd);
                continue;
            }
            pool->stream->last_connection = fd;
        }
        else
        {
            n = read(worker->pipe_worker, &out.buf, sizeof(out.buf));
            if (n < 0 && errno != EINTR)
            {
                swSysError("[Worker#%d] read(%d) failed.", worker->id, worker->pipe_worker);
            }
        }

        /**
         * timer
         */
        if (n < 0)
        {
            if (errno == EINTR && SwooleG.signal_alarm)
            {
                alarm_handler: SwooleG.signal_alarm = 0;
                swTimer_select(&SwooleG.timer);
            }
            continue;
        }

        /**
         * do task
         */
        worker->status = SW_WORKER_BUSY;
        worker->request_time = time(NULL);
        ret = pool->onTask(pool, &out.buf);
        worker->status = SW_WORKER_IDLE;
        worker->request_time = 0;
        worker->traced = 0;

        if (pool->use_socket && pool->stream->last_connection > 0)
        {
            int _end = 0;
            swSocket_write_blocking(pool->stream->last_connection, (void *) &_end, sizeof(_end));
            close(pool->stream->last_connection);
            pool->stream->last_connection = 0;
        }

        /**
         * timer
         */
        if (SwooleG.signal_alarm)
        {
            goto alarm_handler;
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
        pool->packet_buffer = sw_malloc(max_packet_size);
        if (pool->packet_buffer == NULL)
        {
            swSysError("malloc(%d) failed.", max_packet_size);
            return SW_ERR;
        }
        pool->stream->response_buffer = swString_new(SW_BUFFER_SIZE_STD);
        if (pool->stream->response_buffer == NULL)
        {
            sw_free(pool->packet_buffer);
            return SW_ERR;
        }
        pool->max_packet_size = max_packet_size;
        pool->main_loop = swProcessPool_worker_loop_ex;
    }

    return SW_OK;
}

static int swProcessPool_worker_loop_ex(swProcessPool *pool, swWorker *worker)
{
    int n;
    char *data;

    swQueue_data *outbuf = (swQueue_data *) pool->packet_buffer;
    outbuf->mtype = 0;

    while (SwooleG.running > 0)
    {
        /**
         * fetch task
         */
        if (pool->use_msgqueue)
        {
            n = swMsgQueue_pop(pool->queue, outbuf, sizeof(outbuf->mdata));
            if (n < 0 && errno != EINTR)
            {
                swSysError("[Worker#%d] msgrcv() failed.", worker->id);
                break;
            }
            data = outbuf->mdata;
        }
        else if (pool->use_socket)
        {
            int fd = accept(pool->stream->socket, NULL, NULL);
            if (fd < 0)
            {
                if (errno == EAGAIN || errno == EINTR)
                {
                    continue;
                }
                else
                {
                    swSysError("accept(%d) failed.", pool->stream->socket);
                    break;
                }
            }
            int tmp = 0;
            if (swSocket_recv_blocking(fd, &tmp, sizeof(tmp), MSG_WAITALL) <= 0)
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
            if (swSocket_recv_blocking(fd, pool->packet_buffer, n, MSG_WAITALL) <= 0)
            {
                _close: close(fd);
                continue;
            }
            data = pool->packet_buffer;
            pool->stream->last_connection = fd;
        }
        else
        {
            n = read(worker->pipe_worker, pool->packet_buffer, pool->max_packet_size);
            if (n < 0 && errno != EINTR)
            {
                swSysError("[Worker#%d] read(%d) failed.", worker->id, worker->pipe_worker);
            }
            data = pool->packet_buffer;
        }

        /**
         * timer
         */
        if (n < 0)
        {
            if (errno == EINTR && SwooleG.signal_alarm)
            {
                alarm_handler: SwooleG.signal_alarm = 0;
                swTimer_select(&SwooleG.timer);
            }
            continue;
        }

        pool->onMessage(pool, data, n);

        if (pool->use_socket && pool->stream->last_connection > 0)
        {
            swString *resp_buf = pool->stream->response_buffer;
            if (resp_buf && resp_buf->length > 0)
            {
                int _l = htonl(resp_buf->length);
                swSocket_write_blocking(pool->stream->last_connection, &_l, sizeof(_l));
                swSocket_write_blocking(pool->stream->last_connection, resp_buf->str, resp_buf->length);
                swString_clear(resp_buf);
            }
            close(pool->stream->last_connection);
            pool->stream->last_connection = 0;
        }

        /**
         * timer
         */
        if (SwooleG.signal_alarm)
        {
            goto alarm_handler;
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
    int reload_worker_i = 0;
    pid_t reload_worker_pid = 0;
    int ret;
    int status;

    swWorker *reload_workers = sw_calloc(pool->worker_num, sizeof(swWorker));
    if (reload_workers == NULL)
    {
        swError("malloc[reload_workers] failed");
        return SW_ERR;
    }

    while (SwooleG.running)
    {
        pid = wait(&status);
        if (pid < 0)
        {
            if (SwooleG.running == 0)
            {
                break;
            }
            if (pool->reloading == 0)
            {
                if (errno != EINTR)
                {
                    swWarn("[Manager] wait failed. Error: %s [%d]", strerror(errno), errno);
                }
                continue;
            }

            swNotice("reload workers.");

            if (pool->reload_init == 0)
            {
                pool->reload_init = 1;
                memcpy(reload_workers, pool->workers, sizeof(swWorker) * pool->worker_num);
            }

            goto kill_worker;
        }

        if (SwooleG.running == 1)
        {
            swWorker *exit_worker = swHashMap_find_int(pool->map, pid);
            if (exit_worker == NULL)
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
                swWarn("worker#%d abnormal exit, status=%d, signal=%d", exit_worker->id, WEXITSTATUS(status),  WTERMSIG(status));
            }
            new_pid = swProcessPool_spawn(exit_worker);
            if (new_pid < 0)
            {
                swWarn("Fork worker process failed. Error: %s [%d]", strerror(errno), errno);
                sw_free(reload_workers);
                return SW_ERR;
            }
            swHashMap_del_int(pool->map, pid);
            if (pid == reload_worker_pid)
            {
                reload_worker_i++;
            }
        }
        //reload worker
        kill_worker: if (pool->reloading == 1)
        {
            //reload finish
            if (reload_worker_i >= pool->worker_num)
            {
                pool->reloading = pool->reload_init = reload_worker_pid = reload_worker_i = 0;
                continue;
            }
            reload_worker_pid = reload_workers[reload_worker_i].pid;
            ret = kill(reload_worker_pid, SIGTERM);
            if (ret < 0)
            {
                if (errno == ECHILD)
                {
                    reload_worker_i++;
                    goto kill_worker;
                }
                swSysError("[Manager]kill(%d) failed.", reload_workers[reload_worker_i].pid);
                continue;
            }
        }
    }
    sw_free(reload_workers);
    return SW_OK;
}

static void swProcessPool_free(swProcessPool *pool)
{
    int i;
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
            close(pool->stream->socket);
        }
        if (pool->stream->response_buffer)
        {
            swString_free(pool->stream->response_buffer);
        }
        sw_free(pool->stream);
    }

    if (pool->map)
    {
        swHashMap_free(pool->map);
    }
}

