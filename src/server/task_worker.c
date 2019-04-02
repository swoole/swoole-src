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

static swEventData *g_current_task = NULL;

static void swTaskWorker_signal_init(swProcessPool *pool);
static int swTaskWorker_onPipeReceive(swReactor *reactor, swEvent *event);
static int swTaskWorker_loop_async(swProcessPool *pool, swWorker *worker);

/**
 * after pool->create, before pool->start
 */
void swTaskWorker_init(swServer *serv)
{
    swProcessPool *pool = &serv->gs->task_workers;
    pool->ptr = serv;
    pool->onTask = swTaskWorker_onTask;
    pool->onWorkerStart = swTaskWorker_onStart;
    pool->onWorkerStop = swTaskWorker_onStop;
    /**
     * Make the task worker support asynchronous
     */
    if (serv->task_enable_coroutine)
    {
        pool->main_loop = swTaskWorker_loop_async;
    }
    if (serv->task_ipc_mode == SW_TASK_IPC_PREEMPTIVE)
    {
        pool->dispatch_mode = SW_DISPATCH_QUEUE;
    }
}

/**
 * in worker process
 */
int swTaskWorker_onFinish(swReactor *reactor, swEvent *event)
{
    swServer *serv = reactor->ptr;
    swEventData task;
    int n;

    do
    {
        n = read(event->fd, &task, sizeof(task));
    } while (n < 0 && errno == EINTR);

    return serv->onFinish(serv, &task);
}

int swTaskWorker_onTask(swProcessPool *pool, swEventData *task)
{
    int ret = SW_OK;
    swServer *serv = pool->ptr;
    g_current_task = task;

    if (task->info.type == SW_EVENT_PIPE_MESSAGE)
    {
        serv->onPipeMessage(serv, task);
    }
    else
    {
        ret = serv->onTask(serv, task);
    }

    return ret;
}

int swTaskWorker_large_pack(swEventData *task, void *data, int data_len)
{
    swPackage_task pkg;
    bzero(&pkg, sizeof(pkg));

    memcpy(pkg.tmpfile, SwooleG.task_tmpdir, SwooleG.task_tmpdir_len);

    //create temp file
    int tmp_fd = swoole_tmpfile(pkg.tmpfile);
    if (tmp_fd < 0)
    {
        return SW_ERR;
    }

    //write to file
    if (swoole_sync_writefile(tmp_fd, data, data_len) != data_len)
    {
        swWarn("write to tmpfile failed.");
        return SW_ERR;
    }

    task->info.len = sizeof(swPackage_task);
    //use tmp file
    swTask_type(task) |= SW_TASK_TMPFILE;

    pkg.length = data_len;
    memcpy(task->data, &pkg, sizeof(swPackage_task));
    close(tmp_fd);
    return SW_OK;
}

static void swTaskWorker_signal_init(swProcessPool *pool)
{
    /**
     * use user settings
     */
    SwooleG.use_signalfd = SwooleG.enable_signalfd;

    swSignal_add(SIGHUP, NULL);
    swSignal_add(SIGPIPE, NULL);
    swSignal_add(SIGUSR1, swWorker_signal_handler);
    swSignal_add(SIGUSR2, NULL);
    swSignal_add(SIGTERM, swWorker_signal_handler);
    swSignal_add(SIGALRM, swSystemTimer_signal_handler);
#ifdef SIGRTMIN
    swSignal_add(SIGRTMIN, swWorker_signal_handler);
#endif
}

void swTaskWorker_onStart(swProcessPool *pool, int worker_id)
{
    swServer *serv = pool->ptr;
    SwooleWG.id = worker_id;

    if (serv->factory_mode == SW_MODE_BASE)
    {
        swServer_close_port(serv, SW_TRUE);
    }

    /**
     * Make the task worker support asynchronous
     */
    if (serv->task_enable_coroutine)
    {
        SwooleG.main_reactor = sw_malloc(sizeof(swReactor));
        if (SwooleG.main_reactor == NULL)
        {
            swError("[TaskWorker] malloc for reactor failed.");
        }
        if (swReactor_create(SwooleG.main_reactor, SW_REACTOR_MAXEVENTS) < 0)
        {
            swError("[TaskWorker] create reactor failed.");
        }
        SwooleG.enable_signalfd = 1;
    }
    else
    {
        SwooleG.enable_signalfd = 0;
        SwooleG.main_reactor = NULL;
    }

    swTaskWorker_signal_init(pool);
    swWorker_onStart(serv);

    swWorker *worker = swProcessPool_get_worker(pool, worker_id);
    worker->start_time = serv->gs->now;
    worker->request_count = 0;
    worker->traced = 0;
    SwooleWG.worker = worker;
    SwooleWG.worker->status = SW_WORKER_IDLE;
    /**
     * task_max_request
     */
    if (pool->max_request > 0)
    {
        SwooleWG.run_always = 0;
        SwooleWG.max_request = swProcessPool_get_max_request(pool);
    }
    else
    {
        SwooleWG.run_always = 1;
    }
}

void swTaskWorker_onStop(swProcessPool *pool, int worker_id)
{
    swServer *serv = pool->ptr;
    swWorker_onStop(serv);
}

/**
 * receive data from worker process
 */
static int swTaskWorker_onPipeReceive(swReactor *reactor, swEvent *event)
{
    swEventData task;
    swProcessPool *pool = reactor->ptr;
    swWorker *worker = SwooleWG.worker;

    if (read(event->fd, &task, sizeof(task)) > 0)
    {
        worker->status = SW_WORKER_BUSY;
        worker->request_time = time(NULL);
        int retval = swTaskWorker_onTask(pool, &task);
        worker->status = SW_WORKER_IDLE;
        worker->request_time = 0;
        worker->traced = 0;
        worker->request_count++;
        //maximum number of requests, process will exit.
        if (!SwooleWG.run_always && worker->request_count >= SwooleWG.max_request)
        {
            swWorker_stop(worker);
        }
        return retval;
    }
    else
    {
        swSysWarn("read(%d, %ld) failed.", event->fd, sizeof(task));
        return SW_ERR;
    }
}

/**
 * async task worker
 */
static int swTaskWorker_loop_async(swProcessPool *pool, swWorker *worker)
{
    swServer *serv = pool->ptr;
    worker->status = SW_WORKER_IDLE;

    int pipe_worker = worker->pipe_worker;

    swSetNonBlock(pipe_worker);
    SwooleG.main_reactor->ptr = pool;
    SwooleG.main_reactor->add(SwooleG.main_reactor, pipe_worker, SW_FD_PIPE | SW_EVENT_READ);
    SwooleG.main_reactor->setHandle(SwooleG.main_reactor, SW_FD_PIPE, swTaskWorker_onPipeReceive);
    SwooleG.main_reactor->setHandle(SwooleG.main_reactor, SW_FD_WRITE, swReactor_onWrite);

    /**
     * set pipe buffer size
     */
    int i;
    swConnection *pipe_socket;
    for (i = 0; i < serv->worker_num + serv->task_worker_num; i++)
    {
        worker = swServer_get_worker(serv, i);
        pipe_socket = swReactor_get(SwooleG.main_reactor, worker->pipe_master);
        pipe_socket->buffer_size = INT_MAX;
        pipe_socket = swReactor_get(SwooleG.main_reactor, worker->pipe_worker);
        pipe_socket->buffer_size = INT_MAX;
    }

    //main loop
    return SwooleG.main_reactor->wait(SwooleG.main_reactor, NULL);
}

/**
 * Send the task result to worker
 */
int swTaskWorker_finish(swServer *serv, char *data, int data_len, int flags, swEventData *current_task)
{
    swEventData buf;
    bzero(&buf.info, sizeof(buf.info));
    if (serv->task_worker_num < 1)
    {
        swWarn("cannot use task/finish, because no set serv->task_worker_num.");
        return SW_ERR;
    }
    if (current_task == NULL)
    {
        current_task = g_current_task;
    }
    if (current_task->info.type == SW_EVENT_PIPE_MESSAGE)
    {
        swWarn("task/finish is not supported in onPipeMessage callback.");
        return SW_ERR;
    }
    if (swTask_type(current_task) & SW_TASK_NOREPLY)
    {
        swWarn("task->finish() can only be used in the worker process.");
        return SW_ERR;
    }

    uint16_t source_worker_id = current_task->info.from_id;
    swWorker *worker = swServer_get_worker(serv, source_worker_id);

    if (worker == NULL)
    {
        swWarn("invalid worker_id[%d].", source_worker_id);
        return SW_ERR;
    }

    int ret;
    //for swoole_server_task
    if (swTask_type(current_task) & SW_TASK_NONBLOCK)
    {
        buf.info.type = SW_EVENT_FINISH;
        buf.info.fd = current_task->info.fd;
        //callback function
        if (swTask_type(current_task) & SW_TASK_CALLBACK)
        {
            flags |= SW_TASK_CALLBACK;
        }
        else if (swTask_type(current_task) & SW_TASK_COROUTINE)
        {
            flags |= SW_TASK_COROUTINE;
        }
        swTask_type(&buf) = flags;

        //write to file
        if (data_len >= SW_IPC_MAX_SIZE - sizeof(buf.info))
        {
            if (swTaskWorker_large_pack(&buf, data, data_len) < 0)
            {
                swWarn("large task pack failed()");
                return SW_ERR;
            }
        }
        else
        {
            memcpy(buf.data, data, data_len);
            buf.info.len = data_len;
        }

        if (worker->pool->use_socket && worker->pool->stream->last_connection > 0)
        {
            int32_t _len = htonl(data_len);
            ret = swSocket_write_blocking(worker->pool->stream->last_connection, (void *) &_len, sizeof(_len));
            if (ret > 0)
            {
                ret = swSocket_write_blocking(worker->pool->stream->last_connection, data, data_len);
            }
        }
        else
        {
            ret = swWorker_send2worker(worker, &buf, sizeof(buf.info) + buf.info.len, SW_PIPE_MASTER);
        }
    }
    else
    {
        uint64_t flag = 1;

        /**
         * Use worker shm store the result
         */
        swEventData *result = &(serv->task_result[source_worker_id]);
        swPipe *task_notify_pipe = &(serv->task_notify[source_worker_id]);

        //lock worker
        worker->lock.lock(&worker->lock);

        if (swTask_type(current_task) & SW_TASK_WAITALL)
        {
            sw_atomic_t *finish_count = (sw_atomic_t*) result->data;
            char *_tmpfile = result->data + 4;
            int fd = open(_tmpfile, O_APPEND | O_WRONLY);
            if (fd >= 0)
            {
                buf.info.type = SW_EVENT_FINISH;
                buf.info.fd = current_task->info.fd;
                swTask_type(&buf) = flags;
                //result pack
                if (data_len >= SW_IPC_MAX_SIZE - sizeof(buf.info))
                {
                    if (swTaskWorker_large_pack(&buf, data, data_len) < 0)
                    {
                        swWarn("large task pack failed()");
                        buf.info.len = 0;
                    }
                }
                else
                {
                    buf.info.len = data_len;
                    memcpy(buf.data, data, data_len);
                }
                //write to tmpfile
                if (swoole_sync_writefile(fd, &buf, sizeof(buf.info) + buf.info.len) != sizeof(buf.info) + buf.info.len)
                {
                    swSysWarn("write(%s, %ld) failed.", _tmpfile, sizeof(buf.info) + buf.info.len);
                }
                sw_atomic_fetch_add(finish_count, 1);
                close(fd);
            }
        }
        else
        {
            result->info.type = SW_EVENT_FINISH;
            result->info.fd = current_task->info.fd;
            swTask_type(result) = flags;

            if (data_len >= SW_IPC_MAX_SIZE - sizeof(buf.info))
            {
                if (swTaskWorker_large_pack(result, data, data_len) < 0)
                {
                    //unlock worker
                    worker->lock.unlock(&worker->lock);
                    swWarn("large task pack failed()");
                    return SW_ERR;
                }
            }
            else
            {
                memcpy(result->data, data, data_len);
                result->info.len = data_len;
            }
        }

        //unlock worker
        worker->lock.unlock(&worker->lock);

        while (1)
        {
            ret = task_notify_pipe->write(task_notify_pipe, &flag, sizeof(flag));
            if (ret < 0 && swConnection_error(errno) == SW_WAIT)
            {
                if (swSocket_wait(task_notify_pipe->getFd(task_notify_pipe, 1), -1, SW_EVENT_WRITE) == 0)
                {
                    continue;
                }
            }
            break;
        }
    }
    if (ret < 0)
    {
        swSysWarn("TaskWorker: send result to worker failed");
    }
    return ret;
}
