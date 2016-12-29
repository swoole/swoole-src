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

static swEventData *current_task;

static void swTaskWorker_signal_init(void);

void swTaskWorker_init(swProcessPool *pool)
{
    pool->ptr = SwooleG.serv;
    pool->onTask = swTaskWorker_onTask;
    pool->onWorkerStart = swTaskWorker_onStart;
    pool->onWorkerStop = swTaskWorker_onStop;
    pool->type = SW_PROCESS_TASKWORKER;
    pool->start_id = SwooleG.serv->worker_num;
    pool->run_worker_num = SwooleG.task_worker_num;

    if (SwooleG.task_ipc_mode == SW_TASK_IPC_PREEMPTIVE)
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
    current_task = task;

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
    if (swoole_sync_writefile(tmp_fd, data, data_len) <= 0)
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

static void swTaskWorker_signal_init(void)
{
    swSignal_set(SIGHUP, NULL, 1, 0);
    swSignal_set(SIGPIPE, NULL, 1, 0);
    swSignal_set(SIGUSR1, NULL, 1, 0);
    swSignal_set(SIGUSR2, NULL, 1, 0);
    swSignal_set(SIGTERM, swWorker_signal_handler, 1, 0);
    swSignal_set(SIGALRM, swSystemTimer_signal_handler, 1, 0);
#ifdef SIGRTMIN
    swSignal_set(SIGRTMIN, swWorker_signal_handler, 1, 0);
#endif
}

void swTaskWorker_onStart(swProcessPool *pool, int worker_id)
{
    swServer *serv = pool->ptr;
    SwooleWG.id = worker_id;
    SwooleG.pid = getpid();

    SwooleG.use_timer_pipe = 0;
    SwooleG.use_timerfd = 0;

    swServer_close_port(serv, SW_TRUE);

    swTaskWorker_signal_init();
    swWorker_onStart(serv);

    SwooleG.main_reactor = NULL;
    SwooleWG.worker = swProcessPool_get_worker(pool, worker_id);
    SwooleWG.worker->status = SW_WORKER_IDLE;
}

void swTaskWorker_onStop(swProcessPool *pool, int worker_id)
{
    swServer *serv = pool->ptr;
    swWorker_onStop(serv);
}

/**
 * Send the task result to worker
 */
int swTaskWorker_finish(swServer *serv, char *data, int data_len, int flags)
{
    swEventData buf;
    if (SwooleG.task_worker_num < 1)
    {
        swWarn("cannot use task/finish, because no set serv->task_worker_num.");
        return SW_ERR;
    }

    uint16_t source_worker_id = current_task->info.from_id;
    swWorker *worker = swServer_get_worker(serv, source_worker_id);

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
        swTask_type(&buf) = flags;

        //write to file
        if (data_len >= SW_IPC_MAX_SIZE - sizeof(buf.info))
        {
            if (swTaskWorker_large_pack(&buf, data, data_len) < 0 )
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

        ret = swWorker_send2worker(worker, &buf, sizeof(buf.info) + buf.info.len, SW_PIPE_MASTER);
    }
    else
    {
        uint64_t flag = 1;

        /**
         * Use worker shm store the result
         */
        swEventData *result = &(SwooleG.task_result[source_worker_id]);
        swPipe *task_notify_pipe = &(SwooleG.task_notify[source_worker_id]);

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
                if (swoole_sync_writefile(fd, &buf, sizeof(buf.info) + buf.info.len) < 0)
                {
                    swSysError("write(%s, %ld) failed.", result->data, sizeof(buf.info) + buf.info.len);
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
#ifdef HAVE_KQUEUE
            if (ret < 0 && errno == EAGAIN || errno == ENOBUFS)
#else
            if (ret < 0 && errno == EAGAIN)
#endif
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
        swWarn("TaskWorker: send result to worker failed. Error: %s[%d]", strerror(errno), errno);
    }
    return ret;
}
