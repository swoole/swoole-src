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

using swoole::Server;

static void swTaskWorker_signal_init(swProcessPool *pool);
static int swTaskWorker_onPipeReceive(swReactor *reactor, swEvent *event);
static int swTaskWorker_loop_async(swProcessPool *pool, swWorker *worker);
static void swTaskWorker_onStart(swProcessPool *pool, int worker_id);
static void swTaskWorker_onStop(swProcessPool *pool, int worker_id);
static int swTaskWorker_onTask(swProcessPool *pool, swEventData *task);

/**
 * after pool->create, before pool->start
 */
void Server::init_task_workers() {
    swProcessPool *pool = &gs->task_workers;
    pool->ptr = this;
    pool->onTask = swTaskWorker_onTask;
    pool->onWorkerStart = swTaskWorker_onStart;
    pool->onWorkerStop = swTaskWorker_onStop;
    /**
     * Make the task worker support asynchronous
     */
    if (task_enable_coroutine) {
        if (task_ipc_mode == SW_TASK_IPC_MSGQUEUE || task_ipc_mode == SW_TASK_IPC_PREEMPTIVE) {
            swError("cannot use msgqueue when task_enable_coroutine is enable");
            return;
        }
        pool->main_loop = swTaskWorker_loop_async;
    }
    if (task_ipc_mode == SW_TASK_IPC_PREEMPTIVE) {
        pool->dispatch_mode = SW_DISPATCH_QUEUE;
    }
}

static int swTaskWorker_onTask(swProcessPool *pool, swEventData *task) {
    int ret = SW_OK;
    swServer *serv = (swServer *) pool->ptr;
    serv->last_task = task;

    if (task->info.type == SW_SERVER_EVENT_PIPE_MESSAGE) {
        serv->onPipeMessage(serv, task);
    } else {
        ret = serv->onTask(serv, task);
    }

    return ret;
}

int swEventData_large_pack(swEventData *task, const void *data, size_t data_len) {
    swPacket_task pkg;
    sw_memset_zero(&pkg, sizeof(pkg));

    memcpy(pkg.tmpfile, SwooleG.task_tmpdir, SwooleG.task_tmpdir_len);

    // create temp file
    int tmp_fd = swoole_tmpfile(pkg.tmpfile);
    if (tmp_fd < 0) {
        return SW_ERR;
    }

    // write to file
    if (swoole_sync_writefile(tmp_fd, data, data_len) != data_len) {
        swWarn("write to tmpfile failed");
        return SW_ERR;
    }

    task->info.len = sizeof(swPacket_task);
    // use tmp file
    swTask_type(task) |= SW_TASK_TMPFILE;

    pkg.length = data_len;
    memcpy(task->data, &pkg, sizeof(swPacket_task));
    close(tmp_fd);
    return SW_OK;
}

static void swTaskWorker_signal_init(swProcessPool *pool) {
    /**
     * use user settings
     */
    SwooleG.use_signalfd = SwooleG.enable_signalfd;

    swSignal_set(SIGHUP, nullptr);
    swSignal_set(SIGPIPE, nullptr);
    swSignal_set(SIGUSR1, swWorker_signal_handler);
    swSignal_set(SIGUSR2, nullptr);
    swSignal_set(SIGTERM, swWorker_signal_handler);
#ifdef SIGRTMIN
    swSignal_set(SIGRTMIN, swWorker_signal_handler);
#endif
}

static void swTaskWorker_onStart(swProcessPool *pool, int worker_id) {
    swServer *serv = (swServer *) pool->ptr;
    SwooleG.process_id = worker_id;

    if (serv->factory_mode == SW_MODE_BASE) {
        serv->close_port(true);
    }

    /**
     * Make the task worker support asynchronous
     */
    if (serv->task_enable_coroutine) {
        if (swoole_event_init(0) < 0) {
            swError("[TaskWorker] create reactor failed");
            return;
        }
        SwooleG.enable_signalfd = 1;
    } else {
        SwooleG.enable_signalfd = 0;
        SwooleTG.reactor = nullptr;
    }

    swTaskWorker_signal_init(pool);
    serv->worker_start_callback();

    swWorker *worker = pool->get_worker(worker_id);
    worker->start_time = time(nullptr);
    worker->request_count = 0;
    SwooleWG.worker = worker;
    SwooleWG.worker->status = SW_WORKER_IDLE;
    /**
     * task_max_request
     */
    if (pool->max_request > 0) {
        SwooleWG.run_always = false;
        SwooleWG.max_request = pool->get_max_request();
    } else {
        SwooleWG.run_always = true;
    }
}

static void swTaskWorker_onStop(swProcessPool *pool, int worker_id) {
    swoole_event_free();
    swServer *serv = (swServer *) pool->ptr;
    serv->worker_stop_callback();
}

/**
 * receive data from worker process
 */
static int swTaskWorker_onPipeReceive(swReactor *reactor, swEvent *event) {
    swEventData task;
    swProcessPool *pool = (swProcessPool *) reactor->ptr;
    swWorker *worker = SwooleWG.worker;
    swServer *serv = (swServer *) pool->ptr;

    if (read(event->fd, &task, sizeof(task)) > 0) {
        worker->status = SW_WORKER_BUSY;
        int retval = swTaskWorker_onTask(pool, &task);
        worker->status = SW_WORKER_IDLE;
        worker->request_count++;
        // maximum number of requests, process will exit.
        if (!SwooleWG.run_always && worker->request_count >= SwooleWG.max_request) {
            serv->stop_async_worker(worker);
        }
        return retval;
    } else {
        swSysWarn("read(%d, %ld) failed", event->fd, sizeof(task));
        return SW_ERR;
    }
}

/**
 * async task worker
 */
static int swTaskWorker_loop_async(swProcessPool *pool, swWorker *worker) {
    swServer *serv = (swServer *) pool->ptr;
    swSocket *socket = worker->pipe_worker;
    worker->status = SW_WORKER_IDLE;

    swSocket_set_nonblock(socket);
    sw_reactor()->ptr = pool;
    swoole_event_add(socket, SW_EVENT_READ);
    swoole_event_set_handler(SW_FD_PIPE, swTaskWorker_onPipeReceive);

    for (uint i = 0; i < serv->worker_num + serv->task_worker_num; i++) {
        worker = serv->get_worker(i);
        worker->pipe_master->buffer_size = UINT_MAX;
        worker->pipe_worker->buffer_size = UINT_MAX;
    }

    return swoole_event_wait();
}

/**
 * Send the task result to worker
 */
int Server::reply_task_result(const char *data, size_t data_len, int flags, swEventData *current_task) {
    swEventData buf;
    sw_memset_zero(&buf.info, sizeof(buf.info));
    if (task_worker_num < 1) {
        swWarn("cannot use task/finish, because no set task_worker_num");
        return SW_ERR;
    }
    if (current_task == nullptr) {
        current_task = last_task;
    }
    if (current_task->info.type == SW_SERVER_EVENT_PIPE_MESSAGE) {
        swWarn("task/finish is not supported in onPipeMessage callback");
        return SW_ERR;
    }
    if (swTask_type(current_task) & SW_TASK_NOREPLY) {
        swWarn("task->finish() can only be used in the worker process");
        return SW_ERR;
    }

    uint16_t source_worker_id = current_task->info.reactor_id;
    swWorker *worker = get_worker(source_worker_id);

    if (worker == nullptr) {
        swWarn("invalid worker_id[%d]", source_worker_id);
        return SW_ERR;
    }

    int ret;
    // for swoole_server_task
    if (swTask_type(current_task) & SW_TASK_NONBLOCK) {
        buf.info.type = SW_SERVER_EVENT_FINISH;
        buf.info.fd = current_task->info.fd;
        // callback function
        if (swTask_type(current_task) & SW_TASK_CALLBACK) {
            flags |= SW_TASK_CALLBACK;
        } else if (swTask_type(current_task) & SW_TASK_COROUTINE) {
            flags |= SW_TASK_COROUTINE;
        }
        swTask_type(&buf) = flags;

        // write to file
        if (data_len >= SW_IPC_MAX_SIZE - sizeof(buf.info)) {
            if (swEventData_large_pack(&buf, data, data_len) < 0) {
                swWarn("large task pack failed()");
                return SW_ERR;
            }
        } else {
            memcpy(buf.data, data, data_len);
            buf.info.len = data_len;
        }

        if (worker->pool->use_socket && worker->pool->stream_info_->last_connection) {
            int32_t _len = htonl(data_len);
            ret = swSocket_write_blocking(worker->pool->stream_info_->last_connection, (void *) &_len, sizeof(_len));
            if (ret > 0) {
                ret = swSocket_write_blocking(worker->pool->stream_info_->last_connection, data, data_len);
            }
        } else {
            ret = send_to_worker_from_worker(worker, &buf, sizeof(buf.info) + buf.info.len, SW_PIPE_MASTER);
        }
    } else {
        uint64_t flag = 1;

        /**
         * Use worker shm store the result
         */
        swEventData *result = &(task_result[source_worker_id]);
        swPipe *task_notify_pipe = &(task_notify[source_worker_id]);

        // lock worker
        worker->lock.lock(&worker->lock);

        if (swTask_type(current_task) & SW_TASK_WAITALL) {
            sw_atomic_t *finish_count = (sw_atomic_t *) result->data;
            char *_tmpfile = result->data + 4;
            int fd = open(_tmpfile, O_APPEND | O_WRONLY);
            if (fd >= 0) {
                buf.info.type = SW_SERVER_EVENT_FINISH;
                buf.info.fd = current_task->info.fd;
                swTask_type(&buf) = flags;
                // result pack
                if (data_len >= SW_IPC_MAX_SIZE - sizeof(buf.info)) {
                    if (swEventData_large_pack(&buf, data, data_len) < 0) {
                        swWarn("large task pack failed()");
                        buf.info.len = 0;
                    }
                } else {
                    buf.info.len = data_len;
                    memcpy(buf.data, data, data_len);
                }
                // write to tmpfile
                if (swoole_sync_writefile(fd, &buf, sizeof(buf.info) + buf.info.len) !=
                    sizeof(buf.info) + buf.info.len) {
                    swSysWarn("write(%s, %ld) failed", _tmpfile, sizeof(buf.info) + buf.info.len);
                }
                sw_atomic_fetch_add(finish_count, 1);
                ::close(fd);
            }
        } else {
            result->info.type = SW_SERVER_EVENT_FINISH;
            result->info.fd = current_task->info.fd;
            swTask_type(result) = flags;

            if (data_len >= SW_IPC_MAX_SIZE - sizeof(buf.info)) {
                if (swEventData_large_pack(result, data, data_len) < 0) {
                    // unlock worker
                    worker->lock.unlock(&worker->lock);
                    swWarn("large task pack failed()");
                    return SW_ERR;
                }
            } else {
                memcpy(result->data, data, data_len);
                result->info.len = data_len;
            }
        }

        // unlock worker
        worker->lock.unlock(&worker->lock);

        while (1) {
            ret = task_notify_pipe->write(task_notify_pipe, &flag, sizeof(flag));
            if (ret < 0 && swSocket_error(errno) == SW_WAIT) {
                if (swSocket_wait(
                        task_notify_pipe->getSocket(task_notify_pipe, SW_PIPE_WRITE)->fd, -1, SW_EVENT_WRITE) == 0) {
                    continue;
                }
            }
            break;
        }
    }
    if (ret < 0) {
        swSysWarn("TaskWorker: send result to worker failed");
    }
    return ret;
}

swString *swEventData_large_unpack(swEventData *task_result) {
    swPacket_task _pkg;
    memcpy(&_pkg, task_result->data, sizeof(_pkg));

    int tmp_file_fd = open(_pkg.tmpfile, O_RDONLY);
    if (tmp_file_fd < 0) {
        swSysWarn("open(%s) failed", _pkg.tmpfile);
        return nullptr;
    }
    if (SwooleTG.buffer_stack->size < _pkg.length && swString_extend_align(SwooleTG.buffer_stack, _pkg.length) < 0) {
        close(tmp_file_fd);
        return nullptr;
    }
    if (swoole_sync_readfile(tmp_file_fd, SwooleTG.buffer_stack->str, _pkg.length) != _pkg.length) {
        close(tmp_file_fd);
        return nullptr;
    }
    close(tmp_file_fd);
    if (!(swTask_type(task_result) & SW_TASK_PEEK)) {
        unlink(_pkg.tmpfile);
    }
    SwooleTG.buffer_stack->length = _pkg.length;
    return SwooleTG.buffer_stack;
}
