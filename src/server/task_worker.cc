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

#include "swoole_server.h"
#include "swoole_util.h"

using namespace swoole;
using swoole::network::Socket;

static void TaskWorker_signal_init(ProcessPool *pool);
static int TaskWorker_onPipeReceive(Reactor *reactor, Event *event);
static int TaskWorker_loop_async(ProcessPool *pool, Worker *worker);
static void TaskWorker_onStart(ProcessPool *pool, int worker_id);
static void TaskWorker_onStop(ProcessPool *pool, int worker_id);
static int TaskWorker_onTask(ProcessPool *pool, EventData *task);

/**
 * after pool->create, before pool->start
 */
void Server::init_task_workers() {
    ProcessPool *pool = &gs->task_workers;
    pool->ptr = this;
    pool->onTask = TaskWorker_onTask;
    pool->onWorkerStart = TaskWorker_onStart;
    pool->onWorkerStop = TaskWorker_onStop;
    /**
     * Make the task worker support asynchronous
     */
    if (task_enable_coroutine) {
        if (task_ipc_mode == SW_TASK_IPC_MSGQUEUE || task_ipc_mode == SW_TASK_IPC_PREEMPTIVE) {
            swError("cannot use msgqueue when task_enable_coroutine is enable");
            return;
        }
        pool->main_loop = TaskWorker_loop_async;
    }
    if (task_ipc_mode == SW_TASK_IPC_PREEMPTIVE) {
        pool->dispatch_mode = SW_DISPATCH_QUEUE;
    }
}

static int TaskWorker_onTask(ProcessPool *pool, EventData *task) {
    int ret = SW_OK;
    Server *serv = (Server *) pool->ptr;
    serv->last_task = task;

    if (task->info.type == SW_SERVER_EVENT_PIPE_MESSAGE) {
        serv->onPipeMessage(serv, task);
    } else {
        ret = serv->onTask(serv, task);
    }

    return ret;
}

bool EventData::pack(const void *_data, size_t _length) {
    if (_length < SW_IPC_MAX_SIZE - sizeof(info)) {
        memcpy(data, _data, _length);
        info.len = _length;
        return true;
    }

    PacketTask pkg{};

    memcpy(pkg.tmpfile, SwooleG.task_tmpdir, SwooleG.task_tmpdir_len);

    // create temp file
    FileDescriptor _handler(swoole_tmpfile(pkg.tmpfile));

    int tmp_fd = _handler.get();
    if (tmp_fd < 0) {
        return false;
    }

    // write to file
    if (swoole_sync_writefile(tmp_fd, _data, _length) != _length) {
        swWarn("write to tmpfile failed");
        return false;
    }

    info.len = sizeof(pkg);
    // use tmp file
    swTask_type(this) |= SW_TASK_TMPFILE;

    pkg.length = _length;
    memcpy(data, &pkg, sizeof(pkg));

    return true;
}

bool EventData::unpack(String *buffer) {
    PacketTask _pkg{};
    memcpy(&_pkg, data, sizeof(_pkg));

    FileDescriptor _handler(open(_pkg.tmpfile, O_RDONLY));

    int tmp_file_fd = _handler.get();
    if (tmp_file_fd < 0) {
        swSysWarn("open(%s) failed", _pkg.tmpfile);
        return false;
    }
    if (buffer->size < _pkg.length && !buffer->extend(_pkg.length)) {
        return false;
    }
    if (swoole_sync_readfile(tmp_file_fd, buffer->str, _pkg.length) != _pkg.length) {
        return false;
    }
    if (!(swTask_type(this) & SW_TASK_PEEK)) {
        unlink(_pkg.tmpfile);
    }
    buffer->length = _pkg.length;
    return true;
}

static void TaskWorker_signal_init(ProcessPool *pool) {
    /**
     * use user settings
     */
    SwooleG.use_signalfd = SwooleG.enable_signalfd;

    swSignal_set(SIGHUP, nullptr);
    swSignal_set(SIGPIPE, nullptr);
    swSignal_set(SIGUSR1, Server::worker_signal_handler);
    swSignal_set(SIGUSR2, nullptr);
    swSignal_set(SIGTERM, Server::worker_signal_handler);
#ifdef SIGRTMIN
    swSignal_set(SIGRTMIN, Server::worker_signal_handler);
#endif
}

static void TaskWorker_onStart(ProcessPool *pool, int worker_id) {
    Server *serv = (Server *) pool->ptr;
    SwooleG.process_id = worker_id;

    if (serv->is_base_mode()) {
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

    TaskWorker_signal_init(pool);
    serv->worker_start_callback();

    Worker *worker = pool->get_worker(worker_id);
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

static void TaskWorker_onStop(ProcessPool *pool, int worker_id) {
    swoole_event_free();
    Server *serv = (Server *) pool->ptr;
    serv->worker_stop_callback();
}

/**
 * receive data from worker process
 */
static int TaskWorker_onPipeReceive(Reactor *reactor, Event *event) {
    EventData task;
    ProcessPool *pool = (ProcessPool *) reactor->ptr;
    Worker *worker = SwooleWG.worker;
    Server *serv = (Server *) pool->ptr;

    if (event->socket->read(&task, sizeof(task)) > 0) {
        worker->status = SW_WORKER_BUSY;
        int retval = TaskWorker_onTask(pool, &task);
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
static int TaskWorker_loop_async(ProcessPool *pool, Worker *worker) {
    Server *serv = (Server *) pool->ptr;
    Socket *socket = worker->pipe_worker;
    worker->status = SW_WORKER_IDLE;

    socket->set_nonblock();
    sw_reactor()->ptr = pool;
    swoole_event_add(socket, SW_EVENT_READ);
    swoole_event_set_handler(SW_FD_PIPE, TaskWorker_onPipeReceive);

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
int Server::reply_task_result(const char *data, size_t data_len, int flags, EventData *current_task) {
    EventData buf;
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
    Worker *worker = get_worker(source_worker_id);

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
        if (!buf.pack(data, data_len)) {
            swWarn("large task pack failed()");
            return SW_ERR;
        }

        if (worker->pool->use_socket && worker->pool->stream_info_->last_connection) {
            int32_t _len = htonl(data_len);
            ret = worker->pool->stream_info_->last_connection->send_blocking((void *) &_len, sizeof(_len));
            if (ret > 0) {
                ret = worker->pool->stream_info_->last_connection->send_blocking(data, data_len);
            }
        } else {
            ret = send_to_worker_from_worker(worker, &buf, sizeof(buf.info) + buf.info.len, SW_PIPE_MASTER);
        }
    } else {
        uint64_t flag = 1;

        /**
         * Use worker shm store the result
         */
        EventData *result = &(task_result[source_worker_id]);
        Pipe *task_notify_pipe = &(task_notify[source_worker_id]);

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
                if (!buf.pack(data, data_len)) {
                    swWarn("large task pack failed()");
                    buf.info.len = 0;
                }
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
            if (!result->pack(data, data_len)) {
                // unlock worker
                worker->lock.unlock(&worker->lock);
                swWarn("large task pack failed()");
                return SW_ERR;
            }
        }

        // unlock worker
        worker->lock.unlock(&worker->lock);

        while (1) {
            ret = task_notify_pipe->write(task_notify_pipe, &flag, sizeof(flag));
            auto _sock = task_notify_pipe->get_socket(true);
            if (ret < 0 && _sock->catch_error(errno) == SW_WAIT) {
                if (_sock->wait_event(-1, SW_EVENT_WRITE) == 0) {
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
