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
  | Author: Tianfeng Han  <rango@swoole.com>                             |
  +----------------------------------------------------------------------+
*/

#include "swoole_server.h"

namespace swoole {
using network::Socket;

static void TaskWorker_signal_init(ProcessPool *pool);
static int TaskWorker_onPipeReceive(Reactor *reactor, Event *event);
static int TaskWorker_loop_async(ProcessPool *pool, Worker *worker);
static void TaskWorker_onStart(ProcessPool *pool, Worker *worker);
static void TaskWorker_onStop(ProcessPool *pool, Worker *worker);
static int TaskWorker_onTask(ProcessPool *pool, Worker *worker, EventData *task);

/**
 * after pool->create, before pool->start
 */
bool Server::init_task_workers() {
    ProcessPool *pool = get_task_worker_pool();
    pool->ptr = this;
    pool->onTask = TaskWorker_onTask;
    pool->onWorkerStart = TaskWorker_onStart;
    pool->onWorkerStop = TaskWorker_onStop;
    /**
     * Make the task worker support asynchronous
     */
    if (task_enable_coroutine) {
        if (task_ipc_mode == TASK_IPC_MSGQUEUE || task_ipc_mode == TASK_IPC_PREEMPTIVE) {
            swoole_error_log(
                SW_LOG_WARNING, SW_ERROR_WRONG_OPERATION, "cannot use msgqueue when task_enable_coroutine is enable");
            return false;
        }
        pool->main_loop = TaskWorker_loop_async;
    }
    if (task_ipc_mode == TASK_IPC_PREEMPTIVE) {
        pool->schedule_by_sysvmsg = true;
    }
    SW_LOOP_N(task_worker_num) {
        create_worker(&pool->workers[i]);
    }
    return true;
}

static int TaskWorker_call_command_handler(const ProcessPool *pool, const Worker *worker, EventData *req) {
    auto *serv = static_cast<Server *>(pool->ptr);
    int command_id = serv->get_command_id(req);
    const auto iter = serv->command_handlers.find(command_id);
    if (iter == serv->command_handlers.end()) {
        swoole_error_log(SW_LOG_ERROR, SW_ERROR_SERVER_INVALID_COMMAND, "Unknown command[%d]", command_id);
        return SW_OK;
    }

    Server::Command::Handler handler = iter->second;
    PacketPtr packet;
    if (!Server::task_unpack(req, sw_tg_buffer(), &packet)) {
        return SW_OK;
    }

    auto result = handler(serv, std::string(packet.data, packet.length));

    SendData task{};
    task.info.fd = serv->get_task_id(req);
    task.info.reactor_id = worker->id;
    task.info.server_fd = -1;
    task.info.type = SW_SERVER_EVENT_COMMAND_RESPONSE;
    task.info.len = result.length();
    task.data = result.c_str();

    return serv->message_bus.write(serv->get_command_reply_socket(), &task) ? SW_OK : SW_ERR;
}

static int TaskWorker_onTask(ProcessPool *pool, Worker *worker, EventData *task) {
    int ret = SW_OK;
    auto *serv = static_cast<Server *>(pool->ptr);
    serv->last_task = task;

    worker->set_status_to_busy();
    if (task->info.type == SW_SERVER_EVENT_PIPE_MESSAGE) {
        serv->onPipeMessage(serv, task);
    } else if (task->info.type == SW_SERVER_EVENT_SHUTDOWN) {
        worker->shutdown();
        if (swoole_event_is_available()) {
            serv->stop_async_worker(worker);
        }
        return SW_OK;
    } else if (task->info.type == SW_SERVER_EVENT_COMMAND_REQUEST) {
        ret = TaskWorker_call_command_handler(pool, worker, task);
    } else {
        ret = serv->onTask(serv, task);
        /**
         * only server task as requests,
         * do not increase the count for pipeline communication and command processing.
         */
        worker->add_request_count();
    }
    worker->set_status_to_idle();

    return ret;
}

void Server::task_dump(EventData *task) {
    char buf[1024];
    task->info.dump(buf, sizeof(buf));
    sw_printf("%s", buf);

    if (task->info.ext_flags & SW_TASK_TMPFILE) {
        auto pkg = reinterpret_cast<PacketTask *>(task->data);
        sw_printf("Task[tmpfile]=%.*s\n", pkg->length, pkg->tmpfile);
    }
}

bool Server::task_pack(EventData *task, const void *_data, size_t _length) {
    task->info = {};
    task->info.type = SW_SERVER_EVENT_TASK;
    task->info.fd = SwooleG.current_task_id++;
    task->info.reactor_id = swoole_get_worker_id();
    task->info.time = microtime();

    if (_length < SW_IPC_MAX_SIZE - sizeof(task->info)) {
        memcpy(task->data, _data, _length);
        task->info.len = _length;
        return true;
    }

    PacketTask pkg{};
    File file = make_tmpfile();
    if (!file.ready()) {
        return false;
    }

    if (file.write_all(_data, _length) != _length) {
        swoole_warning("write to tmpfile failed");
        return false;
    }

    task->info.len = sizeof(pkg);
    task->info.ext_flags |= SW_TASK_TMPFILE;
    swoole_strlcpy(pkg.tmpfile, file.get_path().c_str(), sizeof(pkg.tmpfile));
    pkg.length = _length;
    memcpy(task->data, &pkg, sizeof(pkg));

    return true;
}

bool Server::task(EventData *_task, int *dst_worker_id, bool blocking) {
    sw_atomic_fetch_add(&gs->tasking_num, 1);

    swResultCode retval;
    if (blocking) {
        retval = get_task_worker_pool()->dispatch_sync(_task, dst_worker_id);
    } else {
        retval = get_task_worker_pool()->dispatch(_task, dst_worker_id);
    }

    if (retval == SW_OK) {
        sw_atomic_fetch_add(&gs->task_count, 1);
        return true;
    }

    sw_atomic_fetch_sub(&gs->tasking_num, 1);
    return false;
}

bool Server::task_sync(EventData *_task, int *dst_worker_id, double timeout) {
    uint64_t notify;
    EventData *task_result = get_task_result();
    sw_memset_zero(task_result, sizeof(*task_result));
    Pipe *pipe = task_notify_pipes.at(swoole_get_worker_id()).get();
    TaskId task_id = get_task_id(_task);

    pipe->clean();
    pipe->set_timeout(timeout);

    if (!task(_task, dst_worker_id, true)) {
        return false;
    }

    SW_LOOP {
        if (pipe->read(&notify, sizeof(notify)) > 0) {
            if (get_task_id(task_result) != task_id) {
                continue;
            }
            return true;
        }
        break;
    }

    return false;
}

int Server::MultiTask::find(TaskId task_id) {
    auto iter = map.find(task_id);
    if (iter != map.end()) {
        return iter->second;
    } else {
        return -1;
    }
}

bool Server::task_sync(MultiTask &mtask, double timeout) {
    WorkerId worker_id = swoole_get_worker_id();
    uint64_t notify;
    EventData *task_result = get_task_result();
    task_result->info = {};
    Pipe *pipe = task_notify_pipes.at(worker_id).get();
    Worker *worker = get_worker(worker_id);
    int dst_worker_id;

    File fp = make_tmpfile();
    if (!fp.ready()) {
        swoole_set_last_error(errno);
        return false;
    }

    std::string file_path = fp.get_path();
    fp.close();

    auto finish_count = reinterpret_cast<int *>(task_result->data);

    worker->lock->lock();
    *finish_count = 0;

    swoole_strlcpy(task_result->data + 4, file_path.c_str(), SW_TASK_TMP_PATH_SIZE);
    worker->lock->unlock();

    // clear history task
    pipe->clean();

    auto n_task = mtask.count;
    SW_LOOP_N(mtask.count) {
        EventData buf;
        TaskId task_id = mtask.pack(i, &buf);
        if (task_id < 0) {
            swoole_warning("task pack failed");
            goto _fail;
        }
        buf.info.ext_flags |= SW_TASK_WAITALL;
        sw_atomic_fetch_add(&gs->tasking_num, 1);
        dst_worker_id = -1;
        if (!task(&buf, &dst_worker_id, true)) {
            swoole_warning("failed to dispatch task");
            task_id = -1;
        _fail:
            mtask.fail(i);
            n_task--;
        } else {
            sw_atomic_fetch_sub(&gs->tasking_num, 1);
        }
        mtask.map[task_id] = i;
    }

    if (n_task == 0) {
        swoole_set_last_error(SW_ERROR_TASK_DISPATCH_FAIL);
        return false;
    }

    if (timeout > 0) {
        pipe->set_timeout(timeout);
    }

    double stated_at = microtime();
    while (*finish_count < n_task) {
        const int ret = pipe->read(&notify, sizeof(notify));
        if (ret <= 0) {
            break;
        }
        if (timeout > 0 && microtime() - stated_at > timeout) {
            break;
        }
    }

    worker->lock->lock();
    auto content = file_get_contents(file_path);
    worker->lock->unlock();

    if (!content) {
        return false;
    }

    do {
        auto *result = reinterpret_cast<EventData *>(content->str + content->offset);
        int index = mtask.find(get_task_id(result));
        if (index != -1) {
            mtask.unpack(index, result);
        }
        content->offset += result->size();
    } while (content->offset < 0 || (size_t) content->offset < content->length);
    // delete tmp file
    unlink(file_path.c_str());

    return true;
}

bool Server::task_unpack(EventData *task, String *buffer, PacketPtr *packet) {
    if (!(task->info.ext_flags & SW_TASK_TMPFILE)) {
        packet->data = task->data;
        packet->length = task->info.len;
        return true;
    }

    PacketTask _pkg{};
    memcpy(&_pkg, task->data, sizeof(_pkg) - 1);

    File fp(_pkg.tmpfile, O_RDONLY);
    if (!fp.ready()) {
        swoole_sys_warning("open(%s) failed", _pkg.tmpfile);
        return false;
    }
    if (buffer->size < _pkg.length && !buffer->extend(_pkg.length)) {
        return false;
    }
    if (fp.read_all(buffer->str, _pkg.length) != _pkg.length) {
        return false;
    }
    if (!(task->info.ext_flags & SW_TASK_PEEK)) {
        unlink(_pkg.tmpfile);
    }
    buffer->length = _pkg.length;
    packet->data = buffer->str;
    packet->length = buffer->length;
    return true;
}

static void TaskWorker_signal_init(ProcessPool *pool) {
    auto *serv = static_cast<Server *>(pool->ptr);
    if (serv->is_thread_mode()) {
        return;
    }
    swoole_signal_set(SIGHUP, nullptr);
    swoole_signal_set(SIGPIPE, nullptr);
    swoole_signal_set(SIGUSR1, nullptr);
    swoole_signal_set(SIGUSR2, nullptr);
    swoole_signal_set(SIGTERM, Server::worker_signal_handler);
    swoole_signal_set(SIGWINCH, Server::worker_signal_handler);
#ifdef SIGRTMIN
    swoole_signal_set(SIGRTMIN, Server::worker_signal_handler);
#endif
}

static void TaskWorker_onStart(ProcessPool *pool, Worker *worker) {
    auto serv = static_cast<Server *>(pool->ptr);

    swoole_set_worker_id(worker->id);
    swoole_set_worker_type(SW_TASK_WORKER);
    /**
     * Make the task worker support asynchronous
     */
    if (serv->task_enable_coroutine) {
        if (swoole_event_init(0) < 0) {
            swoole_error("[TaskWorker] create reactor failed");
            return;
        }
        SwooleG.enable_signalfd = 1;
    } else {
        SwooleG.enable_signalfd = 0;
        SwooleTG.reactor = nullptr;
    }

    TaskWorker_signal_init(pool);
    serv->worker_start_callback(worker);

    worker->init();
    worker->set_max_request(pool->max_request, pool->max_request_grace);
}

static void TaskWorker_onStop(ProcessPool *pool, Worker *worker) {
    swoole_event_free();
    auto *serv = static_cast<Server *>(pool->ptr);
    serv->worker_stop_callback(worker);
}

/**
 * receive data from worker process
 */
static int TaskWorker_onPipeReceive(Reactor *reactor, Event *event) {
    EventData task;
    auto *pool = static_cast<ProcessPool *>(reactor->ptr);
    Worker *worker = sw_worker();
    auto *serv = static_cast<Server *>(pool->ptr);

    if (event->socket->read(&task, sizeof(task)) > 0) {
        int retval = pool->onTask(pool, worker, &task);
        // maximum number of requests, process will exit.
        if (worker->has_exceeded_max_request()) {
            serv->stop_async_worker(worker);
        }
        return retval;
    } else {
        swoole_sys_warning("read(%d, %ld) failed", event->fd, sizeof(task));
        return SW_ERR;
    }
}

/**
 * async task worker
 */
static int TaskWorker_loop_async(ProcessPool *pool, Worker *worker) {
    auto *serv = static_cast<Server *>(pool->ptr);
    Socket *socket = serv->get_worker_pipe_worker_in_message_bus(worker);
    worker->set_status_to_idle();

    socket->set_nonblock();
    sw_reactor()->ptr = pool;
    swoole_event_add(socket, SW_EVENT_READ);
    swoole_event_set_handler(SW_FD_PIPE, SW_EVENT_READ, TaskWorker_onPipeReceive);

    for (uint i = 0; i < serv->worker_num + serv->task_worker_num; i++) {
        worker = serv->get_worker(i);
        serv->get_worker_pipe_worker_in_message_bus(worker)->buffer_size = UINT_MAX;
        serv->get_worker_pipe_master_in_message_bus(worker)->buffer_size = UINT_MAX;
    }

    return swoole_event_wait();
}

/**
 * Send the task result to worker
 */
bool Server::finish(const char *data, size_t data_len, int flags, const EventData *current_task) {
    if (task_worker_num < 1) {
        swoole_warning("cannot use Server::task()/Server::finish() method, because no set [task_worker_num]");
        return false;
    }
    if (current_task == nullptr) {
        current_task = last_task;
    }
    if (current_task->info.type == SW_SERVER_EVENT_PIPE_MESSAGE) {
        swoole_warning("Server::task()/Server::finish() is not supported in onPipeMessage callback");
        return false;
    }
    if (current_task->info.ext_flags & SW_TASK_NOREPLY) {
        swoole_warning("Server::finish() can only be used in the worker process");
        return false;
    }

    uint16_t source_worker_id = current_task->info.reactor_id;
    Worker *worker = get_worker(source_worker_id);

    if (worker == nullptr) {
        swoole_warning("invalid worker_id[%d]", source_worker_id);
        return false;
    }

    ssize_t retval;
    // for swoole_server_task
    if (current_task->info.ext_flags & SW_TASK_NONBLOCK) {
        // write to file
        EventData buf;
        if (!task_pack(&buf, data, data_len)) {
            swoole_warning("large task pack failed()");
            return false;
        }
        // callback function
        if (current_task->info.ext_flags & SW_TASK_CALLBACK) {
            flags |= SW_TASK_CALLBACK;
        } else if (current_task->info.ext_flags & SW_TASK_COROUTINE) {
            flags |= SW_TASK_COROUTINE;
        }
        buf.info.ext_flags |= flags;
        buf.info.type = SW_SERVER_EVENT_FINISH;
        buf.info.fd = get_task_id(current_task);

        if (worker->pool->use_socket && worker->pool->stream_info_->last_connection) {
            uint32_t _len = htonl(data_len);
            retval = worker->pool->stream_info_->last_connection->send_sync((void *) &_len, sizeof(_len));
            if (retval > 0) {
                retval = worker->pool->stream_info_->last_connection->send_sync(data, data_len);
            }
        } else {
            retval = send_to_worker_from_worker(worker, &buf, buf.size(), SW_PIPE_MASTER);
        }
    } else {
        uint64_t flag = 1;

        /**
         * Use worker shm store the result
         */
        EventData *result = &(task_results[source_worker_id]);
        Pipe *pipe = task_notify_pipes.at(source_worker_id).get();

        // lock worker
        worker->lock->lock();

        if (current_task->info.ext_flags & SW_TASK_WAITALL) {
            auto *finish_count = reinterpret_cast<sw_atomic_t *>(result->data);
            char *_tmpfile = result->data + 4;
            File file(_tmpfile, O_APPEND | O_WRONLY);
            if (file.ready()) {
                EventData buf;
                if (!task_pack(&buf, data, data_len)) {
                    swoole_warning("large task pack failed()");
                    buf.info.len = 0;
                }
                buf.info.ext_flags |= flags;
                buf.info.type = SW_SERVER_EVENT_FINISH;
                buf.info.fd = get_task_id(current_task);
                size_t bytes = buf.size();
                swoole_trace_log(SW_TRACE_SERVER, "write %zu bytes to tmp file '%s'", bytes, _tmpfile);

                if (file.write_all(&buf, bytes) != bytes) {
                    swoole_sys_warning("write(%s, %ld) failed", _tmpfile, bytes);
                }
                sw_atomic_fetch_add(finish_count, 1);
            }
        } else {
            if (!task_pack(result, data, data_len)) {
                // unlock worker
                worker->lock->unlock();
                swoole_warning("large task pack failed()");
                return false;
            }
            result->info.ext_flags |= flags;
            result->info.type = SW_SERVER_EVENT_FINISH;
            result->info.fd = get_task_id(current_task);
        }

        // unlock worker
        worker->lock->unlock();

        while (true) {
            retval = pipe->write(&flag, sizeof(flag));
            auto _sock = pipe->get_socket(true);
            if (retval < 0 && _sock->catch_write_error(errno) == SW_WAIT) {
                if (_sock->wait_event(-1, SW_EVENT_WRITE) == 0) {
                    continue;
                }
            }
            break;
        }
    }
    if (retval < 0) {
        if (errno == EAGAIN || errno == ETIMEDOUT || swoole_get_last_error() == SW_ERROR_SOCKET_POLL_TIMEOUT) {
            swoole_error_log(SW_LOG_WARNING, SW_ERROR_SERVER_SEND_TO_WOKER_TIMEOUT, "send result to worker timed out");
        } else {
            swoole_sys_warning("send result to worker failed");
        }
        return false;
    }
    return true;
}
}  // namespace swoole
