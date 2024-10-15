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

Factory *Server::create_process_factory() {
    /**
     * init reactor thread pool
     */
    reactor_threads = new ReactorThread[reactor_num]();
    /**
     * alloc the memory for connection_list
     */
    connection_list = (Connection *) sw_shm_calloc(max_connection, sizeof(Connection));
    if (connection_list == nullptr) {
        swoole_error("calloc[1] failed");
        return nullptr;
    }
    reactor_pipe_num = worker_num / reactor_num;
    return new ProcessFactory(this);
}

void Server::destroy_process_factory() {
    sw_shm_free(connection_list);
    delete[] reactor_threads;

    if (gs->event_workers.message_box) {
        gs->event_workers.message_box->destroy();
    }
}

ProcessFactory::ProcessFactory(Server *server) : Factory(server) {}

ProcessFactory::~ProcessFactory() {}

/**
 * kill and wait all user process
 */
void Factory::kill_user_workers() {
    if (server_->user_worker_map.empty()) {
        return;
    }

    for (auto &kv : server_->user_worker_map) {
        swoole_kill(kv.second->pid, SIGTERM);
    }

    for (auto &kv : server_->user_worker_map) {
        int __stat_loc;
        if (swoole_waitpid(kv.second->pid, &__stat_loc, 0) < 0) {
            swoole_sys_warning("waitpid(%d) failed", kv.second->pid);
        }
    }
}

/**
 * [Manager] kill and wait all event worker process
 */
void Factory::kill_event_workers() {
    int status;

    if (server_->worker_num == 0) {
        return;
    }

    SW_LOOP_N(server_->worker_num) {
        swoole_trace_log(SW_TRACE_SERVER, "kill worker#%d[pid=%d]", server_->workers[i].id, server_->workers[i].pid);
        swoole_kill(server_->workers[i].pid, SIGTERM);
    }
    SW_LOOP_N(server_->worker_num) {
        swoole_trace_log(SW_TRACE_SERVER, "wait worker#%d[pid=%d]", server_->workers[i].id, server_->workers[i].pid);
        if (swoole_waitpid(server_->workers[i].pid, &status, 0) < 0) {
            swoole_sys_warning("waitpid(%d) failed", server_->workers[i].pid);
        }
    }
}

/**
 * [Manager] kill and wait task worker process
 */
void Factory::kill_task_workers() {
    if (server_->task_worker_num == 0) {
        return;
    }
    server_->gs->task_workers.shutdown();
}

pid_t Factory::spawn_event_worker(Worker *worker) {
    pid_t pid = swoole_fork(0);

    if (pid < 0) {
        swoole_sys_warning("failed to fork event worker");
        return SW_ERR;
    } else if (pid == 0) {
        worker->pid = SwooleG.pid;
        SwooleWG.worker = worker;
    } else {
        worker->pid = pid;
        return pid;
    }

    if (server_->is_base_mode()) {
        server_->gs->event_workers.main_loop(&server_->gs->event_workers, worker);
    } else {
        server_->start_event_worker(worker);
    }

    exit(0);
    return 0;
}

pid_t Factory::spawn_user_worker(Worker *worker) {
    pid_t pid = swoole_fork(0);
    if (worker->pid) {
        server_->user_worker_map.erase(worker->pid);
    }
    if (pid < 0) {
        swoole_sys_warning("failed to spawn the user worker");
        return SW_ERR;
    }
    // child
    else if (pid == 0) {
        swoole_set_process_type(SW_PROCESS_USERWORKER);
        swoole_set_process_id(worker->id);
        worker->pid = SwooleG.pid;
        SwooleWG.worker = worker;
        server_->onUserWorkerStart(server_, worker);
        exit(0);
    }
    // parent
    else {
        /**
         * worker: local memory
         * user_workers: shared memory
         */
        server_->get_worker(worker->id)->pid = worker->pid = pid;
        server_->user_worker_map.emplace(std::make_pair(pid, worker));
        return pid;
    }
}

pid_t Factory::spawn_task_worker(Worker *worker) {
    return server_->gs->task_workers.spawn(worker);
}

void Factory::check_worker_exit_status(Worker *worker, const ExitStatus &exit_status) {
    if (exit_status.get_status() != 0) {
        worker->report_error(exit_status);
        server_->call_worker_error_callback(worker, exit_status);
    }
}

bool ProcessFactory::shutdown() {
    int status;

    if (swoole_kill(server_->gs->manager_pid, SIGTERM) < 0) {
        swoole_sys_warning("kill(%d) failed", server_->gs->manager_pid);
    }

    if (swoole_waitpid(server_->gs->manager_pid, &status, 0) < 0) {
        swoole_sys_warning("waitpid(%d) failed", server_->gs->manager_pid);
    }

    return SW_OK;
}

bool Server::create_worker_pipes() {
    SW_LOOP_N(worker_num) {
        auto _sock = new UnixSocket(true, SOCK_DGRAM);
        if (!_sock->ready()) {
            delete _sock;
            return false;
        }

        worker_pipes.emplace_back(_sock);
        workers[i].pipe_master = _sock->get_socket(true);
        workers[i].pipe_worker = _sock->get_socket(false);
        workers[i].pipe_object = _sock;
    }

    init_ipc_max_size();
    if (create_pipe_buffers() < 0) {
        return false;
    }
    return true;
}

bool ProcessFactory::start() {
    if (!server_->create_worker_pipes()) {
        return false;
    }
    return server_->start_manager_process() == SW_OK;
}

/**
 * [ReactorThread] notify info to worker process
 */
bool ProcessFactory::notify(DataHead *ev) {
    SendData task;
    task.info = *ev;
    task.data = nullptr;
    return dispatch(&task);
}

/**
 * [ReactorThread] dispatch request to worker
 */
bool ProcessFactory::dispatch(SendData *task) {
    int fd = task->info.fd;

    int target_worker_id = server_->schedule_worker(fd, task);
    if (target_worker_id < 0) {
        switch (target_worker_id) {
        case Server::DISPATCH_RESULT_DISCARD_PACKET:
            return false;
        case Server::DISPATCH_RESULT_CLOSE_CONNECTION:
            // TODO: close connection
            return false;
        default:
            swoole_warning("invalid target worker id[%d]", target_worker_id);
            return false;
        }
    }

    if (Server::is_stream_event(task->info.type)) {
        Connection *conn = server_->get_connection(fd);
        if (conn == nullptr || conn->active == 0) {
            swoole_warning("dispatch[type=%d] failed, connection#%d is not active", task->info.type, fd);
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

    Worker *worker = server_->get_worker(target_worker_id);

    if (task->info.type == SW_SERVER_EVENT_RECV_DATA) {
        sw_atomic_fetch_add(&worker->dispatch_count, 1);
    }

    SendData _task;
    memcpy(&_task, task, sizeof(SendData));
    network::Socket *sock;
    MessageBus *mb;

    if (server_->is_reactor_thread()) {
        mb = &server_->get_thread(swoole_get_thread_id())->message_bus;
        sock = mb->get_pipe_socket(worker->pipe_master);
    } else {
        mb = &server_->message_bus;
        sock = worker->pipe_master;
    }

    return mb->write(sock, &_task);
}

static bool inline process_is_supported_send_yield(Server *serv, Connection *conn) {
    if (!serv->is_hash_dispatch_mode()) {
        return false;
    } else {
        return serv->schedule_worker(conn->fd, nullptr) == (int) swoole_get_process_id();
    }
}

/**
 * [Worker] send to client, proxy by reactor
 */
bool ProcessFactory::finish(SendData *resp) {
    /**
     * More than the output buffer
     */
    if (resp->info.len > server_->output_buffer_size) {
        swoole_error_log(SW_LOG_WARNING,
                         SW_ERROR_DATA_LENGTH_TOO_LARGE,
                         "The length of data [%u] exceeds the output buffer size[%u], "
                         "please use the sendfile, chunked transfer mode or adjust the output_buffer_size",
                         resp->info.len,
                         server_->output_buffer_size);
        return false;
    }

    SessionId session_id = resp->info.fd;
    Connection *conn;
    if (resp->info.type != SW_SERVER_EVENT_CLOSE) {
        conn = server_->get_connection_verify(session_id);
    } else {
        conn = server_->get_connection_verify_no_ssl(session_id);
    }
    if (!conn) {
        if (resp->info.type != SW_SERVER_EVENT_CLOSE) {
            swoole_error_log(SW_LOG_TRACE, SW_ERROR_SESSION_NOT_EXIST, "session#%ld does not exists", session_id);
        }
        return false;
    } else if ((conn->closed || conn->peer_closed) && resp->info.type != SW_SERVER_EVENT_CLOSE) {
        swoole_error_log(SW_LOG_TRACE,
                         SW_ERROR_SESSION_CLOSED,
                         "send %d bytes failed, because session#%ld is closed",
                         resp->info.len,
                         session_id);
        return false;
    } else if (conn->overflow &&
               (resp->info.type == SW_SERVER_EVENT_SEND_DATA || resp->info.type == SW_SERVER_EVENT_SEND_FILE)) {
        if (server_->send_yield && process_is_supported_send_yield(server_, conn)) {
            swoole_set_last_error(SW_ERROR_OUTPUT_SEND_YIELD);
        } else {
            swoole_error_log(SW_LOG_WARNING,
                             SW_ERROR_OUTPUT_BUFFER_OVERFLOW,
                             "send failed, session=%ld output buffer overflow",
                             session_id);
        }
        return false;
    }

    SendData task;
    memcpy(&task, resp, sizeof(SendData));
    task.info.fd = session_id;
    task.info.reactor_id = conn->reactor_id;
    task.info.server_fd = swoole_get_process_id();

    swoole_trace("worker_id=%d, type=%d", SwooleG.process_id, task.info.type);

    return server_->message_bus.write(server_->get_reactor_pipe_socket(session_id, task.info.reactor_id), &task);
}

bool ProcessFactory::end(SessionId session_id, int flags) {
    SendData _send{};
    DataHead info{};

    _send.info.fd = session_id;
    _send.info.len = 0;
    _send.info.type = SW_SERVER_EVENT_CLOSE;

    Connection *conn = server_->get_connection_verify_no_ssl(session_id);
    if (!conn) {
        swoole_error_log(SW_LOG_TRACE, SW_ERROR_SESSION_NOT_EXIST, "session#%ld does not exists", session_id);
        return false;
    }
    // Reset send buffer, Immediately close the connection.
    if (flags & Server::CLOSE_RESET) {
        conn->close_reset = 1;
    }
    // Server is initiative to close the connection
    if (flags & Server::CLOSE_ACTIVELY) {
        conn->close_actively = 1;
    }

    swoole_trace_log(SW_TRACE_CLOSE, "session_id=%ld, fd=%d", session_id, conn->fd);

    Worker *worker;
    DataHead ev = {};

    /**
     * Only close actively needs to determine whether it is in the process of connection binding.
     * If the worker process is not currently bound to this connection,
     * MUST forward to the correct worker process
     */
    if (conn->close_actively) {
        bool hash = server_->is_hash_dispatch_mode();
        int worker_id = hash ? server_->schedule_worker(conn->fd, nullptr) : conn->fd % server_->worker_num;
        if (server_->is_worker() && (!hash || worker_id == (int) swoole_get_process_id())) {
            goto _close;
        }
        worker = server_->get_worker(worker_id);
        ev.type = SW_SERVER_EVENT_CLOSE;
        ev.fd = session_id;
        ev.reactor_id = conn->reactor_id;
        return server_->send_to_worker_from_worker(worker, &ev, sizeof(ev), SW_PIPE_MASTER) > 0;
    }

_close:
    if (conn->closing) {
        swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SESSION_CLOSING, "session#%ld is closing", session_id);
        return false;
    } else if (!(conn->close_force || conn->close_reset) && conn->closed) {
        swoole_error_log(SW_LOG_TRACE, SW_ERROR_SESSION_CLOSED, "session#%ld is closed", session_id);
        return false;
    }

    if (server_->onClose != nullptr && !conn->closed) {
        info.fd = session_id;
        if (conn->close_actively) {
            info.reactor_id = -1;
        } else {
            info.reactor_id = conn->reactor_id;
        }
        info.server_fd = conn->server_fd;
        conn->closing = 1;
        server_->onClose(server_, &info);
        conn->closing = 0;
    }
    conn->closed = 1;
    conn->close_errno = 0;
    return finish(&_send);
}
}  // namespace swoole
