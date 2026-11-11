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
#include "swoole_api.h"

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
    connection_list = static_cast<Connection *>(sw_shm_calloc(max_connection, sizeof(Connection)));
    if (connection_list == nullptr) {
        swoole_sys_warning("sw_shm_calloc(%u, %zu) for connection_list failed", max_connection, sizeof(Connection));
        return nullptr;
    }
    reactor_pipe_num = worker_num / reactor_num;

    reactor_thread_barrier.init(false, reactor_num + 1);
    gs->manager_barrier.init(true, 2);

    return new ProcessFactory(this);
}

void Server::destroy_process_factory() {
    sw_shm_free(connection_list);
    if (single_thread) {
        // init() ran on the master reactor itself in this mode.
        get_thread(0)->clean();
    }
    delete[] reactor_threads;

    reactor_thread_barrier.destroy();
    gs->manager_barrier.destroy();

    if (get_event_worker_pool()->message_box) {
        get_event_worker_pool()->message_box->destroy();
    }
}

ProcessFactory::ProcessFactory(Server *server) : Factory(server) {}

ProcessFactory::~ProcessFactory() = default;

/**
 * kill and wait all user process
 */
void Factory::kill_user_workers() const {
    if (server_->user_worker_map.empty()) {
        return;
    }

    for (const auto &kv : server_->user_worker_map) {
        swoole_kill(kv.second->pid, SIGTERM);
    }

    for (const auto &kv : server_->user_worker_map) {
        int _stat_loc;
        if (swoole_waitpid(kv.second->pid, &_stat_loc, 0) < 0) {
            swoole_sys_warning("waitpid(%d) failed", kv.second->pid);
        }
    }
}

/**
 * [Manager] kill and wait all event worker process
 */
void Factory::kill_event_workers() const {
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
void Factory::kill_task_workers() const {
    int status;
    if (server_->task_worker_num == 0) {
        return;
    }

    auto pool = server_->get_task_worker_pool();
    pool->kill_all_workers(SIGTERM);

    SW_LOOP_N(server_->task_worker_num) {
        swoole_trace_log(SW_TRACE_SERVER, "wait worker#%d[pid=%d]", pool->workers[i].id, pool->workers[i].pid);
        if (swoole_waitpid(pool->workers[i].pid, &status, 0) < 0) {
            swoole_sys_warning("waitpid(%d) failed", pool->workers[i].pid);
        }
    }
}

pid_t Factory::spawn_event_worker(Worker *worker) const {
    pid_t pid = swoole_fork(0);

    if (pid < 0) {
        swoole_sys_warning("failed to fork event worker");
        return SW_ERR;
    } else if (pid == 0) {
        worker->pid = getpid();
        swoole_set_worker_id(worker->id);
        swoole_set_worker_pid(worker->pid);
        swoole_set_worker_type(SW_EVENT_WORKER);
        SwooleWG.worker = worker;
    } else {
        worker->pid = pid;
        return pid;
    }

    if (server_->is_base_mode()) {
        auto pool = server_->get_event_worker_pool();
        pool->main_loop(pool, worker);
    } else {
        server_->start_event_worker(worker);
    }

    // The worker loop and its native cleanup have finished; bindings may now return to their VM.
    swoole_call_hook(SW_GLOBAL_HOOK_BEFORE_CHILD_PROCESS_EXIT, nullptr);
    exit(0);
    return 0;
}

pid_t Factory::spawn_user_worker(Worker *worker) const {
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
        worker->pid = getpid();
        swoole_set_worker_type(SW_USER_WORKER);
        swoole_set_worker_id(worker->id);
        swoole_set_worker_pid(worker->pid);
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
        server_->user_worker_map.emplace(pid, worker);
        return pid;
    }
}

pid_t Factory::spawn_task_worker(Worker *worker) const {
    return server_->get_task_worker_pool()->spawn(worker);
}

void Factory::check_worker_exit_status(Worker *worker, const ExitStatus &exit_status) const {
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
        auto pipe = std::make_shared<UnixSocket>(true, SOCK_DGRAM);
        if (!pipe->ready()) {
            return false;
        }

        worker_pipes.emplace_back(std::move(pipe));
        const auto &owned_pipe = worker_pipes.back();
        workers[i].pipe_master = owned_pipe->get_socket(true);
        workers[i].pipe_worker = owned_pipe->get_socket(false);
        workers[i].pipe_object = owned_pipe.get();
    }

    init_ipc_max_size();
    create_pipe_buffers();

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
    // the task->info.fd is real fd, not session_id, it will be converted to session after dispatch
    int fd = static_cast<int>(task->info.fd);

    int target_worker_id = server_->schedule_worker(fd, task);
    if (target_worker_id < 0) {
        switch (target_worker_id) {
        case Server::DISPATCH_RESULT_DISCARD_PACKET:
            // Intentional consumption of this packet. Framed protocols must keep reading
            // the connection, rather than interpret the discard as a callback failure.
            return true;
        case Server::DISPATCH_RESULT_CLOSE_CONNECTION:
            // TODO: close connection
            return false;
        default:
            swoole_warning("invalid target worker id[%d]", target_worker_id);
            return false;
        }
    }

    Connection *conn = nullptr;
    if (Server::is_stream_event(task->info.type)) {
        conn = server_->get_connection(fd);
        if (conn == nullptr || conn->active == 0) {
            swoole_warning("dispatch[type=%d] failed, connection#%d is not active", task->info.type, fd);
            return false;
        }
        // converted fd to session_id
        task->info.fd = conn->session_id;
        task->info.server_fd = conn->server_fd;
    }

    Worker *worker = server_->get_worker(target_worker_id);

    const bool receive_data = task->info.type == SW_SERVER_EVENT_RECV_DATA;
    if (receive_data) {
        sw_atomic_long_fetch_add(&worker->dispatch_count, 1);
    }

    SendData _task;
    memcpy(&_task, task, sizeof(SendData));

    ReactorThread *thread = server_->get_thread(swoole_get_thread_id());
    MessageBus *mb = &thread->message_bus;
    Socket *sock = mb->get_pipe_socket(worker->pipe_master);
    // Keep worker-exit bookkeeping off the normal receive dispatch path.
    if (sw_unlikely(task->info.type == SW_SERVER_EVENT_CLOSE) &&
        sw_unlikely(!thread->track_waiting_close(sw_reactor(), conn, worker->pid, worker->id))) {
        return false;
    }
    if (receive_data && task->info.len > 0) {
        // The worker process can consume this queue concurrently with the reactor producer.
        conn->add_recv_queued_bytes<Connection::ReceiveQueueMode::SHARED_PROCESS>(task->info.len);
        swoole_trace_log(SW_TRACE_SERVER,
                         "session_id=%ld, len=%d, qb=%d",
                         conn->session_id,
                         task->info.len,
                         conn->get_recv_queued_bytes());
    }
    if (sw_unlikely(!mb->write(sock, &_task))) {
        if (task->info.type == SW_SERVER_EVENT_CLOSE) {
            thread->remove_waiting_close(conn->session_id);
        }
        if (receive_data && task->info.len > 0) {
            conn->subtract_recv_queued_bytes<Connection::ReceiveQueueMode::SHARED_PROCESS>(task->info.len);
        }
        return false;
    }
    if (receive_data) {
        thread->dispatch_count++;
        sw_atomic_long_fetch_add(&server_->gs->dispatch_count, 1);
        sw_atomic_long_fetch_add(&server_->get_port_by_server_fd(conn->server_fd)->gs->dispatch_count, 1);
    }
    return true;
}

static bool process_is_supported_send_yield(Server *serv, const Connection *conn) {
    if (!serv->is_hash_dispatch_mode()) {
        return false;
    } else {
        return serv->schedule_worker(conn->fd, nullptr) == static_cast<int>(swoole_get_worker_id());
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
    } else if (conn->is_close_requested() && resp->info.type != SW_SERVER_EVENT_CLOSE) {
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
    task.info.server_fd = swoole_get_worker_id();

    swoole_trace("worker_id=%d, type=%d", task.info.server_fd, task.info.type);

    return server_->message_bus.write(server_->get_reactor_pipe_socket(session_id, task.info.reactor_id), &task);
}

bool ProcessFactory::end(SessionId session_id, int flags) {
    Connection *conn = server_->get_connection_verify_no_ssl(session_id);
    if (!conn) {
        swoole_set_last_error(SW_ERROR_SESSION_NOT_EXIST);
        return false;
    }
    // Forward application close to the assigned worker before claiming callback/close handling.
    if (flags & Server::CLOSE_ACTIVELY) {
        const bool hash = server_->is_hash_dispatch_mode();
        const int worker_id = hash ? server_->schedule_worker(conn->fd, nullptr) : conn->fd % server_->worker_num;
        if (!server_->is_worker() || (hash && worker_id != static_cast<int>(swoole_get_worker_id()))) {
            DataHead ev{};
            ev.type = SW_SERVER_EVENT_CLOSE;
            ev.fd = session_id;
            ev.reactor_id = conn->reactor_id;
            ev.ext_flags = flags;
            return server_->send_to_worker_from_worker(
                       server_->get_worker(worker_id), &ev, sizeof(ev), SW_PIPE_MASTER) > 0;
        }
    }
    return server_->finish_close(session_id, flags);
}
}  // namespace swoole
