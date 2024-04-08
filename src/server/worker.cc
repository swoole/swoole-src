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

#include <pwd.h>
#include <grp.h>
#include <sys/uio.h>
#include <sys/mman.h>

#include "swoole_server.h"
#include "swoole_memory.h"
#include "swoole_msg_queue.h"
#include "swoole_coroutine.h"

SW_THREAD_LOCAL swoole::Worker *g_worker_instance;

namespace swoole {
using namespace network;

static int Worker_onPipeReceive(Reactor *reactor, Event *event);
static void Worker_reactor_try_to_exit(Reactor *reactor);

void Server::worker_signal_init(void) {
#ifndef SW_THREAD
    swoole_signal_set(SIGHUP, nullptr);
    swoole_signal_set(SIGPIPE, SIG_IGN);
    swoole_signal_set(SIGUSR1, nullptr);
    swoole_signal_set(SIGUSR2, nullptr);
    // swSignal_set(SIGINT, Server::worker_signal_handler);
    swoole_signal_set(SIGTERM, Server::worker_signal_handler);
    // for test
    swoole_signal_set(SIGVTALRM, Server::worker_signal_handler);
#ifdef SIGRTMIN
    swoole_signal_set(SIGRTMIN, Server::worker_signal_handler);
#endif
#endif
}

void Server::worker_signal_handler(int signo) {
    if (!SwooleG.running || !sw_server() || !sw_worker()) {
        return;
    }
    switch (signo) {
    case SIGTERM:
        // Event worker
        if (swoole_event_is_available()) {
            sw_server()->stop_async_worker(sw_worker());
        }
        // Task worker
        else {
            sw_worker()->shutdown = true;
        }
        break;
    // for test
    case SIGVTALRM:
        swoole_warning("SIGVTALRM coming");
        break;
    case SIGUSR1:
    case SIGUSR2:
        if (sw_logger()) {
            sw_logger()->reopen();
        }
        break;
    default:
#ifdef SIGRTMIN
        if (signo == SIGRTMIN && sw_logger()) {
            sw_logger()->reopen();
        }
#endif
        break;
    }
}

static sw_inline bool Worker_discard_data(Server *serv, Connection *conn, DataHead *info) {
    if (conn == nullptr) {
        if (serv->disable_notify && !serv->discard_timeout_request) {
            return false;
        }
        goto _discard_data;
    } else {
        if (conn->closed) {
            goto _discard_data;
        } else {
            return false;
        }
    }
_discard_data:
    swoole_error_log(SW_LOG_WARNING,
                     SW_ERROR_SESSION_DISCARD_TIMEOUT_DATA,
                     "[2] ignore data[%u bytes] received from session#%ld",
                     info->len,
                     info->fd);
    return true;
}

typedef std::function<int(Server *, RecvData *)> TaskCallback;

static sw_inline void Worker_do_task(Server *serv, Worker *worker, DataHead *info, const TaskCallback &callback) {
    RecvData recv_data;
    auto packet = serv->message_bus.get_packet();
    recv_data.info = *info;
    recv_data.info.len = packet.length;
    recv_data.data = packet.data;

    if (callback(serv, &recv_data) == SW_OK) {
        worker->request_count++;
        sw_atomic_fetch_add(&serv->gs->request_count, 1);
    }
}

void Server::worker_accept_event(DataHead *info) {
    Worker *worker = sw_worker();
    // worker busy
    worker->status = SW_WORKER_BUSY;

    switch (info->type) {
    case SW_SERVER_EVENT_RECV_DATA: {
        Connection *conn = get_connection_verify(info->fd);
        if (conn) {
            if (info->len > 0) {
                auto packet = message_bus.get_packet();
                sw_atomic_fetch_sub(&conn->recv_queued_bytes, packet.length);
                swoole_trace_log(SW_TRACE_SERVER,
                                 "[Worker] session_id=%ld, len=%lu, qb=%d",
                                 conn->session_id,
                                 packet.length,
                                 conn->recv_queued_bytes);
            }
            conn->last_dispatch_time = info->time;
        }
        if (!Worker_discard_data(this, conn, info)) {
            Worker_do_task(this, worker, info, onReceive);
        }
        break;
    }
    case SW_SERVER_EVENT_RECV_DGRAM: {
        Worker_do_task(this, worker, info, onPacket);
        break;
    }
    case SW_SERVER_EVENT_CLOSE: {
#ifdef SW_USE_OPENSSL
        Connection *conn = get_connection_verify_no_ssl(info->fd);
        if (conn && conn->ssl_client_cert && conn->ssl_client_cert_pid == SwooleG.pid) {
            delete conn->ssl_client_cert;
            conn->ssl_client_cert = nullptr;
        }
#endif
        factory->end(info->fd, false);
        break;
    }
    case SW_SERVER_EVENT_CONNECT: {
#ifdef SW_USE_OPENSSL
        // SSL client certificate
        if (info->len > 0) {
            Connection *conn = get_connection_verify_no_ssl(info->fd);
            if (conn) {
                auto packet = message_bus.get_packet();
                conn->ssl_client_cert = new String(packet.data, packet.length);
                conn->ssl_client_cert_pid = SwooleG.pid;
            }
        }
#endif
        if (onConnect) {
            onConnect(this, info);
        }
        break;
    }

    case SW_SERVER_EVENT_BUFFER_FULL: {
        if (onBufferFull) {
            onBufferFull(this, info);
        }
        break;
    }
    case SW_SERVER_EVENT_BUFFER_EMPTY: {
        if (onBufferEmpty) {
            onBufferEmpty(this, info);
        }
        break;
    }
    case SW_SERVER_EVENT_FINISH: {
        onFinish(this, (EventData *) message_bus.get_buffer());
        break;
    }
    case SW_SERVER_EVENT_PIPE_MESSAGE: {
        onPipeMessage(this, (EventData *) message_bus.get_buffer());
        break;
    }
    case SW_SERVER_EVENT_COMMAND_REQUEST: {
        call_command_handler(message_bus, worker->id, pipe_command->get_socket(false));
        break;
    }
    default:
        swoole_warning("[Worker] error event[type=%d]", (int) info->type);
        break;
    }

    // worker idle
    worker->status = SW_WORKER_IDLE;

    // maximum number of requests, process will exit.
    if (!worker->run_always && worker->request_count >= worker->max_request) {
        stop_async_worker(worker);
    }
}

void Server::worker_start_callback(Worker *worker) {
    if (swoole_get_process_id() >= worker_num) {
        swoole_set_process_type(SW_PROCESS_TASKWORKER);
    } else {
        swoole_set_process_type(SW_PROCESS_WORKER);
    }

    int is_root = !geteuid();
    struct passwd *_passwd = nullptr;
    struct group *_group = nullptr;

    if (is_root) {
        // get group info
        if (!group_.empty()) {
            _group = getgrnam(group_.c_str());
            if (!_group) {
                swoole_warning("get group [%s] info failed", group_.c_str());
            }
        }
        // get user info
        if (!user_.empty()) {
            _passwd = getpwnam(user_.c_str());
            if (!_passwd) {
                swoole_warning("get user [%s] info failed", user_.c_str());
            }
        }
        // set process group
        if (_group && setgid(_group->gr_gid) < 0) {
            swoole_sys_warning("setgid to [%s] failed", group_.c_str());
        }
        // set process user
        if (_passwd && setuid(_passwd->pw_uid) < 0) {
            swoole_sys_warning("setuid to [%s] failed", user_.c_str());
        }
        // chroot
        if (!chroot_.empty()) {
            if (::chroot(chroot_.c_str()) == 0) {
                if (chdir("/") < 0) {
                    swoole_sys_warning("chdir(\"/\") failed");
                }
            } else {
                swoole_sys_warning("chroot(\"%s\") failed", chroot_.c_str());
            }
        }
    }

    SW_LOOP_N(worker_num + task_worker_num) {
        if (worker->id == i) {
            continue;
        }
        Worker *other_worker = get_worker(i);
        if (is_worker() && other_worker->pipe_master) {
            other_worker->pipe_master->set_nonblock();
        }
    }

    if (sw_logger()->is_opened()) {
        sw_logger()->reopen();
    }

    g_worker_instance = worker;
    worker->status = SW_WORKER_IDLE;

    if (is_process_mode()) {
        sw_shm_protect(session_list, PROT_READ);
    }

    call_worker_start_callback(worker);
}

void Server::worker_stop_callback(Worker *worker) {
    void *hook_args[2];
    hook_args[0] = this;
    hook_args[1] = (void *) (uintptr_t) worker->id;
    if (swoole_isset_hook(SW_GLOBAL_HOOK_BEFORE_WORKER_STOP)) {
        swoole_call_hook(SW_GLOBAL_HOOK_BEFORE_WORKER_STOP, hook_args);
    }
    if (onWorkerStop) {
        onWorkerStop(this, worker);
    }
    if (!message_bus.empty()) {
        swoole_error_log(
            SW_LOG_WARNING, SW_ERROR_SERVER_WORKER_UNPROCESSED_DATA, "unprocessed data in the worker process buffer");
        message_bus.clear();
    }
}

void Server::stop_async_worker(Worker *worker) {
    worker->status = SW_WORKER_EXIT;
    Reactor *reactor = SwooleTG.reactor;

    /**
     * force to end.
     */
    if (reload_async == 0) {
        running = false;
        reactor->running = false;
        return;
    }

    // The worker process is shutting down now.
    if (reactor->wait_exit) {
        return;
    }

    // Separated from the event worker process pool
    Worker *worker_copy = (Worker *) sw_malloc(sizeof(*worker));
    *worker_copy = *worker;
    g_worker_instance = worker_copy;

    if (worker->pipe_worker && !worker->pipe_worker->removed) {
        reactor->remove_read_event(worker->pipe_worker);
    }

    if (is_base_mode()) {
        if (is_worker()) {
            if (worker->id == 0 && gs->event_workers.running == 0) {
                if (swoole_isset_hook(SW_GLOBAL_HOOK_BEFORE_SERVER_SHUTDOWN)) {
                    swoole_call_hook(SW_GLOBAL_HOOK_BEFORE_SERVER_SHUTDOWN, this);
                }
                if (onBeforeShutdown) {
                    onBeforeShutdown(this);
                }
            }
            for (auto ls : ports) {
                reactor->del(ls->socket);
            }
            if (worker->pipe_master && !worker->pipe_master->removed) {
                reactor->remove_read_event(worker->pipe_master);
            }
            foreach_connection([reactor](Connection *conn) {
                if (!conn->peer_closed && !conn->socket->removed) {
                    reactor->remove_read_event(conn->socket);
                }
            });
            clear_timer();
        }
    } else {
        WorkerStopMessage msg;
        msg.pid = SwooleG.pid;
        msg.worker_id = worker->id;

        if (gs->event_workers.push_message(SW_WORKER_MESSAGE_STOP, &msg, sizeof(msg)) < 0) {
            running = 0;
        }
    }

    reactor->set_wait_exit(true);
    reactor->set_end_callback(Reactor::PRIORITY_TRY_EXIT, Worker_reactor_try_to_exit);
    worker->exit_time = ::time(nullptr);

    Worker_reactor_try_to_exit(reactor);
    if (!reactor->running) {
        running = false;
    }
}

static void Worker_reactor_try_to_exit(Reactor *reactor) {
    Server *serv;
    if (swoole_get_process_type() == SW_PROCESS_TASKWORKER) {
        ProcessPool *pool = (ProcessPool *) reactor->ptr;
        serv = (Server *) pool->ptr;
    } else {
        serv = (Server *) reactor->ptr;
    }
    uint8_t call_worker_exit_func = 0;

    while (1) {
        if (reactor->if_exit()) {
            reactor->running = false;
            break;
        } else {
            if (serv->onWorkerExit && call_worker_exit_func == 0) {
                serv->onWorkerExit(serv, sw_worker());
                call_worker_exit_func = 1;
                continue;
            }
            int remaining_time = serv->max_wait_time - (::time(nullptr) - sw_worker()->exit_time);
            if (remaining_time <= 0) {
                swoole_error_log(
                    SW_LOG_WARNING, SW_ERROR_SERVER_WORKER_EXIT_TIMEOUT, "worker exit timeout, forced termination");
                reactor->running = false;
                break;
            } else {
                int timeout_msec = remaining_time * 1000;
                if (reactor->timeout_msec < 0 || reactor->timeout_msec > timeout_msec) {
                    reactor->timeout_msec = timeout_msec;
                }
            }
        }
        break;
    }
}

void Server::drain_worker_pipe() {
    for (uint32_t i = 0; i < worker_num + task_worker_num; i++) {
        Worker *worker = get_worker(i);
        if (sw_reactor()) {
            if (worker->pipe_worker) {
                sw_reactor()->drain_write_buffer(worker->pipe_worker);
            }
            if (worker->pipe_master) {
                sw_reactor()->drain_write_buffer(worker->pipe_master);
            }
        }
    }
}

/**
 * main loop [Worker]
 */
int Server::start_event_worker(Worker *worker) {
    swoole_set_process_id(worker->id);
    swoole_set_process_type(SW_PROCESS_EVENTWORKER);

    init_worker(worker);

    if (swoole_event_init(0) < 0) {
        return SW_ERR;
    }

    worker_signal_init();

    Reactor *reactor = SwooleTG.reactor;
    /**
     * set pipe buffer size
     */
    for (uint32_t i = 0; i < worker_num + task_worker_num; i++) {
        Worker *_worker = get_worker(i);
        if (_worker->pipe_master) {
            _worker->pipe_master->buffer_size = UINT_MAX;
        }
        if (_worker->pipe_worker) {
            _worker->pipe_worker->buffer_size = UINT_MAX;
        }
    }

    worker->pipe_worker->set_nonblock();
    reactor->ptr = this;
    reactor->add(worker->pipe_worker, SW_EVENT_READ);
    reactor->set_handler(SW_FD_PIPE, Worker_onPipeReceive);

    if (dispatch_mode == DISPATCH_CO_CONN_LB || dispatch_mode == DISPATCH_CO_REQ_LB) {
        reactor->set_end_callback(Reactor::PRIORITY_WORKER_CALLBACK,
                                  [worker](Reactor *) { worker->coroutine_num = Coroutine::count(); });
    }

    worker->status = SW_WORKER_IDLE;
    worker_start_callback(worker);

    // main loop
    reactor->wait(nullptr);
    // drain pipe buffer
    drain_worker_pipe();
    // reactor free
    swoole_event_free();
    // worker shutdown
    worker_stop_callback(worker);

    if (buffer_pool) {
        delete buffer_pool;
    }

    return SW_OK;
}

/**
 * [Worker/TaskWorker/Master] Send data to ReactorThread
 */
ssize_t Server::send_to_reactor_thread(const EventData *ev_data, size_t sendn, SessionId session_id) {
    Socket *pipe_sock = get_reactor_pipe_socket(session_id, ev_data->info.reactor_id);
    if (swoole_event_is_available()) {
        return swoole_event_write(pipe_sock, ev_data, sendn);
    } else {
        return pipe_sock->send_blocking(ev_data, sendn);
    }
}

/**
 * send message from worker to another worker
 */
ssize_t Server::send_to_worker_from_worker(Worker *dst_worker, const void *buf, size_t len, int flags) {
    return dst_worker->send_pipe_message(buf, len, flags);
}

/**
 * receive data from reactor
 */
static int Worker_onPipeReceive(Reactor *reactor, Event *event) {
    Server *serv = (Server *) reactor->ptr;
    PipeBuffer *pipe_buffer = serv->message_bus.get_buffer();

    if (serv->message_bus.read(event->socket) <= 0) {
        return SW_OK;
    }

    serv->worker_accept_event(&pipe_buffer->info);
    serv->message_bus.pop();

    return SW_OK;
}

ssize_t Worker::send_pipe_message(const void *buf, size_t n, int flags) {
    Socket *pipe_sock;

    if (flags & SW_PIPE_MASTER) {
        pipe_sock = pipe_master;
    } else {
        pipe_sock = pipe_worker;
    }

    // message-queue
    if (pool->use_msgqueue) {
        struct {
            long mtype;
            EventData buf;
        } msg;

        msg.mtype = id + 1;
        memcpy(&msg.buf, buf, n);

        return pool->queue->push((QueueNode *) &msg, n) ? n : -1;
    }

    if ((flags & SW_PIPE_NONBLOCK) && swoole_event_is_available()) {
        return swoole_event_write(pipe_sock, buf, n);
    } else {
        return pipe_sock->send_blocking(buf, n);
    }
}
}  // namespace swoole
