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
#include "swoole_hash.h"
#include "swoole_util.h"

#include <cassert>

using std::unordered_map;

namespace swoole {
using namespace network;

static int ReactorThread_onPipeWrite(Reactor *reactor, Event *ev);
static int ReactorThread_onPipeRead(Reactor *reactor, Event *ev);
static int ReactorThread_onRead(Reactor *reactor, Event *ev);
static int ReactorThread_onWrite(Reactor *reactor, Event *ev);
static int ReactorThread_onPacketReceived(Reactor *reactor, Event *event);
static int ReactorThread_onClose(Reactor *reactor, Event *event);
static void ReactorThread_resume_data_receiving(Timer *timer, TimerNode *tnode);

static inline ReturnCode ReactorThread_verify_ssl_state(Reactor *reactor, ListenPort *port, Socket *_socket) {
    auto serv = static_cast<Server *>(reactor->ptr);
    if (!_socket->ssl || _socket->ssl_state == SW_SSL_STATE_READY) {
        return SW_CONTINUE;
    }

    ReturnCode code = _socket->ssl_accept();
    if (code != SW_READY) {
        return code;
    }

    auto conn = static_cast<Connection *>(_socket->object);
    conn->ssl_ready = 1;
    conn->recv_delayed = serv->enable_delay_receive;
    if (!port->get_ssl_client_cert_file().empty()) {
        if (!_socket->ssl_get_peer_certificate(sw_tg_buffer())) {
            if (port->get_ssl_verify_peer()) {
                swoole_error_log(SW_LOG_NOTICE,
                                 SW_ERROR_SSL_EMPTY_PEER_CERTIFICATE,
                                 "peer certificate from fd#%d is required",
                                 _socket->fd);
                return SW_ERROR;
            }
        } else {
            if (!port->get_ssl_verify_peer() || _socket->ssl_verify(port->get_ssl_allow_self_signed())) {
                SendData task;
                task.info.fd = _socket->fd;
                task.info.type = SW_SERVER_EVENT_CONNECT;
                task.info.reactor_id = reactor->id;
                task.info.len = sw_tg_buffer()->length;
                task.data = sw_tg_buffer()->str;
                serv->factory_->dispatch(&task);
                goto _delay_receive;
            } else {
                return SW_ERROR;
            }
        }
    } else if (port->get_ssl_verify_peer()) {
        // SSL_get_verify_result() returns X509_V_OK when the peer did not provide a certificate.
        X509 *cert = _socket->ssl_get_peer_certificate();
        if (cert == nullptr) {
            swoole_error_log(SW_LOG_NOTICE,
                             SW_ERROR_SSL_EMPTY_PEER_CERTIFICATE,
                             "peer certificate from fd#%d is required",
                             _socket->fd);
            return SW_ERROR;
        }
        X509_free(cert);
        if (!_socket->ssl_verify(port->get_ssl_allow_self_signed())) {
            return SW_ERROR;
        }
    }

    if (serv->onConnect) {
        serv->notify(static_cast<Connection *>(_socket->object), SW_SERVER_EVENT_CONNECT);
    }
_delay_receive:
    if (!conn->active || conn->socket != _socket) {
        return SW_WAIT;
    }
    if (!conn->can_receive()) {
        return serv->update_recv_interest(reactor, conn) < 0 ? SW_ERROR : SW_WAIT;
    }

    return SW_READY;
}

/**
 * for udp
 */
static int ReactorThread_onPacketReceived(Reactor *reactor, Event *event) {
    int fd = event->fd;

    auto serv = static_cast<Server *>(reactor->ptr);
    Connection *server_sock = serv->get_connection(fd);
    Socket *sock = server_sock->socket;
    SendData task = {};
    auto pkt = reinterpret_cast<DgramPacket *>(sw_tg_buffer()->str);

    task.info.server_fd = fd;
    task.info.reactor_id = SwooleTG.id;
    task.info.type = SW_SERVER_EVENT_RECV_DGRAM;
    task.info.time = microtime();

    pkt->socket_addr.type = pkt->socket_type = server_sock->socket_type;

_do_recvfrom:

    ssize_t ret = sock->recvfrom(pkt->data, sw_tg_buffer()->size - sizeof(*pkt), 0, &pkt->socket_addr);
    if (ret <= 0) {
        if (errno == EAGAIN) {
            return SW_OK;
        } else {
            swoole_sys_warning("recvfrom(%d) failed", fd);
            return SW_ERR;
        }
    }

#ifdef SW_SUPPORT_DTLS
    auto port = static_cast<ListenPort *>(server_sock->object);

    if (port->is_dtls()) {
        auto *socket = serv->accept_dtls_socket(port, &pkt->socket_addr, pkt->data, ret);
        if (!socket) {
            return SW_ERR;
        }
        serv->dispatch_connection(reactor, socket, port, port->get_fd());

        return SW_OK;
    }
#endif

    if (pkt->socket_type == SW_SOCK_UDP) {
        task.info.fd = *reinterpret_cast<int *>(&pkt->socket_addr.addr.inet_v4.sin_addr);
    } else {
        task.info.fd = swoole_crc32(pkt->socket_addr.get_addr(), pkt->socket_addr.len);
    }

    pkt->length = ret;
    task.info.len = sizeof(*pkt) + ret;
    task.data = reinterpret_cast<char *>(pkt);

    if (!serv->factory_->dispatch(&task)) {
        return SW_ERR;
    } else {
        goto _do_recvfrom;
    }
}

// PROCESS owner reactor only. Register before enqueueing CLOSE so a fast worker acknowledgement
// cannot overtake registration. Defer all PID probes to the timer: a dead dispatch target must
// not prevent enqueueing CLOSE, since a replacement worker can consume the same pipe.
bool ReactorThread::track_waiting_close(Reactor *reactor,
                                        const Connection *conn,
                                        pid_t worker_pid,
                                        WorkerId worker_id) {
    const SessionId session_id = conn->session_id;
    // Ordinary additions to a nonempty map do not restart a full scan. Only the first entry
    // needs an initial check. Exceptions: an unpublished target PID needs a retry, or an
    // already claimed CLOSE may belong to an exit sequence consumed before registration.
    if (waiting_close.empty() || sw_unlikely(worker_pid <= 0) || sw_unlikely(conn->get_close_worker_pid() > 0)) {
        waiting_close_check_pending = true;
    }
    waiting_close[session_id] = {worker_pid, worker_id};
    // Shutdown stops consuming worker replies and retires sessions in the reactor's destroy
    // callback. A late write error must not restart a monitor that would prevent that exit.
    if (!waiting_close_timer && !reactor->wait_exit) {
        // Wake even an otherwise idle reactor, without imposing a lifetime on any session.
        waiting_close_timer = swoole_timer_add(1000L, true, [this, reactor](Timer *, TimerNode *node) {
            if (sw_likely(waiting_close.empty())) {
                // Keep one timer across bursts of promptly acknowledged closes. An idle
                // tick retires it without a shared-sequence load or any process probes.
                swoole_timer_del(node);
                waiting_close_timer = nullptr;
                return;
            }
            check_waiting_close(reactor);
        });
        if (sw_unlikely(!waiting_close_timer)) {
            remove_waiting_close(session_id);
            swoole_warning("failed to monitor worker exit for session#%ld", session_id);
            return false;
        }
    }
    return true;
}

// Owner only, including physical retirement. Leave timer deletion to its next idle callback,
// so the next CLOSE can reuse it without another heap insertion or allocation.
void ReactorThread::remove_waiting_close(SessionId session_id) {
    waiting_close.erase(session_id);
    if (waiting_close.empty()) {
        waiting_close_check_pending = false;
    }
}

// PROCESS owner reactor only. One atomic load per timer tick; only an actual manager-reaped
// exit, the first entry or a necessary recovery check triggers a scan. No per-entry slot lock.
void ReactorThread::check_waiting_close(Reactor *reactor) {
    auto *serv = static_cast<Server *>(reactor->ptr);
    const auto sequence = sw_atomic_load_acquire(&serv->gs->worker_exit_sequence);
    if (sw_likely(sequence == last_worker_exit_sequence && !waiting_close_check_pending)) {
        return;
    }
    // Snapshot before scanning: exits during the scan must trigger another pass next tick.
    last_worker_exit_sequence = sequence;
    waiting_close_check_pending = false;
    std::unordered_map<pid_t, bool> live_processes;
    const auto process_is_alive = [&live_processes](pid_t pid) {
        auto process = live_processes.find(pid);
        if (process == live_processes.end()) {
            int result;
            do {
                result = swoole_kill(pid, 0);
            } while (sw_unlikely(result < 0 && errno == EINTR));
            // EPERM does not prove death, including with worker privilege isolation.
            process = live_processes.emplace(pid, result == 0 || errno != ESRCH).first;
        }
        return process->second;
    };
    for (auto it = waiting_close.begin(); it != waiting_close.end();) {
        const auto session_id = it->first;
        auto &waiting = it->second;
        auto *conn = serv->get_connection_verify_no_ssl(session_id);
        ++it;  // close_connection() erases this session from waiting_close.
        if (sw_unlikely(!conn || !conn->close_waiting_worker)) {
            remove_waiting_close(session_id);
            continue;
        }
        // A replacement can consume a queued CLOSE. Conversely, a yielding old worker can
        // still own onClose after Worker::pid changes. The claim identifies its actual process.
        const pid_t claimed_pid = conn->get_close_worker_pid();
        if (claimed_pid > 0) {
            waiting.worker_pid = claimed_pid;
            if (!process_is_alive(claimed_pid)) {
                Server::close_connection(reactor, conn->socket);
            }
            continue;
        }
        // An unclaimed CLOSE may still be queued, or a worker may have read it before
        // crashing. Preserve the session and resend once to each replacement generation.
        auto *worker = serv->get_worker(waiting.worker_id);
        const pid_t replacement_pid = worker->pid;
        if (replacement_pid <= 0 || replacement_pid == waiting.worker_pid) {
            if (waiting.worker_pid <= 0 || !process_is_alive(waiting.worker_pid)) {
                // The manager publishes exit before callbacks and replacement spawn.
                // Recheck next tick even if no further process exits are reported.
                waiting_close_check_pending = true;
            }
            continue;
        }
        // The old reload worker can still be alive when a newer pipe consumer dies before
        // claiming CLOSE. A changed destination PID is sufficient for an idempotent resend.
        SendData close{};
        close.info.type = SW_SERVER_EVENT_CLOSE;
        close.info.fd = session_id;
        close.info.reactor_id = conn->reactor_id;
        close.info.server_fd = conn->server_fd;
        auto *pipe = message_bus.get_pipe_socket(worker->pipe_master);
        if (sw_likely(message_bus.write(pipe, &close))) {
            // Bypass scheduling: preserve the original logical worker even with custom
            // dispatch. All original/repeated notifications share the same callback claim.
            waiting.worker_pid = replacement_pid;
        } else {
            swoole_trace_log(SW_TRACE_SERVER, "failed to resend CLOSE for session#%ld", session_id);
        }
        // Also cover a replacement that exited before this resend was registered.
        waiting_close_check_pending = true;
    }
}

/**
 * Physical retirement, owning reactor only. Workers request CLOSE through Factory::end/finish_close;
 * they never free reactor sockets or edit readiness directly. The slot lock serializes retirement
 * with worker metadata/callback access; no PHP callback runs while it is held. Keep terminal fields
 * after removing the session mapping so cached worker pointers remain recognizable until reuse.
 */
int Server::close_connection(Reactor *reactor, Socket *socket) {
    auto *serv = static_cast<Server *>(reactor->ptr);
    auto *conn = static_cast<Connection *>(socket->object);
    // Only the owner reactor changes transport membership and Socket identity.
    if (!conn || !conn->active || conn->socket != socket) {
        return SW_OK;
    }
    if (!socket->removed && reactor->del(socket) < 0) {
        return SW_ERR;
    }
    ListenPort *port = serv->get_port_by_server_fd(conn->server_fd);
    const int fd = socket->fd;
    do {
        // Serialize the membership change and scan with publication on other reactors.
        // An owner waiting for a bounds scan must not hold its slot lock.
        std::lock_guard<std::mutex> guard(serv->lock_);
        sw_spinlock(&conn->lock);
        if (!conn->is_close_requested()) {
            conn->begin_close(conn->recv_shutdown ? ConnectionCloseReason::WORKER_SHUTDOWN
                                                  : ConnectionCloseReason::SERVER_ERROR);
            conn->close_abort = true;
        }
        serv->get_session(conn->session_id)->fd = 0;
        conn->session_released = true;
        conn->active = 0;
        sw_spinlock_release(&conn->lock);

        if (fd == serv->get_maxfd()) {
            const int min_fd = serv->get_minfd();
            int find_max_fd = fd - 1;
            while (find_max_fd > min_fd && !serv->is_valid_connection(serv->get_connection(find_max_fd))) {
                --find_max_fd;
            }
            serv->set_maxfd(find_max_fd);
        }
    } while (0);

    if (conn->timer) {
        swoole_timer_del(conn->timer);
        conn->timer = nullptr;
    }
    if (serv->is_process_mode()) {
        serv->get_thread(reactor->id)->remove_waiting_close(conn->session_id);
    }

    if (conn->websocket_buffer) {
        delete conn->websocket_buffer;
        conn->websocket_buffer = nullptr;
    }

    sw_atomic_long_fetch_add(&serv->gs->close_count, 1);
    sw_atomic_long_fetch_add(&port->gs->close_count, 1);

    if (serv->is_base_mode()) {
        sw_atomic_fetch_sub(&serv->gs->connection_nums[reactor->id], 1);
        sw_atomic_fetch_sub(&port->gs->connection_nums[reactor->id], 1);
    } else {
        sw_atomic_fetch_sub(&serv->gs->connection_num, 1);
        sw_atomic_fetch_sub(&port->gs->connection_num, 1);
    }

    swoole_trace("Close Event.fd=%d|from=%d", socket->fd, reactor->id);

    if (socket->ssl) {
        conn->socket->ssl_quiet_shutdown = conn->is_close_aborting();
        conn->socket->ssl_close();
    }
#ifdef SW_SUPPORT_DTLS
    if (socket->dtls) {
        port->remove_dtls_session(socket->fd);
    }
#endif

    // free the reception memory buffer
    if (socket->recv_buffer) {
        delete socket->recv_buffer;
        socket->recv_buffer = nullptr;
    }

    if (port->open_http_protocol && conn->object) {
        port->destroy_http_request(conn);
    }

    if (port->open_redis_protocol && conn->object) {
        sw_free(conn->object);
    }

#ifdef SW_USE_SOCKET_LINGER
    if (conn->is_close_reset()) {
        struct linger linger;
        linger.l_onoff = 1;
        linger.l_linger = 0;
        if (conn->socket->set_option(SOL_SOCKET, SO_LINGER, &linger, sizeof(struct linger)) != 0) {
            swoole_sys_warning("setsockopt(SO_LINGER) failed");
        }
    }
#endif

    conn->socket = nullptr;
    conn->object = nullptr;

    return Reactor::_close(reactor, socket);
}

/**
 * close the connection
 */
static int ReactorThread_onClose(Reactor *reactor, Event *event) {
    auto *serv = static_cast<Server *>(reactor->ptr);
    Connection *conn = serv->get_connection(event->fd);
    if (!conn || !conn->active || conn->socket != event->socket) {
        return SW_OK;
    }
    const auto reason = event->socket->recv_eof ? ConnectionCloseReason::PEER_EOF
                        : conn->close_errno     ? ConnectionCloseReason::IO_ERROR
                                                : ConnectionCloseReason::SOCKET_EVENT;
    return serv->request_close(reactor, conn, reason);
}

static void ReactorThread_resume_http_request(Reactor *reactor, Connection *conn) {
    auto *serv = static_cast<Server *>(reactor->ptr);
    const SessionId session_id = conn->session_id;
    reactor->defer([serv, reactor, session_id](void *) {
        Connection *conn = serv->get_connection_verify(session_id);
        if (!conn || !conn->http_request_waiting || !conn->can_receive()) {
            return;
        }
        conn->http_request_waiting = 0;
        Socket *socket = conn->socket;
        socket->skip_recv = 1;

        Event event{};
        event.fd = conn->fd;
        event.reactor_id = reactor->id;
        event.type = SW_FD_SESSION;
        event.socket = socket;
        ListenPort *port = serv->get_port_by_server_fd(conn->server_fd);
        port->onRead(reactor, port, &event);
    });
}

// Owner-reactor API: derive readiness from independent receive policies, preserving pending WRITE.
// Socket::removed is a backend registration fact and must never be used as a close/pause reason.
int Server::update_recv_interest(Reactor *reactor, Connection *conn, bool clear_write) const {
    Socket *socket = conn->socket;
    int events = clear_write ? 0 : socket->events & ~SW_EVENT_READ;
    if (conn->can_receive()) {
        events |= SW_EVENT_READ;
    }
    // Registration follows policy; removed never explains why receiving stopped.
    if (events == 0) {
        return socket->removed ? SW_OK : reactor->del(socket);
    }
    if (socket->removed) {
        if (reactor->add(socket, events) < 0) {
            return SW_ERR;
        }
    } else if (events != socket->events && reactor->set(socket, events) < 0) {
        return SW_ERR;
    }
    // Pipelined requests already in the buffer won't raise another read event.
    if (conn->http_request_waiting && (events & SW_EVENT_READ)) {
        ReactorThread_resume_http_request(reactor, conn);
    }
    return SW_OK;
}

// Owner-reactor API for EOF, I/O/protocol errors and timeouts. Stop I/O, publish the first cause,
// and notify the assigned worker once. PROCESS notification is asynchronous; BASE/THREAD may invoke
// worker code synchronously, so revalidate the session after any callback and never touch a retired slot.
int Server::request_close(Reactor *reactor, Connection *conn, ConnectionCloseReason reason, bool reset) const {
    if (!conn || !conn->active) {
        return SW_OK;
    }
    const SessionId session_id = conn->session_id;
    Socket *socket = conn->socket;
    // Detach first. A backend error must not leave a new close state with a cancelled timer.
    if (!socket->removed && reactor->del(socket) < 0) {
        return SW_ERR;
    }
    conn->begin_close(reason);
    conn->close_abort = true;
    if (reset) {
        conn->request_reset();
    }
    if (conn->timer) {
        swoole_timer_del(conn->timer);
        conn->timer = nullptr;
        conn->recv_throttled = 0;
    }
    if (disable_notify || !conn->is_ssl_ready() || conn->close_worker_received) {
        return close_connection(reactor, socket);
    }
    conn->close_waiting_worker = 1;
    if (conn->close_notification_started) {
        return SW_OK;
    }
    conn->close_notification_started = 1;
    // EOF and idle expiry notify the peer while its worker is busy. Other errors and
    // explicit resets must not call shutdown(): an early FIN would mask the RST that
    // close() may send for unread input or an explicit reset. Polling is already disabled,
    // so no more application reads can occur while the session awaits worker cleanup.
    if (!conn->is_close_reset() && (socket->recv_eof || reason == ConnectionCloseReason::PEER_EOF ||
                                    reason == ConnectionCloseReason::IDLE_TIMEOUT)) {
        // After peer EOF the receive side is already closed. Darwin rejects SHUT_RDWR
        // with ENOTCONN in that state before shutting down writes, so send FIN with SHUT_WR.
        const int how = socket->recv_eof || reason == ConnectionCloseReason::PEER_EOF ? SHUT_WR : SHUT_RDWR;
        if (socket->shutdown(how) < 0 && how == SHUT_RDWR && sw_errno() == ENOTCONN) {
            // FIN may arrive while reads are paused, before the idle timer observes EOF.
            // Complete the write shutdown even when Darwin has already closed reception.
            socket->shutdown(SHUT_WR);
        }
    }
    // BASE/THREAD notification can enter PHP synchronously, which may close and reuse this slot.
    // Resolve the original session again before cleaning it up.
    bool notified;
    try {
        notified = notify(conn, SW_SERVER_EVENT_CLOSE);
    } catch (...) {
        conn = get_connection_verify_no_ssl(session_id);
        if (conn && conn->socket == socket) {
            close_connection(reactor, socket);
        }
        throw;
    }
    conn = get_connection_verify_no_ssl(session_id);
    if (notified) {
        return SW_OK;
    }
    // Failed enqueue cannot produce an acknowledgement. Release instead of stranding an unregistered fd.
    if (conn && conn->socket == socket) {
        swoole_error_log(SW_LOG_WARNING,
                         SW_ERROR_SESSION_CLOSING,
                         "close notification failed for session#%ld; releasing transport",
                         session_id);
        return close_connection(reactor, socket);
    }
    return SW_ERR;
}

// Owning reactor only. First stop polling and notify the worker through request_close().
// Retire after callback dispatch. PROCESS worker death is handled by its owner's waiting map;
// elapsed time alone must never retire a session while a live worker still owes onClose.
int Server::request_force_close(Reactor *reactor, Connection *conn, ConnectionCloseReason reason) const {
    if (!conn || !conn->active) {
        return SW_OK;
    }
    if (conn->close_waiting_worker) {
        sw_spinlock(&conn->lock);
        const bool callback_dispatched =
            conn->close_callback_state == CloseCallbackState::DISPATCHED || (!onClose && conn->close_worker_started);
        sw_spinlock_release(&conn->lock);
        return callback_dispatched ? close_connection(reactor, conn->socket) : SW_OK;
    }
    return request_close(reactor, conn, reason);
}

void ReactorThread::shutdown(Reactor *reactor) {
    auto *serv = static_cast<Server *>(reactor->ptr);
    if (heartbeat_pipe && !heartbeat_pipe->get_socket(true)->removed) {
        reactor->del(heartbeat_pipe->get_socket(true));
    }
    // stop listen UDP Port
    if (serv->have_dgram_sock == 1) {
        for (auto ls : serv->ports) {
            if (ls->is_dgram()) {
                if (ls->socket->fd % serv->reactor_num != reactor->id) {
                    continue;
                }
                if (!ls->socket->removed) {
                    reactor->del(ls->socket);
                }
            }
        }
    }

    if (heartbeat_timer) {
        swoole_timer_del(heartbeat_timer);
        heartbeat_timer = nullptr;
    }
    if (waiting_close_timer) {
        // Worker pipes stop being read below, so pending CLOSE acknowledgements cannot
        // empty this map. Workers are stopped only after reactor threads have joined.
        // Cancel the monitor now; the destroy callback retires sessions after output drains.
        swoole_timer_del(waiting_close_timer);
        waiting_close_timer = nullptr;
    }

    reactor->add_destroy_callback([serv, reactor](void *) {
        serv->foreach_connection_on_reactor(
            reactor, [reactor](Connection *conn) { Server::close_connection(reactor, conn->socket); });
    });

    if (serv->is_thread_mode()) {
        serv->stop_async_worker(serv->get_worker(reactor->id));
        return;
    }

    SW_LOOP_N(serv->worker_num) {
        if (i % serv->reactor_num != reactor->id) {
            continue;
        }
        Socket *socket = message_bus.get_pipe_socket(serv->get_worker_pipe_master(i));
        reactor->remove_read_event(socket);
    }

    serv->foreach_connection_on_reactor(reactor, [serv, reactor](Connection *conn) {
        conn->recv_shutdown = 1;
        serv->update_recv_interest(reactor, conn);
    });

    reactor->set_wait_exit(true);
}

int ReactorThread::close_connection(Reactor *reactor, SessionId session_id, ConnectionCloseReason reason) {
    auto *serv = static_cast<Server *>(reactor->ptr);
    Connection *conn = serv->get_connection_verify_no_ssl(session_id);
    if (!conn) {
        swoole_error_log(SW_LOG_TRACE,
                         SW_ERROR_SESSION_NOT_EXIST,
                         "force close connection failed, session#%ld does not exist",
                         session_id);
        return SW_OK;
    }

    return serv->request_force_close(reactor, conn, reason);
}

/**
 * receive data from worker process pipe
 */
static int ReactorThread_onPipeRead(Reactor *reactor, Event *ev) {
    SendData _send;
    auto *serv = static_cast<Server *>(reactor->ptr);
    ReactorThread *thread = serv->get_thread(reactor->id);
    size_t heartbeat_closes = 0;

    SW_LOOP {
        PipeBuffer *resp = thread->message_bus.get_buffer();
        ssize_t n = thread->message_bus.read_with_buffer(ev->socket);
        if (n <= 0) {
            return SW_OK;
        }
        switch (resp->info.type) {
        case SW_SERVER_EVENT_INCOMING: {
            auto packet = thread->message_bus.get_packet();
            if (packet.length != sizeof(Socket *)) {
                swoole_warning("invalid incoming connection handoff");
                break;
            }
            Socket *socket;
            memcpy(&socket, packet.data, sizeof(socket));
            const int server_fd = resp->info.server_fd;
            auto *port = serv->get_port_by_server_fd(server_fd);
            if (!reactor->wait_exit && !reactor->terminated) {
                serv->initialize_connection(reactor, IncomingConnection(socket, port, server_fd));
            } else {
                serv->abort_connection(reactor, port, socket);
            }
            break;
        }
        case SW_SERVER_EVENT_COMMAND_REQUEST: {
            serv->call_command_handler(thread->message_bus, thread->id, thread->pipe_command);
            break;
        }
        case SW_SERVER_EVENT_COMMAND_RESPONSE: {
            auto packet = thread->message_bus.get_packet();
            serv->call_command_callback(resp->info.fd, std::string(packet.data, packet.length));
            break;
        }
        case SW_SERVER_EVENT_SHUTDOWN: {
            thread->shutdown(reactor);
            break;
        }
        case SW_SERVER_EVENT_SHUTDOWN_SIGNAL: {
            swoole_kill(getpid(), SIGTERM);
            break;
        }
        case SW_SERVER_EVENT_FINISH: {
            serv->onFinish(serv, reinterpret_cast<EventData *>(resp));
            break;
        }
        case SW_SERVER_EVENT_PIPE_MESSAGE: {
            serv->onPipeMessage(serv, reinterpret_cast<EventData *>(resp));
            break;
        }
        case SW_SERVER_EVENT_CLOSE_FORCE: {
            serv->close_idle_connection(reactor, resp->info.fd);
            // A large expiry wave must yield to normal I/O. Level-triggered readiness
            // will schedule the remaining requests on the next event-loop iteration.
            if (++heartbeat_closes >= 64) {
                thread->message_bus.pop();
                return SW_OK;
            }
            break;
        }
        case SW_SERVER_EVENT_CLOSE_FORWARD: {
            serv->factory_->end(resp->info.fd, resp->info.ext_flags | Server::CLOSE_ACTIVELY);
            break;
        }
        default: {
            PacketPtr packet = thread->message_bus.get_packet();
            _send.info = resp->info;
            _send.info.len = packet.length;
            _send.data = packet.data;
            // The worker has already reported the file as sent, so the client would wait for a body that never comes.
            if (serv->send_to_connection(&_send) < 0 && _send.info.type == SW_SERVER_EVENT_SEND_FILE) {
                Connection *conn = serv->get_connection_verify_no_ssl(_send.info.fd);
                // Repeated errors use the same idempotent close transition, including while waiting for a worker.
                if (conn) {
                    thread->close_connection(reactor, _send.info.fd);
                }
            }
            break;
        }
        }
        thread->message_bus.pop();
    }

    return SW_OK;
}

/**
 * [ReactorThread] worker pipe can write.
 */
static int ReactorThread_onPipeWrite(Reactor *reactor, Event *ev) {
    int ret;

    auto *serv = static_cast<Server *>(reactor->ptr);
    Buffer *buffer = ev->socket->out_buffer;

    while (!Buffer::empty(buffer)) {
        const BufferChunk *chunk = buffer->front();
        auto *send_data = reinterpret_cast<EventData *>(chunk->value.str);

        // Drop events whose session no longer exists. Live-session close filtering belongs to the worker,
        // preserving the order of data already queued before its close notification.
        if (Server::is_stream_event(send_data->info.type)) {
            // send_data->info.fd is session_id
            Connection *conn = serv->get_connection_verify(send_data->info.fd);
            if (conn) {
                conn->last_send_time = microtime();
            } else if (serv->discard_timeout_request) {
                swoole_error_log(SW_LOG_WARNING,
                                 SW_ERROR_SESSION_DISCARD_TIMEOUT_DATA,
                                 "[1] ignore data[%u bytes] received from session#%ld",
                                 send_data->info.len,
                                 send_data->info.fd);
                serv->discard_reactor_event(send_data);
                buffer->pop();
                continue;
            }
        }

        // Keep the front packet owned by the queue until the nonblocking datagram write succeeds.
        // EAGAIN leaves it in place for the next writable event, including after worker replacement.
        // Popping before send would lose data on EAGAIN or require another queue to preserve ordering.
        ret = ev->socket->send(chunk->value.str, chunk->length, 0);
        if (ret < 0) {
            return (ev->socket->catch_write_error(errno) == SW_WAIT) ? SW_OK : SW_ERR;
        } else {
            buffer->pop();
        }
    }

    if (Buffer::empty(buffer)) {
        if (reactor->remove_write_event(ev->socket) < 0) {
            swoole_sys_warning("reactor->set(%d) failed", ev->fd);
        }
    }

    return SW_OK;
}

void Server::init_reactor(Reactor *reactor) {
    // support 64K packet
    if (have_dgram_sock) {
        sw_tg_buffer()->extend();
    }
    // UDP Packet
    reactor->set_handler(SW_FD_DGRAM_SERVER, SW_EVENT_READ, ReactorThread_onPacketReceived);
    // Write
    reactor->set_handler(SW_FD_SESSION, SW_EVENT_WRITE, ReactorThread_onWrite);
    // Read
    reactor->set_handler(SW_FD_SESSION, SW_EVENT_READ, ReactorThread_onRead);

    // listen the all tcp port
    for (auto port : ports) {
        port->init_protocol();
    }
}

static int ReactorThread_onRead(Reactor *reactor, Event *event) {
    auto *serv = static_cast<Server *>(reactor->ptr);
    Connection *conn = serv->get_connection(event->fd);
    /**
     * invalid event
     * The server has been actively closed the connection, the client also initiated off, fd has been reused.
     */
    if (!conn || !conn->active || conn->socket != event->socket) {
        return SW_OK;
    }
    if (!conn->can_receive()) {
        return serv->update_recv_interest(reactor, conn);
    }
    ListenPort *port = serv->get_port_by_fd(event->fd);
#ifdef SW_SUPPORT_DTLS
    if (port->is_dtls()) {
        dtls::Session *session = port->get_dtls_session(event->fd);
        if (!session) {
            serv->abort_connection(reactor, port, event->socket);
            return SW_OK;
        }
        dtls::Buffer *buffer = static_cast<dtls::Buffer *>(sw_malloc(sizeof(*buffer) + SW_BUFFER_SIZE_UDP));
        if (!buffer) {
            serv->abort_connection(reactor, port, event->socket);
            return SW_OK;
        }
        const auto length = event->socket->read(buffer->data, SW_BUFFER_SIZE_UDP);
        if (length <= 0) {
            const auto error = errno;
            sw_free(buffer);
            if (length < 0 && event->socket->catch_read_error(error) == SW_CLOSE) {
                conn->close_errno = error;
                return serv->request_close(reactor, conn, ConnectionCloseReason::IO_ERROR);
            }
            return SW_OK;
        }
        buffer->length = length;
        session->append(buffer);
        if (!session->listened && !session->listen()) {
            serv->abort_connection(reactor, port, event->socket);
            return SW_OK;
        }
    }
#endif
    ReturnCode code = ReactorThread_verify_ssl_state(reactor, port, event->socket);
    switch (code) {
    case SW_ERROR:
        serv->abort_connection(reactor, port, event->socket);
        return SW_OK;
    case SW_READY:
#ifdef SW_SUPPORT_DTLS
        if (event->socket->dtls) {
            return SW_OK;
        }
#endif
        break;
    case SW_WAIT:
        return SW_OK;
    case SW_CONTINUE:
        break;
    default:
        abort();
    }

    conn->set_last_recv_time(microtime());
    long last_recv_bytes = event->socket->total_recv_bytes;

    int retval = port->onRead(reactor, port, event);

    long socket_recv_bytes = event->socket->total_recv_bytes - last_recv_bytes;
    if (socket_recv_bytes > 0) {
        sw_atomic_long_fetch_add(&port->gs->total_recv_bytes, socket_recv_bytes);
        sw_atomic_long_fetch_add(&serv->gs->total_recv_bytes, socket_recv_bytes);
    }
    if (!conn->active || conn->socket != event->socket) {
        return retval;
    }
    if (!conn->is_close_requested() && !conn->timer && serv->is_process_mode() && serv->max_queued_bytes &&
        conn->get_recv_queued_bytes() > serv->max_queued_bytes) {
        conn->waiting_time = 1;
        conn->timer =
            swoole_timer_add((long) conn->waiting_time, false, ReactorThread_resume_data_receiving, event->socket);
        if (conn->timer) {
            conn->recv_throttled = 1;
            serv->update_recv_interest(reactor, conn);
        }
    }
    return retval;
}

static int ReactorThread_onWrite(Reactor *reactor, Event *ev) {
    int ret;
    auto serv = static_cast<Server *>(reactor->ptr);
    auto socket = ev->socket;
    int fd = ev->fd;
    auto port = serv->get_port_by_fd(fd);

    if (serv->is_process_mode()) {
        assert(fd % serv->reactor_num == reactor->id);
        assert(fd % serv->reactor_num == SwooleTG.id);
    }

    Connection *conn = serv->get_connection(fd);
    if (conn == nullptr || conn->active == 0) {
        return SW_ERR;
    }

    if (conn->socket != socket || conn->close_waiting_worker) {
        return SW_OK;
    }

    while (!Buffer::empty(socket->out_buffer)) {
        BufferChunk *chunk = socket->out_buffer->front();
        if (chunk->type == BufferChunk::TYPE_CLOSE) {
            return reactor->close(reactor, socket);
        } else if (chunk->type == BufferChunk::TYPE_SENDFILE) {
            ret = socket->handle_sendfile();
        } else {
            ret = socket->handle_send();
            if (SW_OK == ret) {
                conn->send_queued_bytes = socket->out_buffer->length();
            }
        }

        if (ret < 0) {
            if (socket->close_wait) {
                conn->close_errno = errno;
                return reactor->trigger_close_event(ev);
            } else if (socket->send_wait) {
                break;
            }
        }
    }

    if (conn->overflow && socket->get_out_buffer_length() < socket->buffer_size) {
        conn->overflow = 0;
    }

    if (serv->onBufferEmpty && conn->high_watermark) {
        if (socket->get_out_buffer_length() <= port->buffer_low_watermark) {
            conn->high_watermark = 0;
            serv->notify(conn, SW_SERVER_EVENT_BUFFER_EMPTY);
        }
    }

    if (!conn->active || conn->socket != socket) {
        return SW_OK;
    }
    if (socket->send_timer) {
        if (Buffer::empty(socket->out_buffer)) {
            swoole_timer_del(socket->send_timer);
            socket->send_timer = nullptr;
        } else {
            swoole_timer_delay(socket->send_timer, sec2msec(port->max_idle_time));
        }
    }

    // remove EPOLLOUT event
    if (!socket->removed && Buffer::empty(socket->out_buffer)) {
        // Draining output clears only WRITE. User pause, backpressure, shutdown and close remain independent.
        return serv->update_recv_interest(reactor, conn, true);
    }
    return SW_OK;
}

void Server::heartbeat_check(Timer *timer, TimerNode *tnode) {
    auto *reactor = static_cast<Reactor *>(tnode->data);
    static_cast<Server *>(reactor->ptr)->check_idle_connections(reactor);
}

/**
 * [master]
 */
int Server::start_reactor_threads() {
    if (swoole_event_init(0) < 0) {
        return SW_ERR;
    }

    Reactor *reactor = sw_reactor();

    for (const auto port : ports) {
        if (port->is_dgram()) {
            continue;
        }
        if (port->listen() < 0) {
            swoole_event_free();
            return SW_ERR;
        }
        reactor->add(port->socket, SW_EVENT_READ);
    }

    store_listen_socket();

    if (single_thread) {
        get_thread(0)->init(this, reactor, 0);
        goto _init_master_thread;
    }
    /**
     * multi-threads
     */
    else {
        /**
         * set a special id
         */
        reactor->id = reactor_num;
        SwooleTG.id = reactor_num;
    }

    SW_LOOP_N(reactor_num) {
        get_thread(i)->thread = std::thread([=]() {
            swoole_thread_init(false);
            reactor_thread_main_loop(this, i);
            swoole_thread_clean(false);
        });
    }

_init_master_thread:

    /**
     * heartbeat thread
     */
    if (heartbeat_check_interval >= 1) {
        if (single_thread) {
            heartbeat_timer = swoole_timer_add(sec2msec(heartbeat_check_interval), true, heartbeat_check, reactor);
        }
    }

    return start_master_thread(reactor);
}

// Runs in the owning execution context: PROCESS reactor thread in master, THREAD event worker,
// or the master reactor in single_thread mode. Install handlers and private pipe endpoints here,
// before the startup barrier publishes them to accept/heartbeat producers. A Connection must
// not be initialized by a producer while this owner is still preparing its event loop.
int ReactorThread::init(Server *serv, Reactor *reactor, uint16_t reactor_id) {
    reactor->ptr = serv;
    reactor->id = reactor_id;
    reactor->wait_exit = false;
    reactor->max_socket = serv->get_max_connection();
    reactor->close = Server::close_connection;
    reactor->default_error_handler = ReactorThread_onClose;

    reactor->set_handler(SW_FD_PIPE, SW_EVENT_READ, ReactorThread_onPipeRead);
    reactor->set_handler(SW_FD_PIPE, SW_EVENT_WRITE, ReactorThread_onPipeWrite);

    // listen UDP port
    if (serv->have_dgram_sock == 1) {
        for (auto ls : serv->ports) {
            if (ls->is_stream()) {
                continue;
            }
            int server_fd = ls->socket->fd;
            if (server_fd % serv->reactor_num != reactor_id) {
                continue;
            }
            Connection *serv_sock = serv->get_connection(server_fd);
            serv_sock->fd = server_fd;
            serv_sock->socket_type = ls->type;
            serv_sock->object = ls;
            ls->thread_id = pthread_self();
            if (reactor->add(ls->socket, SW_EVENT_READ) < 0) {
                return SW_ERR;
            }
        }
    }

    serv->init_reactor(reactor);

    if (serv->is_thread_mode()) {
        Worker *worker = serv->get_worker(reactor_id);
        serv->init_event_worker(worker);
        auto pipe_worker = message_bus.get_pipe_socket(worker->pipe_worker);
        reactor->add(pipe_worker, SW_EVENT_READ);

        if (serv->heartbeat_check_interval > 0) {
            heartbeat_timer =
                swoole_timer_add(sec2msec(serv->heartbeat_check_interval), true, Server::heartbeat_check, reactor);
        }
    } else {
        serv->init_pipe_sockets(&message_bus);
    }

    if (serv->is_process_mode() && !serv->single_thread && serv->heartbeat_check_interval > 0) {
        auto pipe = std::make_unique<UnixSocket>(false, SOCK_DGRAM);
        if (!pipe->ready() || !pipe->set_buffer_size(SW_IPC_BUFFER_MAX_SIZE) ||
            reactor->add(pipe->get_socket(true), SW_EVENT_READ) != SW_OK) {
            return SW_ERR;
        }
        heartbeat_pipe = std::move(pipe);
    }

    if (serv->pipe_command) {
        auto pipe_socket = serv->pipe_command->get_socket(false);
        message_bus.init_pipe_socket(pipe_socket);
        pipe_command = message_bus.get_pipe_socket(pipe_socket);
        pipe_command->buffer_size = UINT_MAX;
    }

    message_bus.set_id_generator(serv->msg_id_generator);
    message_bus.set_buffer_size(serv->ipc_max_size);
    message_bus.set_always_chunked_transfer();
    message_bus.alloc_buffer();

    SW_LOOP_N(serv->worker_num) {
        if (i % serv->reactor_num != reactor_id) {
            continue;
        }
        Socket *socket = message_bus.get_pipe_socket(serv->get_worker_pipe_master(i));
        if (reactor->add(socket, SW_EVENT_READ) < 0) {
            return SW_ERR;
        }
        /**
         * It will only send data to the notify pipeline synchronously,
         * which is thread-safe and does not require separate memory
         */
        if (notify_pipe == nullptr) {
            notify_pipe = serv->workers[i].pipe_worker;
        }
    }

    if (serv->is_thread_mode()) {
        // The logical ReactorThread retains its native pipe queues across worker replacement.
        // Register pending writes on the new reactor before WorkerStart can append more packets.
        // Traverse the bus's own wrappers so worker, task-worker and command pipes follow the same rules.
        if (!message_bus.foreach_pipe_socket([reactor](Socket *socket) {
                return Buffer::empty(socket->out_buffer) || reactor->add_write_event(socket) == SW_OK;
            })) {
            return SW_ERR;
        }
    }

    return SW_OK;
}

void ReactorThread::clean() {
    // Pair with init() in the reactor's execution context. Native output queues have a separate
    // lifetime: reload hands them to the next worker, while final shutdown drains them before release.
    waiting_close.clear();
    waiting_close_check_pending = false;
    if (waiting_close_timer && swoole_timer_is_available()) {
        swoole_timer_del(waiting_close_timer);
    }
    waiting_close_timer = nullptr;
    message_bus.free_buffer();
}

void ReactorThread::drain_pipe_buffers(Server *serv, int timeout_msec) {
    bool pending = false;
    message_bus.foreach_pipe_socket([&pending](Socket *socket) {
        pending = !Buffer::empty(socket->out_buffer);
        return !pending;
    });
    if (!pending) {
        return;
    }
    if (timeout_msec <= 0) {
        discard_pipe_buffers(serv);
        return;
    }

    // The request's main reactor has already been freed. Use a write-only reactor here:
    // it cannot accept connections or invoke request handlers while PHP is shutting down.
    Reactor reactor;
    if (!reactor.ready()) {
        return;
    }
    reactor.ptr = serv;
    reactor.id = id;
    reactor.wait_exit = true;
    reactor.timeout_msec = timeout_msec;
    reactor.set_handler(SW_FD_PIPE, SW_EVENT_WRITE, ReactorThread_onPipeWrite);
    ON_SCOPE_EXIT {
        message_bus.foreach_pipe_socket([&reactor](Socket *socket) {
            if (reactor.exists(socket->fd)) {
                reactor.del(socket);
            }
            return true;
        });
    };

    bool registered = message_bus.foreach_pipe_socket([&reactor](Socket *socket) {
        if (Buffer::empty(socket->out_buffer)) {
            return true;
        }
        // A shutdown callback may have created its own event loop. Detach its pipe watch before
        // lending the wrapper to this reactor so that both event loops cannot own the same queue.
        if (sw_reactor() && sw_reactor()->exists(socket->fd)) {
            sw_reactor()->del(socket);
        }
        return reactor.add(socket, SW_EVENT_WRITE) == SW_OK;
    });
    if (!registered) {
        return;
    }

    int64_t deadline = time<std::chrono::milliseconds>(true) + timeout_msec;
    reactor.set_end_callback(Reactor::PRIORITY_TRY_EXIT, [deadline](Reactor *reactor) {
        int64_t remaining = deadline - time<std::chrono::milliseconds>(true);
        if (reactor->if_exit() || remaining <= 0) {
            reactor->running = false;
        } else {
            reactor->timeout_msec = static_cast<int>(remaining);
        }
    });
    reactor.wait();
    if (time<std::chrono::milliseconds>(true) >= deadline) {
        // Only the expired wait budget permits dropping still-sendable packets, including owned sendfiles.
        discard_pipe_buffers(serv);
    }
}

void ReactorThread::discard_pipe_buffers(const Server *serv) {
    // Drop queued handoffs/sendfiles through the same cleanup as master-produced packets.
    serv->discard_reactor_output(message_bus);
}

void Server::reactor_thread_main_loop(Server *serv, int reactor_id) {
    ReactorThread *thread = serv->get_thread(reactor_id);
    thread->id = reactor_id;
    SwooleTG.message_bus = &thread->message_bus;

    if (swoole_event_init(0) < 0) {
        return;
    }

    if (!serv->is_thread_mode()) {
        swoole_set_thread_id(reactor_id);
        swoole_set_thread_type(Server::THREAD_REACTOR);
    }

    Reactor *reactor = sw_reactor();
    if (thread->init(serv, reactor, reactor_id) < 0) {
        swoole_event_free();
        return;
    }

    if (serv->is_thread_mode()) {
        // WorkerStart may send to connections owned by another worker. Initialize the entire reactor first:
        // MessageBus needs its ID generator and chunk buffer, and queued writes need the pipe event handlers.
        // Initializing only the pipe sockets before entering PHP does not make these operations ready.
        serv->call_worker_start_callback(serv->get_worker(reactor_id));
    }

    // wait other thread
    if (serv->is_process_mode()) {
        serv->reactor_thread_barrier.wait();
    }
    // main loop
    swoole_event_wait();
    if (serv->is_thread_mode()) {
        serv->call_worker_stop_callback(serv->get_worker(reactor_id));
    }
    thread->clean();
}

static void ReactorThread_resume_data_receiving(Timer *timer, TimerNode *tnode) {
    auto *socket = static_cast<Socket *>(tnode->data);
    auto *conn = static_cast<Connection *>(socket->object);
    auto *serv = static_cast<Server *>(timer->get_reactor()->ptr);
    if (!conn || !conn->active || conn->socket != socket || conn->timer != tnode) {
        return;
    }
    conn->timer = nullptr;
    conn->recv_throttled = 0;
    if (!conn->is_close_requested() && conn->get_recv_queued_bytes() > serv->max_queued_bytes) {
        if (conn->waiting_time != 1024) {
            conn->waiting_time *= 2;
        }
        conn->timer = swoole_timer_add((long) conn->waiting_time, false, ReactorThread_resume_data_receiving, socket);
        conn->recv_throttled = conn->timer != nullptr;
    }
    serv->update_recv_interest(timer->get_reactor(), conn);
}

/**
 * dispatch request data [only data frame]
 */
int Server::dispatch_task(const Protocol *proto, Socket *_socket, const RecvData *rdata) {
    auto *serv = static_cast<Server *>(proto->private_data_2);
    SendData task;

    auto *conn = static_cast<Connection *>(_socket->object);

    sw_memset_zero(&task.info, sizeof(task.info));
    task.info.server_fd = conn->server_fd;
    task.info.reactor_id = conn->reactor_id;
    task.info.ext_flags = rdata->info.ext_flags;
    task.info.type = SW_SERVER_EVENT_RECV_DATA;
    task.info.time = conn->get_last_recv_time();

    swoole_trace("dispatch task, size=%u bytes", rdata->info.len);

    task.info.fd = conn->fd;
    task.info.len = rdata->info.len;
    task.data = rdata->data;

    return serv->factory_->dispatch(&task) ? SW_OK : SW_ERR;
}

void Server::join_heartbeat_thread() {
    /**
     * Master shutdown joins the heartbeat producer before reactor pipe ownership is destroyed.
     * Notify interrupts the periodic condition-variable wait. An in-flight send_sync() is not
     * cancelled by this notification; it returns according to the write endpoint's timeout.
     * Never hold heartbeat_mutex_ across join: the exiting thread must reacquire it.
     */
    if (heartbeat_thread.joinable()) {
        swoole_trace_log(SW_TRACE_SERVER, "terminate heartbeat thread");
        do {
            std::lock_guard<std::mutex> guard(heartbeat_mutex_);
            heartbeat_stop_requested_ = true;
        } while (0);
        heartbeat_cv_.notify_one();
        heartbeat_thread.join();
    }
}

void Server::join_reactor_thread() {
    if (single_thread) {
        return;
    }

    if (heartbeat_check_interval > 0) {
        join_heartbeat_thread();
    }

    for (int i = 0; i < reactor_num; i++) {
        ReactorThread *thread = get_thread(i);
        if (!thread->thread.joinable()) {
            continue;
        }
        if (thread->notify_pipe) {
            DataHead ev = {};
            ev.type = SW_SERVER_EVENT_SHUTDOWN;
            thread->notify_pipe->send_sync((void *) &ev, sizeof(ev));
        }
        thread->thread.join();
    }
}

// Called by the master after the reactor startup barrier. The spawned thread has no event loop:
// it scans shared metadata, releases slot locks, then synchronously submits per-session requests.
// Only reactors may touch connection Sockets or decide whether a queued timeout is still current.
void Server::start_heartbeat_thread() {
    do {
        std::lock_guard<std::mutex> guard(heartbeat_mutex_);
        heartbeat_stop_requested_ = false;
    } while (0);

    heartbeat_thread = std::thread([this]() {
        swoole_signal_block_all();
        swoole_set_thread_type(THREAD_HEARTBEAT);
        swoole_set_thread_id(reactor_num + 1);

        std::unique_lock<std::mutex> guard(heartbeat_mutex_);
        while (!heartbeat_stop_requested_) {
            guard.unlock();
            // Do the large scan here, away from every reactor's I/O loop. The scanner releases
            // the slot lock before this callback: backpressure must never block recv/close/reuse.
            foreach_idle_connection(microtime(), [this](SessionId session_id, ReactorId owner) {
                do {
                    std::lock_guard<std::mutex> guard(heartbeat_mutex_);
                    if (heartbeat_stop_requested_) {
                        return false;
                    }
                } while (0);
                DataHead event{};
                event.type = SW_SERVER_EVENT_CLOSE_FORCE;
                event.fd = session_id;
                event.reactor_id = owner;
                // Only this thread writes the endpoint. send_sync waits without an event loop;
                // the receiver rechecks session/activity/protect before applying the force close.
                auto *pipe_socket = get_thread(owner)->heartbeat_pipe->get_socket(false);
                if (pipe_socket->send_sync(&event, sizeof(event)) < 0) {
                    swoole_sys_warning("send heartbeat close to reactor#%u failed", static_cast<unsigned>(owner));
                }
                return true;
            });
            guard.lock();
            heartbeat_cv_.wait_for(
                guard, std::chrono::seconds(heartbeat_check_interval), [this]() { return heartbeat_stop_requested_; });
        }
    });
}

}  // namespace swoole
