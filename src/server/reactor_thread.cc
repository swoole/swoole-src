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
#include "swoole_memory.h"
#include "swoole_hash.h"
#include "swoole_util.h"

#include <assert.h>

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

#ifdef SW_USE_OPENSSL
static inline ReturnCode ReactorThread_verify_ssl_state(Reactor *reactor, ListenPort *port, Socket *_socket) {
    Server *serv = (Server *) reactor->ptr;
    if (!_socket->ssl || _socket->ssl_state == SW_SSL_STATE_READY) {
        return SW_CONTINUE;
    }

    ReturnCode code = _socket->ssl_accept();
    if (code != SW_READY) {
        return code;
    }

    Connection *conn = (Connection *) _socket->object;
    conn->ssl_ready = 1;
    if (!port->ssl_context->client_cert_file.empty()) {
        if (!_socket->ssl_get_peer_certificate(sw_tg_buffer())) {
            if (port->ssl_context->verify_peer) {
                return SW_ERROR;
            }
        } else {
            if (!port->ssl_context->verify_peer || _socket->ssl_verify(port->ssl_context->allow_self_signed)) {
                SendData task;
                task.info.fd = _socket->fd;
                task.info.type = SW_SERVER_EVENT_CONNECT;
                task.info.reactor_id = reactor->id;
                task.info.len = sw_tg_buffer()->length;
                task.data = sw_tg_buffer()->str;
                serv->factory->dispatch(&task);
                goto _delay_receive;
            } else {
                return SW_ERROR;
            }
        }
    }

    if (serv->onConnect) {
        serv->notify((Connection *) _socket->object, SW_SERVER_EVENT_CONNECT);
    }
_delay_receive:
    if (serv->enable_delay_receive) {
        if (reactor->del(_socket) < 0) {
            return SW_ERROR;
        }
    }

    return SW_READY;
}
#endif

/**
 * for udp
 */
static int ReactorThread_onPacketReceived(Reactor *reactor, Event *event) {
    int fd = event->fd;
    ssize_t ret;

    Server *serv = (Server *) reactor->ptr;
    Connection *server_sock = serv->get_connection(fd);
    network::Socket *sock = server_sock->socket;
    SendData task = {};
    DgramPacket *pkt = (DgramPacket *) sw_tg_buffer()->str;

    task.info.server_fd = fd;
    task.info.reactor_id = SwooleTG.id;
    task.info.type = SW_SERVER_EVENT_RECV_DGRAM;
    task.info.time = microtime();

    pkt->socket_addr.type = pkt->socket_type = server_sock->socket_type;

_do_recvfrom:

    ret = sock->recvfrom(pkt->data, sw_tg_buffer()->size - sizeof(*pkt), 0, &pkt->socket_addr);
    if (ret <= 0) {
        if (errno == EAGAIN) {
            return SW_OK;
        } else {
            swoole_sys_warning("recvfrom(%d) failed", fd);
            return SW_ERR;
        }
    }

#ifdef SW_SUPPORT_DTLS
    ListenPort *port = (ListenPort *) server_sock->object;

    if (port->is_dtls()) {
        dtls::Session *session = serv->accept_dtls_connection(port, &pkt->socket_addr);
        if (!session) {
            return SW_ERR;
        }

        session->append(pkt->data, ret);

        if (!session->listen()) {
            return Server::close_connection(reactor, session->socket);
        }

        Connection *conn = (Connection *) session->socket->object;
        if (serv->single_thread) {
            if (serv->connection_incoming(reactor, conn) < 0) {
                reactor->close(reactor, session->socket);
                return SW_OK;
            }
        } else {
            DataHead ev{};
            ev.type = SW_SERVER_EVENT_INCOMING;
            ev.fd = conn->session_id;
            ev.reactor_id = conn->reactor_id;
            if (serv->send_to_reactor_thread((EventData *) &ev, sizeof(ev), conn->session_id) < 0) {
                reactor->close(reactor, session->socket);
                return SW_OK;
            }
        }

        return SW_OK;
    }
#endif

    if (pkt->socket_type == SW_SOCK_UDP) {
        task.info.fd = *(int *) &pkt->socket_addr.addr.inet_v4.sin_addr;
    } else {
        task.info.fd = swoole_crc32(pkt->socket_addr.get_addr(), pkt->socket_addr.len);
    }

    pkt->length = ret;
    task.info.len = sizeof(*pkt) + ret;
    task.data = (char *) pkt;

    if (!serv->factory->dispatch(&task)) {
        return SW_ERR;
    } else {
        goto _do_recvfrom;
    }
}

/**
 * close connection
 */
int Server::close_connection(Reactor *reactor, Socket *socket) {
    Server *serv = (Server *) reactor->ptr;
    Connection *conn = (Connection *) socket->object;
    ListenPort *port = serv->get_port_by_fd(socket->fd);

    if (conn->timer) {
        swoole_timer_del(conn->timer);
    }

    if (!socket->removed && reactor->del(socket) < 0) {
        return SW_ERR;
    }

    sw_atomic_fetch_add(&serv->gs->close_count, 1);
    sw_atomic_fetch_add(&port->gs->close_count, 1);

    if (serv->is_base_mode()) {
        sw_atomic_fetch_sub(&serv->gs->connection_nums[reactor->id], 1);
        sw_atomic_fetch_sub(&port->gs->connection_nums[reactor->id], 1);
    } else {
        sw_atomic_fetch_sub(&serv->gs->connection_num, 1);
        sw_atomic_fetch_sub(&port->gs->connection_num, 1);
    }

    swoole_trace("Close Event.fd=%d|from=%d", socket->fd, reactor->id);

#ifdef SW_USE_OPENSSL
    if (socket->ssl) {
        conn->socket->ssl_quiet_shutdown = conn->peer_closed;
        conn->socket->ssl_close();
    }
#ifdef SW_SUPPORT_DTLS
    if (socket->dtls) {
        dtls::Session *session = port->dtls_sessions->find(socket->fd)->second;
        port->dtls_sessions->erase(socket->fd);
        delete session;
    }
#endif
#endif

    // free the receive memory buffer
    if (socket->recv_buffer) {
        delete socket->recv_buffer;
        socket->recv_buffer = nullptr;
    }

    if (port->open_http_protocol && conn->object) {
        serv->destroy_http_request(conn);
    }
    if (port->open_redis_protocol && conn->object) {
        sw_free(conn->object);
        conn->object = nullptr;
    }

#ifdef SW_USE_SOCKET_LINGER
    if (conn->close_force || conn->close_reset) {
        struct linger linger;
        linger.l_onoff = 1;
        linger.l_linger = 0;
        if (conn->socket->set_option(SOL_SOCKET, SO_LINGER, &linger, sizeof(struct linger)) != 0) {
            swoole_sys_warning("setsockopt(SO_LINGER) failed");
        }
    }
#endif

    Session *session = serv->get_session(conn->session_id);
    session->fd = 0;
    /**
     * reset maxfd, for connection_list
     */
    int fd = socket->fd;

    serv->lock();
    if (fd == serv->get_maxfd()) {
        int find_max_fd = fd - 1;
        swoole_trace("set_maxfd=%d|close_fd=%d\n", find_max_fd, fd);
        // find the new max_fd
        for (; !serv->is_valid_connection(serv->get_connection(find_max_fd)) && find_max_fd > serv->get_minfd();
             find_max_fd--) {
            // pass
        }
        serv->set_maxfd(find_max_fd);
    }
    serv->unlock();

    *conn = {};
    return Reactor::_close(reactor, socket);
}

/**
 * close the connection
 */
static int ReactorThread_onClose(Reactor *reactor, Event *event) {
    Server *serv = (Server *) reactor->ptr;
    int fd = event->fd;
    DataHead notify_ev{};
    Socket *socket = event->socket;

    assert(fd % serv->reactor_num == reactor->id);
    assert(fd % serv->reactor_num == SwooleTG.id);

    notify_ev.reactor_id = reactor->id;
    notify_ev.fd = fd;
    notify_ev.type = SW_SERVER_EVENT_CLOSE;

    swoole_trace_log(SW_TRACE_CLOSE, "client[fd=%d] close the connection", fd);

    Connection *conn = serv->get_connection(fd);
    if (conn == nullptr || conn->active == 0) {
        return SW_ERR;
    } else if (serv->disable_notify) {
        Server::close_connection(reactor, socket);
        return SW_OK;
    } else if (reactor->del(socket) == 0) {
        if (conn->close_queued) {
            Server::close_connection(reactor, socket);
            return SW_OK;
        } else {
            /**
             * peer_closed indicates that the client has closed the connection
             * and the connection is no longer available.
             */
            conn->peer_closed = 1;
            return serv->factory->notify(&notify_ev);
        }
    } else {
        return SW_ERR;
    }
}

void ReactorThread::shutdown(Reactor *reactor) {
    Server *serv = (Server *) reactor->ptr;
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

    if (serv->is_thread_mode()) {
        Socket *socket = message_bus.get_pipe_socket(serv->get_worker_pipe_worker(reactor->id));
        reactor->del(socket);
    }

    SW_LOOP_N(serv->worker_num) {
        if (i % serv->reactor_num != reactor->id) {
            continue;
        }
        Socket *socket = message_bus.get_pipe_socket(serv->get_worker_pipe_master(i));
        reactor->del(socket);
    }

    serv->foreach_connection([serv, reactor](Connection *conn) {
        if (conn->fd % serv->reactor_num != reactor->id) {
            return;
        }
        if (!conn->peer_closed && !conn->socket->removed) {
            reactor->remove_read_event(conn->socket);
        }
    });

    if (serv->is_thread_mode()) {
        serv->stop_async_worker(serv->get_worker(reactor->id));
    }

    reactor->set_wait_exit(true);
}

int ReactorThread::close_connection(Reactor *reactor, SessionId session_id) {
    Server *serv = (Server *) reactor->ptr;
    Connection *conn = serv->get_connection_verify_no_ssl(session_id);
    if (!conn) {
        swoole_error_log(SW_LOG_TRACE,
                         SW_ERROR_SESSION_NOT_EXIST,
                         "force close connection failed, session#%ld does not exist",
                         session_id);
        return SW_OK;
    }

    if (serv->disable_notify || conn->close_force) {
        return Server::close_connection(reactor, conn->socket);
    }

#ifdef SW_USE_OPENSSL
    /**
     * SSL connections that have not completed the handshake,
     * do not need to notify the workers, just close
     */
    if (conn->ssl && !conn->ssl_ready) {
        return Server::close_connection(reactor, conn->socket);
    }
#endif
    conn->close_force = 1;
    Event _ev = {};
    _ev.fd = conn->fd;
    _ev.socket = conn->socket;
    reactor->trigger_close_event(&_ev);

    return SW_OK;
}

/**
 * receive data from worker process pipe
 */
static int ReactorThread_onPipeRead(Reactor *reactor, Event *ev) {
    SendData _send;
    Server *serv = (Server *) reactor->ptr;
    ReactorThread *thread = serv->get_thread(reactor->id);

    SW_LOOP {
        PipeBuffer *resp = thread->message_bus.get_buffer();
        ssize_t n = thread->message_bus.read_with_buffer(ev->socket);
        if (n <= 0) {
            return n;
        }
        if (resp->info.type == SW_SERVER_EVENT_INCOMING) {
            Connection *conn = serv->get_connection_verify_no_ssl(resp->info.fd);
            if (conn && serv->connection_incoming(reactor, conn) < 0) {
                reactor->close(reactor, conn->socket);
            }
        } else if (resp->info.type == SW_SERVER_EVENT_COMMAND_REQUEST) {
            serv->call_command_handler(thread->message_bus, thread->id, thread->pipe_command);
        } else if (resp->info.type == SW_SERVER_EVENT_COMMAND_RESPONSE) {
            auto packet = thread->message_bus.get_packet();
            serv->call_command_callback(resp->info.fd, std::string(packet.data, packet.length));
        } else if (resp->info.type == SW_SERVER_EVENT_SHUTDOWN) {
            thread->shutdown(reactor);
        } else if (resp->info.type == SW_SERVER_EVENT_FINISH) {
            serv->onFinish(serv, (EventData *) resp);
        } else if (resp->info.type == SW_SERVER_EVENT_PIPE_MESSAGE) {
            serv->onPipeMessage(serv, (EventData *) resp);
        } else if (resp->info.type == SW_SERVER_EVENT_CLOSE_FORCE) {
            thread->close_connection(reactor, resp->info.fd);
        } else {
            PacketPtr packet = thread->message_bus.get_packet();
            _send.info = resp->info;
            _send.info.len = packet.length;
            _send.data = packet.data;
            serv->send_to_connection(&_send);
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

    Server *serv = (Server *) reactor->ptr;
    Buffer *buffer = ev->socket->out_buffer;

    while (!Buffer::empty(buffer)) {
        BufferChunk *chunk = buffer->front();
        EventData *send_data = (EventData *) chunk->value.str;

        // server actively closed connection, should discard the data
        if (Server::is_stream_event(send_data->info.type)) {
            // send_data->info.fd is session_id
            Connection *conn = serv->get_connection_verify(send_data->info.fd);
            if (conn) {
                conn->last_send_time = microtime();
                if (conn->closed) {
                    swoole_error_log(SW_LOG_NOTICE,
                                     SW_ERROR_SESSION_CLOSED_BY_SERVER,
                                     "Session#%ld is closed by server",
                                     send_data->info.fd);
                _discard:
                    buffer->pop();
                    continue;
                }
            } else if (serv->discard_timeout_request) {
                swoole_error_log(SW_LOG_WARNING,
                                 SW_ERROR_SESSION_DISCARD_TIMEOUT_DATA,
                                 "[1] ignore data[%u bytes] received from session#%ld",
                                 send_data->info.len,
                                 send_data->info.fd);
                goto _discard;
            }
        }

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
    reactor->set_handler(SW_FD_DGRAM_SERVER, ReactorThread_onPacketReceived);
    // Write
    reactor->set_handler(SW_FD_SESSION | SW_EVENT_WRITE, ReactorThread_onWrite);
    // Read
    reactor->set_handler(SW_FD_SESSION | SW_EVENT_READ, ReactorThread_onRead);

    // listen the all tcp port
    for (auto port : ports) {
        if (port->is_dgram()
#ifdef SW_SUPPORT_DTLS
            && !(port->is_dtls())
#endif
        ) {
            continue;
        }
        init_port_protocol(port);
    }
}

static int ReactorThread_onRead(Reactor *reactor, Event *event) {
    Server *serv = (Server *) reactor->ptr;
    Connection *conn = serv->get_connection(event->fd);
    /**
     * invalid event
     * The server has been actively closed the connection, the client also initiated off, fd has been reused.
     */
    if (!conn || conn->server_fd == 0) {
        return SW_OK;
    }
    ListenPort *port = serv->get_port_by_fd(event->fd);
#ifdef SW_USE_OPENSSL
#ifdef SW_SUPPORT_DTLS
    if (port->is_dtls()) {
        dtls::Buffer *buffer = (dtls::Buffer *) sw_malloc(sizeof(*buffer) + SW_BUFFER_SIZE_UDP);
        buffer->length = event->socket->read(buffer->data, SW_BUFFER_SIZE_UDP);
        dtls::Session *session = port->dtls_sessions->find(event->fd)->second;
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
#endif

    conn->last_recv_time = microtime();
    long last_recv_bytes = event->socket->total_recv_bytes;

    int retval = port->onRead(reactor, port, event);

    long socket_recv_bytes = event->socket->total_recv_bytes - last_recv_bytes;
    if (socket_recv_bytes > 0) {
        sw_atomic_fetch_add(&port->gs->total_recv_bytes, socket_recv_bytes);
        sw_atomic_fetch_add(&serv->gs->total_recv_bytes, socket_recv_bytes);
    }
    if (!conn->active) {
        return retval;
    }
    if (serv->is_process_mode() && serv->max_queued_bytes && conn->recv_queued_bytes > serv->max_queued_bytes) {
        conn->waiting_time = 1;
        conn->timer =
            swoole_timer_add((long) conn->waiting_time, false, ReactorThread_resume_data_receiving, event->socket);
        if (conn->timer) {
            reactor->remove_read_event(event->socket);
        }
    }
    return retval;
}

static int ReactorThread_onWrite(Reactor *reactor, Event *ev) {
    int ret;
    Server *serv = (Server *) reactor->ptr;
    Socket *socket = ev->socket;
    int fd = ev->fd;

    if (serv->is_process_mode()) {
        assert(fd % serv->reactor_num == reactor->id);
        assert(fd % serv->reactor_num == SwooleTG.id);
    }

    Connection *conn = serv->get_connection(fd);
    if (conn == nullptr || conn->active == 0) {
        return SW_ERR;
    }

    swoole_trace_log(SW_TRACE_REACTOR,
                     "fd=%d, conn->close_notify=%d, serv->disable_notify=%d, conn->close_force=%d",
                     fd,
                     conn->close_notify,
                     serv->disable_notify,
                     conn->close_force);

    if (conn->close_notify) {
#ifdef SW_USE_OPENSSL
        if (socket->ssl && socket->ssl_state != SW_SSL_STATE_READY) {
            return Server::close_connection(reactor, socket);
        }
#endif
        serv->notify(conn, SW_SERVER_EVENT_CLOSE);
        conn->close_notify = 0;
        return SW_OK;
    } else if (serv->disable_notify && conn->close_force) {
        return Server::close_connection(reactor, socket);
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

    if (conn->overflow && socket->out_buffer->length() < socket->buffer_size) {
        conn->overflow = 0;
    }

    if (serv->onBufferEmpty && conn->high_watermark) {
        ListenPort *port = serv->get_port_by_fd(fd);
        if (socket->out_buffer->length() <= port->buffer_low_watermark) {
            conn->high_watermark = 0;
            serv->notify(conn, SW_SERVER_EVENT_BUFFER_EMPTY);
        }
    }

    if (socket->send_timer) {
        swoole_timer_del(socket->send_timer);
        socket->send_timer = nullptr;
    }

    // remove EPOLLOUT event
    if (!conn->peer_closed && !socket->removed && Buffer::empty(socket->out_buffer)) {
        reactor->set(socket, SW_EVENT_READ);
    }
    return SW_OK;
}

/**
 * [master]
 */
int Server::start_reactor_threads() {
    if (swoole_event_init(0) < 0) {
        return SW_ERR;
    }

    Reactor *reactor = sw_reactor();

    for (auto iter = ports.begin(); iter != ports.end(); iter++) {
        auto port = *iter;
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
            swoole_thread_init();
            reactor_thread_main_loop(this, i);
            swoole_thread_clean();
        });
    }

_init_master_thread:

    /**
     * heartbeat thread
     */
    if (heartbeat_check_interval >= 1) {
        start_heartbeat_thread();
    }

    return start_master_thread(reactor);
}

int ReactorThread::init(Server *serv, Reactor *reactor, uint16_t reactor_id) {
    reactor->ptr = serv;
    reactor->id = reactor_id;
    reactor->wait_exit = 0;
    reactor->max_socket = serv->get_max_connection();
    reactor->close = Server::close_connection;
    reactor->default_error_handler = ReactorThread_onClose;

    reactor->set_handler(SW_FD_PIPE | SW_EVENT_READ, ReactorThread_onPipeRead);
    reactor->set_handler(SW_FD_PIPE | SW_EVENT_WRITE, ReactorThread_onPipeWrite);

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
            if (ls->type == SW_SOCK_UDP) {
                serv_sock->info.addr.inet_v4.sin_port = htons(ls->port);
            } else if (ls->type == SW_SOCK_UDP6) {
                serv_sock->info.addr.inet_v6.sin6_port = htons(ls->port);
            }
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
    serv->init_pipe_sockets(&message_bus);

    if (serv->is_thread_mode()) {
        Worker *worker = serv->get_worker(reactor_id);
        serv->init_event_worker(worker);
        auto pipe_worker = message_bus.get_pipe_socket(worker->pipe_worker);
        reactor->add(pipe_worker, SW_EVENT_READ);
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
    if (!message_bus.alloc_buffer()) {
        return SW_ERR;
    }

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

    return SW_OK;
}

void ReactorThread::clean() {
    message_bus.free_buffer();
}

void Server::reactor_thread_main_loop(Server *serv, int reactor_id) {
    SwooleTG.id = reactor_id;
    SwooleTG.type = Server::THREAD_REACTOR;

    ReactorThread *thread = serv->get_thread(reactor_id);
    thread->id = reactor_id;
    SwooleTG.message_bus = &thread->message_bus;

    if (swoole_event_init(0) < 0) {
        return;
    }

    if (serv->is_thread_mode()) {
        serv->call_worker_start_callback(serv->get_worker(reactor_id));
    }

    Reactor *reactor = sw_reactor();
    if (thread->init(serv, reactor, reactor_id) < 0) {
        return;
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
    Socket *_socket = (Socket *) tnode->data;
    Connection *conn = (Connection *) _socket->object;

    if (conn->recv_queued_bytes > sw_server()->max_queued_bytes) {
        if (conn->waiting_time != 1024) {
            conn->waiting_time *= 2;
        }
        conn->timer = swoole_timer_add((long) conn->waiting_time, false, ReactorThread_resume_data_receiving, _socket);
        if (conn->timer) {
            return;
        }
    }

    timer->get_reactor()->add_read_event(_socket);
    conn->timer = nullptr;
}

/**
 * dispatch request data [only data frame]
 */
int Server::dispatch_task(const Protocol *proto, Socket *_socket, const RecvData *rdata) {
    Server *serv = (Server *) proto->private_data_2;
    SendData task;

    Connection *conn = (Connection *) _socket->object;
    ListenPort *port = serv->get_port_by_fd(conn->fd);

    sw_memset_zero(&task.info, sizeof(task.info));
    task.info.server_fd = conn->server_fd;
    task.info.reactor_id = conn->reactor_id;
    task.info.ext_flags = rdata->info.ext_flags;
    task.info.type = SW_SERVER_EVENT_RECV_DATA;
    task.info.time = conn->last_recv_time;

    swoole_trace("dispatch task, size=%u bytes", rdata->info.len);

    task.info.fd = conn->fd;
    task.info.len = rdata->info.len;
    task.data = rdata->data;

    if (rdata->info.len > 0) {
        sw_atomic_fetch_add(&conn->recv_queued_bytes, rdata->info.len);
        swoole_trace_log(SW_TRACE_SERVER,
                         "session_id=%ld, len=%d, qb=%d",
                         conn->session_id,
                         rdata->info.len,
                         conn->recv_queued_bytes);
    }

    if (!serv->factory->dispatch(&task)) {
        if (rdata->info.len > 0) {
            sw_atomic_fetch_sub(&conn->recv_queued_bytes, rdata->info.len);
        }
        return SW_ERR;
    } else {
        if (serv->is_process_mode()) {
            ReactorThread *thread = serv->get_thread(conn->reactor_id);
            thread->dispatch_count++;
        }
        sw_atomic_fetch_add(&serv->gs->dispatch_count, 1);
        sw_atomic_fetch_add(&port->gs->dispatch_count, 1);
        return SW_OK;
    }
}

void Server::join_heartbeat_thread() {
    /**
     * Shutdown heartbeat thread
     */
    if (heartbeat_thread.joinable()) {
        swoole_trace_log(SW_TRACE_SERVER, "terminate heartbeat thread");
        if (pthread_cancel(heartbeat_thread.native_handle()) < 0) {
            swoole_sys_warning("pthread_cancel(%ld) failed", (ulong_t) heartbeat_thread.native_handle());
        }
        // wait thread
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
        if (thread->notify_pipe) {
            DataHead ev = {};
            ev.type = SW_SERVER_EVENT_SHUTDOWN;
            if (thread->notify_pipe->send_blocking((void *) &ev, sizeof(ev)) < 0) {
                goto _cancel;
            }
        } else {
        _cancel:
            if (pthread_cancel(thread->thread.native_handle()) < 0) {
                swoole_sys_warning("pthread_cancel(%ld) failed", (long) thread->thread.native_handle());
            }
        }
        thread->thread.join();
    }
}

void Server::start_heartbeat_thread() {
    heartbeat_thread = std::thread([this]() {
        swoole_signal_block_all();

        SwooleTG.type = THREAD_HEARTBEAT;
        SwooleTG.id = reactor_num + 1;

        while (running) {
            double now = microtime();
            foreach_connection([this, now](Connection *conn) {
                SessionId session_id = conn->session_id;
                if (session_id <= 0) {
                    return;
                }
                if (is_healthy_connection(now, conn)) {
                    return;
                }
                DataHead ev{};
                ev.type = SW_SERVER_EVENT_CLOSE_FORCE;
                // convert fd to session_id, in order to verify the connection before the force close connection
                ev.fd = session_id;
                get_reactor_pipe_socket(session_id, conn->reactor_id)->send_blocking(&ev, sizeof(ev));
            });
            sleep(heartbeat_check_interval);
        }
    });
}

}  // namespace swoole
