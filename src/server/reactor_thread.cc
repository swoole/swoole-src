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
#include "swoole_memory.h"
#include "swoole_hash.h"
#include "swoole_http.h"
#include "swoole_client.h"
#include "swoole_websocket.h"

#include <assert.h>

using std::unordered_map;
using namespace swoole;
using namespace swoole::network;

int swFactoryProcess_create(Factory *factory, uint32_t worker_num);

static void ReactorThread_loop(Server *serv, int reactor_id);
static int ReactorThread_init(Server *serv, Reactor *reactor, uint16_t reactor_id);
static int ReactorThread_onPipeWrite(Reactor *reactor, Event *ev);
static int ReactorThread_onPipeRead(Reactor *reactor, Event *ev);
static int ReactorThread_onRead(Reactor *reactor, Event *ev);
static int ReactorThread_onWrite(Reactor *reactor, Event *ev);
static int ReactorThread_onPacketReceived(Reactor *reactor, Event *event);
static int ReactorThread_onClose(Reactor *reactor, Event *event);
static void ReactorThread_onStreamResponse(Stream *stream, const char *data, uint32_t length);
static void ReactorThread_shutdown(Reactor *reactor);
static void ReactorThread_resume_data_receiving(Timer *timer, TimerNode *tnode);

#ifdef SW_USE_OPENSSL
static inline enum swReturn_code ReactorThread_verify_ssl_state(Reactor *reactor, ListenPort *port, Socket *_socket) {
    Server *serv = (Server *) reactor->ptr;
    if (!_socket->ssl || _socket->ssl_state == SW_SSL_STATE_READY) {
        return SW_CONTINUE;
    }

    enum swReturn_code code = swSSL_accept(_socket);
    if (code != SW_READY) {
        return code;
    }

    Connection *conn = (Connection *) _socket->object;
    conn->ssl_ready = 1;
    if (port->ssl_option.client_cert_file) {
        int retval = swSSL_get_peer_cert(_socket->ssl, SwooleTG.buffer_stack->str, SwooleTG.buffer_stack->size);
        if (retval < 0) {
            if (port->ssl_option.verify_peer) {
                return SW_ERROR;
            }
        } else {
            if (!port->ssl_option.verify_peer || swSSL_verify(_socket, port->ssl_option.allow_self_signed) == SW_OK) {
                swFactory *factory = &serv->factory;
                SendData task;
                task.info.fd = _socket->fd;
                task.info.type = SW_SERVER_EVENT_CONNECT;
                task.info.reactor_id = reactor->id;
                task.info.len = retval;
                task.data = SwooleTG.buffer_stack->str;
                factory->dispatch(factory, &task);
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
        if (reactor->del(reactor, _socket) < 0) {
            return SW_ERROR;
        }
    }

    return SW_READY;
}
#endif

static void ReactorThread_onStreamResponse(Stream *stream, const char *data, uint32_t length) {
    SendData response;
    DataHead *pkg_info = (DataHead *) data;
    Server *serv = (Server *) stream->private_data;
    Connection *conn = serv->get_connection_verify(pkg_info->fd);
    if (!conn) {
        swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SESSION_NOT_EXIST, "connection[fd=%d] does not exists", pkg_info->fd);
        return;
    }
    if (data == nullptr) {
        Event _ev = {};
        _ev.fd = conn->fd;
        _ev.socket = conn->socket;
        sw_reactor()->trigger_close_event(&_ev);
        return;
    }
    response.info.fd = conn->session_id;
    response.info.type = pkg_info->type;
    response.info.len = length - sizeof(DataHead);
    response.data = data + sizeof(DataHead);
    serv->send_to_connection(&response);
}

/**
 * for udp
 */
static int ReactorThread_onPacketReceived(Reactor *reactor, Event *event) {
    int fd = event->fd;
    int ret;

    Server *serv = (Server *) reactor->ptr;
    Connection *server_sock = serv->get_connection(fd);
    network::Socket *sock = server_sock->socket;
    SendData task = {};
    swDgramPacket *pkt = (swDgramPacket *) SwooleTG.buffer_stack->str;
    swFactory *factory = &serv->factory;

    task.info.server_fd = fd;
    task.info.reactor_id = SwooleTG.id;
    task.info.type = SW_SERVER_EVENT_RECV_DGRAM;
#ifdef SW_BUFFER_RECV_TIME
    task.info.time = swoole_microtime();
#endif

    int socket_type = server_sock->socket_type;

_do_recvfrom:

    ret = sock->recvfrom(pkt->data, SwooleTG.buffer_stack->size - sizeof(*pkt), 0, &pkt->socket_addr);
    if (ret <= 0) {
        if (errno == EAGAIN) {
            return SW_OK;
        } else {
            swSysWarn("recvfrom(%d) failed", fd);
            return SW_ERR;
        }
    }

#ifdef SW_SUPPORT_DTLS
    ListenPort *port = (ListenPort *) server_sock->object;

    if (port->ssl_option.protocols & SW_SSL_DTLS) {
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
            DataHead ev = {};
            ev.type = SW_SERVER_EVENT_INCOMING;
            ev.fd = session->socket->fd;
            Socket *_pipe_sock = serv->get_reactor_thread_pipe(conn->session_id, conn->reactor_id);
            ReactorThread *thread = serv->get_thread(SwooleTG.id);
            Socket *socket = &thread->pipe_sockets[_pipe_sock->fd];
            if (reactor->write(reactor, socket, &ev, sizeof(ev)) < 0) {
                reactor->close(reactor, session->socket);
                return SW_OK;
            }
        }

        return SW_OK;
    }
#endif

    if (socket_type == SW_SOCK_UDP) {
        memcpy(&task.info.fd, &pkt->socket_addr.addr.inet_v4.sin_addr, sizeof(task.info.fd));
    } else if (socket_type == SW_SOCK_UDP6) {
        memcpy(&task.info.fd, &pkt->socket_addr.addr.inet_v6.sin6_addr, sizeof(task.info.fd));
    } else {
        task.info.fd = swoole_crc32(pkt->socket_addr.addr.un.sun_path, pkt->socket_addr.len);
    }

    pkt->socket_type = socket_type;
    pkt->length = ret;
    task.info.len = sizeof(*pkt) + ret;
    task.data = (char *) pkt;

    if (!factory->dispatch(factory, &task)) {
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

    if (!socket->removed && reactor->del(reactor, socket) < 0) {
        return SW_ERR;
    }

    sw_atomic_fetch_add(&serv->gs->close_count, 1);
    sw_atomic_fetch_sub(&serv->gs->connection_num, 1);

    swTrace("Close Event.fd=%d|from=%d", socket->fd, reactor->id);

#ifdef SW_USE_OPENSSL
    if (socket->ssl) {
        conn->socket->ssl_quiet_shutdown = conn->peer_closed;
        swSSL_close(conn->socket);
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
        swString_free(socket->recv_buffer);
        socket->recv_buffer = nullptr;
    }

    sw_atomic_fetch_sub(port->connection_num, 1);

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
        if (setsockopt(fd, SOL_SOCKET, SO_LINGER, &linger, sizeof(struct linger)) != 0) {
            swSysWarn("setsockopt(SO_LINGER) failed");
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
        swTrace("set_maxfd=%d|close_fd=%d\n", find_max_fd, fd);
        // find the new max_fd
        for (; serv->is_valid_connection(serv->get_connection(find_max_fd)) && find_max_fd > serv->get_minfd();
                find_max_fd--) {
            // pass
        }
        serv->set_maxfd(find_max_fd);
    }
    serv->unlock();

    sw_memset_zero(conn, sizeof(Connection));
    return swReactor_close(reactor, socket);
}

/**
 * close the connection
 */
static int ReactorThread_onClose(Reactor *reactor, Event *event) {
    Server *serv = (Server *) reactor->ptr;
    int fd = event->fd;
    DataHead notify_ev;
    sw_memset_zero(&notify_ev, sizeof(notify_ev));
    Socket *socket = event->socket;

    assert(fd % serv->reactor_num == reactor->id);
    assert(fd % serv->reactor_num == SwooleTG.id);

    notify_ev.reactor_id = reactor->id;
    notify_ev.fd = fd;
    notify_ev.type = SW_SERVER_EVENT_CLOSE;

    swTraceLog(SW_TRACE_CLOSE, "client[fd=%d] close the connection", fd);

    Connection *conn = serv->get_connection(fd);
    if (conn == nullptr || conn->active == 0) {
        return SW_ERR;
    } else if (serv->disable_notify) {
        Server::close_connection(reactor, socket);
        return SW_OK;
    } else if (reactor->del(reactor, socket) == 0) {
        if (conn->close_queued) {
            Server::close_connection(reactor, socket);
            return SW_OK;
        } else {
            /**
             * peer_closed indicates that the client has closed the connection
             * and the connection is no longer available.
             */
            conn->peer_closed = 1;
            return serv->factory.notify(&serv->factory, &notify_ev);
        }
    } else {
        return SW_ERR;
    }
}

static void ReactorThread_shutdown(Reactor *reactor) {
    Server *serv = (Server *) reactor->ptr;
    // stop listen UDP Port
    if (serv->have_dgram_sock == 1) {
        for (auto ls : serv->ports) {
            if (ls->is_dgram()) {
                if (ls->socket->fd % serv->reactor_num != reactor->id) {
                    continue;
                }
                reactor->del(reactor, ls->socket);
            }
        }
    }

    serv->foreach_connection([serv, reactor](Connection *conn) {
        if (conn->fd % serv->reactor_num != reactor->id) {
            return;
        }
        if (!conn->peer_closed && !conn->socket->removed) {
            reactor->remove_read_event(conn->socket);
        }
    });

    reactor->set_wait_exit(true);
}

/**
 * receive data from worker process pipe
 */
static int ReactorThread_onPipeRead(Reactor *reactor, Event *ev) {
    SendData _send;

    Server *serv = (Server *) reactor->ptr;
    ReactorThread *thread = serv->get_thread(reactor->id);
    String *package = nullptr;
    PipeBuffer *resp = serv->pipe_buffers[reactor->id];

#ifdef SW_REACTOR_RECV_AGAIN
    while (1)
#endif
    {
        ssize_t n = read(ev->fd, resp, serv->ipc_max_size);
        if (n > 0) {
            // packet chunk
            if (resp->info.flags & SW_EVENT_DATA_CHUNK) {
                int worker_id = resp->info.server_fd;
                int key = (ev->fd << 16) + worker_id;
                auto it = thread->send_buffers.find(key);
                if (it == thread->send_buffers.end()) {
                    package = swString_new(SW_BUFFER_SIZE_BIG);
                    if (package == nullptr) {
                        swSysWarn("get buffer(worker-%d) failed", worker_id);
                        return SW_OK;
                    } else {
                        thread->send_buffers.emplace(std::make_pair(key, package));
                    }
                } else {
                    package = it->second;
                }
                // merge data to package buffer
                package->append(resp->data, n - sizeof(resp->info));
                // wait more data
                if (!(resp->info.flags & SW_EVENT_DATA_END)) {
                    return SW_OK;
                }
                _send.info = resp->info;
                _send.data = package->str;
                _send.info.len = package->length;
                serv->send_to_connection(&_send);
                swString_free(package);
                thread->send_buffers.erase(key);
            } else {
                /**
                 * connection incoming
                 */
                if (resp->info.type == SW_SERVER_EVENT_INCOMING) {
                    int fd = resp->info.fd;
                    Connection *conn = serv->get_connection(fd);
                    if (serv->connection_incoming(reactor, conn) < 0) {
                        return reactor->close(reactor, conn->socket);
                    }
                }
                /**
                 * server shutdown
                 */
                else if (resp->info.type == SW_SERVER_EVENT_SHUTDOWN) {
                    ReactorThread_shutdown(reactor);
                } else if (resp->info.type == SW_SERVER_EVENT_CLOSE_FORCE) {
                    uint32_t session_id = resp->info.fd;
                    Connection *conn = serv->get_connection_verify(session_id);

                    if (!conn) {
                        swoole_error_log(SW_LOG_NOTICE,
                                         SW_ERROR_SESSION_NOT_EXIST,
                                         "force close connection failed, session#%d does not exist",
                                         session_id);
                        return SW_ERR;
                    }

                    if (serv->disable_notify || conn->close_force) {
                        return Server::close_connection(reactor, conn->socket);
                    }

                    conn->close_force = 1;
                    Event _ev = {};
                    _ev.fd = conn->fd;
                    _ev.socket = conn->socket;
                    reactor->trigger_close_event(&_ev);
                } else {
                    _send.info = resp->info;
                    _send.data = resp->data;
                    serv->send_to_connection(&_send);
                }
            }
        } else if (errno == EAGAIN) {
            return SW_OK;
        } else {
            swSysWarn("read(worker_pipe) failed");
            return SW_ERR;
        }
    }

    return SW_OK;
}

ssize_t Server::send_to_worker_from_master(Worker *worker, const void *data, size_t len) {
    if (SwooleTG.reactor) {
        ReactorThread *thread = get_thread(SwooleTG.id);
        Socket *socket = &thread->pipe_sockets[worker->pipe_master->fd];
        return swoole_event_write(socket, data, len);
    } else {
        return worker->pipe_master->send_blocking(data, len);
    }
}

/**
 * [ReactorThread] worker pipe can write.
 */
static int ReactorThread_onPipeWrite(Reactor *reactor, Event *ev) {
    int ret;

    Connection *conn;
    Server *serv = (Server *) reactor->ptr;
    Buffer *buffer = ev->socket->out_buffer;

    while (!Buffer::empty(buffer)) {
        BufferChunk *chunk = buffer->front();
        EventData *send_data = (EventData *) chunk->value.ptr;

        // server active close, discard data.
        if (Server::is_stream_event(send_data->info.type)) {
            // send_data->info.fd is session_id
            conn = serv->get_connection_verify(send_data->info.fd);
            if (conn) {
                if (conn->closed) {
                    swoole_error_log(SW_LOG_NOTICE,
                                     SW_ERROR_SESSION_CLOSED_BY_SERVER,
                                     "Session#%d is closed by server",
                                     send_data->info.fd);
                _discard:
                    buffer->pop();
                    continue;
                }
            } else if (serv->discard_timeout_request) {
                swoole_error_log(SW_LOG_WARNING,
                                 SW_ERROR_SESSION_DISCARD_TIMEOUT_DATA,
                                 "[1] received the wrong data[%d bytes] from socket#%d",
                                 send_data->info.len,
                                 send_data->info.fd);
                goto _discard;
            }
        }

        ret = ev->socket->send(chunk->value.ptr, chunk->length, 0);
        if (ret < 0) {
            return (ev->socket->catch_error(errno) == SW_WAIT) ? SW_OK : SW_ERR;
        } else {
            buffer->pop();
        }
    }

    if (Buffer::empty(buffer)) {
        if (reactor->remove_write_event(ev->socket) < 0) {
            swSysWarn("reactor->set(%d) failed", ev->fd);
        }
    }

    return SW_OK;
}

void Server::init_reactor(Reactor *reactor) {
    // support 64K packet
    if (have_dgram_sock) {
        SwooleTG.buffer_stack->extend();
    }
    // UDP Packet
    reactor->set_handler(SW_FD_DGRAM_SERVER, ReactorThread_onPacketReceived);
    // Write
    reactor->set_handler(SW_FD_SESSION | SW_EVENT_WRITE, ReactorThread_onWrite);
    // Read
    reactor->set_handler(SW_FD_SESSION | SW_EVENT_READ, ReactorThread_onRead);

    if (dispatch_mode == SW_DISPATCH_STREAM) {
        Client::init_reactor(reactor);
    }

    // listen the all tcp port
    for (auto port : ports) {
        if (port->is_dgram()
#ifdef SW_SUPPORT_DTLS
            && !(port->ssl_option.protocols & SW_SSL_DTLS)
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
    if (port->ssl_option.protocols & SW_SSL_DTLS) {
        dtls::Buffer *buffer = (dtls::Buffer *) sw_malloc(sizeof(*buffer) + SW_BUFFER_SIZE_UDP);
        buffer->length = read(event->fd, buffer->data, SW_BUFFER_SIZE_UDP);
        dtls::Session *session = port->dtls_sessions->find(event->fd)->second;
        session->append(buffer);
        if (!session->listened && !session->listen()) {
            Server::close_connection(reactor, event->socket);
            return SW_OK;
        }
    }
#endif
    enum swReturn_code code = ReactorThread_verify_ssl_state(reactor, port, event->socket);
    switch (code) {
    case SW_ERROR:
        return Server::close_connection(reactor, event->socket);
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

    conn->last_time = time(nullptr);
#ifdef SW_BUFFER_RECV_TIME
    conn->last_time_usec = swoole_microtime();
#endif

    int retval = port->onRead(reactor, port, event);
    if (!conn->active) {
        return retval;
    }
    if (serv->is_process_mode() && serv->max_queued_bytes && conn->queued_bytes > serv->max_queued_bytes) {
        conn->waiting_time = 1;
        conn->timer = swoole_timer_add(conn->waiting_time, false, ReactorThread_resume_data_receiving, event->socket);
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

    swTraceLog(SW_TRACE_REACTOR,
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
        _close_fd:
            reactor->close(reactor, socket);
            return SW_OK;
        } else if (chunk->type == BufferChunk::TYPE_SENDFILE) {
            ret = socket->handle_sendfile();
        } else {
            ret = socket->handle_send();
        }

        if (ret < 0) {
            if (socket->close_wait) {
                conn->close_errno = errno;
                goto _close_fd;
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
        reactor->set(reactor, socket, SW_EVENT_READ);
    }
    return SW_OK;
}

int Server::create_reactor_threads() {
    int ret = 0;
    /**
     * init reactor thread pool
     */
    reactor_threads = new ReactorThread[reactor_num]();
    /**
     * alloc the memory for connection_list
     */
    connection_list = (Connection *) sw_shm_calloc(max_connection, sizeof(Connection));
    if (connection_list == nullptr) {
        swError("calloc[1] failed");
        return SW_ERR;
    }
    if (worker_num < 1) {
        swError("Fatal Error: worker_num < 1");
        return SW_ERR;
    }
    ret = swFactoryProcess_create(&(factory), worker_num);
    if (ret < 0) {
        swError("create factory failed");
        return SW_ERR;
    }
    reactor_pipe_num = worker_num / reactor_num;
    return SW_OK;
}

/**
 * [master]
 */
int Server::start_reactor_threads() {
    if (swoole_event_init(0) < 0) {
        return SW_ERR;
    }

    Reactor *reactor = SwooleTG.reactor;

#ifdef HAVE_SIGNALFD
    if (SwooleG.use_signalfd) {
        swSignalfd_setup(reactor);
    }
#endif

    for (auto iter = ports.begin(); iter != ports.end(); iter++) {
        auto port = *iter;
        if (port->is_dgram()) {
            continue;
        }
        if (port->listen() < 0) {
            swoole_event_free();
            return SW_ERR;
        }
        reactor->add(reactor, port->socket, SW_EVENT_READ);
    }

    /**
     * create reactor thread
     */
    ReactorThread *thread;
    int i;

    store_listen_socket();

    if (single_thread) {
        ReactorThread_init(this, reactor, 0);
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

#ifdef HAVE_PTHREAD_BARRIER
    // init thread barrier
    pthread_barrier_init(&barrier, nullptr, reactor_num + 1);
#endif
    for (i = 0; i < reactor_num; i++) {
        thread = &(reactor_threads[i]);
        thread->thread = std::thread(ReactorThread_loop, this, i);
    }
#ifdef HAVE_PTHREAD_BARRIER
    // wait reactor thread
    pthread_barrier_wait(&barrier);
#else
    SW_START_SLEEP;
#endif

_init_master_thread:

    /**
     * heartbeat thread
     */
    if (heartbeat_check_interval >= 1 && heartbeat_check_interval <= heartbeat_idle_time) {
        swTrace("hb timer start, time: %d live time:%d", heartbeat_check_interval, heartbeat_idle_time);
        start_heartbeat_thread();
    }

    SwooleTG.type = SW_THREAD_MASTER;
    SwooleTG.update_time = 1;
    SwooleTG.reactor = reactor;

    if (SwooleTG.timer && SwooleTG.timer->get_reactor() == nullptr) {
        SwooleTG.timer->reinit(reactor);
    }

    SwooleG.pid = getpid();
    SwooleG.process_type = SW_PROCESS_MASTER;

    reactor->ptr = this;
    reactor->set_handler(SW_FD_STREAM_SERVER, Server::accept_connection);

    if (hooks[Server::HOOK_MASTER_START]) {
        call_hook(Server::HOOK_MASTER_START, this);
    }

    /**
     * 1 second timer
     */
    if ((master_timer = swoole_timer_add(1000, true, Server::timer_callback, this)) == nullptr) {
        swoole_event_free();
        return SW_ERR;
    }

    if (onStart) {
        onStart(this);
    }

    return swoole_event_wait();
}

static int ReactorThread_init(Server *serv, Reactor *reactor, uint16_t reactor_id) {
    ReactorThread *thread = serv->get_thread(reactor_id);

    reactor->ptr = serv;
    reactor->id = reactor_id;
    reactor->wait_exit = 0;
    reactor->max_socket = serv->get_max_connection();
    reactor->close = Server::close_connection;

    reactor->set_exit_condition(Reactor::EXIT_CONDITION_DEFAULT, [thread](Reactor *reactor, int &event_num) -> bool {
        return reactor->event_num == thread->pipe_num;
    });

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
            if (reactor->add(reactor, ls->socket, SW_EVENT_READ) < 0) {
                return SW_ERR;
            }
        }
    }

    serv->init_reactor(reactor);

    int max_pipe_fd = serv->get_worker(serv->worker_num - 1)->pipe_master->fd + 2;
    thread->pipe_sockets = (Socket *) sw_calloc(max_pipe_fd, sizeof(Socket));
    if (!thread->pipe_sockets) {
        swSysError("calloc(%d, %ld) failed", max_pipe_fd, sizeof(Socket));
        return SW_ERR;
    }

    for (uint32_t i = 0; i < serv->worker_num; i++) {
        int pipe_fd = serv->workers[i].pipe_master->fd;
        Socket *socket = &thread->pipe_sockets[pipe_fd];

        socket->fd = pipe_fd;
        socket->fdtype = SW_FD_PIPE;
        socket->buffer_size = UINT_MAX;

        if (i % serv->reactor_num != reactor_id) {
            continue;
        }

        socket->set_nonblock();

        if (reactor->add(reactor, socket, SW_EVENT_READ) < 0) {
            return SW_ERR;
        }
        if (thread->notify_pipe == nullptr) {
            thread->notify_pipe = serv->workers[i].pipe_worker;
        }
        thread->pipe_num++;
    }

    return SW_OK;
}

/**
 * ReactorThread main Loop
 */
static void ReactorThread_loop(Server *serv, int reactor_id) {
    SwooleTG.id = reactor_id;
    SwooleTG.type = SW_THREAD_REACTOR;

    SwooleTG.buffer_stack = swString_new(SW_STACK_BUFFER_SIZE);
    if (SwooleTG.buffer_stack == nullptr) {
        return;
    }

    ReactorThread *thread = serv->get_thread(reactor_id);

    swoole_event_init(0);
    Reactor *reactor = SwooleTG.reactor;

#ifdef HAVE_CPU_AFFINITY
    // cpu affinity setting
    if (serv->open_cpu_affinity) {
        cpu_set_t cpu_set;
        CPU_ZERO(&cpu_set);

        if (serv->cpu_affinity_available_num) {
            CPU_SET(serv->cpu_affinity_available[reactor_id % serv->cpu_affinity_available_num], &cpu_set);
        } else {
            CPU_SET(reactor_id % SW_CPU_NUM, &cpu_set);
        }

        if (0 != pthread_setaffinity_np(pthread_self(), sizeof(cpu_set), &cpu_set)) {
            swSysWarn("pthread_setaffinity_np() failed");
        }
    }
#endif

    swSignal_none();

    if (ReactorThread_init(serv, reactor, reactor_id) < 0) {
        return;
    }

    // wait other thread
#ifdef HAVE_PTHREAD_BARRIER
    pthread_barrier_wait(&serv->barrier);
#else
    SW_START_SLEEP;
#endif
    // main loop
    swoole_event_wait();

    for (auto it = thread->send_buffers.begin(); it != thread->send_buffers.end(); it++) {
        swString_free(it->second);
    }
    sw_free(thread->pipe_sockets);

    swString_free(SwooleTG.buffer_stack);
}

static void ReactorThread_resume_data_receiving(Timer *timer, TimerNode *tnode) {
    Socket *_socket = (Socket *) tnode->data;
    Connection *conn = (Connection *) _socket->object;

    if (conn->queued_bytes > sw_server()->max_queued_bytes) {
        if (conn->waiting_time != 1024) {
            conn->waiting_time *= 2;
        }
        conn->timer = swoole_timer_add(conn->waiting_time, false, ReactorThread_resume_data_receiving, _socket);
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
int Server::dispatch_task(Protocol *proto, Socket *_socket, const char *data, uint32_t length) {
    Server *serv = (Server *) proto->private_data_2;
    SendData task;

    Connection *conn = (Connection *) _socket->object;

    sw_memset_zero(&task.info, sizeof(task.info));
    task.info.server_fd = conn->server_fd;
    task.info.reactor_id = conn->reactor_id;
    task.info.ext_flags = proto->ext_flags;
    proto->ext_flags = 0;
    task.info.type = SW_SERVER_EVENT_RECV_DATA;
#ifdef SW_BUFFER_RECV_TIME
    task.info.info.time = conn->last_time_usec;
#endif

    swTrace("send string package, size=%ld bytes", (long) length);

    if (serv->stream_socket_file) {
        Stream *stream = Stream::create(serv->stream_socket_file, 0, SW_SOCK_UNIX_STREAM);
        if (!stream) {
            return SW_ERR;
        }
        stream->response = ReactorThread_onStreamResponse;
        stream->private_data = serv;
        ListenPort *port = serv->get_port_by_fd(conn->fd);
        stream->set_max_length(port->protocol.package_max_length);

        task.info.fd = conn->session_id;

        if (stream->send((char *) &task.info, sizeof(task.info)) < 0) {
        _cancel:
            stream->cancel = 1;
            delete stream;
            return SW_ERR;
        }
        if (stream->send(data, length) < 0) {
            goto _cancel;
        }
        return SW_OK;
    } else {
        task.info.fd = conn->fd;
        task.info.len = length;
        task.data = data;
        if (!serv->factory.dispatch(&serv->factory, &task)) {
            return SW_ERR;
        }
        if (serv->max_queued_bytes && length > 0) {
            sw_atomic_fetch_add(&conn->queued_bytes, length);
            swTraceLog(SW_TRACE_SERVER, "[Master] len=%d, qb=%d\n", length, conn->queued_bytes);
        }
        return SW_OK;
    }
}

void Server::join_reactor_thread() {
    if (single_thread) {
        return;
    }
    ReactorThread *thread;
    /**
     * Shutdown heartbeat thread
     */
    if (heartbeat_thread.joinable()) {
        swTraceLog(SW_TRACE_SERVER, "terminate heartbeat thread");
        if (pthread_cancel(heartbeat_thread.native_handle()) < 0) {
            swSysWarn("pthread_cancel(%ld) failed", (ulong_t) heartbeat_thread.native_handle());
        }
        // wait thread
        heartbeat_thread.join();
    }
    /**
     * kill threads
     */
    for (int i = 0; i < reactor_num; i++) {
        thread = get_thread(i);
        if (thread->notify_pipe) {
            DataHead ev = {};
            ev.type = SW_SERVER_EVENT_SHUTDOWN;
            if (thread->notify_pipe->send_blocking((void *) &ev, sizeof(ev)) < 0) {
                goto _cancel;
            }
        } else {
        _cancel:
            if (pthread_cancel(thread->thread.native_handle()) < 0) {
                swSysWarn("pthread_cancel(%ld) failed", (long) thread->thread.native_handle());
            }
        }
        thread->thread.join();
    }
}

void Server::destroy_reactor_threads() {
    factory.free(&factory);
    sw_shm_free(connection_list);
    delete[] reactor_threads;

    if (message_box) {
        message_box->destroy();
    }
}

void Server::start_heartbeat_thread() {
    heartbeat_thread = std::thread([this]() {
        swSignal_none();

        int checktime;

        SwooleTG.type = SW_THREAD_HEARTBEAT;
        SwooleTG.id = reactor_num;

        while (running) {
            checktime = (int) ::time(nullptr) - heartbeat_idle_time;
            foreach_connection([this, checktime](Connection *conn) {
                if (conn->protect || conn->last_time == 0 || conn->last_time > checktime) {
                    return;
                }
                DataHead ev{};
                ev.type = SW_SERVER_EVENT_CLOSE_FORCE;
                // convert fd to session_id, in order to verify the connection before the force close connection
                ev.fd = conn->session_id;
                Socket *_pipe_sock = get_reactor_thread_pipe(conn->session_id, conn->reactor_id);
                _pipe_sock->send_blocking((void *) &ev, sizeof(ev));
            });
            sleep(heartbeat_check_interval);
        }
    });
}
