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
#include "swoole_memory.h"
#include "thread_pool.h"
#include "hash.h"
#include "http.h"
#include "client.h"
#include "websocket.h"

#include <assert.h>

using std::unordered_map;
using namespace swoole;

static void swReactorThread_loop(swServer *serv, int reactor_id);
static int swReactorThread_init(swServer *serv, swReactor *reactor, uint16_t reactor_id);
static int swReactorThread_onPipeWrite(swReactor *reactor, swEvent *ev);
static int swReactorThread_onPipeRead(swReactor *reactor, swEvent *ev);
static int swReactorThread_onRead(swReactor *reactor, swEvent *ev);
static int swReactorThread_onWrite(swReactor *reactor, swEvent *ev);
static int swReactorThread_onPacketReceived(swReactor *reactor, swEvent *event);
static int swReactorThread_onClose(swReactor *reactor, swEvent *event);
static void swReactorThread_onStreamResponse(swStream *stream, const char *data, uint32_t length);
static void swReactorThread_shutdown(swReactor *reactor);
static void swReactorThread_resume_data_receiving(swTimer *timer, swTimer_node *tnode);

#ifdef SW_USE_OPENSSL
static inline enum swReturn_code swReactorThread_verify_ssl_state(swReactor *reactor,
                                                                  swListenPort *port,
                                                                  swSocket *_socket) {
    swServer *serv = (swServer *) reactor->ptr;
    if (!_socket->ssl || _socket->ssl_state == SW_SSL_STATE_READY) {
        return SW_CONTINUE;
    }

    enum swReturn_code code = swSSL_accept(_socket);
    if (code != SW_READY) {
        return code;
    }

    swConnection *conn = (swConnection *) _socket->object;
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
                swSendData task;
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
        serv->notify(serv, (swConnection *) _socket->object, SW_SERVER_EVENT_CONNECT);
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

static void swReactorThread_onStreamResponse(swStream *stream, const char *data, uint32_t length) {
    swSendData response;
    swDataHead *pkg_info = (swDataHead *) data;
    swServer *serv = (swServer *) stream->private_data;
    swConnection *conn = serv->get_connection_verify(pkg_info->fd);
    if (!conn) {
        swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SESSION_NOT_EXIST, "connection[fd=%d] does not exists", pkg_info->fd);
        return;
    }
    if (data == nullptr) {
        swEvent _ev = {};
        _ev.fd = conn->fd;
        _ev.socket = conn->socket;
        swReactor_trigger_close_event(sw_reactor(), &_ev);
        return;
    }
    response.info.fd = conn->session_id;
    response.info.type = pkg_info->type;
    response.info.len = length - sizeof(swDataHead);
    response.data = data + sizeof(swDataHead);
    serv->send_to_connection(&response);
}

/**
 * for udp
 */
static int swReactorThread_onPacketReceived(swReactor *reactor, swEvent *event) {
    int fd = event->fd;
    int ret;

    swServer *serv = (swServer *) reactor->ptr;
    swConnection *server_sock = &serv->connection_list[fd];
    swSendData task = {};
    swDgramPacket *pkt = (swDgramPacket *) SwooleTG.buffer_stack->str;
    swFactory *factory = &serv->factory;

    pkt->socket_addr.len = sizeof(pkt->socket_addr.addr);

    task.info.server_fd = fd;
    task.info.reactor_id = SwooleTG.id;
    task.info.type = SW_SERVER_EVENT_SNED_DGRAM;
#ifdef SW_BUFFER_RECV_TIME
    task.info.time = swoole_microtime();
#endif

    int socket_type = server_sock->socket_type;

_do_recvfrom:

    ret = recvfrom(fd,
                   pkt->data,
                   SwooleTG.buffer_stack->size - sizeof(*pkt),
                   0,
                   (struct sockaddr *) &pkt->socket_addr.addr,
                   &pkt->socket_addr.len);

    if (ret <= 0) {
        if (errno == EAGAIN) {
            return SW_OK;
        } else {
            swSysWarn("recvfrom(%d) failed", fd);
            return SW_ERR;
        }
    }

#ifdef SW_SUPPORT_DTLS
    swListenPort *port = (swListenPort *) server_sock->object;

    if (port->ssl_option.dtls) {
        swoole::dtls::Session *session = swServer_dtls_accept(serv, port, &pkt->socket_addr);

        if (!session) {
            return SW_ERR;
        }

        session->append(pkt->data, ret);

        if (!session->listen()) {
            return Server::close_connection(reactor, session->socket);
        }

        swConnection *conn = (swConnection *) session->socket->object;
        if (serv->single_thread) {
            if (swServer_connection_incoming(serv, reactor, conn) < 0) {
                reactor->close(reactor, session->socket);
                return SW_OK;
            }
        } else {
            swDataHead ev = {};
            ev.type = SW_SERVER_EVENT_INCOMING;
            ev.fd = session->socket->fd;
            swSocket *_pipe_sock = swServer_get_send_pipe(serv, conn->session_id, conn->reactor_id);
            ReactorThread *thread = serv->get_thread(SwooleTG.id);
            swSocket *socket = &thread->pipe_sockets[_pipe_sock->fd];
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

    if (factory->dispatch(factory, &task) < 0) {
        return SW_ERR;
    } else {
        goto _do_recvfrom;
    }
}

/**
 * close connection
 */
int Server::close_connection(swReactor *reactor, swSocket *socket) {
    swServer *serv = (swServer *) reactor->ptr;
    swConnection *conn = (swConnection *) socket->object;
    swListenPort *port = serv->get_port_by_fd(socket->fd);

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
        swHttp_free_request(conn);
    }
    if (port->open_redis_protocol && conn->object) {
        sw_free(conn->object);
        conn->object = nullptr;
    }

#ifdef SW_USE_SOCKET_LINGER
    if (conn->close_force) {
        struct linger linger;
        linger.l_onoff = 1;
        linger.l_linger = 0;
        if (setsockopt(fd, SOL_SOCKET, SO_LINGER, &linger, sizeof(struct linger)) != 0) {
            swSysWarn("setsockopt(SO_LINGER) failed");
        }
    }
#endif

    swSession *session = serv->get_session(conn->session_id);
    session->fd = 0;
    /**
     * reset maxfd, for connection_list
     */
    int fd = socket->fd;

    if (fd == serv->get_maxfd()) {
        serv->lock();
        int find_max_fd = fd - 1;
        swTrace("set_maxfd=%d|close_fd=%d\n", find_max_fd, fd);
        /**
         * Find the new max_fd
         */
        for (; serv->connection_list[find_max_fd].active == 0 && find_max_fd > serv->get_minfd(); find_max_fd--) {
            // pass
        }
        serv->set_maxfd(find_max_fd);
        serv->unlock();
    }
    sw_memset_zero(conn, sizeof(swConnection));
    return swReactor_close(reactor, socket);
}

/**
 * close the connection
 */
static int swReactorThread_onClose(swReactor *reactor, swEvent *event) {
    swServer *serv = (swServer *) reactor->ptr;
    int fd = event->fd;
    swDataHead notify_ev;
    sw_memset_zero(&notify_ev, sizeof(notify_ev));
    swSocket *socket = event->socket;

    assert(fd % serv->reactor_num == reactor->id);
    assert(fd % serv->reactor_num == SwooleTG.id);

    notify_ev.reactor_id = reactor->id;
    notify_ev.fd = fd;
    notify_ev.type = SW_SERVER_EVENT_CLOSE;

    swTraceLog(SW_TRACE_CLOSE, "client[fd=%d] close the connection", fd);

    swConnection *conn = serv->get_connection(fd);
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

static void swReactorThread_shutdown(swReactor *reactor) {
    swServer *serv = (swServer *) reactor->ptr;
    // stop listen UDP Port
    if (serv->have_dgram_sock == 1) {
        for (auto ls : serv->ports) {
            if (swSocket_is_dgram(ls->type)) {
                if (ls->socket->fd % serv->reactor_num != reactor->id) {
                    continue;
                }
                reactor->del(reactor, ls->socket);
            }
        }
    }

    int fd;
    int serv_max_fd = serv->get_maxfd();
    int serv_min_fd = serv->get_minfd();

    for (fd = serv_min_fd; fd <= serv_max_fd; fd++) {
        if (fd % serv->reactor_num != reactor->id) {
            continue;
        }
        swConnection *conn = serv->get_connection(fd);
        if (swServer_connection_valid(serv, conn) && !conn->peer_closed && !conn->socket->removed) {
            swReactor_remove_read_event(reactor, conn->socket);
        }
    }

    swReactor_wait_exit(reactor, 1);
}

/**
 * receive data from worker process pipe
 */
static int swReactorThread_onPipeRead(swReactor *reactor, swEvent *ev) {
    swSendData _send;

    swServer *serv = (swServer *) reactor->ptr;
    ReactorThread *thread = serv->get_thread(reactor->id);
    swString *package = nullptr;
    swPipeBuffer *resp = serv->pipe_buffers[reactor->id];

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
                swString_append_ptr(package, resp->data, n - sizeof(resp->info));
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
                    swConnection *conn = serv->get_connection(fd);
                    if (swServer_connection_incoming(serv, reactor, conn) < 0) {
                        return reactor->close(reactor, conn->socket);
                    }
                }
                /**
                 * server shutdown
                 */
                else if (resp->info.type == SW_SERVER_EVENT_SHUTDOWN) {
                    swReactorThread_shutdown(reactor);
                } else if (resp->info.type == SW_SERVER_EVENT_CLOSE_FORCE) {
                    uint32_t session_id = resp->info.fd;
                    swConnection *conn = serv->get_connection_verify(session_id);

                    if (!conn) {
                        swoole_error_log(SW_LOG_NOTICE,
                                         SW_ERROR_SESSION_NOT_EXIST,
                                         "force close connection failed, session#%d does not exist",
                                         session_id);
                        return SW_ERR;
                    }

                    conn->close_force = 1;
                    swEvent _ev = {};
                    _ev.fd = conn->fd;
                    _ev.socket = conn->socket;
                    swReactor_trigger_close_event(reactor, &_ev);
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

int Server::send_to_worker_from_master(swWorker *worker, const void *data, size_t len) {
    if (SwooleTG.reactor) {
        ReactorThread *thread = get_thread(SwooleTG.id);
        swSocket *socket = &thread->pipe_sockets[worker->pipe_master->fd];
        return swoole_event_write(socket, data, len);
    } else {
        return swSocket_write_blocking(worker->pipe_master, data, len);
    }
}

/**
 * [ReactorThread] worker pipe can write.
 */
static int swReactorThread_onPipeWrite(swReactor *reactor, swEvent *ev) {
    int ret;

    swBuffer_chunk *chunk = nullptr;
    swEventData *send_data;
    swConnection *conn;
    swServer *serv = (swServer *) reactor->ptr;
    swBuffer *buffer = ev->socket->out_buffer;

    while (!swBuffer_empty(buffer)) {
        chunk = swBuffer_get_chunk(buffer);
        send_data = (swEventData *) chunk->store.ptr;

        // server active close, discard data.
        if (swEventData_is_stream(send_data->info.type)) {
            // send_data->info.fd is session_id
            conn = serv->get_connection_verify(send_data->info.fd);
            if (conn) {
                if (conn->closed) {
                    swoole_error_log(SW_LOG_NOTICE,
                                     SW_ERROR_SESSION_CLOSED_BY_SERVER,
                                     "Session#%d is closed by server",
                                     send_data->info.fd);
                _discard:
                    swBuffer_pop_chunk(buffer, chunk);
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

        ret = swSocket_send(ev->socket, chunk->store.ptr, chunk->length, 0);
        if (ret < 0) {
            return (swSocket_error(errno) == SW_WAIT) ? SW_OK : SW_ERR;
        } else {
            swBuffer_pop_chunk(buffer, chunk);
        }
    }

    if (swBuffer_empty(buffer)) {
        if (swReactor_remove_write_event(reactor, ev->socket) < 0) {
            swSysWarn("reactor->set(%d) failed", ev->fd);
        }
    }

    return SW_OK;
}

void Server::init_reactor(swReactor *reactor) {
    // support 64K packet
    if (have_dgram_sock) {
        swString_extend_align(SwooleTG.buffer_stack, SwooleTG.buffer_stack->size * 2);
    }
    // UDP Packet
    reactor->set_handler(SW_FD_DGRAM_SERVER, swReactorThread_onPacketReceived);
    // Write
    reactor->set_handler(SW_FD_SESSION | SW_EVENT_WRITE, swReactorThread_onWrite);
    // Read
    reactor->set_handler(SW_FD_SESSION | SW_EVENT_READ, swReactorThread_onRead);

    if (dispatch_mode == SW_DISPATCH_STREAM) {
        swClient_init_reactor(reactor);
    }

    // listen the all tcp port
    for (auto port : ports) {
        if (swSocket_is_dgram(port->type)
#ifdef SW_SUPPORT_DTLS
            && !port->ssl_option.dtls
#endif
        ) {
            continue;
        }
        init_port_protocol(port);
    }
}

static int swReactorThread_onRead(swReactor *reactor, swEvent *event) {
    swServer *serv = (swServer *) reactor->ptr;
    swConnection *conn = serv->get_connection(event->fd);
    /**
     * invalid event
     * The server has been actively closed the connection, the client also initiated off, fd has been reused.
     */
    if (!conn || conn->server_fd == 0) {
        return SW_OK;
    }
    swListenPort *port = serv->get_port_by_fd(event->fd);
#ifdef SW_USE_OPENSSL
#ifdef SW_SUPPORT_DTLS
    if (port->ssl_option.dtls) {
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
    enum swReturn_code code = swReactorThread_verify_ssl_state(reactor, port, event->socket);
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
    if (serv->factory_mode == SW_MODE_PROCESS && serv->max_queued_bytes &&
        conn->queued_bytes > serv->max_queued_bytes) {
        conn->waiting_time = 1;
        conn->timer = swoole_timer_add(conn->waiting_time, false, swReactorThread_resume_data_receiving, event->socket);
        if (conn->timer) {
            swReactor_remove_read_event(sw_reactor(), event->socket);
        }
    }
    return retval;
}

static int swReactorThread_onWrite(swReactor *reactor, swEvent *ev) {
    int ret;
    swServer *serv = (swServer *) reactor->ptr;
    swSocket *socket = ev->socket;
    swBuffer_chunk *chunk;
    int fd = ev->fd;

    if (serv->factory_mode == SW_MODE_PROCESS) {
        assert(fd % serv->reactor_num == reactor->id);
        assert(fd % serv->reactor_num == SwooleTG.id);
    }

    swConnection *conn = serv->get_connection(fd);
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
        serv->notify(serv, conn, SW_SERVER_EVENT_CLOSE);
        conn->close_notify = 0;
        return SW_OK;
    } else if (serv->disable_notify && conn->close_force) {
        return Server::close_connection(reactor, socket);
    }

    while (!swBuffer_empty(socket->out_buffer)) {
        chunk = swBuffer_get_chunk(socket->out_buffer);
        if (chunk->type == SW_CHUNK_CLOSE) {
        _close_fd:
            reactor->close(reactor, socket);
            return SW_OK;
        } else if (chunk->type == SW_CHUNK_SENDFILE) {
            ret = swSocket_onSendfile(socket, chunk);
        } else {
            ret = swSocket_buffer_send(socket);
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

    if (conn->overflow && socket->out_buffer->length < socket->buffer_size) {
        conn->overflow = 0;
    }

    if (serv->onBufferEmpty && conn->high_watermark) {
        swListenPort *port = serv->get_port_by_fd(fd);
        if (socket->out_buffer->length <= port->buffer_low_watermark) {
            conn->high_watermark = 0;
            serv->notify(serv, conn, SW_SERVER_EVENT_BUFFER_EMPTY);
        }
    }

    // remove EPOLLOUT event
    if (!conn->peer_closed && !socket->removed && swBuffer_empty(socket->out_buffer)) {
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
    connection_list = (swConnection *) sw_shm_calloc(max_connection, sizeof(swConnection));
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
    return SW_OK;
}

/**
 * [master]
 */
int Server::start_reactor_threads() {
    if (swoole_event_init(0) < 0) {
        return SW_ERR;
    }

    swReactor *reactor = SwooleTG.reactor;

#ifdef HAVE_SIGNALFD
    if (SwooleG.use_signalfd) {
        swSignalfd_setup(reactor);
    }
#endif

    // set listen socket options
    std::vector<swListenPort *>::iterator ls;
    for (ls = ports.begin(); ls != ports.end(); ls++) {
        if (swSocket_is_dgram((*ls)->type)) {
            continue;
        }
        if (swPort_listen(*ls) < 0) {
        _failed:
            swoole_event_free();
            return SW_ERR;
        }
        reactor->add(reactor, (*ls)->socket, SW_EVENT_READ);
    }

    /**
     * create reactor thread
     */
    ReactorThread *thread;
    int i;

    swServer_store_listen_socket(this);

    if (single_thread) {
        swReactorThread_init(this, reactor, 0);
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
        thread->thread = std::thread(swReactorThread_loop, this, i);
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

    if (SwooleTG.timer && SwooleTG.timer->reactor == nullptr) {
        swTimer_reinit(SwooleTG.timer, reactor);
    }

    SwooleG.pid = getpid();
    SwooleG.process_type = SW_PROCESS_MASTER;

    reactor->ptr = this;
    reactor->set_handler(SW_FD_STREAM_SERVER, Server::accept_connection);

    if (hooks[SW_SERVER_HOOK_MASTER_START]) {
        call_hook(SW_SERVER_HOOK_MASTER_START, this);
    }

    /**
     * 1 second timer
     */
    if ((master_timer = swoole_timer_add(1000, SW_TRUE, swServer_master_onTimer, this)) == nullptr) {
        goto _failed;
    }

    if (onStart) {
        onStart(this);
    }

    return swoole_event_wait();
}

static int swReactorThread_init(swServer *serv, swReactor *reactor, uint16_t reactor_id) {
    ReactorThread *thread = serv->get_thread(reactor_id);

    reactor->ptr = serv;
    reactor->id = reactor_id;
    reactor->wait_exit = 0;
    reactor->max_socket = serv->max_connection;
    reactor->close = Server::close_connection;

    reactor->set_exit_condition(
        SW_REACTOR_EXIT_CONDITION_DEFAULT,
        [thread](swReactor *reactor, int &event_num) -> bool { return reactor->event_num == thread->pipe_num; });

    reactor->default_error_handler = swReactorThread_onClose;

    reactor->set_handler(SW_FD_PIPE | SW_EVENT_READ, swReactorThread_onPipeRead);
    reactor->set_handler(SW_FD_PIPE | SW_EVENT_WRITE, swReactorThread_onPipeWrite);

    // listen UDP port
    if (serv->have_dgram_sock == 1) {
        for (auto ls : serv->ports) {
            if (swSocket_is_stream(ls->type)) {
                continue;
            }
            int server_fd = ls->socket->fd;
            if (server_fd % serv->reactor_num != reactor_id) {
                continue;
            }
            if (ls->type == SW_SOCK_UDP) {
                serv->connection_list[server_fd].info.addr.inet_v4.sin_port = htons(ls->port);
            } else if (ls->type == SW_SOCK_UDP6) {
                serv->connection_list[server_fd].info.addr.inet_v6.sin6_port = htons(ls->port);
            }
            serv->connection_list[server_fd].fd = server_fd;
            serv->connection_list[server_fd].socket_type = ls->type;
            serv->connection_list[server_fd].object = ls;
            ls->thread_id = pthread_self();
            if (reactor->add(reactor, ls->socket, SW_EVENT_READ) < 0) {
                return SW_ERR;
            }
        }
    }

    serv->init_reactor(reactor);

    int max_pipe_fd = serv->get_worker(serv->worker_num - 1)->pipe_master->fd + 2;
    thread->pipe_sockets = (swSocket *) sw_calloc(max_pipe_fd, sizeof(swSocket));
    if (!thread->pipe_sockets) {
        swSysError("calloc(%d, %ld) failed", max_pipe_fd, sizeof(swSocket));
        return SW_ERR;
    }

    for (uint32_t i = 0; i < serv->worker_num; i++) {
        int pipe_fd = serv->workers[i].pipe_master->fd;
        swSocket *socket = &thread->pipe_sockets[pipe_fd];

        socket->fd = pipe_fd;
        socket->fdtype = SW_FD_PIPE;
        socket->buffer_size = UINT_MAX;

        if (i % serv->reactor_num != reactor_id) {
            continue;
        }

        swSocket_set_nonblock(socket);

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
static void swReactorThread_loop(swServer *serv, int reactor_id) {
    SwooleTG.id = reactor_id;
    SwooleTG.type = SW_THREAD_REACTOR;

    SwooleTG.buffer_stack = swString_new(SW_STACK_BUFFER_SIZE);
    if (SwooleTG.buffer_stack == nullptr) {
        return;
    }

    ReactorThread *thread = serv->get_thread(reactor_id);

    swoole_event_init(0);
    swReactor *reactor = SwooleTG.reactor;

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

    if (swReactorThread_init(serv, reactor, reactor_id) < 0) {
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

static void swReactorThread_resume_data_receiving(swTimer *timer, swTimer_node *tnode) {
    swSocket *_socket = (swSocket *) tnode->data;
    swConnection *conn = (swConnection *) _socket->object;

    if (conn->queued_bytes > sw_server()->max_queued_bytes) {
        if (conn->waiting_time != 1024) {
            conn->waiting_time *= 2;
        }
        conn->timer = swoole_timer_add(conn->waiting_time, false, swReactorThread_resume_data_receiving, _socket);
        if (conn->timer) {
            return;
        }
    }

    swReactor_add_read_event(sw_reactor(), _socket);
    conn->timer = nullptr;
}

/**
 * dispatch request data [only data frame]
 */
int Server::dispatch_task(swProtocol *proto, swSocket *_socket, const char *data, uint32_t length) {
    swServer *serv = (swServer *) proto->private_data_2;
    swSendData task;

    swConnection *conn = (swConnection *) _socket->object;

    sw_memset_zero(&task.info, sizeof(task.info));
    task.info.server_fd = conn->server_fd;
    task.info.reactor_id = conn->reactor_id;
    task.info.ext_flags = proto->ext_flags;
    proto->ext_flags = 0;
    task.info.type = SW_SERVER_EVENT_SEND_DATA;
#ifdef SW_BUFFER_RECV_TIME
    task.info.info.time = conn->last_time_usec;
#endif

    swTrace("send string package, size=%ld bytes", (long) length);

    if (serv->stream_socket_file) {
        swStream *stream = swStream_new(serv->stream_socket_file, 0, SW_SOCK_UNIX_STREAM);
        if (stream == nullptr) {
            return SW_ERR;
        }
        stream->response = swReactorThread_onStreamResponse;
        stream->private_data = serv;
        swListenPort *port = serv->get_port_by_fd(conn->fd);
        swStream_set_max_length(stream, port->protocol.package_max_length);

        task.info.fd = conn->session_id;

        if (swStream_send(stream, (char *) &task.info, sizeof(task.info)) < 0) {
        _cancel:
            stream->cancel = 1;
            return SW_ERR;
        }
        if (swStream_send(stream, data, length) < 0) {
            goto _cancel;
        }
        return SW_OK;
    } else {
        task.info.fd = conn->fd;
        task.info.len = length;
        task.data = data;
        if (serv->factory.dispatch(&serv->factory, &task) < 0) {
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
        thread = &(reactor_threads[i]);
        if (thread->notify_pipe) {
            swDataHead ev = {};
            ev.type = SW_SERVER_EVENT_SHUTDOWN;
            if (swSocket_write_blocking(thread->notify_pipe, (void *) &ev, sizeof(ev)) < 0) {
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

        int fd;
        int serv_max_fd;
        int serv_min_fd;
        int checktime;

        SwooleTG.type = SW_THREAD_HEARTBEAT;
        SwooleTG.id = reactor_num;

        while (running) {
            serv_max_fd = get_maxfd();
            serv_min_fd = get_minfd();

            checktime = (int) ::time(nullptr) - heartbeat_idle_time;

            for (fd = serv_min_fd; fd <= serv_max_fd; fd++) {
                swTrace("check fd=%d", fd);
                swConnection *conn = get_connection(fd);
                if (swServer_connection_valid(this, conn)) {
                    if (conn->protect || conn->last_time > checktime) {
                        continue;
                    }
                    swDataHead ev = {};
                    ev.type = SW_SERVER_EVENT_CLOSE_FORCE;
                    // convert fd to session_id, in order to verify the connection before the force close connection
                    ev.fd = conn->session_id;
                    swSocket *_pipe_sock = swServer_get_send_pipe(this, conn->session_id, conn->reactor_id);
                    swSocket_write_blocking(_pipe_sock, (void *) &ev, sizeof(ev));
                }
            }
            sleep(heartbeat_check_interval);
        }
    });
}
