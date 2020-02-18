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
#include "hash.h"
#include "client.h"
#include "websocket.h"

#include <unordered_map>

using std::unordered_map;

static int swReactorThread_loop(swThreadParam *param);
static int swReactorThread_init(swServer *serv, swReactor *reactor, uint16_t reactor_id);
static int swReactorThread_onPipeWrite(swReactor *reactor, swEvent *ev);
static int swReactorThread_onPipeRead(swReactor *reactor, swEvent *ev);
static int swReactorThread_onRead(swReactor *reactor, swEvent *ev);
static int swReactorThread_onWrite(swReactor *reactor, swEvent *ev);
static int swReactorThread_onPacketReceived(swReactor *reactor, swEvent *event);
static int swReactorThread_onClose(swReactor *reactor, swEvent *event);
static void swReactorThread_onStreamResponse(swStream *stream, char *data, uint32_t length);
static int swReactorThread_is_empty(swReactor *reactor);
static void swReactorThread_shutdown(swReactor *reactor);
static void swReactorThread_resume_data_receiving(swTimer *timer, swTimer_node *tnode);

static void swHeartbeatThread_start(swServer *serv);
static void swHeartbeatThread_loop(swThreadParam *param);

#ifdef SW_USE_OPENSSL
static sw_inline int swReactorThread_verify_ssl_state(swReactor *reactor, swListenPort *port, swSocket *_socket)
{
    swServer *serv = (swServer *) reactor->ptr;

    if (_socket->ssl_state == 0 && _socket->ssl)
    {
        int ret = swSSL_accept(_socket);
        if (ret == SW_READY)
        {
            swConnection *conn = (swConnection *) _socket->object;
            conn->ssl_ready = 1;
            if (port->ssl_option.client_cert_file)
            {
                ret = swSSL_get_client_certificate(_socket->ssl, SwooleTG.buffer_stack->str, SwooleTG.buffer_stack->size);
                if (ret < 0)
                {
                    goto _no_client_cert;
                }
                else
                {
                    if (!port->ssl_option.verify_peer || swSSL_verify(_socket, port->ssl_option.allow_self_signed) == SW_OK)
                    {
                        swFactory *factory = &serv->factory;
                        swSendData task;
                        task.info.fd = _socket->fd;
                        task.info.type = SW_SERVER_EVENT_CONNECT;
                        task.info.reactor_id = reactor->id;
                        task.info.len = ret;
                        task.data = SwooleTG.buffer_stack->str;
                        factory->dispatch(factory, &task);
                        goto _delay_receive;
                    }
                    else
                    {
                        return SW_ERR;
                    }
                }
            }
            _no_client_cert:
            if (port->ssl_option.verify_peer)
            {
                return SW_ERR;
            }
            if (serv->onConnect)
            {
                serv->notify(serv, (swConnection *) _socket->object, SW_SERVER_EVENT_CONNECT);
            }
            _delay_receive:
            if (serv->enable_delay_receive)
            {
                _socket->listen_wait = 1;
                return reactor->del(reactor, _socket);
            }
            return SW_OK;
        }
        else if (ret == SW_WAIT)
        {
            return SW_OK;
        }
        else
        {
            return SW_ERR;
        }
    }
    return SW_OK;
}
#endif

static void swReactorThread_onStreamResponse(swStream *stream, char *data, uint32_t length)
{
    swSendData response;
    swDataHead *pkg_info = (swDataHead *) data;
    swServer *serv = (swServer *) stream->private_data;
    swConnection *conn = swServer_connection_verify(serv, pkg_info->fd);
    if (!conn)
    {
        swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SESSION_NOT_EXIST, "connection[fd=%d] does not exists", pkg_info->fd);
        return;
    }
    response.info.fd = conn->session_id;
    response.info.type = pkg_info->type;
    response.info.len = length - sizeof(swDataHead);
    response.data = data + sizeof(swDataHead);
    swServer_master_send(serv, &response);
}

/**
 * for udp
 */
static int swReactorThread_onPacketReceived(swReactor *reactor, swEvent *event)
{
    int fd = event->fd;
    int ret;

    swServer *serv = (swServer *) reactor->ptr;
    swConnection *server_sock = &serv->connection_list[fd];
    swSendData task;
    swDgramPacket *pkt = (swDgramPacket *) SwooleTG.buffer_stack->str;
    swFactory *factory = &serv->factory;

    pkt->socket_addr.len = sizeof(pkt->socket_addr.addr);

    bzero(&task.info, sizeof(task.info));
    task.info.server_fd = fd;
    task.info.reactor_id = SwooleTG.id;
    task.info.type = SW_SERVER_EVENT_SNED_DGRAM;
#ifdef SW_BUFFER_RECV_TIME
    task.info.time = swoole_microtime();
#endif

    int socket_type = server_sock->socket_type;

    _do_recvfrom:
    ret = recvfrom(
        fd, pkt->data, SwooleTG.buffer_stack->size - sizeof(*pkt), 0,
        (struct sockaddr *) &pkt->socket_addr.addr, &pkt->socket_addr.len
    );

    if (ret <= 0)
    {
        if (errno == EAGAIN)
        {
            return SW_OK;
        }
        else
        {
            swSysWarn("recvfrom(%d) failed", fd);
            return ret;
        }
    }

    if (socket_type == SW_SOCK_UDP)
    {
        memcpy(&task.info.fd, &pkt->socket_addr.addr.inet_v4.sin_addr, sizeof(task.info.fd));
    }
    else if (socket_type == SW_SOCK_UDP6)
    {
        memcpy(&task.info.fd, &pkt->socket_addr.addr.inet_v6.sin6_addr, sizeof(task.info.fd));
    }
    else
    {
        task.info.fd = swoole_crc32(pkt->socket_addr.addr.un.sun_path, pkt->socket_addr.len);
    }

    pkt->socket_type = socket_type;
    pkt->length = ret;
    task.info.len = sizeof(*pkt) + ret;
    task.data = (char*) pkt;

    if (factory->dispatch(factory, &task) < 0)
    {
        return SW_ERR;
    }
    else
    {
        goto _do_recvfrom;
    }
}

/**
 * close connection
 */
int swReactorThread_close(swReactor *reactor, swSocket *socket)
{
    swServer *serv = (swServer *) reactor->ptr;
    swConnection *conn = (swConnection *) socket->object;

    if (conn->timer)
    {
        swoole_timer_del(conn->timer);
    }

    if (!socket->removed && reactor->del(reactor, socket) < 0)
    {
        return SW_ERR;
    }

    sw_atomic_fetch_add(&serv->stats->close_count, 1);
    sw_atomic_fetch_sub(&serv->stats->connection_num, 1);

    swTrace("Close Event.fd=%d|from=%d", socket->fd, reactor->id);

#ifdef SW_USE_OPENSSL
    if (conn->socket->ssl)
    {
        swSSL_close(conn->socket);
    }
#endif

    //free the receive memory buffer
    swSocket_free_buffer(conn->socket);

    swListenPort *port = swServer_get_port(serv, socket->fd);
    sw_atomic_fetch_sub(&port->connection_num, 1);

    if (port->open_http_protocol && conn->object)
    {
        swHttpRequest_free(conn);
    }
    if (port->open_redis_protocol && conn->object)
    {
        sw_free(conn->object);
        conn->object = nullptr;
    }

#ifdef SW_USE_SOCKET_LINGER
    if (conn->close_force)
    {
        struct linger linger;
        linger.l_onoff = 1;
        linger.l_linger = 0;
        if (setsockopt(fd, SOL_SOCKET, SO_LINGER, &linger, sizeof(struct linger)) != 0)
        {
            swSysWarn("setsockopt(SO_LINGER) failed");
        }
    }
#endif

    swSession *session = swServer_get_session(serv, conn->session_id);
    session->fd = 0;
    /**
     * reset maxfd, for connection_list
     */
    int fd = socket->fd;
    if (fd == swServer_get_maxfd(serv))
    {
        swServer_lock(serv);
        int find_max_fd = fd - 1;
        swTrace("set_maxfd=%d|close_fd=%d\n", find_max_fd, fd);
        /**
         * Find the new max_fd
         */
        for (; serv->connection_list[find_max_fd].active == 0 && find_max_fd > swServer_get_minfd(serv); find_max_fd--)
        {
            //pass
        }
        swServer_set_maxfd(serv, find_max_fd);
        swServer_unlock(serv);
    }
    bzero(conn, sizeof(swConnection));
    return swReactor_close(reactor, socket);
}

/**
 * close the connection
 */
static int swReactorThread_onClose(swReactor *reactor, swEvent *event)
{
    swServer *serv = (swServer *) reactor->ptr;
    int fd = event->fd;
    swDataHead notify_ev;
    bzero(&notify_ev, sizeof(notify_ev));
    swSocket *socket = event->socket;

    assert(fd % serv->reactor_num == reactor->id);
    assert(fd % serv->reactor_num == SwooleTG.id);

    notify_ev.reactor_id = reactor->id;
    notify_ev.fd = fd;
    notify_ev.type = SW_SERVER_EVENT_CLOSE;

    swTraceLog(SW_TRACE_CLOSE, "client[fd=%d] close the connection", fd);

    swConnection *conn = swServer_connection_get(serv, fd);
    if (conn == NULL || conn->active == 0)
    {
        return SW_ERR;
    }
    else if (serv->disable_notify)
    {
        swReactorThread_close(reactor, socket);
        return SW_OK;
    }
    else if (reactor->del(reactor, socket) == 0)
    {
        if (conn->close_queued)
        {
            swReactorThread_close(reactor, socket);
            return SW_OK;
        }
        else
        {
            conn->peer_closed = 1;
            return serv->factory.notify(&serv->factory, &notify_ev);
        }
    }
    else
    {
        return SW_ERR;
    }
}

static void swReactorThread_shutdown(swReactor *reactor)
{
    swServer *serv = (swServer *) reactor->ptr;
    //stop listen UDP Port
    if (serv->have_dgram_sock == 1)
    {
        swListenPort *ls;
        LL_FOREACH(serv->listen_list, ls)
        {
            if (ls->type == SW_SOCK_UDP || ls->type == SW_SOCK_UDP6 || ls->type == SW_SOCK_UNIX_DGRAM)
            {
                if (ls->socket->fd % serv->reactor_num != reactor->id)
                {
                    continue;
                }
                reactor->del(reactor, ls->socket);
            }
        }
    }

    int fd;
    int serv_max_fd = swServer_get_maxfd(serv);
    int serv_min_fd = swServer_get_minfd(serv);

    for (fd = serv_min_fd; fd <= serv_max_fd; fd++)
    {
        if (fd % serv->reactor_num != reactor->id)
        {
            continue;
        }
        swConnection *conn = swServer_connection_get(serv, fd);
        if (conn && conn->socket && conn->active && !conn->peer_closed && conn->socket->fdtype == SW_FD_SESSION)
        {
            swReactor_remove_read_event(reactor, conn->socket);
        }
    }

    reactor->wait_exit = 1;
}

/**
 * receive data from worker process pipe
 */
static int swReactorThread_onPipeRead(swReactor *reactor, swEvent *ev)
{
    swSendData _send;

    swServer *serv = (swServer *) reactor->ptr;
    swReactorThread *thread = swServer_get_thread(serv, reactor->id);
    swString *package = nullptr;
    swPipeBuffer *resp = serv->pipe_buffers[reactor->id];

#ifdef SW_REACTOR_RECV_AGAIN
    while (1)
#endif
    {
        ssize_t n = read(ev->fd, resp, serv->ipc_max_size);
        if (n > 0)
        {
            //packet chunk
            if (resp->info.flags & SW_EVENT_DATA_CHUNK)
            {
                int worker_id = resp->info.server_fd;
                int key = (ev->fd << 16) + worker_id;
                auto it = thread->send_buffers->find(key);
                if (it == thread->send_buffers->end())
                {
                    package = swString_new(SW_BUFFER_SIZE_BIG);
                    if (package == nullptr)
                    {
                        swSysWarn("get buffer(worker-%d) failed", worker_id);
                        return SW_OK;
                    }
                    else
                    {
                        thread->send_buffers->emplace(std::make_pair(key, package));
                    }
                }
                else
                {
                    package = it->second;
                }
                //merge data to package buffer
                swString_append_ptr(package, resp->data, n - sizeof(resp->info));
                //wait more data
                if (!(resp->info.flags & SW_EVENT_DATA_END))
                {
                    return SW_OK;
                }
                _send.info = resp->info;
                _send.data = package->str;
                _send.info.len = package->length;
                swServer_master_send(serv, &_send);
                swString_free(package);
                thread->send_buffers->erase(key);
            }
            else
            {
                /**
                 * connection incoming
                 */
                if (resp->info.type == SW_SERVER_EVENT_INCOMING)
                {
                    int fd = resp->info.fd;
                    swConnection *conn = swServer_connection_get(serv, fd);
                    if (swServer_connection_incoming(serv, reactor, conn) < 0)
                    {
                        return reactor->close(reactor, conn->socket);
                    }
                }
                /**
                 * server shutdown
                 */
                else if (resp->info.type == SW_SERVER_EVENT_SHUTDOWN)
                {
                    swReactorThread_shutdown(reactor);
                }
                else
                {
                    _send.info = resp->info;
                    _send.data = resp->data;
                    swServer_master_send(serv, &_send);
                }
            }
        }
        else if (errno == EAGAIN)
        {
            return SW_OK;
        }
        else
        {
            swSysWarn("read(worker_pipe) failed");
            return SW_ERR;
        }
    }

    return SW_OK;
}

int swReactorThread_send2worker(swServer *serv, swWorker *worker, void *data, size_t len)
{
    if (SwooleTG.reactor)
    {
        swReactorThread *thread = swServer_get_thread(serv, SwooleTG.id);
        swSocket *socket = &thread->pipe_sockets[worker->pipe_master->fd];
        return swoole_event_write(socket, data, len);
    }
    else
    {
        return swSocket_write_blocking(worker->pipe_master->fd, data, len);
    }
}

/**
 * [ReactorThread] worker pipe can write.
 */
static int swReactorThread_onPipeWrite(swReactor *reactor, swEvent *ev)
{
    int ret;

    swBuffer_chunk *chunk = NULL;
    swEventData *send_data;
    swConnection *conn;
    swServer *serv = (swServer *) reactor->ptr;
    swBuffer *buffer = ev->socket->out_buffer;

    while (!swBuffer_empty(buffer))
    {
        chunk = swBuffer_get_chunk(buffer);
        send_data = (swEventData *) chunk->store.ptr;

        //server active close, discard data.
        if (swEventData_is_stream(send_data->info.type))
        {
            //send_data->info.fd is session_id
            conn = swServer_connection_verify(serv, send_data->info.fd);
            if (conn)
            {
                if (conn->closed)
                {
                    swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SESSION_CLOSED_BY_SERVER, "Session#%d is closed by server", send_data->info.fd);
                    _discard:
                    swBuffer_pop_chunk(buffer, chunk);
                    continue;
                }
            }
            else if (serv->discard_timeout_request)
            {
                swoole_error_log(
                    SW_LOG_WARNING, SW_ERROR_SESSION_DISCARD_TIMEOUT_DATA,
                    "[1] received the wrong data[%d bytes] from socket#%d",
                    send_data->info.len, send_data->info.fd
                );
                goto _discard;
            }
        }

        ret = swSocket_send(ev->socket, chunk->store.ptr, chunk->length, 0);
        if (ret < 0)
        {
            return (swConnection_error(errno) == SW_WAIT) ? SW_OK : SW_ERR;
        }
        else
        {
            swBuffer_pop_chunk(buffer, chunk);
        }
    }

    if (swBuffer_empty(buffer))
    {
        if (swReactor_remove_write_event(reactor, ev->socket) < 0)
        {
            swSysWarn("reactor->set(%d) failed", ev->fd);
        }
    }

    return SW_OK;
}

void swReactorThread_set_protocol(swServer *serv, swReactor *reactor)
{
    //64k packet
    if (serv->have_dgram_sock)
    {
        swString_extend_align(SwooleTG.buffer_stack, SwooleTG.buffer_stack->size * 2);
    }
    //UDP Packet
    swReactor_set_handler(reactor, SW_FD_DGRAM_SERVER, swReactorThread_onPacketReceived);
    //Write
    swReactor_set_handler(reactor, SW_FD_SESSION | SW_EVENT_WRITE, swReactorThread_onWrite);
    //Read
    swReactor_set_handler(reactor, SW_FD_SESSION | SW_EVENT_READ, swReactorThread_onRead);

    swListenPort *ls;
    //listen the all tcp port
    LL_FOREACH(serv->listen_list, ls)
    {
        if (swSocket_is_dgram(ls->type))
        {
            continue;
        }
        swPort_set_protocol(serv, ls);
    }
}

static int swReactorThread_onRead(swReactor *reactor, swEvent *event)
{
    swServer *serv = (swServer *) reactor->ptr;
    swConnection *conn = swServer_connection_get(serv, event->fd);
    /**
     * invalid event
     * The server has been actively closed the connection, the client also initiated off, fd has been reused.
     */
    if (!conn || conn->server_fd == 0)
    {
        return SW_OK;
    }
    swListenPort *port = swServer_get_port(serv, event->fd);
#ifdef SW_USE_OPENSSL
    if (swReactorThread_verify_ssl_state(reactor, port, event->socket) < 0)
    {
        return swReactorThread_close(reactor, event->socket);
    }
#endif

    conn->last_time = serv->gs->now;
#ifdef SW_BUFFER_RECV_TIME
    conn->last_time_usec = swoole_microtime();
#endif

    int retval = port->onRead(reactor, port, event);
    if (serv->factory_mode == SW_MODE_PROCESS && serv->max_queued_bytes && conn->queued_bytes > serv->max_queued_bytes)
    {
        conn->waiting_time = 1;
        conn->timer = swoole_timer_add(conn->waiting_time, false, swReactorThread_resume_data_receiving, event->socket);
        if (conn->timer)
        {
            swReactor_remove_read_event(sw_reactor(), event->socket);
        }
    }
    return retval;
}

static int swReactorThread_onWrite(swReactor *reactor, swEvent *ev)
{
    int ret;
    swServer *serv = (swServer *) reactor->ptr;
    swSocket *socket = ev->socket;
    swBuffer_chunk *chunk;
    int fd = ev->fd;

    if (serv->factory_mode == SW_MODE_PROCESS)
    {
        assert(fd % serv->reactor_num == reactor->id);
        assert(fd % serv->reactor_num == SwooleTG.id);
    }

    swConnection *conn = swServer_connection_get(serv, fd);
    if (conn == NULL || conn->active == 0)
    {
        return SW_ERR;
    }

    swTraceLog(SW_TRACE_REACTOR, "fd=%d, conn->close_notify=%d, serv->disable_notify=%d, conn->close_force=%d",
            fd, conn->close_notify, serv->disable_notify, conn->close_force);

    if (conn->close_notify)
    {
#ifdef SW_USE_OPENSSL
        if (conn->socket->ssl && conn->socket->ssl_state != SW_SSL_STATE_READY)
        {
            return swReactorThread_close(reactor, socket);
        }
#endif
        serv->notify(serv, conn, SW_SERVER_EVENT_CLOSE);
        conn->close_notify = 0;
        return SW_OK;
    }
    else if (serv->disable_notify && conn->close_force)
    {
        return swReactorThread_close(reactor, socket);
    }

    while (!swBuffer_empty(conn->socket->out_buffer))
    {
        chunk = swBuffer_get_chunk(conn->socket->out_buffer);
        if (chunk->type == SW_CHUNK_CLOSE)
        {
            _close_fd:
            reactor->close(reactor, socket);
            return SW_OK;
        }
        else if (chunk->type == SW_CHUNK_SENDFILE)
        {
            ret = swSocket_onSendfile(socket, chunk);
        }
        else
        {
            ret = swSocket_buffer_send(socket);
        }

        if (ret < 0)
        {
            if (conn->socket->close_wait)
            {
                conn->close_errno = errno;
                goto _close_fd;
            }
            else if (conn->socket->send_wait)
            {
                break;
            }
        }
    }

    if (conn->overflow && conn->socket->out_buffer->length < conn->socket->buffer_size)
    {
        conn->overflow = 0;
    }

    if (serv->onBufferEmpty && conn->high_watermark)
    {
        swListenPort *port = swServer_get_port(serv, fd);
        if (conn->socket->out_buffer->length <= port->buffer_low_watermark)
        {
            conn->high_watermark = 0;
            serv->notify(serv, conn, SW_SERVER_EVENT_BUFFER_EMPTY);
        }
    }

    //remove EPOLLOUT event
    if (!conn->peer_closed && swBuffer_empty(conn->socket->out_buffer))
    {
        reactor->set(reactor, socket, SW_EVENT_READ);
    }
    return SW_OK;
}

int swReactorThread_create(swServer *serv)
{
    int ret = 0;
    /**
     * init reactor thread pool
     */
    serv->reactor_threads = (swReactorThread *) SwooleG.memory_pool->alloc(SwooleG.memory_pool, (serv->reactor_num * sizeof(swReactorThread)));
    if (serv->reactor_threads == NULL)
    {
        swError("calloc[reactor_threads] fail.alloc_size=%d", (int )(serv->reactor_num * sizeof(swReactorThread)));
        return SW_ERR;
    }
    /**
     * alloc the memory for connection_list
     */
    serv->connection_list = (swConnection *) sw_shm_calloc(serv->max_connection, sizeof(swConnection));
    if (serv->connection_list == NULL)
    {
        swError("calloc[1] failed");
        return SW_ERR;
    }
    if (serv->worker_num < 1)
    {
        swError("Fatal Error: serv->worker_num < 1");
        return SW_ERR;
    }
    ret = swFactoryProcess_create(&(serv->factory), serv->worker_num);
    if (ret < 0)
    {
        swError("create factory failed");
        return SW_ERR;
    }
    return SW_OK;
}

/**
 * [master]
 */
int swReactorThread_start(swServer *serv)
{
    if (swoole_event_init() < 0)
    {
        return SW_ERR;
    }

    swReactor *reactor = SwooleTG.reactor;

#ifdef HAVE_SIGNALFD
    if (SwooleG.use_signalfd)
    {
        swSignalfd_setup(reactor);
    }
#endif

    //set listen socket options
    swListenPort *ls;
    LL_FOREACH(serv->listen_list, ls)
    {
        if (swSocket_is_dgram(ls->type))
        {
            continue;
        }
        if (swPort_listen(ls) < 0)
        {
            _failed:
            reactor->free(reactor);
            SwooleTG.reactor = nullptr;
            sw_free(reactor);
            return SW_ERR;
        }
    }

    if (serv->stream_socket)
    {
        swSocket_free(serv->stream_socket);
        serv->stream_socket = nullptr;
    }

    /**
     * create reactor thread
     */
    swThreadParam *param;
    swReactorThread *thread;
    pthread_t pidt;
    int i;

    swServer_store_listen_socket(serv);

#ifdef HAVE_REUSEPORT
    SwooleG.reuse_port = 0;
#endif

    LL_FOREACH(serv->listen_list, ls)
    {
        if (swSocket_is_dgram(ls->type))
        {
            continue;
        }
        reactor->add(reactor, ls->socket, SW_EVENT_READ);
    }

    if (serv->single_thread)
    {
        swReactorThread_init(serv, reactor, 0);
        goto _init_master_thread;
    }
    /**
     * multi-threads
     */
    else
    {
        /**
         * set a special id
         */
        reactor->id = serv->reactor_num;
        SwooleTG.id = serv->reactor_num;
    }

#ifdef HAVE_PTHREAD_BARRIER
    //init thread barrier
    pthread_barrier_init(&serv->barrier, NULL, serv->reactor_num + 1);
#endif

    //create reactor thread
    for (i = 0; i < serv->reactor_num; i++)
    {
        thread = &(serv->reactor_threads[i]);
        param = (swThreadParam *) SwooleG.memory_pool->alloc(SwooleG.memory_pool, sizeof(swThreadParam));
        if (param == NULL)
        {
            swError("malloc failed");
            goto _failed;
        }

        param->object = serv;
        param->pti = i;

        if (pthread_create(&pidt, NULL, (void * (*)(void *)) swReactorThread_loop, (void *) param) < 0)
        {
            swSysError("pthread_create[tcp_reactor] failed");
        }
        thread->thread_id = pidt;
    }
#ifdef HAVE_PTHREAD_BARRIER
    //wait reactor thread
    pthread_barrier_wait(&serv->barrier);
#else
    SW_START_SLEEP;
#endif

    _init_master_thread:

    /**
     * heartbeat thread
     */
    if (serv->heartbeat_check_interval >= 1 && serv->heartbeat_check_interval <= serv->heartbeat_idle_time)
    {
        swTrace("hb timer start, time: %d live time:%d", serv->heartbeat_check_interval, serv->heartbeat_idle_time);
        swHeartbeatThread_start(serv);
    }

    SwooleTG.type = SW_THREAD_MASTER;
    SwooleTG.update_time = 1;
    SwooleTG.reactor = reactor;

    if (SwooleTG.timer && SwooleTG.timer->reactor == nullptr)
    {
        swTimer_reinit(SwooleTG.timer, reactor);
    }

    SwooleG.pid = getpid();
    SwooleG.process_type = SW_PROCESS_MASTER;

    reactor->ptr = serv;
    swReactor_set_handler(reactor, SW_FD_STREAM_SERVER, swServer_master_onAccept);

    if (serv->hooks[SW_SERVER_HOOK_MASTER_START])
    {
        swServer_call_hook(serv, SW_SERVER_HOOK_MASTER_START, serv);
    }

    /**
     * 1 second timer, update serv->gs->now
     */
    if ((serv->master_timer = swoole_timer_add(1000, SW_TRUE, swServer_master_onTimer, serv)) == NULL)
    {
        goto _failed;
    }

    if (serv->onStart)
    {
        serv->onStart(serv);
    }

    return swoole_event_wait();
}

static int swReactorThread_init(swServer *serv, swReactor *reactor, uint16_t reactor_id)
{
    swReactorThread *thread = swServer_get_thread(serv, reactor_id);

    reactor->ptr = serv;
    reactor->id = reactor_id;
    reactor->wait_exit = 0;
    reactor->max_socket = serv->max_connection;
    reactor->close = swReactorThread_close;
    reactor->is_empty = swReactorThread_is_empty;

    reactor->default_error_handler = swReactorThread_onClose;

    swReactor_set_handler(reactor, SW_FD_PIPE | SW_EVENT_READ, swReactorThread_onPipeRead);
    swReactor_set_handler(reactor, SW_FD_PIPE | SW_EVENT_WRITE, swReactorThread_onPipeWrite);

    //listen UDP port
    if (serv->have_dgram_sock == 1)
    {
        swListenPort *ls;
        LL_FOREACH(serv->listen_list, ls)
        {
            if (!swSocket_is_dgram(ls->type))
            {
                continue;
            }
            int server_fd = ls->socket->fd;
            if (server_fd % serv->reactor_num != reactor_id)
            {
                continue;
            }
            if (ls->type == SW_SOCK_UDP)
            {
                serv->connection_list[server_fd].info.addr.inet_v4.sin_port = htons(ls->port);
            }
            else if (ls->type == SW_SOCK_UDP6)
            {
                serv->connection_list[server_fd].info.addr.inet_v6.sin6_port = htons(ls->port);
            }
            serv->connection_list[server_fd].fd = server_fd;
            serv->connection_list[server_fd].socket_type = ls->type;
            serv->connection_list[server_fd].object = ls;
            ls->thread_id = pthread_self();
            if (reactor->add(reactor, ls->socket, SW_EVENT_READ) < 0)
            {
                return SW_ERR;
            }
        }
    }

    //set protocol function point
    swReactorThread_set_protocol(serv, reactor);

    thread->send_buffers = new unordered_map<int, swString *>;

    int max_pipe_fd = swServer_get_worker(serv, serv->worker_num - 1)->pipe_master->fd + 2;
    thread->pipe_sockets = (swSocket *) sw_calloc(max_pipe_fd, sizeof(swSocket));
    if (!thread->pipe_sockets)
    {
        swSysError("calloc(%d, %ld) failed", max_pipe_fd, sizeof(swSocket));
        return SW_ERR;
    }

    for (uint32_t i = 0; i < serv->worker_num; i++)
    {
        int pipe_fd = serv->workers[i].pipe_master->fd;
        swSocket *socket = &thread->pipe_sockets[pipe_fd];

        socket->fd = pipe_fd;
        socket->fdtype = SW_FD_PIPE;
        socket->buffer_size = UINT_MAX;

        if (i % serv->reactor_num != reactor_id)
        {
            continue;
        }

        swSocket_set_nonblock(socket);

        if (reactor->add(reactor, socket, SW_EVENT_READ) < 0)
        {
            return SW_ERR;
        }
        if (thread->notify_pipe == 0)
        {
            thread->notify_pipe = serv->workers[i].pipe_worker->fd;
        }
        thread->pipe_num++;
    }

    return SW_OK;
}

static int swReactorThread_is_empty(swReactor *reactor)
{
    if (reactor->defer_tasks)
    {
        return SW_FALSE;
    }

    swServer *serv = (swServer *) reactor->ptr;
    swReactorThread *thread = swServer_get_thread(serv, reactor->id);
    return reactor->event_num == thread->pipe_num;
}

/**
 * ReactorThread main Loop
 */
static int swReactorThread_loop(swThreadParam *param)
{
    swServer *serv = (swServer *) param->object;
    int reactor_id = param->pti;
    int ret;

    SwooleTG.id = reactor_id;
    SwooleTG.type = SW_THREAD_REACTOR;

    SwooleTG.buffer_stack = swString_new(SW_STACK_BUFFER_SIZE);
    if (SwooleTG.buffer_stack == NULL)
    {
        return SW_ERR;
    }

    swReactorThread *thread = swServer_get_thread(serv, reactor_id);
    swReactor *reactor = &thread->reactor;

    SwooleTG.reactor = reactor;

#ifdef HAVE_CPU_AFFINITY
    //cpu affinity setting
    if (serv->open_cpu_affinity)
    {
        cpu_set_t cpu_set;
        CPU_ZERO(&cpu_set);

        if (serv->cpu_affinity_available_num)
        {
            CPU_SET(serv->cpu_affinity_available[reactor_id % serv->cpu_affinity_available_num], &cpu_set);
        }
        else
        {
            CPU_SET(reactor_id % SW_CPU_NUM, &cpu_set);
        }

        if (0 != pthread_setaffinity_np(pthread_self(), sizeof(cpu_set), &cpu_set))
        {
            swSysWarn("pthread_setaffinity_np() failed");
        }
    }
#endif

    ret = swReactor_create(reactor, SW_REACTOR_MAXEVENTS);
    if (ret < 0)
    {
        return SW_ERR;
    }

    swSignal_none();

    if (swReactorThread_init(serv, reactor, reactor_id) < 0)
    {
        return SW_ERR;
    }

    //wait other thread
#ifdef HAVE_PTHREAD_BARRIER
    pthread_barrier_wait(&serv->barrier);
#else
    SW_START_SLEEP;
#endif
    //main loop
    reactor->wait(reactor, NULL);
    //shutdown
    reactor->free(reactor);

    SwooleTG.reactor = nullptr;

    for (auto it = thread->send_buffers->begin(); it != thread->send_buffers->end(); it++)
    {
        swString_free(it->second);
    }
    delete thread->send_buffers;

    swString_free(SwooleTG.buffer_stack);
    pthread_exit(0);
    return SW_OK;
}

static void swReactorThread_resume_data_receiving(swTimer *timer, swTimer_node *tnode)
{
    swSocket *_socket = (swSocket *) tnode->data;
    swConnection *conn = (swConnection *) _socket->object;

    if (conn->queued_bytes > sw_server()->max_queued_bytes)
    {
        if (conn->waiting_time != 1024)
        {
            conn->waiting_time *= 2;
        }
        conn->timer = swoole_timer_add(conn->waiting_time, false, swReactorThread_resume_data_receiving, _socket);
        if (conn->timer)
        {
            return;
        }
    }

    swReactor_add_read_event(sw_reactor(), _socket);
    conn->timer = nullptr;
}

/**
 * dispatch request data [only data frame]
 */
int swReactorThread_dispatch(swProtocol *proto, swSocket *_socket, char *data, uint32_t length)
{
    swServer *serv = (swServer *) proto->private_data_2;
    swSendData task;

    swConnection *conn = (swConnection *) _socket->object;

    bzero(&task.info, sizeof(task.info));
    task.info.server_fd = conn->server_fd;
    task.info.reactor_id = conn->reactor_id;
    task.info.ext_flags = proto->ext_flags;
    proto->ext_flags = 0;
    task.info.type = SW_SERVER_EVENT_SEND_DATA;
#ifdef SW_BUFFER_RECV_TIME
    task.info.info.time = conn->last_time_usec;
#endif

    swTrace("send string package, size=%ld bytes", (long)length);

    if (serv->stream_socket_file)
    {
        swStream *stream = swStream_new(serv->stream_socket_file, 0, SW_SOCK_UNIX_STREAM);
        if (stream == NULL)
        {
            return SW_ERR;
        }
        stream->response = swReactorThread_onStreamResponse;
        stream->private_data = serv;
        swListenPort *port = swServer_get_port(serv, conn->fd);
        swStream_set_max_length(stream, port->protocol.package_max_length);

        task.info.fd = conn->session_id;

        if (swStream_send(stream, (char*) &task.info, sizeof(task.info)) < 0)
        {
            _cancel:
            stream->cancel = 1;
            return SW_ERR;
        }
        if (swStream_send(stream, data, length) < 0)
        {
            goto _cancel;
        }
        return SW_OK;
    }
    else
    {
        task.info.fd = conn->fd;
        task.info.len = length;
        task.data = data;
        if (serv->factory.dispatch(&serv->factory, &task) < 0)
        {
            return SW_ERR;
        }
        if (serv->max_queued_bytes && length > 0)
        {
            sw_atomic_fetch_add(&conn->queued_bytes, length);
            swTraceLog(SW_TRACE_SERVER, "[Master] len=%d, qb=%d\n", length, conn->queued_bytes);
        }
        return SW_OK;
    }
}

void swReactorThread_join(swServer *serv)
{
    if (serv->single_thread)
    {
        return;
    }
    swReactorThread *thread;
    /**
     * Shutdown heartbeat thread
     */
    if (serv->heartbeat_pidt)
    {
        swTraceLog(SW_TRACE_SERVER, "terminate heartbeat thread");
        if (pthread_cancel(serv->heartbeat_pidt) < 0)
        {
            swSysWarn("pthread_cancel(%ld) failed", (ulong_t )serv->heartbeat_pidt);
        }
        //wait thread
        if (pthread_join(serv->heartbeat_pidt, NULL) < 0)
        {
            swSysWarn("pthread_join(%ld) failed", (ulong_t )serv->heartbeat_pidt);
        }
    }
    /**
     * kill threads
     */
    for (int i = 0; i < serv->reactor_num; i++)
    {
        thread = &(serv->reactor_threads[i]);
        if (thread->notify_pipe)
        {
            swDataHead ev = {};
            ev.type = SW_SERVER_EVENT_SHUTDOWN;
            if (swSocket_write_blocking(thread->notify_pipe, (void *) &ev, sizeof(ev)) < 0)
            {
                goto _cancel;
            }
        }
        else
        {
            _cancel: if (pthread_cancel(thread->thread_id) < 0)
            {
                swSysWarn("pthread_cancel(%ld) failed", (long ) thread->thread_id);
            }
        }
        //wait thread
        if (pthread_join(thread->thread_id, NULL) != 0)
        {
            swSysWarn("pthread_join(%ld) failed", (long ) thread->thread_id);
        }
    }
}

void swReactorThread_free(swServer *serv)
{
    serv->factory.free(&serv->factory);
    sw_shm_free(serv->connection_list);
}

static void swHeartbeatThread_start(swServer *serv)
{
    pthread_t thread_id;
    swThreadParam *param = (swThreadParam *) SwooleG.memory_pool->alloc(SwooleG.memory_pool, sizeof(swThreadParam));
    if (param == NULL)
    {
        swError("heartbeat_param malloc failed");
        return;
    }

    param->object = serv;
    param->pti = 0;

    if (pthread_create(&thread_id, NULL, (void * (*)(void *)) swHeartbeatThread_loop, (void *) param) < 0)
    {
        swWarn("pthread_create[hbcheck] failed");
    }
    serv->heartbeat_pidt = thread_id;
}

static void swHeartbeatThread_loop(swThreadParam *param)
{
    swSignal_none();

    swServer *serv = (swServer *) param->object;
    swConnection *conn;
    swReactor *reactor;

    int fd;
    int serv_max_fd;
    int serv_min_fd;
    int checktime;

    SwooleTG.type = SW_THREAD_HEARTBEAT;
    SwooleTG.id = serv->reactor_num;

    while (SwooleG.running)
    {
        serv_max_fd = swServer_get_maxfd(serv);
        serv_min_fd = swServer_get_minfd(serv);

        checktime = (int) time(NULL) - serv->heartbeat_idle_time;

        for (fd = serv_min_fd; fd <= serv_max_fd; fd++)
        {
            swTrace("check fd=%d", fd);
            conn = swServer_connection_get(serv, fd);

            if (conn && conn->socket && conn->active == 1 && conn->closed == 0 && conn->socket->fdtype == SW_FD_SESSION)
            {
                if (conn->protect || conn->last_time > checktime)
                {
                    continue;
                }

                conn->close_force = 1;
                conn->close_notify = 1;

                if (serv->single_thread)
                {
                    reactor = SwooleTG.reactor;
                }
                else
                {
                    reactor = &serv->reactor_threads[conn->reactor_id].reactor;
                }
                //notify to reactor thread
                if (conn->peer_closed)
                {
                    serv->notify(serv, conn, SW_SERVER_EVENT_CLOSE);
                }
                else
                {
                    reactor->set(reactor, conn->socket, SW_EVENT_WRITE);
                }
            }
        }
        sleep(serv->heartbeat_check_interval);
    }
    pthread_exit(0);
}
