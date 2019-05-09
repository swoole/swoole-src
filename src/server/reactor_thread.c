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

#include "swoole.h"
#include "server.h"
#include "hash.h"
#include "client.h"
#include "websocket.h"

static int swReactorThread_loop(swThreadParam *param);
static int swReactorThread_init_reactor(swServer *serv, swReactor *reactor, uint16_t reactor_id);
static int swReactorThread_onPipeWrite(swReactor *reactor, swEvent *ev);
static int swReactorThread_onPipeReceive(swReactor *reactor, swEvent *ev);
static int swReactorThread_onRead(swReactor *reactor, swEvent *ev);
static int swReactorThread_onWrite(swReactor *reactor, swEvent *ev);
static int swReactorThread_onPackage(swReactor *reactor, swEvent *event);
static int swReactorThread_onClose(swReactor *reactor, swEvent *event);
static void swReactorThread_onStreamResponse(swStream *stream, char *data, uint32_t length);

static void swHeartbeatThread_start(swServer *serv);
static void swHeartbeatThread_loop(swThreadParam *param);

#ifdef SW_USE_OPENSSL
static sw_inline int swReactorThread_verify_ssl_state(swReactor *reactor, swListenPort *port, swConnection *conn)
{
    swServer *serv = reactor->ptr;
    if (conn->ssl_state == 0 && conn->ssl)
    {
        int ret = swSSL_accept(conn);
        if (ret == SW_READY)
        {
            if (port->ssl_option.client_cert_file)
            {
                ret = swSSL_get_client_certificate(conn->ssl, SwooleTG.buffer_stack->str, SwooleTG.buffer_stack->size);
                if (ret < 0)
                {
                    goto no_client_cert;
                }
                else
                {
                    if (!port->ssl_option.verify_peer || swSSL_verify(conn, port->ssl_option.allow_self_signed) == SW_OK)
                    {
                        swFactory *factory = &serv->factory;
                        swSendData task;
                        task.info.fd = conn->fd;
                        task.info.type = SW_EVENT_CONNECT;
                        task.info.from_id = conn->from_id;
                        task.info.len = ret;
                        task.data = SwooleTG.buffer_stack->str;
                        factory->dispatch(factory, &task);
                        goto delay_receive;
                    }
                    else
                    {
                        return SW_ERR;
                    }
                }
            }
            no_client_cert:
            if (port->ssl_option.verify_peer)
            {
                return SW_ERR;
            }
            if (serv->onConnect)
            {
                serv->notify(serv, conn, SW_EVENT_CONNECT);
            }
            delay_receive:
            if (serv->enable_delay_receive)
            {
                conn->listen_wait = 1;
                return reactor->del(reactor, conn->fd);
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
    swConnection *conn = swServer_connection_verify(SwooleG.serv, pkg_info->fd);
    if (!conn)
    {
        swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SESSION_NOT_EXIST, "connection[fd=%d] does not exists", pkg_info->fd);
        return;
    }
    response.info.fd = conn->session_id;
    response.info.type = pkg_info->type;
    response.info.len = length - sizeof(swDataHead);
    response.data = data + sizeof(swDataHead);
    swServer_master_send(SwooleG.serv, &response);
}

/**
 * for udp
 */
static int swReactorThread_onPackage(swReactor *reactor, swEvent *event)
{
    int fd = event->fd;
    int ret;

    swServer *serv = SwooleG.serv;
    swConnection *server_sock = &serv->connection_list[fd];
    swSendData task;
    swDgramPacket *pkt = (swDgramPacket *) SwooleTG.buffer_stack->str;
    swFactory *factory = &serv->factory;

    pkt->info.len = sizeof(pkt->info.addr);

    bzero(&task.info, sizeof(task.info));
    task.info.from_fd = fd;
    task.info.from_id = SwooleTG.id;
#ifdef SW_BUFFER_RECV_TIME
    task.info.time = swoole_microtime();
#endif

    int socket_type = server_sock->socket_type;
    switch(socket_type)
    {
    case SW_SOCK_UDP6:
        task.info.type = SW_EVENT_UDP6;
        break;
    case SW_SOCK_UNIX_DGRAM:
        task.info.type = SW_EVENT_UNIX_DGRAM;
        break;
    case SW_SOCK_UDP:
    default:
        task.info.type = SW_EVENT_UDP;
        break;
    }

    do_recvfrom: ret = recvfrom(fd, pkt->data, SwooleTG.buffer_stack->size - sizeof(*pkt), 0,
            (struct sockaddr *) &pkt->info.addr, &pkt->info.len);

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

    //IPv4
    if (socket_type == SW_SOCK_UDP)
    {
        memcpy(&task.info.fd, &pkt->info.addr.inet_v4.sin_addr, sizeof(task.info.fd));
    }
    //IPv6
    else if (socket_type == SW_SOCK_UDP6)
    {
        memcpy(&task.info.fd, &pkt->info.addr.inet_v6.sin6_addr, sizeof(task.info.fd));
    }
    else
    {
        task.info.fd = swoole_crc32(pkt->info.addr.un.sun_path, pkt->info.len);
    }

    pkt->length = ret;
    task.info.len = sizeof(*pkt) + ret;
    task.data = (char*) pkt;

    if (factory->dispatch(factory, &task) < 0)
    {
        return SW_ERR;
    }
    else
    {
        goto do_recvfrom;
    }
}

/**
 * close connection
 */
int swReactorThread_close(swReactor *reactor, int fd)
{
    swServer *serv = (swServer *) reactor->ptr;
    swConnection *conn = swServer_connection_get(serv, fd);
    if (conn == NULL)
    {
        swWarn("[Reactor]connection not found. fd=%d|max_fd=%d", fd, swServer_get_maxfd(serv));
        return SW_ERR;
    }

    if (serv->factory_mode == SW_MODE_PROCESS)
    {
        assert(fd % serv->reactor_num == reactor->id);
        assert(fd % serv->reactor_num == SwooleTG.id);
    }

    if (conn->removed == 0 && reactor->del(reactor, fd) < 0)
    {
        return SW_ERR;
    }

    sw_atomic_fetch_add(&serv->stats->close_count, 1);
    sw_atomic_fetch_sub(&serv->stats->connection_num, 1);

    swTrace("Close Event.fd=%d|from=%d", fd, reactor->id);

#ifdef SW_USE_OPENSSL
    if (conn->ssl)
    {
        swSSL_close(conn);
    }
#endif

    //free the receive memory buffer
    swServer_free_buffer(serv, fd);

    swListenPort *port = swServer_get_port(serv, fd);
    sw_atomic_fetch_sub(&port->connection_num, 1);

    if (port->open_http_protocol && conn->object)
    {
        swHttpRequest_free(conn);
    }
    if (port->open_redis_protocol && conn->object)
    {
        sw_free(conn->object);
        conn->object = NULL;
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
    if (fd == swServer_get_maxfd(serv))
    {
        SwooleGS->lock.lock(&SwooleGS->lock);
        int find_max_fd = fd - 1;
        swTrace("set_maxfd=%d|close_fd=%d\n", find_max_fd, fd);
        /**
         * Find the new max_fd
         */
        for (; serv->connection_list[find_max_fd].active == 0 && find_max_fd > swServer_get_minfd(serv); find_max_fd--)
            ;
        swServer_set_maxfd(serv, find_max_fd);
        SwooleGS->lock.unlock(&SwooleGS->lock);
    }

    return swReactor_close(reactor, fd);
}

/**
 * close the connection
 */
static int swReactorThread_onClose(swReactor *reactor, swEvent *event)
{
    swServer *serv = reactor->ptr;
    int fd = event->fd;
    swDataHead notify_ev;
    bzero(&notify_ev, sizeof(notify_ev));

    assert(fd % serv->reactor_num == reactor->id);
    assert(fd % serv->reactor_num == SwooleTG.id);

    notify_ev.from_id = reactor->id;
    notify_ev.fd = fd;
    notify_ev.type = SW_EVENT_CLOSE;

    swTraceLog(SW_TRACE_CLOSE, "client[fd=%d] close the connection", fd);

    swConnection *conn = swServer_connection_get(serv, fd);
    if (conn == NULL || conn->active == 0)
    {
        return SW_ERR;
    }
    else if (serv->disable_notify)
    {
        swReactorThread_close(reactor, fd);
        return SW_OK;
    }
    else if (reactor->del(reactor, fd) == 0)
    {
        if (conn->close_queued)
        {
            swReactorThread_close(reactor, fd);
            return SW_OK;
        }
        else
        {
            return serv->factory.notify(&serv->factory, &notify_ev);
        }
    }
    else
    {
        return SW_ERR;
    }
}

/**
 * receive data from worker process pipe
 */
static int swReactorThread_onPipeReceive(swReactor *reactor, swEvent *ev)
{
    int n;
    swSendData _send;

    swServer *serv = reactor->ptr;
    swPackage_response pkg_resp;
    swWorker *worker;
    swPipeBuffer *resp = serv->pipe_buffers[reactor->id];

#ifdef SW_REACTOR_RECV_AGAIN
    while (1)
#endif
    {
        n = read(ev->fd, resp, serv->ipc_max_size);
        if (n > 0)
        {
            memcpy(&_send.info, &resp->info, sizeof(_send.info));
            //pipe data
            if (_send.info.from_fd == SW_RESPONSE_SMALL)
            {
                _send.data = resp->data;
                _send.info.len = resp->info.len;
                swServer_master_send(serv, &_send);
            }
            //use send shm
            else if (_send.info.from_fd == SW_RESPONSE_SHM)
            {
                memcpy(&pkg_resp, resp->data, sizeof(pkg_resp));
                worker = swServer_get_worker(serv, pkg_resp.worker_id);

                _send.data = worker->send_shm;
                _send.info.len = pkg_resp.length;

#if 0
                struct
                {
                    uint32_t worker;
                    uint32_t index;
                    uint32_t serid;
                } pkg_header;

                memcpy(&pkg_header, _send.data + 4, sizeof(pkg_header));
                swWarn("fd=%d, worker=%d, index=%d, serid=%d", _send.info.fd, pkg_header.worker, pkg_header.index, pkg_header.serid);
#endif
                swServer_master_send(serv, &_send);
                worker->lock.unlock(&worker->lock);
            }
            //use tmp file
            else if (_send.info.from_fd == SW_RESPONSE_TMPFILE)
            {
                swString *data = swTaskWorker_large_unpack((swEventData *) resp);
                if (data == NULL)
                {
                    return SW_ERR;
                }
                _send.data = data->str;
                _send.info.len = data->length;
                swServer_master_send(serv, &_send);
            }
            //reactor thread exit
            else if (_send.info.from_fd == SW_RESPONSE_EXIT)
            {
                reactor->running = 0;
                return SW_OK;
            }
            //will never be here
            else
            {
                abort();
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

int swReactorThread_send2worker(swServer *serv, swWorker *worker, void *data, int len)
{
    int ret = -1;

    //reactor thread
    if (SwooleTG.type == SW_THREAD_REACTOR)
    {
        int pipe_fd = worker->pipe_master;
        int thread_id = serv->connection_list[pipe_fd].from_id;
        swReactorThread *thread = swServer_get_thread(serv, thread_id);
        swLock *lock = serv->connection_list[pipe_fd].object;

        //lock thread
        lock->lock(lock);

        swBuffer *buffer = serv->connection_list[pipe_fd].in_buffer;
        if (swBuffer_empty(buffer))
        {
            ret = write(pipe_fd, (void *) data, len);
            if (ret < 0 && swConnection_error(errno) == SW_WAIT)
            {
                if (thread->reactor.set(&thread->reactor, pipe_fd, SW_FD_PIPE | SW_EVENT_READ | SW_EVENT_WRITE) < 0)
                {
                    swSysWarn("reactor->set(%d, PIPE | READ | WRITE) failed", pipe_fd);
                }
                goto append_pipe_buffer;
            }
        }
        else
        {
            append_pipe_buffer:
            if (swBuffer_append(buffer, data, len) < 0)
            {
                swWarn("append to pipe_buffer failed");
                ret = SW_ERR;
            }
            else
            {
                ret = SW_OK;
            }
        }
        //release thread lock
        lock->unlock(lock);
    }
    //master/udp thread
    else
    {
        int pipe_fd = worker->pipe_master;
        ret = swSocket_write_blocking(pipe_fd, data, len);
    }
    return ret;
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
    swServer *serv = reactor->ptr;
    swBuffer *buffer = serv->connection_list[ev->fd].in_buffer;
    swLock *lock = serv->connection_list[ev->fd].object;

    //lock thread
    lock->lock(lock);

    while (!swBuffer_empty(buffer))
    {
        chunk = swBuffer_get_chunk(buffer);
        send_data = chunk->store.ptr;

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
                    _discard: swBuffer_pop_chunk(buffer, chunk);
                    continue;
                }
            }
            else if (serv->discard_timeout_request)
            {
                swoole_error_log(SW_LOG_WARNING, SW_ERROR_SESSION_DISCARD_TIMEOUT_DATA,
                        "[1]received the wrong data[%d bytes] from socket#%d", send_data->info.len, send_data->info.fd);
                goto _discard;
            }
        }

        ret = write(ev->fd, chunk->store.ptr, chunk->length);
        if (ret < 0)
        {
            //release lock
            lock->unlock(lock);
            return (swConnection_error(errno) == SW_WAIT) ? SW_OK : SW_ERR;
        }
        else
        {
            swBuffer_pop_chunk(buffer, chunk);
        }
    }

    //remove EPOLLOUT event
    if (swBuffer_empty(buffer))
    {
        if (serv->connection_list[ev->fd].from_id == SwooleTG.id)
        {
            ret = reactor->set(reactor, ev->fd, SW_FD_PIPE | SW_EVENT_READ);
        }
        else
        {
            ret = reactor->del(reactor, ev->fd);
        }
        if (ret < 0)
        {
            swSysWarn("reactor->set(%d) failed", ev->fd);
        }
    }

    //release lock
    lock->unlock(lock);

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
    reactor->setHandle(reactor, SW_FD_UDP, swReactorThread_onPackage);
    //Write
    reactor->setHandle(reactor, SW_FD_TCP | SW_EVENT_WRITE, swReactorThread_onWrite);
    //Read
    reactor->setHandle(reactor, SW_FD_TCP | SW_EVENT_READ, swReactorThread_onRead);

    swListenPort *ls;
    //listen the all tcp port
    LL_FOREACH(serv->listen_list, ls)
    {
        if (swSocket_is_dgram(ls->type))
        {
            continue;
        }
        swPort_set_protocol(ls);
    }
}

static int swReactorThread_onRead(swReactor *reactor, swEvent *event)
{
    swServer *serv = reactor->ptr;
    /**
     * invalid event
     * The server has been actively closed the connection, the client also initiated off, fd has been reused.
     */
    if (event->socket->from_fd == 0)
    {
        return SW_OK;
    }
    swListenPort *port = swServer_get_port(serv, event->fd);
#ifdef SW_USE_OPENSSL
    if (swReactorThread_verify_ssl_state(reactor, port, event->socket) < 0)
    {
        return swReactorThread_close(reactor, event->fd);
    }
#endif

    event->socket->last_time = serv->gs->now;
#ifdef SW_BUFFER_RECV_TIME
    event->socket->last_time_usec = swoole_microtime();
#endif

    return port->onRead(reactor, port, event);
}

static int swReactorThread_onWrite(swReactor *reactor, swEvent *ev)
{
    int ret;
    swServer *serv = (swServer *) reactor->ptr;
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

    swTraceLog(SW_TRACE_REACTOR, "fd=%d, conn->connect_notify=%d, conn->close_notify=%d, serv->disable_notify=%d, conn->close_force=%d",
            fd, conn->connect_notify, conn->close_notify, serv->disable_notify, conn->close_force);

    if (conn->connect_notify)
    {
        conn->connect_notify = 0;
#ifdef SW_USE_OPENSSL
        if (conn->ssl)
        {
            goto listen_read_event;
        }
#endif
        //notify worker process
        if (serv->onConnect)
        {
            serv->notify(serv, conn, SW_EVENT_CONNECT);
            if (!swBuffer_empty(conn->out_buffer))
            {
                goto _pop_chunk;
            }
        }
        //delay receive, wait resume command.
        if (serv->enable_delay_receive)
        {
            conn->listen_wait = 1;
            return reactor->del(reactor, fd);
        }
        else
        {
#ifdef SW_USE_OPENSSL
            listen_read_event:
#endif
            return reactor->set(reactor, fd, SW_EVENT_TCP | SW_EVENT_READ);
        }
    }
    else if (conn->close_notify)
    {
#ifdef SW_USE_OPENSSL
        if (conn->ssl && conn->ssl_state != SW_SSL_STATE_READY)
        {
            return swReactorThread_close(reactor, fd);
        }
#endif
        serv->notify(serv, conn, SW_EVENT_CLOSE);
        conn->close_notify = 0;
        return SW_OK;
    }
    else if (serv->disable_notify && conn->close_force)
    {
        return swReactorThread_close(reactor, fd);
    }

    _pop_chunk: while (!swBuffer_empty(conn->out_buffer))
    {
        chunk = swBuffer_get_chunk(conn->out_buffer);
        if (chunk->type == SW_CHUNK_CLOSE)
        {
            close_fd: reactor->close(reactor, fd);
            return SW_OK;
        }
        else if (chunk->type == SW_CHUNK_SENDFILE)
        {
            ret = swConnection_onSendfile(conn, chunk);
        }
        else
        {
            ret = swConnection_buffer_send(conn);
        }

        if (ret < 0)
        {
            if (conn->close_wait)
            {
                goto close_fd;
            }
            else if (conn->send_wait)
            {
                break;
            }
        }
    }

    if (conn->overflow && conn->out_buffer->length < conn->buffer_size)
    {
        conn->overflow = 0;
    }

    if (serv->onBufferEmpty && conn->high_watermark)
    {
        swListenPort *port = swServer_get_port(serv, fd);
        if (conn->out_buffer->length <= port->buffer_low_watermark)
        {
            conn->high_watermark = 0;
            serv->notify(serv, conn, SW_EVENT_BUFFER_EMPTY);
        }
    }

    //remove EPOLLOUT event
    if (!conn->removed && swBuffer_empty(conn->out_buffer))
    {
        reactor->set(reactor, fd, SW_FD_TCP | SW_EVENT_READ);
    }
    return SW_OK;
}

int swReactorThread_create(swServer *serv)
{
    int ret = 0;
    /**
     * init reactor thread pool
     */
    serv->reactor_threads = SwooleG.memory_pool->alloc(SwooleG.memory_pool, (serv->reactor_num * sizeof(swReactorThread)));
    if (serv->reactor_threads == NULL)
    {
        swError("calloc[reactor_threads] fail.alloc_size=%d", (int )(serv->reactor_num * sizeof(swReactorThread)));
        return SW_ERR;
    }

    /**
     * alloc the memory for connection_list
     */
    serv->connection_list = sw_shm_calloc(serv->max_connection, sizeof(swConnection));
    if (serv->connection_list == NULL)
    {
        swError("calloc[1] failed");
        return SW_ERR;
    }

    //create factry object
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
    int ret;
    swReactor *main_reactor = sw_malloc(sizeof(swReactor));
    if (!main_reactor)
    {
        swWarn("malloc(%ld) failed", sizeof(swReactor));
        return SW_ERR;
    }

    ret = swReactor_create(main_reactor, SW_REACTOR_MAXEVENTS);
    if (ret < 0)
    {
        sw_free(main_reactor);
        swWarn("Reactor create failed");
        return SW_ERR;
    }

    main_reactor->thread = 1;
    main_reactor->socket_list = serv->connection_list;
    main_reactor->disable_accept = 0;
    main_reactor->enable_accept = swServer_enable_accept;

#ifdef HAVE_SIGNALFD
    if (SwooleG.use_signalfd)
    {
        swSignalfd_setup(main_reactor);
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
            _failed: main_reactor->free(main_reactor);
            sw_free(main_reactor);
            return SW_ERR;
        }
    }

    if (serv->stream_fd > 0)
    {
        close(serv->stream_fd);
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
        if (ls->type == SW_SOCK_UDP || ls->type == SW_SOCK_UDP6 || ls->type == SW_SOCK_UNIX_DGRAM)
        {
            continue;
        }
        main_reactor->add(main_reactor, ls->sock, SW_FD_LISTEN);
    }

    if (serv->single_thread)
    {
        swReactorThread_init_reactor(serv, main_reactor, 0);
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
        main_reactor->id = serv->reactor_num;
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
        param = SwooleG.memory_pool->alloc(SwooleG.memory_pool, sizeof(swThreadParam));
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

    SwooleG.main_reactor = main_reactor;
    SwooleG.pid = getpid();
    SwooleG.process_type = SW_PROCESS_MASTER;

    main_reactor->ptr = serv;
    main_reactor->setHandle(main_reactor, SW_FD_LISTEN, swServer_master_onAccept);

    if (serv->hooks[SW_SERVER_HOOK_MASTER_START])
    {
        swServer_call_hook(serv, SW_SERVER_HOOK_MASTER_START, serv);
    }

    /**
     * 1 second timer, update serv->gs->now
     */
    swTimer_node *update_timer;
    if ((update_timer = swTimer_add(&SwooleG.timer, 1000, 1, serv, swServer_master_onTimer)) == NULL)
    {
        goto _failed;
    }

    if (serv->onStart != NULL)
    {
        serv->onStart(serv);
    }

    int retval = main_reactor->wait(main_reactor, NULL);

    if (update_timer)
    {
        swTimer_del(&SwooleG.timer, update_timer);
    }

    return retval;
}


int swReactorThread_init_reactor(swServer *serv, swReactor *reactor, uint16_t reactor_id)
{
    swReactorThread *thread = swServer_get_thread(serv, reactor_id);

    reactor->ptr = serv;
    reactor->id = reactor_id;
    reactor->thread = 1;
    reactor->socket_list = serv->connection_list;
    reactor->max_socket = serv->max_connection;
    reactor->close = swReactorThread_close;

    reactor->setHandle(reactor, SW_FD_CLOSE, swReactorThread_onClose);
    reactor->setHandle(reactor, SW_FD_PIPE | SW_EVENT_READ, swReactorThread_onPipeReceive);
    reactor->setHandle(reactor, SW_FD_PIPE | SW_EVENT_WRITE, swReactorThread_onPipeWrite);

    //listen UDP
    if (serv->have_dgram_sock == 1)
    {
        swListenPort *ls;
        LL_FOREACH(serv->listen_list, ls)
        {
            if (ls->type == SW_SOCK_UDP || ls->type == SW_SOCK_UDP6 || ls->type == SW_SOCK_UNIX_DGRAM)
            {
                if (ls->sock % serv->reactor_num != reactor_id)
                {
                    continue;
                }
                if (ls->type == SW_SOCK_UDP)
                {
                    serv->connection_list[ls->sock].info.addr.inet_v4.sin_port = htons(ls->port);
                }
                else if (ls->type == SW_SOCK_UDP6)
                {
                    serv->connection_list[ls->sock].info.addr.inet_v6.sin6_port = htons(ls->port);
                }
                serv->connection_list[ls->sock].fd = ls->sock;
                serv->connection_list[ls->sock].socket_type = ls->type;
                serv->connection_list[ls->sock].object = ls;
                ls->thread_id = pthread_self();
                if (reactor->add(reactor, ls->sock, SW_FD_UDP) < 0)
                {
                    return SW_ERR;
                }
            }
        }
    }

    //set protocol function point
    swReactorThread_set_protocol(serv, reactor);

    int i = 0, pipe_fd;
    for (i = 0; i < serv->worker_num; i++)
    {
        if (i % serv->reactor_num != reactor_id)
        {
            continue;
        }

        pipe_fd = serv->workers[i].pipe_master;

        //for request
        swBuffer *buffer = swBuffer_new(0);
        if (!buffer)
        {
            swWarn("create buffer failed");
            return SW_ERR;
        }
        serv->connection_list[pipe_fd].in_buffer = buffer;

        //for response
        swSetNonBlock(pipe_fd);
        if (reactor->add(reactor, pipe_fd, SW_FD_PIPE) < 0)
        {
            return SW_ERR;
        }

        if (thread->notify_pipe == 0)
        {
            thread->notify_pipe = serv->workers[i].pipe_worker;
        }

        /**
         * mapping reactor_id and worker pipe
         */
        serv->connection_list[pipe_fd].from_id = reactor_id;
        serv->connection_list[pipe_fd].fd = pipe_fd;
        serv->connection_list[pipe_fd].object = sw_malloc(sizeof(swLock));

        /**
         * create pipe lock
         */
        if (serv->connection_list[pipe_fd].object == NULL)
        {
            swWarn("create pipe mutex lock failed");
            return SW_ERR;
        }
        swMutex_create(serv->connection_list[pipe_fd].object, 0);
    }

    return SW_OK;
}

/**
 * ReactorThread main Loop
 */
static int swReactorThread_loop(swThreadParam *param)
{
    swServer *serv = param->object;
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

    reactor->onFinish = NULL;
    reactor->onTimeout = NULL;

    if (swReactorThread_init_reactor(serv, reactor, reactor_id) < 0)
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

    swString_free(SwooleTG.buffer_stack);
    pthread_exit(0);
    return SW_OK;
}

/**
 * dispatch request data [only data frame]
 */
int swReactorThread_dispatch(swConnection *conn, char *data, uint32_t length)
{
    swServer *serv = SwooleG.serv;
    swSendData task;

    bzero(&task.info, sizeof(task.info));
    task.info.from_fd = conn->from_fd;
    task.info.from_id = conn->from_id;
    task.info.type = SW_EVENT_TCP;
#ifdef SW_BUFFER_RECV_TIME
    task.info.info.time = conn->last_time_usec;
#endif

    swTrace("send string package, size=%ld bytes", (long)length);

    if (serv->stream_socket)
    {
        swStream *stream = swStream_new(serv->stream_socket, 0, SW_SOCK_UNIX_STREAM);
        if (stream == NULL)
        {
            return SW_ERR;
        }
        stream->response = swReactorThread_onStreamResponse;
        swListenPort *port = swServer_get_port(serv, conn->fd);
        swStream_set_max_length(stream, port->protocol.package_max_length);

        task.info.fd = conn->session_id;

        if (swStream_send(stream, (char*) &task.info, sizeof(task.info)) < 0)
        {
            _cancel: stream->cancel = 1;
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
        return serv->factory.dispatch(&serv->factory, &task);
    }
}

void swReactorThread_free(swServer *serv)
{
    int i;
    swReactorThread *thread;

    if (!serv->gs->start)
    {
        return;
    }

    for (i = 0; i < serv->reactor_num; i++)
    {
        thread = &(serv->reactor_threads[i]);
        if (thread->notify_pipe)
        {
            swDataHead ev;
            memset(&ev, 0, sizeof(ev));
            ev.from_fd = SW_RESPONSE_EXIT;
            if (swSocket_write_blocking(thread->notify_pipe, (void *) &ev, sizeof(ev)) < 0)
            {
                goto cancel;
            }
        }
        else
        {
            cancel: if (pthread_cancel(thread->thread_id) < 0)
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

static void swHeartbeatThread_start(swServer *serv)
{
    swThreadParam *param;
    pthread_t thread_id;
    param = SwooleG.memory_pool->alloc(SwooleG.memory_pool, sizeof(swThreadParam));
    if (param == NULL)
    {
        swError("heartbeat_param malloc fail\n");
        return;
    }

    param->object = serv;
    param->pti = 0;

    if (pthread_create(&thread_id, NULL, (void * (*)(void *)) swHeartbeatThread_loop, (void *) param) < 0)
    {
        swWarn("pthread_create[hbcheck] fail");
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

            if (conn != NULL && conn->active == 1 && conn->closed == 0 && conn->fdtype == SW_FD_TCP)
            {
                if (conn->protect || conn->last_time > checktime)
                {
                    continue;
                }

                conn->close_force = 1;
                conn->close_notify = 1;

                if (serv->single_thread)
                {
                    reactor = SwooleG.main_reactor;
                }
                else
                {
                    reactor = &serv->reactor_threads[conn->from_id].reactor;
                }
                //notify to reactor thread
                if (conn->removed)
                {
                    serv->notify(serv, conn, SW_EVENT_CLOSE);
                }
                else
                {
                    reactor->set(reactor, fd, SW_FD_TCP | SW_EVENT_WRITE);
                }
            }
        }
        sleep(serv->heartbeat_check_interval);
    }
    pthread_exit(0);
}
