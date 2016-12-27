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
#include "Server.h"
#include "websocket.h"

static int swReactorThread_loop(swThreadParam *param);
static int swReactorThread_onPipeWrite(swReactor *reactor, swEvent *ev);
static int swReactorThread_onPipeReceive(swReactor *reactor, swEvent *ev);

static int swReactorThread_onRead(swReactor *reactor, swEvent *ev);
static int swReactorThread_onWrite(swReactor *reactor, swEvent *ev);
static int swReactorThread_onPackage(swReactor *reactor, swEvent *event);

#if 0
static int swReactorThread_dispatch_array_buffer(swReactorThread *thread, swConnection *conn);
#endif

#ifdef SW_USE_RINGBUFFER
static sw_inline void swReactorThread_yield(swReactorThread *thread)
{
    swEvent event;
    swServer *serv = SwooleG.serv;
    int i;
    for (i = 0; i < serv->reactor_pipe_num; i++)
    {
        event.fd = thread->pipe_read_list[i];
        swReactorThread_onPipeReceive(&thread->reactor, &event);
    }
    swYield();
}

static sw_inline void* swReactorThread_alloc(swReactorThread *thread, uint32_t size)
{
    void *ptr = NULL;
    int try_count = 0;

    while (1)
    {
        ptr = thread->buffer_input->alloc(thread->buffer_input, size);
        if (ptr == NULL)
        {
            if (try_count > SW_RINGBUFFER_WARNING)
            {
                swWarn("memory pool is full. Wait memory collect. alloc(%d)", size);
                usleep(1000);
                try_count = 0;
            }
            try_count++;
            swReactorThread_yield(thread);
            continue;
        }
        break;
    }
    //debug("%p\n", ptr);
    return ptr;
}
#endif

#ifdef SW_USE_OPENSSL
static sw_inline int swReactorThread_verify_ssl_state(swReactor *reactor, swListenPort *port, swConnection *conn)
{
    swServer *serv = reactor->ptr;
    if (conn->ssl_state == 0 && conn->ssl)
    {
        int ret = swSSL_accept(conn);
        if (ret == SW_READY)
        {
            if (port->ssl_client_cert_file)
            {
                swDispatchData task;
                ret = swSSL_get_client_certificate(conn->ssl, task.data.data, sizeof(task.data.data));
                if (ret < 0)
                {
                    goto no_client_cert;
                }
                else
                {
                    swFactory *factory = &SwooleG.serv->factory;
                    task.target_worker_id = -1;
                    task.data.info.fd = conn->fd;
                    task.data.info.type = SW_EVENT_CONNECT;
                    task.data.info.from_id = conn->from_id;
                    task.data.info.len = ret;
                    factory->dispatch(factory, &task);
                    goto delay_receive;
                }
            }
            no_client_cert:
            if (SwooleG.serv->onConnect)
            {
                swServer_tcp_notify(SwooleG.serv, conn, SW_EVENT_CONNECT);
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

/**
 * for udp
 */
static int swReactorThread_onPackage(swReactor *reactor, swEvent *event)
{
    int fd = event->fd;
    int ret;

    swServer *serv = SwooleG.serv;
    swConnection *server_sock = &serv->connection_list[fd];
    swDispatchData task;
    swSocketAddress info;
    swDgramPacket pkt;
    swFactory *factory = &serv->factory;

    info.len = sizeof(info.addr);
    bzero(&task.data.info, sizeof(task.data.info));
    task.data.info.from_fd = fd;
    task.data.info.from_id = SwooleTG.id;

    int socket_type = server_sock->socket_type;
    switch(socket_type)
    {
    case SW_SOCK_UDP6:
        task.data.info.type = SW_EVENT_UDP6;
        break;
    case SW_SOCK_UNIX_DGRAM:
        task.data.info.type = SW_EVENT_UNIX_DGRAM;
        break;
    case SW_SOCK_UDP:
    default:
        task.data.info.type = SW_EVENT_UDP;
        break;
    }

    char packet[SW_BUFFER_SIZE_UDP];
    do_recvfrom:
    ret = recvfrom(fd, packet, SW_BUFFER_SIZE_UDP, 0, (struct sockaddr *) &info.addr, &info.len);

    if (ret > 0)
    {
        pkt.length = ret;

        //IPv4
        if (socket_type == SW_SOCK_UDP)
        {
            pkt.port = ntohs(info.addr.inet_v4.sin_port);
            pkt.addr.v4.s_addr = info.addr.inet_v4.sin_addr.s_addr;
            task.data.info.fd = pkt.addr.v4.s_addr;
        }
        //IPv6
        else if (socket_type == SW_SOCK_UDP6)
        {
            pkt.port = ntohs(info.addr.inet_v6.sin6_port);
            memcpy(&pkt.addr.v6, &info.addr.inet_v6.sin6_addr, sizeof(info.addr.inet_v6.sin6_addr));
            memcpy(&task.data.info.fd, &info.addr.inet_v6.sin6_addr, sizeof(task.data.info.fd));
        }
        //Unix Dgram
        else
        {
            pkt.addr.un.path_length = strlen(info.addr.un.sun_path) + 1;
            pkt.length += pkt.addr.un.path_length;
            pkt.port = 0;
            memcpy(&task.data.info.fd, info.addr.un.sun_path + pkt.addr.un.path_length - 6, sizeof(task.data.info.fd));
        }

        task.target_worker_id = -1;
        uint32_t header_size = sizeof(pkt);

        //dgram header
        memcpy(task.data.data, &pkt, sizeof(pkt));
        //unix dgram
        if (socket_type == SW_SOCK_UNIX_DGRAM)
        {
            header_size += pkt.addr.un.path_length;
            memcpy(task.data.data + sizeof(pkt), info.addr.un.sun_path, pkt.addr.un.path_length);
        }
        //dgram body
        if (pkt.length > SW_BUFFER_SIZE - sizeof(pkt))
        {
            task.data.info.len = SW_BUFFER_SIZE;
        }
        else
        {
            task.data.info.len = pkt.length + sizeof(pkt);
        }
        //dispatch packet header
        memcpy(task.data.data + header_size, packet, task.data.info.len - header_size);

        uint32_t send_n = pkt.length + header_size;
        if (socket_type == SW_SOCK_UNIX_DGRAM)
        {
            send_n -= pkt.addr.un.path_length;
        }
        uint32_t offset = 0;

        /**
         * lock target
         */
        SwooleTG.factory_lock_target = 1;

        if (factory->dispatch(factory, &task) < 0)
        {
            return SW_ERR;
        }

        send_n -= task.data.info.len;
        if (send_n == 0)
        {
            /**
             * unlock
             */
            SwooleTG.factory_target_worker = -1;
            SwooleTG.factory_lock_target = 0;
            goto do_recvfrom;
        }

        offset = SW_BUFFER_SIZE - header_size;
        while (send_n > 0)
        {
            task.data.info.len = send_n > SW_BUFFER_SIZE ? SW_BUFFER_SIZE : send_n;
            memcpy(task.data.data, packet + offset, task.data.info.len);
            send_n -= task.data.info.len;
            offset += task.data.info.len;

            if (factory->dispatch(factory, &task) < 0)
            {
                break;
            }
        }
        /**
         * unlock
         */
        SwooleTG.factory_target_worker = -1;
        SwooleTG.factory_lock_target = 0;
        goto do_recvfrom;
    }
    else
    {
        if (errno == EAGAIN)
        {
            return SW_OK;
        }
        else
        {
            swSysError("recvfrom(%d) failed.", fd);
        }
    }
    return ret;
}

/**
 * close connection
 */
int swReactorThread_close(swReactor *reactor, int fd)
{
    swServer *serv = SwooleG.serv;
    swConnection *conn = swServer_connection_get(serv, fd);
    if (conn == NULL)
    {
        swWarn("[Reactor]connection not found. fd=%d|max_fd=%d", fd, swServer_get_maxfd(serv));
        return SW_ERR;
    }

    if (!conn->removed && reactor->del(reactor, fd) < 0)
    {
        return SW_ERR;
    }

    if (serv->factory_mode == SW_MODE_PROCESS)
    {
        assert(fd % serv->reactor_num == reactor->id);
        assert(fd % serv->reactor_num == SwooleTG.id);
    }

    sw_atomic_fetch_add(&SwooleStats->close_count, 1);
    sw_atomic_fetch_sub(&SwooleStats->connection_num, 1);

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
    if (port->open_http_protocol && conn->object)
    {
        swHttpRequest_free(conn);
    }

#ifdef SW_USE_SOCKET_LINGER
    if (conn->close_force)
    {
        struct linger linger;
        linger.l_onoff = 1;
        linger.l_linger = 0;
        if (setsockopt(fd, SOL_SOCKET, SO_LINGER, &linger, sizeof(struct linger)) == -1)
        {
            swWarn("setsockopt(SO_LINGER) failed. Error: %s[%d]", strerror(errno), errno);
        }
    }
#endif

#ifdef SW_REACTOR_USE_SESSION
    swSession *session = swServer_get_session(serv, conn->session_id);
    session->fd = 0;
#endif

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
int swReactorThread_onClose(swReactor *reactor, swEvent *event)
{
    swServer *serv = reactor->ptr;
    if (serv->factory_mode == SW_MODE_SINGLE)
    {
        return swReactorProcess_onClose(reactor, event);
    }

    int fd = event->fd;
    swDataHead notify_ev;
    bzero(&notify_ev, sizeof(notify_ev));

    assert(fd % serv->reactor_num == reactor->id);
    assert(fd % serv->reactor_num == SwooleTG.id);

    notify_ev.from_id = reactor->id;
    notify_ev.fd = fd;
    notify_ev.type = SW_EVENT_CLOSE;

    swConnection *conn = swServer_connection_get(SwooleG.serv, fd);
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
        return SwooleG.factory->notify(SwooleG.factory, &notify_ev);
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
    swEventData resp;
    swSendData _send;

    swPackage_response pkg_resp;
    swWorker *worker;

#ifdef SW_REACTOR_RECV_AGAIN
    while (1)
#endif
    {
        n = read(ev->fd, &resp, sizeof(resp));
        if (n > 0)
        {
            memcpy(&_send.info, &resp.info, sizeof(resp.info));
            //pipe data
            if (_send.info.from_fd == SW_RESPONSE_SMALL)
            {
                _send.data = resp.data;
                _send.length = resp.info.len;
                swReactorThread_send(&_send);
            }
            //use send shm
            else if (_send.info.from_fd == SW_RESPONSE_SHM)
            {
                memcpy(&pkg_resp, resp.data, sizeof(pkg_resp));
                worker = swServer_get_worker(SwooleG.serv, pkg_resp.worker_id);

                _send.data = worker->send_shm;
                _send.length = pkg_resp.length;

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
                swReactorThread_send(&_send);
                worker->lock.unlock(&worker->lock);
            }
            //use tmp file
            else if (_send.info.from_fd == SW_RESPONSE_TMPFILE)
            {
                swString *data = swTaskWorker_large_unpack(&resp);
                if (data == NULL)
                {
                    return SW_ERR;
                }
                _send.data = data->str;
                _send.length = data->length;
                swReactorThread_send(&_send);
            }
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
            swWarn("read(worker_pipe) failed. Error: %s[%d]", strerror(errno), errno);
            return SW_ERR;
        }
    }

    return SW_OK;
}

int swReactorThread_send2worker(void *data, int len, uint16_t target_worker_id)
{
    swServer *serv = SwooleG.serv;

    assert(target_worker_id < serv->worker_num);

    int ret = -1;
    swWorker *worker = &(serv->workers[target_worker_id]);

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
#ifdef HAVE_KQUEUE
            if (ret < 0 && (errno == EAGAIN || errno == ENOBUFS))
#else
            if (ret < 0 && errno == EAGAIN)
#endif
            {
                if (thread->reactor.set(&thread->reactor, pipe_fd, SW_FD_PIPE | SW_EVENT_READ | SW_EVENT_WRITE) < 0)
                {
                    swSysError("reactor->set(%d, PIPE | READ | WRITE) failed.", pipe_fd);
                }
                goto append_pipe_buffer;
            }
        }
        else
        {
            append_pipe_buffer:
            if (buffer->length > serv->pipe_buffer_size)
            {
                swYield();
                swSocket_wait(pipe_fd, SW_SOCKET_OVERFLOW_WAIT, SW_EVENT_WRITE);
            }
            if (swBuffer_append(buffer, data, len) < 0)
            {
                swWarn("append to pipe_buffer failed.");
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
 * send to client or append to out_buffer
 */
int swReactorThread_send(swSendData *_send)
{
    swServer *serv = SwooleG.serv;
    uint32_t session_id = _send->info.fd;
    void *_send_data = _send->data;
    uint32_t _send_length = _send->length;

    swConnection *conn;
    if (_send->info.type != SW_EVENT_CLOSE)
    {
        conn = swServer_connection_verify(serv, session_id);
    }
    else
    {
        conn = swServer_connection_verify_no_ssl(serv, session_id);
    }
    if (!conn)
    {
        if (_send->info.type == SW_EVENT_TCP)
        {
            swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SESSION_NOT_EXIST, "send %d byte failed, session#%d does not exist.", _send_length, session_id);
        }
        else
        {
            swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SESSION_NOT_EXIST, "send event$[%d] failed, session#%d does not exist.", _send->info.type, session_id);
        }
        return SW_ERR;
    }

    int fd = conn->fd;
    swReactor *reactor;

    if (serv->factory_mode == SW_MODE_SINGLE)
    {
        reactor = &(serv->reactor_threads[0].reactor);
    }
    else
    {
        reactor = &(serv->reactor_threads[conn->from_id].reactor);
    }

    /**
     * Reset send buffer, Immediately close the connection.
     */
    if (_send->info.type == SW_EVENT_CLOSE && (conn->close_reset || conn->removed))
    {
        goto close_fd;
    }
    else if (_send->info.type == SW_EVENT_CONFIRM)
    {
        reactor->add(reactor, conn->fd, conn->fdtype | SW_EVENT_READ);
        conn->listen_wait = 0;
        return SW_OK;
    }

    if (swBuffer_empty(conn->out_buffer))
    {
        /**
         * close connection.
         */
        if (_send->info.type == SW_EVENT_CLOSE)
        {
            close_fd:
            reactor->close(reactor, fd);
            return SW_OK;
        }
#ifdef SW_REACTOR_SYNC_SEND
        //Direct send
        if (_send->info.type != SW_EVENT_SENDFILE)
        {
            if (!conn->direct_send)
            {
                goto buffer_send;
            }

            int n;

            direct_send:
            n = swConnection_send(conn, _send_data, _send_length, 0);
            if (n == _send_length)
            {
                return SW_OK;
            }
            else if (n > 0)
            {
                _send_data += n;
                _send_length -= n;
                goto buffer_send;
            }
            else if (errno == EINTR)
            {
                goto direct_send;
            }
            else
            {
                goto buffer_send;
            }
        }
#endif
        //buffer send
        else
        {
#ifdef SW_REACTOR_SYNC_SEND
            buffer_send:
#endif
            if (!conn->out_buffer)
            {
                conn->out_buffer = swBuffer_new(SW_BUFFER_SIZE);
                if (conn->out_buffer == NULL)
                {
                    return SW_ERR;
                }
            }
        }
    }

    swBuffer_trunk *trunk;
    //close connection
    if (_send->info.type == SW_EVENT_CLOSE)
    {
        trunk = swBuffer_new_trunk(conn->out_buffer, SW_CHUNK_CLOSE, 0);
        trunk->store.data.val1 = _send->info.type;
    }
    //sendfile to client
    else if (_send->info.type == SW_EVENT_SENDFILE)
    {
        swConnection_sendfile(conn, _send_data + sizeof(off_t), *((off_t *) _send_data));
    }
    //send data
    else
    {
        //connection is closed
        if (conn->removed)
        {
            swWarn("connection#%d is closed by client.", fd);
            return SW_ERR;
        }
        //connection output buffer overflow
        if (conn->out_buffer->length >= conn->buffer_size)
        {
            swoole_error_log(SW_LOG_WARNING, SW_ERROR_OUTPUT_BUFFER_OVERFLOW, "connection#%d output buffer overflow.", fd);
            conn->overflow = 1;
        }

        int _length = _send_length;
        void* _pos = _send_data;
        int _n;

        //buffer enQueue
        while (_length > 0)
        {
            _n = _length >= SW_BUFFER_SIZE_BIG ? SW_BUFFER_SIZE_BIG : _length;
            swBuffer_append(conn->out_buffer, _pos, _n);
            _pos += _n;
            _length -= _n;
        }

        swListenPort *port = swServer_get_port(serv, fd);
        if (serv->onBufferFull && conn->out_buffer->length >= port->buffer_high_watermark)
        {
            swServer_tcp_notify(serv, conn, SW_EVENT_BUFFER_FULL);
            conn->high_watermark = 1;
        }
    }

    //listen EPOLLOUT event
    if (reactor->set(reactor, fd, SW_EVENT_TCP | SW_EVENT_WRITE | SW_EVENT_READ) < 0
            && (errno == EBADF || errno == ENOENT))
    {
        goto close_fd;
    }

    return SW_OK;
}

/**
 * [ReactorThread] worker pipe can write.
 */
static int swReactorThread_onPipeWrite(swReactor *reactor, swEvent *ev)
{
    int ret;

    swBuffer_trunk *trunk = NULL;
    swEventData *send_data;
    swConnection *conn;
    swServer *serv = reactor->ptr;
    swBuffer *buffer = serv->connection_list[ev->fd].in_buffer;
    swLock *lock = serv->connection_list[ev->fd].object;

    //lock thread
    lock->lock(lock);

    while (!swBuffer_empty(buffer))
    {
        trunk = swBuffer_get_trunk(buffer);
        send_data = trunk->store.ptr;

        //server active close, discard data.
        if (swEventData_is_stream(send_data->info.type))
        {
            //send_data->info.fd is session_id
            conn = swServer_connection_verify(serv, send_data->info.fd);
            if (conn == NULL || conn->closed)
            {
#ifdef SW_USE_RINGBUFFER
                swReactorThread *thread = swServer_get_thread(SwooleG.serv, SwooleTG.id);
                swPackage package;
                memcpy(&package, send_data->data, sizeof(package));
                thread->buffer_input->free(thread->buffer_input, package.data);
#endif
                if (conn && conn->closed)
                {
                    swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SESSION_CLOSED_BY_SERVER, "Session#%d is closed by server.", send_data->info.fd);
                }
                swBuffer_pop_trunk(buffer, trunk);
                continue;
            }
        }

        ret = write(ev->fd, trunk->store.ptr, trunk->length);
        if (ret < 0)
        {
            //release lock
            lock->unlock(lock);
#ifdef HAVE_KQUEUE
            return (errno == EAGAIN || errno == ENOBUFS) ? SW_OK : SW_ERR;
#else
            return errno == EAGAIN ? SW_OK : SW_ERR;
#endif
        }
        else
        {
            swBuffer_pop_trunk(buffer, trunk);
        }
    }

    //remove EPOLLOUT event
    if (swBuffer_empty(buffer))
    {
        if (SwooleG.serv->connection_list[ev->fd].from_id == SwooleTG.id)
        {
            ret = reactor->set(reactor, ev->fd, SW_FD_PIPE | SW_EVENT_READ);
        }
        else
        {
            ret = reactor->del(reactor, ev->fd);
        }
        if (ret < 0)
        {
            swSysError("reactor->set(%d) failed.", ev->fd);
        }
    }

    //release lock
    lock->unlock(lock);

    return SW_OK;
}

void swReactorThread_set_protocol(swServer *serv, swReactor *reactor)
{
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
    event->socket->last_time = SwooleGS->now;
    return port->onRead(reactor, port, event);
}

static int swReactorThread_onWrite(swReactor *reactor, swEvent *ev)
{
    int ret;
    swServer *serv = SwooleG.serv;
    int fd = ev->fd;

    if (serv->factory_mode == SW_MODE_PROCESS)
    {
        assert(fd % serv->reactor_num == reactor->id);
        assert(fd % serv->reactor_num == SwooleTG.id);
    }

    swConnection *conn = swServer_connection_get(serv, fd);
    if (conn->active == 0)
    {
        return SW_OK;
    }
    //notify worker process
    else if (conn->connect_notify)
    {
        swServer_tcp_notify(serv, conn, SW_EVENT_CONNECT);
        conn->connect_notify = 0;
        if (serv->enable_delay_receive)
        {
            conn->listen_wait = 1;
            return reactor->del(reactor, fd);
        }
        else
        {
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
        swServer_tcp_notify(serv, conn, SW_EVENT_CLOSE);
        conn->close_notify = 0;
        return SW_OK;
    }
    else if (serv->disable_notify && conn->close_force)
    {
        return swReactorThread_close(reactor, fd);
    }

    swBuffer_trunk *chunk;

    while (!swBuffer_empty(conn->out_buffer))
    {
        chunk = swBuffer_get_trunk(conn->out_buffer);
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
            swServer_tcp_notify(serv, conn, SW_EVENT_BUFFER_EMPTY);
            conn->high_watermark = 0;
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
    if (serv->factory_mode == SW_MODE_PROCESS)
    {
        serv->connection_list = sw_shm_calloc(serv->max_connection, sizeof(swConnection));
    }
    else
    {
        serv->connection_list = sw_calloc(serv->max_connection, sizeof(swConnection));
    }
    if (serv->connection_list == NULL)
    {
        swError("calloc[1] failed");
        return SW_ERR;
    }

    //create factry object
    if (serv->factory_mode == SW_MODE_THREAD)
    {
        if (serv->worker_num < 1)
        {
            swError("Fatal Error: serv->worker_num < 1");
            return SW_ERR;
        }
        ret = swFactoryThread_create(&(serv->factory), serv->worker_num);
    }
    else if (serv->factory_mode == SW_MODE_PROCESS)
    {
        if (serv->worker_num < 1)
        {
            swError("Fatal Error: serv->worker_num < 1");
            return SW_ERR;
        }
        ret = swFactoryProcess_create(&(serv->factory), serv->worker_num);
    }
    else
    {
        ret = swFactory_create(&(serv->factory));
    }

    if (ret < 0)
    {
        swError("create factory failed");
        return SW_ERR;
    }
    return SW_OK;
}

int swReactorThread_start(swServer *serv, swReactor *main_reactor_ptr)
{
    swThreadParam *param;
    swReactorThread *thread;
    pthread_t pidt;
    int i;

    swServer_store_listen_socket(serv);

#ifdef HAVE_REUSEPORT
    SwooleG.reuse_port = 0;
#endif

    swListenPort *ls;
    LL_FOREACH(serv->listen_list, ls)
    {
        if (ls->type == SW_SOCK_UDP || ls->type == SW_SOCK_UDP6 || ls->type == SW_SOCK_UNIX_DGRAM)
        {
            continue;
        }
        main_reactor_ptr->add(main_reactor_ptr, ls->sock, SW_FD_LISTEN);
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
            return SW_ERR;
        }

        param->object = serv;
        param->pti = i;

        if (pthread_create(&pidt, NULL, (void * (*)(void *)) swReactorThread_loop, (void *) param) < 0)
        {
            swError("pthread_create[tcp_reactor] failed. Error: %s[%d]", strerror(errno), errno);
        }
        thread->thread_id = pidt;
    }
#ifdef HAVE_PTHREAD_BARRIER
    //wait reactor thread
    pthread_barrier_wait(&serv->barrier);
#else
    SW_START_SLEEP;
#endif

    return SW_OK;
}

/**
 * ReactorThread main Loop
 */
static int swReactorThread_loop(swThreadParam *param)
{
    swServer *serv = SwooleG.serv;
    int ret;
    int reactor_id = param->pti;

    pthread_t thread_id = pthread_self();

    SwooleTG.factory_lock_target = 0;
    SwooleTG.factory_target_worker = -1;
    SwooleTG.id = reactor_id;
    SwooleTG.type = SW_THREAD_REACTOR;

    swReactorThread *thread = swServer_get_thread(serv, reactor_id);
    swReactor *reactor = &thread->reactor;

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

        if (0 != pthread_setaffinity_np(thread_id, sizeof(cpu_set), &cpu_set))
        {
            swSysError("pthread_setaffinity_np() failed");
        }
    }
#endif

    ret = swReactor_create(reactor, SW_REACTOR_MAXEVENTS);
    if (ret < 0)
    {
        return SW_ERR;
    }

    swSignal_none();

    reactor->ptr = serv;
    reactor->id = reactor_id;
    reactor->thread = 1;
    reactor->socket_list = serv->connection_list;
    reactor->max_socket = serv->max_connection;

    reactor->onFinish = NULL;
    reactor->onTimeout = NULL;
    reactor->close = swReactorThread_close;

    reactor->setHandle(reactor, SW_FD_CLOSE, swReactorThread_onClose);
    reactor->setHandle(reactor, SW_FD_PIPE | SW_EVENT_READ, swReactorThread_onPipeReceive);
    reactor->setHandle(reactor, SW_FD_PIPE | SW_EVENT_WRITE, swReactorThread_onPipeWrite);

    //listen UDP
    if (serv->have_udp_sock == 1)
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
                else
                {
                    serv->connection_list[ls->sock].info.addr.inet_v6.sin6_port = htons(ls->port);
                }
                serv->connection_list[ls->sock].fd = ls->sock;
                serv->connection_list[ls->sock].socket_type = ls->type;
                serv->connection_list[ls->sock].object = ls;
                ls->thread_id = thread_id;
                reactor->add(reactor, ls->sock, SW_FD_UDP);
            }
        }
    }

    //set protocol function point
    swReactorThread_set_protocol(serv, reactor);

    int i = 0, pipe_fd;
#ifdef SW_USE_RINGBUFFER
    int j = 0;
#endif

    if (serv->factory_mode == SW_MODE_PROCESS)
    {
#ifdef SW_USE_RINGBUFFER
        thread->pipe_read_list = sw_calloc(serv->reactor_pipe_num, sizeof(int));
        if (thread->pipe_read_list == NULL)
        {
            swSysError("thread->buffer_pipe create failed");
            return SW_ERR;
        }
#endif

        for (i = 0; i < serv->worker_num; i++)
        {
            if (i % serv->reactor_num == reactor_id)
            {
                pipe_fd = serv->workers[i].pipe_master;

                //for request
                swBuffer *buffer = swBuffer_new(sizeof(swEventData));
                if (!buffer)
                {
                    swWarn("create buffer failed.");
                    break;
                }
                serv->connection_list[pipe_fd].in_buffer = buffer;

                //for response
                swSetNonBlock(pipe_fd);
                reactor->add(reactor, pipe_fd, SW_FD_PIPE);

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
                    swWarn("create pipe mutex lock failed.");
                    break;
                }
                swMutex_create(serv->connection_list[pipe_fd].object, 0);

#ifdef SW_USE_RINGBUFFER
                thread->pipe_read_list[j] = pipe_fd;
                j++;
#endif
            }
        }
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
    pthread_exit(0);
    return SW_OK;
}

int swReactorThread_dispatch(swConnection *conn, char *data, uint32_t length)
{
    swFactory *factory = SwooleG.factory;
    swDispatchData task;

    task.data.info.fd = conn->fd;
    task.data.info.from_id = conn->from_id;

    swTrace("send string package, size=%ld bytes.", (long)length);

#ifdef SW_USE_RINGBUFFER
    swServer *serv = SwooleG.serv;
    swReactorThread *thread = swServer_get_thread(serv, SwooleTG.id);
    int target_worker_id = swServer_worker_schedule(serv, conn->fd);

    swPackage package;
    package.length = length;
    package.data = swReactorThread_alloc(thread, package.length);

    task.data.info.type = SW_EVENT_PACKAGE;
    task.data.info.len = sizeof(package);
    task.target_worker_id = target_worker_id;

    //swoole_dump_bin(package.data, 's', buffer->length);
    memcpy(package.data, data, package.length);
    memcpy(task.data.data, &package, sizeof(package));

    //dispatch failed, free the memory.
    if (factory->dispatch(factory, &task) < 0)
    {
        thread->buffer_input->free(thread->buffer_input, package.data);
    }
    else
    {
        return SW_OK;
    }
#else

    task.data.info.type = SW_EVENT_PACKAGE_START;
    task.target_worker_id = -1;

    /**
     * lock target
     */
    SwooleTG.factory_lock_target = 1;

    size_t send_n = length;
    size_t offset = 0;

    while (send_n > 0)
    {
        if (send_n > SW_BUFFER_SIZE)
        {
            task.data.info.len = SW_BUFFER_SIZE;
        }
        else
        {
            task.data.info.type = SW_EVENT_PACKAGE_END;
            task.data.info.len = send_n;
        }

        task.data.info.fd = conn->fd;
        memcpy(task.data.data, data + offset, task.data.info.len);

        send_n -= task.data.info.len;
        offset += task.data.info.len;

        swTrace("dispatch, type=%d|len=%d\n", task.data.info.type, task.data.info.len);

        if (factory->dispatch(factory, &task) < 0)
        {
            break;
        }
    }

    /**
     * unlock
     */
    SwooleTG.factory_target_worker = -1;
    SwooleTG.factory_lock_target = 0;

#endif
    return SW_OK;
}

#if 0
int swReactorThread_dispatch_array_buffer(swReactorThread *thread, swConnection *conn)
{
    swDispatchData task;
    swFactory *factory = SwooleG.factory;

    task.data.info.fd = conn->fd;
    task.data.info.from_id = conn->from_id;

    swBuffer *buffer = conn->in_buffer;
    swBuffer_trunk *trunk = swBuffer_get_trunk(buffer);

#ifdef SW_USE_RINGBUFFER
    swServer *serv = SwooleG.serv;
    uint16_t target_worker_id = swServer_worker_schedule(serv, conn->fd);
    swPackage package;

    package.length = 0;
    package.data = swReactorThread_alloc(thread, buffer->length);

    task.data.info.type = SW_EVENT_PACKAGE;

    while (trunk != NULL)
    {
        task.data.info.len = trunk->length;
        memcpy(package.data + package.length, trunk->store.ptr, trunk->length);
        package.length += trunk->length;

        swBuffer_pop_trunk(buffer, trunk);
        trunk = swBuffer_get_trunk(buffer);
    }
    task.data.info.len = sizeof(package);
    task.target_worker_id = target_worker_id;
    memcpy(task.data.data, &package, sizeof(package));
    //swWarn("[ReactorThread] copy_n=%d", package.length);
    //dispatch failed, free the memory.
    if (factory->dispatch(factory, &task) < 0)
    {
        thread->buffer_input->free(thread->buffer_input, package.data);
    }
    else
    {
        return SW_OK;
    }
#else
    int ret;
    task.data.info.type = SW_EVENT_PACKAGE_START;
    task.target_worker_id = -1;

    /**
     * lock target
     */
    SwooleTG.factory_lock_target = 1;

    while (trunk != NULL)
    {
        task.data.info.fd = conn->fd;
        task.data.info.len = trunk->length;
        memcpy(task.data.data, trunk->store.ptr, task.data.info.len);
        //package end
        if (trunk->next == NULL)
        {
            task.data.info.type = SW_EVENT_PACKAGE_END;
        }
        ret = factory->dispatch(factory, &task);
        //TODO: 处理数据失败，数据将丢失
        if (ret < 0)
        {
            swWarn("factory->dispatch() failed.");
        }
        swBuffer_pop_trunk(buffer, trunk);
        trunk = swBuffer_get_trunk(buffer);

        swTrace("send2worker[trunk_num=%d][type=%d]", buffer->trunk_num, task.data.info.type);
    }
    /**
     * unlock
     */
    SwooleTG.factory_target_worker = -1;
    SwooleTG.factory_lock_target = 0;

#endif
    return SW_OK;
}
#endif

void swReactorThread_free(swServer *serv)
{
    int i;
    swReactorThread *thread;

    if (SwooleGS->start == 0)
    {
        return;
    }

#ifdef __MACH__
    exit(0);
#endif

    for (i = 0; i < serv->reactor_num; i++)
    {
        thread = &(serv->reactor_threads[i]);
        thread->reactor.running = 0;
        SW_START_SLEEP;
        if (thread->thread_id && pthread_cancel(thread->thread_id) != 0)
        {
            swSysError("pthread_cancel(%ld) failed.", (long ) thread->thread_id);
        }
        //wait thread
        if (thread->thread_id && pthread_join(thread->thread_id, NULL) != 0)
        {
            swSysError("pthread_join(%ld) failed.", (long ) thread->thread_id);
        }
        //release the lock
        SwooleGS->lock.unlock(&SwooleGS->lock);
#ifdef SW_USE_RINGBUFFER
        thread->buffer_input->destroy(thread->buffer_input);
#endif
    }
}
