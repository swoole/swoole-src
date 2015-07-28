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
#include "Http.h"
#include "websocket.h"
#include "mqtt.h"

static int swUDPThread_start(swServer *serv);

static int swReactorThread_loop_udp(swThreadParam *param);
static int swReactorThread_loop_tcp(swThreadParam *param);
static int swReactorThread_loop_unix_dgram(swThreadParam *param);

static int swReactorThread_onPipeWrite(swReactor *reactor, swEvent *ev);
static int swReactorThread_onClose(swReactor *reactor, swEvent *event);
static int swReactorThread_onReceive_no_buffer(swReactor *reactor, swEvent *event);
static int swReactorThread_onReceive_buffer_check_length(swReactor *reactor, swEvent *event);
static int swReactorThread_onReceive_buffer_check_eof(swReactor *reactor, swEvent *event);
static int swReactorThread_onReceive_http_request(swReactor *reactor, swEvent *event);
static int swReactorThread_onReceive_websocket(swReactor *reactor, swEvent *event);
static int swReactorThread_onPipeReceive(swReactor *reactor, swEvent *ev);
static int swReactorThread_onPackage(swReactor *reactor, swEvent *event);
static int swReactorThread_onWrite(swReactor *reactor, swEvent *ev);

static int swReactorThread_send_string_buffer(swConnection *conn, char *data, uint32_t length);
//static int swReactorThread_send_in_buffer(swReactorThread *thread, swConnection *conn);

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

    info.len = sizeof(info.addr);
    bzero(&task.data.info, sizeof(task.data.info));
    task.data.info.from_fd = fd;

    int socket_type = server_sock->socket_type;
    int buffer_size;

    //IPv4
    if (socket_type == SW_SOCK_UDP)
    {
        task.data.info.type = SW_EVENT_UDP;
        buffer_size = SW_IPC_MAX_SIZE - sizeof(struct _swDataHead);
    }
    //IPv6
    else
    {
        task.data.info.type = SW_EVENT_UDP6;
        buffer_size = SW_IPC_MAX_SIZE - sizeof(struct _swDataHead) - sizeof(info.addr.inet_v6.sin6_addr);
    }

    ret = recvfrom(fd, task.data.data, buffer_size, 0, (struct sockaddr *) &info.addr, &info.len);
    if (ret > 0)
    {
        //IPv4, swDataHead + data
        if (socket_type == SW_SOCK_UDP)
        {
            //UDP的from_id是PORT，FD是IP
            task.data.info.from_id = ntohs(info.addr.inet_v4.sin_port);
            task.data.info.fd = info.addr.inet_v4.sin_addr.s_addr;
            task.data.info.len = ret;
        }
        //IPv6, swDataHead + data + sin6_addr
        else
        {
            task.data.info.from_id = ntohs(info.addr.inet_v6.sin6_port);
            //fd record the offset
            task.data.info.fd = ret;
            memcpy(task.data.data + ret, &info.addr.inet_v6.sin6_addr, sizeof(info.addr.inet_v6.sin6_addr));
            task.data.info.len = ret + sizeof(info.addr.inet_v6.sin6_addr);
        }

        task.target_worker_id = -1;

        swTrace("recvfrom udp socket. fd=%d|data=%*s", fd, ret, task.data.data);
        ret = serv->factory.dispatch(&serv->factory, &task);
        if (ret < 0)
        {
            swWarn("factory->dispatch[udp packet] failed");
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

    sw_atomic_fetch_add(&SwooleStats->close_count, 1);
    sw_atomic_fetch_sub(&SwooleStats->connection_num, 1);

    swTrace("Close Event.fd=%d|from=%d", fd, reactor->id);

    //clear output buffer
    if (serv->open_eof_check || serv->open_length_check)
    {
        if (conn->object)
        {
            swString_free(conn->object);
            conn->object = NULL;
        }
    }
    else if (serv->open_http_protocol)
    {
        if (conn->object)
        {
            if (conn->websocket_status >= WEBSOCKET_STATUS_HANDSHAKE)
            {
                swString *str = (swString *) conn->object;
                swString_free(str);
                conn->websocket_status = 0;
            }
            else
            {
                swHttpRequest *request = (swHttpRequest *) conn->object;
                if (request->buffer)
                {
                    swTrace("Connection Close. free buffer=%p, request=%p\n", request->buffer, request);
                    swHttpRequest_free(conn, request);
                }
                sw_free(request);
            }
            conn->object = NULL;
        }
    }

#if 0
    //立即关闭socket，清理缓存区
    if (0)
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
static int swReactorThread_onClose(swReactor *reactor, swEvent *event)
{
    swServer *serv = reactor->ptr;
    if (serv->factory_mode == SW_MODE_SINGLE)
    {
        return swReactorProcess_onClose(reactor, event);
    }

    int fd = event->fd;
    swDataHead notify_ev;
    bzero(&notify_ev, sizeof(notify_ev));

    notify_ev.from_id = reactor->id;
    notify_ev.fd = fd;
    notify_ev.type = SW_EVENT_CLOSE;

    swConnection *conn = swServer_connection_get(SwooleG.serv, fd);
    if (conn == NULL || conn->active == 0)
    {
        return SW_ERR;
    }
    if (serv->disable_notify)
    {
        return swReactorThread_close(reactor, fd);
    }
    if (reactor->del(reactor, fd) == 0)
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
            if (_send.info.from_fd == SW_RESPONSE_SMALL)
            {
                _send.data = resp.data;
                _send.length = resp.info.len;
                swReactorThread_send(&_send);
            }
            else
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

    swConnection *conn = swServer_connection_verify(serv, session_id);
    if (!conn)
    {
        if (_send->info.type == SW_EVENT_TCP)
        {
            swWarn("send %d byte failed, session#%d is closed.", _send_length, session_id);
        }
        else
        {
            swWarn("send [%d] failed, session#%d is closed.", _send->info.type, session_id);
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
        swConnection_sendfile(conn, _send_data);
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
        if (conn->out_buffer->length >= serv->buffer_output_size)
        {
            swWarn("connection#%d output buffer overflow.", fd);
            conn->overflow = 1;
        }
        //buffer enQueue
        swBuffer_append(conn->out_buffer, _send_data, _send_length);
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
                    swWarn("session#%d is closed by server.", send_data->info.fd);
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

static int swReactorThread_onWrite(swReactor *reactor, swEvent *ev)
{
    int ret;
    swServer *serv = SwooleG.serv;
    int fd = ev->fd;

    swConnection *conn = swServer_connection_get(serv, fd);
    if (conn->active == 0)
    {
        return SW_OK;
    }
    //notify worker process
    else if (conn->connect_notify)
    {
        swDataHead connect_event;
        connect_event.type = SW_EVENT_CONNECT;
        connect_event.from_id = reactor->id;
        connect_event.fd = fd;
        if (serv->factory.notify(&serv->factory, &connect_event) < 0)
        {
            swWarn("send notification [fd=%d] failed.", fd);
        }
        conn->connect_notify = 0;
        return reactor->set(reactor, fd, SW_EVENT_TCP | SW_EVENT_READ);
    }
    else if (conn->close_notify)
    {
        swDataHead close_event;
        close_event.type = SW_EVENT_CLOSE;
        close_event.from_id = reactor->id;
        close_event.fd = fd;

        if (serv->factory.notify(&serv->factory, &close_event) < 0)
        {
            swWarn("send notification [fd=%d] failed.", fd);
        }
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
                return SW_OK;
            }
        }
    }

    if (conn->overflow && conn->out_buffer->length < SwooleG.socket_buffer_size)
    {
        conn->overflow = 0;
    }

    //remove EPOLLOUT event
    if (swBuffer_empty(conn->out_buffer))
    {
        reactor->set(reactor, fd, SW_FD_TCP | SW_EVENT_READ);
        conn->direct_send = 1;
    }
    return SW_OK;
}

static int swReactorThread_onReceive_buffer_check_eof(swReactor *reactor, swEvent *event)
{
    swServer *serv = SwooleG.serv;
    swConnection *conn = swServer_connection_get(serv, event->fd);
    swProtocol *protocol = &serv->protocol;

    if (conn->object == NULL)
    {
        conn->object = swString_new(SW_BUFFER_SIZE);
        //alloc memory failed.
        if (!conn->object)
        {
            return SW_ERR;
        }
    }

    if (swProtocol_recv_check_eof(protocol, conn, conn->object) < 0)
    {
        swTrace("Close Event.FD=%d|From=%d", event->fd, event->from_id);
        swReactorThread_onClose(reactor, event);
    }

    return SW_OK;
}

static int swReactorThread_onReceive_no_buffer(swReactor *reactor, swEvent *event)
{
    int ret, n;
    swServer *serv = reactor->ptr;
    swFactory *factory = &(serv->factory);
    swDispatchData task;
    swConnection *conn = swServer_connection_get(serv, event->fd);

#ifdef SW_USE_EPOLLET
    n = swRead(event->fd, task.data.data, SW_BUFFER_SIZE);
#else
    //非ET模式会持续通知
    n = swConnection_recv(conn, task.data.data, SW_BUFFER_SIZE, 0);
#endif

    if (n < 0)
    {
        switch (swConnection_error(errno))
        {
        case SW_ERROR:
            swSysError("recv from connection#%d failed.", event->fd);
            return SW_OK;
        case SW_CLOSE:
            goto close_fd;
        default:
            return SW_OK;
        }
    }
    //需要检测errno来区分是EAGAIN还是ECONNRESET
    else if (n == 0)
    {
        close_fd: swReactorThread_onClose(reactor, event);
        return SW_OK;
    }
    else
    {
        swTrace("recv: %s|fd=%d|len=%d\n", task.data.data, event->fd, n);
        //更新最近收包时间
        conn->last_time = SwooleGS->now;

        //heartbeat ping package
        if (serv->heartbeat_ping_length == n)
        {
            if (serv->heartbeat_pong_length > 0)
            {
                send(event->fd, serv->heartbeat_pong, serv->heartbeat_pong_length, 0);
            }
            return SW_OK;
        }

        task.data.info.fd = event->fd;
        task.data.info.from_id = event->from_id;
        task.data.info.len = n;
        task.data.info.type = SW_EVENT_TCP;
        task.target_worker_id = -1;

#ifdef SW_USE_RINGBUFFER
        swPackage package;
        if (serv->factory_mode == SW_MODE_PROCESS)
        {
            uint16_t target_worker_id = swServer_worker_schedule(serv, conn->fd);
            package.length = task.data.info.len;
            package.data = swReactorThread_alloc(&serv->reactor_threads[SwooleTG.id], package.length);
            task.data.info.type = SW_EVENT_PACKAGE;

            memcpy(package.data, task.data.data, task.data.info.len);
            task.data.info.len = sizeof(package);
            task.target_worker_id = target_worker_id;
            memcpy(task.data.data, &package, sizeof(package));
        }
#endif
        //dispatch to worker process
        ret = factory->dispatch(factory, &task);

#ifdef SW_USE_RINGBUFFER
        if (ret < 0)
        {
            swMemoryPool *pool = serv->reactor_threads[SwooleTG.id].buffer_input;
            pool->free(pool, package.data);
        }
#endif

#ifdef SW_USE_EPOLLET
        //缓存区还有数据没读完，继续读，EPOLL的ET模式
        if (sw_errno == EAGAIN)
        {
            swWarn("sw_errno == EAGAIN");
            ret = swReactorThread_onReceive_no_buffer(reactor, event);
        }
#endif
        return ret;
    }
    return SW_OK;
}

void swReactorThread_set_protocol(swServer *serv, swReactor *reactor)
{
    //udp receive
    reactor->setHandle(reactor, SW_FD_UDP, swReactorThread_onPackage);
    //write
    reactor->setHandle(reactor, SW_FD_TCP | SW_EVENT_WRITE, swReactorThread_onWrite);

    //Thread mode must copy the data.
    //will free after onFinish
    if (serv->open_eof_check)
    {
        serv->protocol.onPackage = swReactorThread_send_string_buffer;
        reactor->setHandle(reactor, SW_FD_TCP, swReactorThread_onReceive_buffer_check_eof);
    }
    else if (serv->open_length_check)
    {
        serv->protocol.get_package_length = swProtocol_get_package_length;
        serv->protocol.onPackage = swReactorThread_send_string_buffer;
        reactor->setHandle(reactor, SW_FD_TCP, swReactorThread_onReceive_buffer_check_length);
    }
    else if (serv->open_http_protocol)
    {
        reactor->setHandle(reactor, SW_FD_TCP, swReactorThread_onReceive_http_request);
    }
    else if (serv->open_mqtt_protocol)
    {
        serv->protocol.get_package_length = swMqtt_get_package_length;
        reactor->setHandle(reactor, SW_FD_TCP, swReactorThread_onReceive_buffer_check_length);
    }
    else
    {
        reactor->setHandle(reactor, SW_FD_TCP, swReactorThread_onReceive_no_buffer);
    }
}

static int swReactorThread_onReceive_buffer_check_length(swReactor *reactor, swEvent *event)
{
    swServer *serv = reactor->ptr;
    swConnection *conn = swServer_connection_get(serv, event->fd);
    swProtocol *protocol = &serv->protocol;

    if (conn->object == NULL)
    {
        conn->object = swString_new(SW_BUFFER_SIZE_BIG);
        //alloc memory failed.
        if (!conn->object)
        {
            return SW_ERR;
        }
    }

    if (swProtocol_recv_check_length(protocol, conn, conn->object) < 0)
    {
        swTrace("Close Event.FD=%d|From=%d", event->fd, event->from_id);
        swReactorThread_onClose(reactor, event);
    }

    return SW_OK;
}

static int swReactorThread_onReceive_websocket(swReactor *reactor, swEvent *event)
{
    swServer *serv = reactor->ptr;
    swConnection *conn = swServer_connection_get(serv, event->fd);

    char recv_buf[SW_BUFFER_SIZE_BIG];
    char tmp_buf[SW_BUFFER_SIZE_BIG];

    int n = swConnection_recv(conn, recv_buf, SW_BUFFER_SIZE_BIG, 0);
    if (n < 0)
    {
        switch (swConnection_error(errno))
        {
        case SW_ERROR:
            swSysError("recv from connection#%d failed.", event->fd);
            return SW_OK;
        case SW_CLOSE:
            goto close_fd;
        default:
            return SW_OK;
        }
    }
    else if (n == 0)
    {
        close_fd: swTrace("Close Event.FD=%d|From=%d", event->fd, event->from_id);
        swReactorThread_onClose(reactor, event);
        return SW_OK;
    }
    else
    {
        conn->last_time = SwooleGS->now;
        swString tmp_package;
        swString *package;
        void *tmp_ptr = recv_buf;
        uint32_t tmp_n = n;
        int ret = 0;
        //new package
        if (conn->object == NULL)
        {
            do_parse_package: do
            {
                tmp_package.offset = 0;
                tmp_package.length = 0;
                tmp_package.str = NULL;
                ret = swWebSocket_decode_frame((char *) tmp_ptr, &tmp_package, tmp_n);
                swTrace("weboscket frame decode ret: %d\n", ret);
                //invalid package, close connection.
                if (ret < 0)
                {
                    goto close_fd;
                }
                //complete package
                //swTrace("weboscket frame decode ret: %d, %d, %d, %d\n", tmp_package.length, tmp_package.offset, tmp_package.size, tmp_n);
                if (tmp_package.size <= tmp_n)
                {
//                    tmp_package.str = (void *) tmp_ptr;
//                    swoole_dump_bin(buffer.str, 's', buffer.length);
//                    swTrace("send data %s", tmp_package.str);
                    int opcode = tmp_package.str[1];
                    switch (opcode)
                    {
                    case WEBSOCKET_OPCODE_CONTINUATION_FRAME:
                    case WEBSOCKET_OPCODE_TEXT_FRAME:
                    case WEBSOCKET_OPCODE_BINARY_FRAME:
                        swReactorThread_send_string_buffer(conn, tmp_package.str, tmp_package.length);
                        break;

                    case WEBSOCKET_OPCODE_PING:  //ping
                        if (tmp_package.str[0] == 0 || 0x7d < (tmp_package.length - 2))
                        {
                            goto close_fd;
                            return SW_ERR;
                        }
//                        tmp_package.str[0] = FRAME_SET_FIN(1) | FRAME_SET_OPCODE(WEBSOCKET_OPCODE_PONG);
                        swString *pongFrame = swString_new(tmp_package.length+tmp_package.offset);
                        swWebSocket_encode(pongFrame, tmp_package.str+=2, tmp_package.length-2, WEBSOCKET_OPCODE_PONG, 1, 0);
                        ret = swConnection_send(conn, pongFrame->str, pongFrame->length, 0);
                        swString_free(pongFrame);
                        break;

                    case WEBSOCKET_OPCODE_PONG:  //pong
                        if (tmp_package.str[0] == 0)
                        {
                            goto close_fd;
                            return SW_ERR;
                        }
                        break;

                    case WEBSOCKET_OPCODE_CONNECTION_CLOSE:
                        //swTrace("fd: %d close, opcode:%d, lenght: %d\n", conn->fd, opcode, tmp_package.length);
                        if (0x7d < (tmp_package.length - 2))
                        {
                            swTrace("close error\n");
                            return SW_ERR;
                        }
                        tmp_package.str[0] = 0x88;
                        tmp_package.str[1] = 0x00;
                        tmp_package.length = 2;
                        swConnection_send(conn, tmp_package.str, 2, 0);
                        swReactorThread_onClose(reactor, event);
                        break;
                    }

                    tmp_n -= tmp_package.size;
                    if (tmp_n > 0 && tmp_n < 3)
                    {
                        goto wait_more;
                    }
                    //reset recv_buf
                    memcpy(tmp_buf, recv_buf + tmp_package.size, tmp_n);
                    memcpy(recv_buf, tmp_buf, tmp_n);
                    tmp_ptr = recv_buf;
                    continue;
                }
                //wait more data
                else
                {
                    wait_more: package = swString_new(tmp_package.size);
                    if (package == NULL)
                    {
                        return SW_ERR;
                    } swTrace("waite more:%d\n", tmp_n);
                    memcpy(package->str, (void *) tmp_ptr, (uint32_t) tmp_n);
                    package->length += tmp_n;
                    conn->object = (void *) package;
                    break;
                }
            } while (tmp_n > 0);
            return SW_OK;
        }
        //package wait data
        else
        {
            package = conn->object;
            //swTraceLog(40, "wait_data, size=%d, length=%d", buffer->size, buffer->length);

            /**
             * Also on the require_n byte data is complete.
             */
            int require_n = package->size - package->length;

            /**
             * Data is not complete, continue to wait
             */
            if (require_n > n)
            {
                memcpy(package->str + package->length, recv_buf, n);
                package->length += n;
                return SW_OK;
            }
            else
            {
                memcpy(package->str + package->length, recv_buf, require_n);
                package->length += require_n;

                //send buffer to worker pipe
                //swReactorThread_send_string_buffer(swServer_get_thread(serv, reactor->id), conn, package);

                ret = swWebSocket_decode_frame(package->str, &tmp_package, package->length);
                if (ret < 0)
                {
                    goto close_fd;
                }
                int opcode = tmp_package.str[1];
                switch (opcode)
                {
                case WEBSOCKET_OPCODE_CONTINUATION_FRAME:
                case WEBSOCKET_OPCODE_TEXT_FRAME:
                case WEBSOCKET_OPCODE_BINARY_FRAME:
                    swReactorThread_send_string_buffer(conn, tmp_package.str, tmp_package.length);
                    tmp_package.offset = 0;
                    tmp_package.length = 0;
                    tmp_package.str = NULL;
                    break;
                case WEBSOCKET_OPCODE_PING:  //ping
                    if (tmp_package.str[0] == 0 || 0x7d < (tmp_package.length - 2))
                    {
                        goto close_fd;
                        return SW_ERR;
                    }
                    //tmp_package.str[0] = FRAME_SET_FIN(1) | FRAME_SET_OPCODE(opcode);
                    //swConnection_send(conn, tmp_package.str, tmp_package.length, 0);
                    swString *pongFrame = swString_new(tmp_package.length+tmp_package.offset);
                    swWebSocket_encode(pongFrame, tmp_package.str+=2, tmp_package.length-2, WEBSOCKET_OPCODE_PONG, 1, 0);
                    ret = swConnection_send(conn, pongFrame->str, pongFrame->length, 0);
                    swString_free(pongFrame);
                    break;
                case WEBSOCKET_OPCODE_PONG:  //pong
                    if (tmp_package.str[0] == 0)
                    {
                        goto close_fd;
                        return SW_ERR;
                    }
                    break;
                case WEBSOCKET_OPCODE_CONNECTION_CLOSE:
                    //swTrace("fd: %d close, opcode:%d, lenght: %d\n", conn->fd, opcode, tmp_package.length);
                    if (0x7d < (tmp_package.length - 2))
                    {
                        swTrace("close error\n");
                        return SW_ERR;
                    }
                    tmp_package.str[0] = 0x88;
                    tmp_package.str[1] = 0x00;
                    tmp_package.length = 2;
                    swConnection_send(conn, tmp_package.str, 2, 0);
                    swReactorThread_onClose(reactor, event);
                    return SW_OK;
                }
                //free the buffer memory
                swString_free((swString *) package);
                conn->object = NULL;

                //still have the data, to parse
                if (n - require_n > 0)
                {
                    //reset tmp_n
                    tmp_n = n - require_n;
                    //reset recv_buf
                    memcpy(tmp_buf, recv_buf + require_n, tmp_n);
                    memcpy(recv_buf, tmp_buf, tmp_n);
                    tmp_ptr = recv_buf;
                    goto do_parse_package;
                }
            }
        }
    }
    return SW_OK;
}

/**
 * For Http Protocol
 */
static int swReactorThread_onReceive_http_request(swReactor *reactor, swEvent *event)
{
    swServer *serv = reactor->ptr;
    swConnection *conn = event->socket;

    if (conn->websocket_status >= WEBSOCKET_STATUS_HANDSHAKE)
    {
        if (conn->websocket_status == WEBSOCKET_STATUS_HANDSHAKE)
        {
            if (conn->object != NULL)
            {
                swHttpRequest *request = (swHttpRequest *) conn->object;
                swHttpRequest_free(conn, request);
                conn->object = NULL;
            }
            conn->websocket_status = WEBSOCKET_STATUS_FRAME;
        }
        return swReactorThread_onReceive_websocket(reactor, event);
    }

    int n = 0;
    char *buf;
    int buf_len;
    char recv_buf[SW_BUFFER_SIZE];

    swHttpRequest *request;
    swString tmp_package;
    swProtocol *protocol = &serv->protocol;

    //new http request
    if (conn->object == NULL)
    {
        request = sw_malloc(sizeof(swHttpRequest));
        bzero(request, sizeof(swHttpRequest));
        conn->object = request;
    }
    else
    {
        request = (swHttpRequest *) conn->object;
    }

    recv_data:
    if (request->method == 0)
    {
        buf = recv_buf;
        buf_len = SW_BUFFER_SIZE;
    }
    else
    {
        buf = request->buffer->str + request->buffer->length;
        buf_len = request->buffer->size - request->buffer->length;
    }

    n = swConnection_recv(conn, buf, buf_len, 0);
    if (n < 0)
    {
        switch (swConnection_error(errno))
        {
        case SW_ERROR:
            swSysError("recv from connection#%d failed.", event->fd);
            return SW_OK;
        case SW_CLOSE:
            goto close_fd;
        default:
            return SW_OK;
        }
    }
    else if (n == 0)
    {
        close_fd:
        swHttpRequest_free(conn, request);
        swReactorThread_onClose(reactor, event);
        return SW_OK;
    }
    else
    {
        conn->last_time = SwooleGS->now;

        swTrace("receive %d bytes: %*s\n", n, n, buf);

        if (request->method == 0)
        {
            bzero(&tmp_package, sizeof(tmp_package));
            tmp_package.str = recv_buf;
            tmp_package.size = SW_BUFFER_SIZE;
            request->buffer = &tmp_package;
        }

        swString *buffer = request->buffer;
        buffer->length += n;

        if (request->method == 0 && swHttpRequest_get_protocol(request) < 0)
        {
            swWarn("get protocol failed.");
            request->buffer = NULL;

#ifdef SW_HTTP_BAD_REQUEST
            if (swConnection_send(conn, SW_STRL(SW_HTTP_BAD_REQUEST) - 1, 0) < 0)
            {
                swSysError("send() failed.");
            }
#endif
            goto close_fd;
        }

        swTrace("request->method=%d", request->method);

        //GET HEAD DELETE OPTIONS
        if (request->method == HTTP_GET || request->method == HTTP_HEAD || request->method == HTTP_OPTIONS
                || request->method == HTTP_DELETE)
        {
            if (memcmp(buffer->str + buffer->length - 4, "\r\n\r\n", 4) == 0)
            {
                swReactorThread_send_string_buffer(conn, buffer->str, buffer->length);
                swHttpRequest_free(conn, request);
            }
            else if (buffer->size == buffer->length)
            {
                swWarn("http header is too long.");
                goto close_fd;
            }
            //wait more data
            else
            {
                wait_more_data: if (!conn->http_buffered)
                {
                    swTrace("wait more data. content_length=%d, header_length=%d", request->content_length, request->header_length);
                    request->buffer = swString_dup2(buffer);
                    conn->http_buffered = 1;
                }
                goto recv_data;
            }
        }
        //POST PUT
        else if (request->method == HTTP_POST || request->method == HTTP_PUT || request->method == HTTP_PATCH)
        {
            if (request->content_length == 0)
            {
                if (swHttpRequest_get_content_length(request) < 0)
                {
                    if (buffer->size == buffer->length)
                    {
                        swWarn("http header is too long.");
                        goto close_fd;
                    }
                    else
                    {
                        goto wait_more_data;
                    }
                }
            }
            else if (request->content_length > protocol->package_max_length)
            {
                swWarn("content-length more than the package_max_length[%d].", protocol->package_max_length);
                goto close_fd;
            }

            //http header is not the end
            if (request->header_length == 0)
            {
                if (!conn->http_buffered)
                {
                    request->buffer = swString_dup2(buffer);
                    conn->http_buffered = 1;
                    return SW_OK;
                }
                else
                {
                    if (buffer->size == buffer->length)
                    {
                        swWarn("http header is too long.");
                        goto close_fd;
                    }
                    if (swHttpRequest_get_header_length(request) < 0)
                    {
                        return SW_OK;
                    }
                }
            }

            uint32_t request_size = request->content_length + request->header_length;

            //discard the redundant data
            if (buffer->length > request_size)
            {
                buffer->length = request_size;
            }

            if (buffer->length == request_size)
            {
                swReactorThread_send_string_buffer(conn, buffer->str, buffer->length);
                swHttpRequest_free(conn, request);
            }
            else
            {
#ifdef SW_HTTP_100_CONTINUE
                //Expect: 100-continue
                if (swHttpRequest_has_expect_header(request))
                {
                    swSendData _send;
                    _send.data = "HTTP/1.1 100 Continue\r\n\r\n";
                    _send.length = strlen(_send.data);

                    int send_times = 0;
                    direct_send:
                    n = swConnection_send(conn, _send.data, _send.length, 0);
                    if (n < _send.length)
                    {
                        _send.data += n;
                        _send.length -= n;
                        send_times++;
                        if (send_times < 10)
                        {
                            goto direct_send;
                        }
                        else
                        {
                            swWarn("send http header failed");
                        }
                    }
                }
                else
                {
                    swTrace("PostWait: request->content_length=%d, buffer->length=%zd, request->header_length=%d\n",
                            request->content_length, buffer->length, request->header_length);
                }
#endif
                if (conn->http_buffered)
                {
                    if (request->content_length > buffer->size && swString_extend(buffer, request->content_length) < 0)
                    {
                        swWarn("malloc failed.");
                        return SW_OK;
                    }
                }
                else
                {
                    buffer->size = request_size;
                }
                goto wait_more_data;
            }
        }
        else
        {
            swWarn("method no support");
            goto close_fd;
        }
    }
    return SW_OK;
}

int swReactorThread_create(swServer *serv)
{
    int ret = 0;

    /**
     * init reactor thread pool
     */
    serv->reactor_threads = SwooleG.memory_pool->alloc(SwooleG.memory_pool,
            (serv->reactor_num * sizeof(swReactorThread)));
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

    int i, ret;

    //listen UDP
    if (serv->have_udp_sock == 1)
    {
        if (swUDPThread_start(serv) < 0)
        {
            swError("udp thread start failed.");
            return SW_ERR;
        }
    }

    //listen TCP
    if (serv->have_tcp_sock == 1)
    {
        swListenPort *ls;
        LL_FOREACH(serv->listen_list, ls)
        {
            ret = swServer_listen(serv, ls);
            if (ret < 0)
            {
                return SW_ERR;
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

            if (pthread_create(&pidt, NULL, (void * (*)(void *)) swReactorThread_loop_tcp, (void *) param) < 0)
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
    }
    //timer
    if (SwooleG.timer.fd > 0)
    {
        main_reactor_ptr->add(main_reactor_ptr, SwooleG.timer.fd, SW_FD_TIMER);
    }
    return SW_OK;
}

/**
 * ReactorThread main Loop
 */
static int swReactorThread_loop_tcp(swThreadParam *param)
{
    swServer *serv = SwooleG.serv;
    int ret;
    int reactor_id = param->pti;

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

        if (0 != pthread_setaffinity_np(pthread_self(), sizeof(cpu_set), &cpu_set))
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
            if (i % serv->reactor_num == reactor_id)
            {
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

static int swUDPThread_start(swServer *serv)
{
    swThreadParam *param;
    pthread_t thread_id;
    swListenPort *ls;

    void * (*thread_loop)(void *);

    LL_FOREACH(serv->listen_list, ls)
    {
        param = SwooleG.memory_pool->alloc(SwooleG.memory_pool, sizeof(swThreadParam));
        //UDP
        if (ls->type == SW_SOCK_UDP || ls->type == SW_SOCK_UDP6 || ls->type == SW_SOCK_UNIX_DGRAM)
        {
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

            param->object = serv;
            param->pti = ls->sock;

            if (ls->type == SW_SOCK_UNIX_DGRAM)
            {
                thread_loop = (void * (*)(void *)) swReactorThread_loop_unix_dgram;
            }
            else
            {
                thread_loop = (void * (*)(void *)) swReactorThread_loop_udp;
            }

            if (pthread_create(&thread_id, NULL, thread_loop, (void *) param) < 0)
            {
                swWarn("pthread_create[udp_listener] fail");
                return SW_ERR;
            }
            ls->thread_id = thread_id;
        }
    }
    return SW_OK;
}

/**
 * udp listener thread
 */
static int swReactorThread_loop_udp(swThreadParam *param)
{
    swEvent event;

    int fd = param->pti;

    SwooleTG.factory_lock_target = 0;
    SwooleTG.factory_target_worker = -1;
    SwooleTG.id = fd;
    SwooleTG.type = SW_THREAD_UDP;

    swSignal_none();

    //blocking
    swSetBlock(fd);
    event.fd = fd;

    while (SwooleG.running == 1)
    {
        swReactorThread_onPackage(NULL, &event);
    }
    pthread_exit(0);
    return 0;
}

static int swReactorThread_send_string_buffer(swConnection *conn, char *data, uint32_t length)
{
    swFactory *factory = SwooleG.factory;
    swDispatchData task;

    task.data.info.fd = conn->fd;
    task.data.info.from_id = conn->from_id;

    swTrace("send string package, size=%ld bytes.", length);

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
int swReactorThread_send_in_buffer(swReactorThread *thread, swConnection *conn)
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

/**
 * unix socket dgram thread
 */
static int swReactorThread_loop_unix_dgram(swThreadParam *param)
{
    int n;
    swServer *serv = param->object;
    swDispatchData task;
    struct sockaddr_un addr_un;
    socklen_t addrlen = sizeof(struct sockaddr_un);
    int sock = param->pti;

    uint16_t sun_path_offset;
    uint8_t sun_path_len;

    SwooleTG.factory_lock_target = 0;
    SwooleTG.factory_target_worker = -1;
    SwooleTG.id = param->pti;
    SwooleTG.type = SW_THREAD_UNIX_DGRAM;

    swSignal_none();

    //blocking
    swSetBlock(sock);

    bzero(&task.data.info, sizeof(task.data.info));
    task.data.info.from_fd = sock;
    task.data.info.type = SW_EVENT_UNIX_DGRAM;
    int buffer_size = SW_IPC_MAX_SIZE - sizeof(struct _swDataHead) - sizeof(addr_un.sun_path);

    while (SwooleG.running == 1)
    {
        n = recvfrom(sock, task.data.data, buffer_size, 0, (struct sockaddr *) &addr_un, &addrlen);
        if (n > 0)
        {
            //unix dgram, swDataHead + data + sun_path
            sun_path_len = strlen(addr_un.sun_path) + 1;
            sun_path_offset = n;
            task.data.info.fd = sun_path_offset;
            task.data.info.len = n + sun_path_len;
            task.target_worker_id = -1;
            memcpy(task.data.data + n, addr_un.sun_path, sun_path_len);
            swTrace("recvfrom udp socket.fd=%d|data=%s", sock, task.data.data);

            n = serv->factory.dispatch(&serv->factory, &task);
            if (n < 0)
            {
                swWarn("factory->dispatch[udp packet] fail\n");
            }
        }
    }
    pthread_exit(0);
    return 0;
}

void swReactorThread_free(swServer *serv)
{
    int i;
    swReactorThread *thread;

    if (SwooleGS->start == 0)
    {
        return;
    }

    if (serv->have_tcp_sock == 1)
    {
        for (i = 0; i < serv->reactor_num; i++)
        {
            thread = &(serv->reactor_threads[i]);
            thread->reactor.running = 0;
            SW_START_SLEEP;
            pthread_cancel(thread->thread_id);
            //wait thread
            if (pthread_join(thread->thread_id, NULL))
            {
                swWarn("pthread_join() failed. Error: %s[%d]", strerror(errno), errno);
            }
            //release the lock
            SwooleGS->lock.unlock(&SwooleGS->lock);
#ifdef SW_USE_RINGBUFFER
            thread->buffer_input->destroy(thread->buffer_input);
#endif
        }
    }

    if (serv->have_udp_sock == 1)
    {
        swListenPort *ls;
        LL_FOREACH(serv->listen_list, ls)
        {
            if (ls->type == SW_SOCK_UDP || ls->type == SW_SOCK_UDP6 || ls->type == SW_SOCK_UNIX_DGRAM)
            {
                pthread_cancel(ls->thread_id);
                if (pthread_join(ls->thread_id, NULL))
                {
                    swWarn("pthread_join() failed. Error: %s[%d]", strerror(errno), errno);
                }
            }
        }
    }
}

