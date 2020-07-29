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
#include "client.h"
#include "swoole_cxx.h"
#include "async.h"

#include "coroutine_c_api.h"
#include "coroutine_socket.h"
#include "coroutine_system.h"

using swoole::CallbackManager;
using swoole::coroutine::Socket;
using swoole::coroutine::System;

#ifdef SW_USE_MALLOC_TRIM
#ifdef __APPLE__
#include <sys/malloc.h>
#else
#include <malloc.h>
#endif
#endif

static void reactor_timeout(swReactor *reactor);
static void reactor_finish(swReactor *reactor);
static void reactor_begin(swReactor *reactor);
static void defer_task_do(swReactor *reactor);
static void defer_task_add(swReactor *reactor, swCallback callback, void *data);

int swReactor_create(swReactor *reactor, int max_event)
{
    int ret;
    bzero(reactor, sizeof(swReactor));

#ifdef HAVE_EPOLL
    ret = swReactorEpoll_create(reactor, max_event);
#elif defined(HAVE_KQUEUE)
    ret = swReactorKqueue_create(reactor, max_event);
#elif defined(HAVE_POLL)
    ret = swReactorPoll_create(reactor, max_event);
#else
    ret = swReactorSelect_create(reactor);
#endif

    reactor->running = 1;

    reactor->onFinish = reactor_finish;
    reactor->onTimeout = reactor_timeout;
    reactor->is_empty = swReactor_empty;

    reactor->write = swReactor_write;
    reactor->close = swReactor_close;

    reactor->defer = defer_task_add;
    reactor->defer_tasks = nullptr;

    reactor->socket_array = SwooleG.socket_array;
    reactor->default_write_handler = swReactor_onWrite;

    Socket::init_reactor(reactor);
    System::init_reactor(reactor);
    swClient_init_reactor(reactor);

    if (SwooleG.hooks[SW_GLOBAL_HOOK_ON_REACTOR_CREATE])
    {
        swoole_call_hook(SW_GLOBAL_HOOK_ON_REACTOR_CREATE, reactor);
    }

    return ret;
}

int swReactor_set_handler(swReactor *reactor, int _fdtype, swReactor_handler handle)
{
    int fdtype = swReactor_fdtype(_fdtype);

    if (fdtype >= SW_MAX_FDTYPE)
    {
        swWarn("fdtype > SW_MAX_FDTYPE[%d]", SW_MAX_FDTYPE);
        return SW_ERR;
    }

    if (swReactor_event_read(_fdtype))
    {
        reactor->read_handler[fdtype] = handle;
    }
    else if (swReactor_event_write(_fdtype))
    {
        reactor->write_handler[fdtype] = handle;
    }
    else if (swReactor_event_error(_fdtype))
    {
        reactor->error_handler[fdtype] = handle;
    }
    else
    {
        swWarn("unknow fdtype");
        return SW_ERR;
    }

    return SW_OK;
}

swSocket* swReactor_get(swReactor *reactor, int fd)
{
    swArray *array = reactor->socket_array;
    if (fd >= (array->page_num * array->page_size))
    {
        SwooleG.lock.lock(&SwooleG.lock);
        swSocket *_socket = (swSocket *) swArray_alloc(array, fd);
        SwooleG.lock.unlock(&SwooleG.lock);
        return _socket;
    }
    else
    {
        return (swSocket *) swArray_alloc(array, fd);
    }
}

int swReactor_empty(swReactor *reactor)
{
    //timer, defer tasks
    if ((reactor->timer && reactor->timer->num > 0) || reactor->defer_tasks || swoole_coroutine_wait_count() > 0)
    {
        return SW_FALSE;
    }

    int event_num = reactor->event_num;
    int empty = SW_FALSE;
    //aio thread pool
    if (SwooleTG.aio_init && SwooleTG.aio_task_num == 0)
    {
        event_num--;
    }
    //signalfd
    if (swReactor_isset_handler(reactor, SW_FD_SIGNAL))
    {
        event_num--;
    }
    //no event
    if (event_num == 0)
    {
        empty = SW_TRUE;
    }
    return empty;
}

/**
 * execute when reactor timeout and reactor finish
 */
static void reactor_finish(swReactor *reactor)
{
    //check timer
    if (reactor->check_timer)
    {
        swTimer_select(reactor->timer);
    }
    //defer tasks
    if (reactor->defer_tasks)
    {
        defer_task_do(reactor);
    }
    //callback at the end
    if (reactor->idle_task.callback)
    {
        reactor->idle_task.callback(reactor->idle_task.data);
    }
    //check signal
    if (sw_unlikely(reactor->singal_no))
    {
        swSignal_callback(reactor->singal_no);
        reactor->singal_no = 0;
    }
    //the event loop is empty
    if (reactor->wait_exit && reactor->is_empty(reactor))
    {
        reactor->running = 0;
    }
#ifdef SW_USE_MALLOC_TRIM
    time_t now = time(NULL);
    if (reactor->last_malloc_trim_time < now - SW_MALLOC_TRIM_INTERVAL)
    {
        malloc_trim(SW_MALLOC_TRIM_PAD);
        reactor->last_malloc_trim_time = now;
    }
#endif
}

static void reactor_timeout(swReactor *reactor)
{
    reactor_finish(reactor);
}

void swReactor_activate_future_task(swReactor *reactor)
{
    reactor->onBegin = reactor_begin;
}

static void reactor_begin(swReactor *reactor)
{
    if (reactor->future_task.callback)
    {
        reactor->future_task.callback(reactor->future_task.data);
    }
}

static void socket_close(void *ptr)
{
    swSocket *sock = (swSocket *) ptr;
    if (sock->fd != -1 && close(sock->fd) != 0)
    {
        swSysWarn("close(%d) failed", sock->fd);
    }
}

int swReactor_close(swReactor *reactor, int fd)
{
    swSocket *socket = swReactor_get(reactor, fd);
    if (socket->out_buffer)
    {
        swBuffer_free(socket->out_buffer);
        socket->out_buffer = NULL;
    }
    if (socket->in_buffer)
    {
        swBuffer_free(socket->in_buffer);
        socket->in_buffer = NULL;
    }

    bzero(socket, sizeof(swSocket));
    socket->removed = 1;
    socket->fd = fd;

    swTraceLog(SW_TRACE_CLOSE, "fd=%d", fd);
    swoole_event_defer(socket_close, socket);

    return SW_OK;
}

int swReactor_write(swReactor *reactor, int fd, const void *buf, int n)
{
    int ret;
    swSocket *socket = swReactor_get(reactor, fd);
    swBuffer *buffer = socket->out_buffer;
    const char *ptr = (const char *) buf;

    if (socket->fd <= 0)
    {
        socket->fd = fd;
    }

    if (socket->buffer_size == 0)
    {
        socket->buffer_size = SwooleG.socket_buffer_size;
    }

    if (socket->nonblock == 0)
    {
        swoole_fcntl_set_option(fd, 1, -1);
        socket->nonblock = 1;
    }

    if ((uint32_t) n > socket->buffer_size)
    {
        swoole_error_log(SW_LOG_WARNING, SW_ERROR_PACKAGE_LENGTH_TOO_LARGE, "data is too large, cannot exceed buffer size");
        return SW_ERR;
    }

    if (swBuffer_empty(buffer))
    {
#ifdef SW_USE_OPENSSL
        if (socket->ssl_send)
        {
            goto _do_buffer;
        }
#endif
        _do_send:
        ret = swConnection_send(socket, ptr, n, 0);

        if (ret > 0)
        {
            if (n == ret)
            {
                return ret;
            }
            else
            {
                ptr += ret;
                n -= ret;
                goto _do_buffer;
            }
        }
        else if (swConnection_error(errno) == SW_WAIT)
        {
            _do_buffer:
            if (!socket->out_buffer)
            {
                buffer = swBuffer_new(socket->fdtype == SW_FD_PIPE ? 0 : SW_SEND_BUFFER_SIZE);
                if (!buffer)
                {
                    swWarn("create worker buffer failed");
                    return SW_ERR;
                }
                socket->out_buffer = buffer;
            }

            socket->events |= SW_EVENT_WRITE;

            if (socket->events & SW_EVENT_READ)
            {
                if (reactor->set(reactor, fd, socket->fdtype | socket->events) < 0)
                {
                    swSysWarn("reactor->set(%d, SW_EVENT_WRITE) failed", fd);
                }
            }
            else
            {
                if (reactor->add(reactor, fd, socket->fdtype | SW_EVENT_WRITE) < 0)
                {
                    swSysWarn("reactor->add(%d, SW_EVENT_WRITE) failed", fd);
                }
            }

            goto _append_buffer;
        }
        else if (errno == EINTR)
        {
            goto _do_send;
        }
        else
        {
            SwooleG.error = errno;
            return SW_ERR;
        }
    }
    else
    {
        _append_buffer:
        if (buffer->length > socket->buffer_size)
        {
            if (socket->dontwait)
            {
                SwooleG.error = SW_ERROR_OUTPUT_BUFFER_OVERFLOW;
                return SW_ERR;
            }
            else
            {
                swoole_error_log(SW_LOG_WARNING, SW_ERROR_OUTPUT_BUFFER_OVERFLOW, "socket#%d output buffer overflow", fd);
                swYield();
                swSocket_wait(fd, SW_SOCKET_OVERFLOW_WAIT, SW_EVENT_WRITE);
            }
        }

        if (swBuffer_append(buffer, ptr, n) < 0)
        {
            return SW_ERR;
        }
    }
    return SW_OK;
}

int swReactor_onWrite(swReactor *reactor, swEvent *ev)
{
    int ret;
    int fd = ev->fd;

    swSocket *socket = swReactor_get(reactor, fd);
    swBuffer_chunk *chunk = NULL;
    swBuffer *buffer = socket->out_buffer;

    //send to socket
    while (!swBuffer_empty(buffer))
    {
        chunk = swBuffer_get_chunk(buffer);
        if (chunk->type == SW_CHUNK_CLOSE)
        {
            _close_fd:
            reactor->close(reactor, ev->fd);
            return SW_OK;
        }
        else if (chunk->type == SW_CHUNK_SENDFILE)
        {
            ret = swConnection_onSendfile(socket, chunk);
        }
        else
        {
            ret = swConnection_buffer_send(socket);
        }

        if (ret < 0)
        {
            if (socket->close_wait)
            {
                goto _close_fd;
            }
            else if (socket->send_wait)
            {
                return SW_OK;
            }
        }
    }

    //remove EPOLLOUT event
    if (swBuffer_empty(buffer))
    {
        swReactor_remove_write_event(reactor, fd);
    }

    return SW_OK;
}

int swReactor_wait_write_buffer(swReactor *reactor, int fd)
{
    swSocket *conn = swReactor_get(reactor, fd);
    swEvent event;

    if (!swBuffer_empty(conn->out_buffer))
    {
        swSocket_set_blocking(fd);
        event.fd = fd;
        return swReactor_onWrite(reactor, &event);
    }
    return SW_OK;
}

void swReactor_add_destroy_callback(swReactor *reactor, swCallback cb, void *data)
{
    CallbackManager *cm = (CallbackManager *) reactor->destroy_callbacks;
    if (cm == nullptr)
    {
        cm = new CallbackManager;
        reactor->destroy_callbacks = cm;
    }
    cm->append(cb, data);
}

static void defer_task_do(swReactor *reactor)
{
    CallbackManager *cm = (CallbackManager *) reactor->defer_tasks;
    reactor->defer_tasks = nullptr;
    cm->execute();
    delete cm;
}

static void defer_task_add(swReactor *reactor, swCallback callback, void *data)
{
    CallbackManager *cm = (CallbackManager *) reactor->defer_tasks;
    if (cm == nullptr)
    {
        cm = new CallbackManager;
        reactor->defer_tasks = cm;
    }
    cm->append(callback, data);
}

void swReactor_destroy(swReactor *reactor)
{
    if (reactor->destroy_callbacks)
    {
        CallbackManager *cm = (CallbackManager *) reactor->destroy_callbacks;
        cm->execute();
        reactor->destroy_callbacks = nullptr;
        delete cm;
    }
    reactor->free(reactor);
}
