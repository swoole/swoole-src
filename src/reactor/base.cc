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
#include "swoole_socket.h"
#include "swoole_reactor.h"
#include "coroutine_c_api.h"
#include <system_error>

using swoole::CallbackManager;
using swoole::Reactor;

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

Reactor::Reactor(int max_event)
{
    int ret;

#ifdef HAVE_EPOLL
    ret = swReactorEpoll_create(this, max_event);
#elif defined(HAVE_KQUEUE)
    ret = swReactorKqueue_create(this, max_event);
#elif defined(HAVE_POLL)
    ret = swReactorPoll_create(this, max_event);
#else
    ret = swReactorSelect_create(this);
#endif

    if (ret < 0)
    {
        throw std::system_error();
    }

    running = 1;

    onFinish = reactor_finish;
    onTimeout = reactor_timeout;
    can_exit = SwooleG.reactor_can_exit;

    write = swReactor_write;
    close = swReactor_close;

    default_write_handler = swReactor_onWrite;

    if (SwooleG.hooks[SW_GLOBAL_HOOK_ON_REACTOR_CREATE])
    {
        swoole_call_hook(SW_GLOBAL_HOOK_ON_REACTOR_CREATE, this);
    }

    add_end_callback(SW_REACTOR_PRIORITY_DEFER_TASKS, [this](void *)
    {
        CallbackManager *cm = defer_tasks;
        defer_tasks = nullptr;
        cm->execute();
        delete cm;
    });

    add_end_callback(SW_REACTOR_PRIORITY_IDLE_TASK, [this](void *)
    {
        if (idle_task.callback)
        {
            idle_task.callback(idle_task.data);
        }
    });

    add_end_callback(SW_REACTOR_PRIORITY_SIGNAL_CALLBACK, [this](void *)
    {
        if (sw_unlikely(singal_no))
        {
            swSignal_callback(singal_no);
            singal_no = 0;
        }
    });

    add_end_callback(SW_REACTOR_PRIORITY_TRY_EXIT, [this](void *)
    {
        if (wait_exit && is_empty(this))
        {
            running = 0;
        }
    });

#ifdef SW_USE_MALLOC_TRIM
    add_end_callback(SW_REACTOR_PRIORITY_MALLOC_TRIM, [this](void *)
    {
        time_t now = ::time(nullptr);
        if (last_malloc_trim_time < now - SW_MALLOC_TRIM_INTERVAL)
        {
            malloc_trim(SW_MALLOC_TRIM_PAD);
            last_malloc_trim_time = now;
        }
    });
#endif
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

int swReactor_empty(swReactor *reactor)
{
//    if (reactor->timer && reactor->timer->num > 0)
//    {
//        return SW_FALSE;
//    }
    if (reactor->defer_tasks)
    {
        return SW_FALSE;
    }
    if (swoole_coroutine_wait_count() > 0)
    {
        return SW_FALSE;
    }
    if (reactor->co_signal_listener_num > 0)
    {
        return SW_FALSE;
    }
    if (reactor->signal_listener_num > 0 && SwooleG.wait_signal)
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
    //custom
    if (reactor->can_exit && !reactor->can_exit(reactor))
    {
        empty = SW_FALSE;
    }
    return empty;
}

/**
 * execute when reactor timeout and reactor finish
 */
static void reactor_finish(swReactor *reactor)
{
    for (auto kv : reactor->end_callbacks)
    {
        kv.second(reactor);
    }
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

int swReactor_close(swReactor *reactor, swSocket *socket)
{
    if (socket->out_buffer)
    {
        swBuffer_free(socket->out_buffer);
        socket->out_buffer = nullptr;
    }
    if (socket->in_buffer)
    {
        swBuffer_free(socket->in_buffer);
        socket->in_buffer = nullptr;
    }

    swTraceLog(SW_TRACE_CLOSE, "fd=%d", socket->fd);

    swSocket_free(socket);

    return SW_OK;
}

int swReactor_write(swReactor *reactor, swSocket *socket, const void *buf, int n)
{
    int ret;
    swBuffer *buffer = socket->out_buffer;
    const char *ptr = (const char *) buf;
    int fd = socket->fd;

    if (socket->buffer_size == 0)
    {
        socket->buffer_size = SwooleG.socket_buffer_size;
    }

    if (socket->nonblock == 0)
    {
        swoole_fcntl_set_option(socket->fd, 1, -1);
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
        ret = swSocket_send(socket, ptr, n, 0);

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
        else if (swSocket_error(errno) == SW_WAIT)
        {
            _do_buffer:
            if (!socket->out_buffer)
            {
                buffer = swBuffer_new(socket->chunk_size);
                if (!buffer)
                {
                    swWarn("create worker buffer failed");
                    return SW_ERR;
                }
                socket->out_buffer = buffer;
            }

            swReactor_add_write_event(reactor, socket);
            goto _append_buffer;
        }
        else if (errno == EINTR)
        {
            goto _do_send;
        }
        else
        {
            swoole_set_last_error(errno);
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
                swoole_set_last_error(SW_ERROR_OUTPUT_BUFFER_OVERFLOW);
                return SW_ERR;
            }
            else
            {
                swoole_error_log(SW_LOG_WARNING, SW_ERROR_OUTPUT_BUFFER_OVERFLOW, "socket#%d output buffer overflow", fd);
                swYield();
                swSocket_wait(socket->fd, SW_SOCKET_OVERFLOW_WAIT, SW_EVENT_WRITE);
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

    swSocket *socket = ev->socket;
    swBuffer_chunk *chunk = nullptr;
    swBuffer *buffer = socket->out_buffer;

    //send to socket
    while (!swBuffer_empty(buffer))
    {
        chunk = swBuffer_get_chunk(buffer);
        if (chunk->type == SW_CHUNK_CLOSE)
        {
            _close_fd:
            reactor->close(reactor, ev->socket);
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
        swReactor_remove_write_event(reactor, ev->socket);
    }

    return SW_OK;
}

int swReactor_wait_write_buffer(swReactor *reactor, swSocket *socket)
{
    swEvent event = {};

    if (!swBuffer_empty(socket->out_buffer))
    {
        swSocket_set_block(socket);
        event.socket = socket;
        event.fd = socket->fd;
        return swReactor_onWrite(reactor, &event);
    }
    
    return SW_OK;
}

void Reactor::add_destroy_callback(swCallback cb, void *data)
{
    destroy_callbacks.append(cb, data);
}

void Reactor::add_end_callback(int priority, swCallback fn)
{
    end_callbacks.emplace(std::make_pair(priority, fn));
}

void Reactor::defer(swCallback cb, void *data)
{
    if (defer_tasks == nullptr)
    {
        defer_tasks = new CallbackManager;
    }
    defer_tasks->append(cb, data);
}

Reactor::~Reactor()
{
    destroy_callbacks.execute();
    this->free(this);
}
