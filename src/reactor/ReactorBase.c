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
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
  +----------------------------------------------------------------------+
*/

#include "swoole.h"
#include "Connection.h"

static void swReactor_onTimeout_and_Finish(swReactor *reactor);
static void swReactor_onTimeout(swReactor *reactor);
static void swReactor_onFinish(swReactor *reactor);
static int swReactor_write(swReactor *reactor, int fd, void *buf, int n);

int swReactor_auto(swReactor *reactor, int max_event)
{
    int ret;

    bzero(reactor, sizeof(swReactor));

    //event less than SW_REACTOR_MINEVENTS, use poll/select
    if (max_event <= SW_REACTOR_MINEVENTS)
    {
#ifdef SW_MAINREACTOR_USE_POLL
        ret = swReactorPoll_create(reactor, SW_REACTOR_MINEVENTS);
#else
        ret = swReactorSelect_create(reactor);
#endif
    }
    //use epoll or kqueue
    else
    {
#ifdef HAVE_EPOLL
        ret = swReactorEpoll_create(reactor, max_event);
#elif defined(HAVE_KQUEUE)
        ret = swReactorKqueue_create(reactor, max_event);
#elif defined(SW_MAINREACTOR_USE_POLL)
        ret = swReactorPoll_create(reactor, max_event);
#else
        ret = swReactorSelect_create(SwooleG.main_reactor);
#endif
    }

    reactor->onFinish = swReactor_onFinish;
    reactor->onTimeout = swReactor_onTimeout;

    reactor->write = swReactor_write;
    reactor->close = swReactor_close;

    return ret;
}

swReactor_handle swReactor_getHandle(swReactor *reactor, int event_type, int fdtype)
{
    if (event_type == SW_EVENT_WRITE)
    {
        return (reactor->write_handle[fdtype] != NULL) ? reactor->write_handle[fdtype] : reactor->handle[SW_FD_WRITE];
    }
    if (event_type == SW_EVENT_ERROR)
    {
        return (reactor->error_handle[fdtype] != NULL) ? reactor->error_handle[fdtype] : reactor->handle[SW_FD_CLOSE];
    }
    return reactor->handle[fdtype];
}

int swReactor_setHandle(swReactor *reactor, int _fdtype, swReactor_handle handle)
{
    int fdtype = swReactor_fdtype(_fdtype);

    if (fdtype >= SW_MAX_FDTYPE)
    {
        swWarn("fdtype > SW_MAX_FDTYPE[%d]", SW_MAX_FDTYPE);
        return SW_ERR;
    }

    if (swReactor_event_read(_fdtype))
    {
        reactor->handle[fdtype] = handle;
    }
    else if (swReactor_event_write(_fdtype))
    {
        reactor->write_handle[fdtype] = handle;
    }
    else if (swReactor_event_error(_fdtype))
    {
        reactor->error_handle[fdtype] = handle;
    }
    else
    {
        swWarn("unknow fdtype");
        return SW_ERR;
    }

    return SW_OK;
}

int swReactor_add(swReactor *reactor, int fd, int fdtype)
{
    if (fd >= reactor->max_socket)
    {
        if (reactor->thread || fd > SwooleG.max_sockets)
        {
            swWarn("fd[%d] is invalid.", fd);
            return SW_ERR;
        }

        if (reactor->max_socket == 0)
        {
            reactor->max_socket = fd * 2;
            reactor->sockets = sw_calloc(reactor->max_socket, sizeof(swConnection));
        }
        else
        {
            int max_socket = reactor->max_socket * 2;
            if (max_socket > SwooleG.max_sockets)
            {
                max_socket = SwooleG.max_sockets + 1;
            }
            reactor->sockets = sw_calloc(max_socket, sizeof(swConnection));
            reactor->max_socket = max_socket;
        }

        if (!reactor->sockets)
        {
            swSysError("Fatal Error: malloc(%ld) failed.", reactor->max_socket * sizeof(swConnection));
            return SW_ERR;
        }
    }

    reactor->sockets[fd].active = 1;
    reactor->sockets[fd].fd = fd;
    reactor->sockets[fd].type = swReactor_fdtype(fdtype);
    reactor->sockets[fd].events = swReactor_events(fdtype);

    return SW_OK;
}

int swReactor_del(swReactor *reactor, int fd)
{
    assert(fd < reactor->max_socket);

    reactor->sockets[fd].active = 0;
    reactor->sockets[fd].events = 0;

    return SW_OK;
}

/**
 * execute when reactor timeout and reactor finish
 */
static void swReactor_onTimeout_and_Finish(swReactor *reactor)
{
    //check timer
    if (reactor->check_timer)
    {
        SwooleG.timer.select(&SwooleG.timer);
    }
    if (SwooleG.serv && swIsMaster())
    {
        swoole_update_time();
    }
}

static void swReactor_onTimeout(swReactor *reactor)
{
    swReactor_onTimeout_and_Finish(reactor);
}

static void swReactor_onFinish(swReactor *reactor)
{
    //client exit
    if (SwooleG.serv == NULL && reactor->event_num == 0)
    {
        SwooleG.running = 0;
    }
    //check signal
    if (reactor->singal_no)
    {
        swSignal_callback(reactor->singal_no);
        reactor->singal_no = 0;
    }
    swReactor_onTimeout_and_Finish(reactor);
}

int swReactor_close(swReactor *reactor, int fd)
{
    swConnection *socket = &reactor->sockets[fd];

    if (socket->out_buffer != NULL)
    {
        swBuffer_free(socket->out_buffer);
        socket->out_buffer = NULL;
    }
    if (socket->in_buffer != NULL)
    {
        swBuffer_free(socket->in_buffer);
        socket->in_buffer = NULL;
    }
#ifdef SW_USE_OPENSSL
    if (socket->ssl)
    {
        swSSL_close(socket);
    }
#endif

    bzero(socket, sizeof(swConnection));

    return close(fd);
}

static int swReactor_write(swReactor *reactor, int fd, void *buf, int n)
{
    int ret;
    swConnection *socket = &reactor->sockets[fd];
    swBuffer *buffer = socket->out_buffer;
    socket->fd = fd;

    if (swBuffer_empty(buffer))
    {
        ret = swConnection_send(socket, buf, n, 0);

        if (ret < 0 && errno == EAGAIN)
        {
            if (!socket->out_buffer)
            {
                buffer = swBuffer_new(sizeof(swEventData));
                if (!buffer)
                {
                    swWarn("create worker buffer failed.");
                    return SW_ERR;
                }
                socket->out_buffer = buffer;
            }

            socket->events |= SW_EVENT_WRITE;

            if (socket->events & SW_EVENT_READ)
            {
                 SwooleG.main_reactor->set(SwooleG.main_reactor, fd, socket->type | socket->events);
            }
            else
            {
                SwooleG.main_reactor->add(SwooleG.main_reactor, fd, socket->type | socket->events);
            }
            goto append_pipe_buffer;
        }
    }
    else
    {
        append_pipe_buffer:
        if (swBuffer_append(buffer, buf, n) < 0)
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

    swConnection *socket = &reactor->sockets[fd];
    swBuffer_trunk *chunk = NULL;
    swBuffer *buffer = socket->out_buffer;

    //send to socket
    while (!swBuffer_empty(buffer))
    {
        chunk = swBuffer_get_trunk(buffer);
        if (chunk->type == SW_CHUNK_CLOSE)
        {
            close_fd:
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
                goto close_fd;
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
        socket->events &= ~SW_EVENT_WRITE;

        if (socket->events & SW_EVENT_READ)
        {
            ret = reactor->set(reactor, fd, socket->type | socket->events);
        }
        else
        {
            ret = reactor->del(reactor, fd);
        }
        if (ret < 0)
        {
            swSysError("reactor->set() failed.");
        }
    }
    return SW_OK;
}

