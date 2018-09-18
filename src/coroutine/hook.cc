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

#include "socket.h"
#include "async.h"
#include "coroutine.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/poll.h>
#include <string>
#include <iostream>

using namespace swoole;
using namespace std;

extern "C"
{

int swoole_coroutine_socket(int domain, int type, int protocol)
{
    if (SwooleG.main_reactor == nullptr || coroutine_get_current_cid() == -1)
    {
        return socket(domain, type, protocol);
    }
    enum swSocket_type sock_type = get_socket_type(domain, type, protocol);
    Socket *sock = new Socket(sock_type);
    return sock->socket->fd;
}

ssize_t swoole_coroutine_send(int sockfd, const void *buf, size_t len, int flags)
{
    if (SwooleG.main_reactor == nullptr || coroutine_get_current_cid() == -1)
    {
        _no_coro: return ::send(sockfd, buf, len, flags);
    }
    swConnection *conn = swReactor_get(SwooleG.main_reactor, sockfd);
    if (conn == nullptr)
    {
        goto _no_coro;
    }
    Socket *socket = (Socket *) conn->object;
    ssize_t retval = socket->send(buf, len);
    if (retval < 0)
    {
        errno = socket->errCode;
        return -1;
    }
    else
    {
        errno = 0;
        return retval;
    }
}

ssize_t swoole_coroutine_sendmsg(int sockfd, const struct msghdr *msg, int flags)
{
    if (SwooleG.main_reactor == nullptr || coroutine_get_current_cid() == -1)
    {
        _no_coro: return ::sendmsg(sockfd, msg, flags);
    }
    swConnection *conn = swReactor_get(SwooleG.main_reactor, sockfd);
    if (conn == nullptr)
    {
        goto _no_coro;
    }
    Socket *socket = (Socket *) conn->object;
    ssize_t retval = socket->sendmsg(msg, flags);
    if (retval < 0)
    {
        errno = socket->errCode;
        return -1;
    }
    else
    {
        errno = 0;
        return retval;
    }
}

ssize_t swoole_coroutine_recvmsg(int sockfd, struct msghdr *msg, int flags)
{
    if (SwooleG.main_reactor == nullptr || coroutine_get_current_cid() == -1)
    {
        _no_coro: return ::recvmsg(sockfd, msg, flags);
    }
    swConnection *conn = swReactor_get(SwooleG.main_reactor, sockfd);
    if (conn == nullptr)
    {
        goto _no_coro;
    }
    Socket *socket = (Socket *) conn->object;
    ssize_t retval = socket->recvmsg(msg, flags);
    if (retval < 0)
    {
        errno = socket->errCode;
        return -1;
    }
    else
    {
        errno = 0;
        return retval;
    }
}

ssize_t swoole_coroutine_recv(int sockfd, void *buf, size_t len, int flags)
{
    if (SwooleG.main_reactor == nullptr || coroutine_get_current_cid() == -1)
    {
        _no_coro: return ::recv(sockfd, buf, len, flags);
    }
    swConnection *conn = swReactor_get(SwooleG.main_reactor, sockfd);
    if (conn == nullptr)
    {
        goto _no_coro;
    }
    Socket *socket = (Socket *) conn->object;
    ssize_t retval = socket->recv(buf, len);
    if (retval < 0)
    {
        errno = socket->errCode;
        return -1;
    }
    else
    {
        errno = 0;
        return retval;
    }
}

int swoole_coroutine_close(int fd)
{
    if (SwooleG.main_reactor == nullptr || coroutine_get_current_cid() == -1)
    {
        _no_coro: return close(fd);
    }
    swConnection *conn = swReactor_get(SwooleG.main_reactor, fd);
    if (conn == nullptr)
    {
        goto _no_coro;
    }
    else
    {
        delete (Socket *) conn->object;
        return 0;
    }
}

int swoole_coroutine_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    if (SwooleG.main_reactor == nullptr || coroutine_get_current_cid() == -1)
    {
        _no_coro: return connect(sockfd, addr, addrlen);
    }
    swConnection *conn = swReactor_get(SwooleG.main_reactor, sockfd);
    if (conn == nullptr)
    {
        goto _no_coro;
    }
    Socket *socket = (Socket *) conn->object;
    if (socket->connect(addr, addrlen) == false)
    {
        errno = socket->errCode;
        return -1;
    }
    else
    {
        errno = 0;
        return 0;
    }
}

int swoole_coroutine_poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
    if (SwooleG.main_reactor == nullptr || coroutine_get_current_cid() == -1 || nfds != 1)
    {
        _poll: return poll(fds, nfds, timeout);
    }
    swConnection *conn = swReactor_get(SwooleG.main_reactor, fds[0].fd);
    if (conn == nullptr)
    {
        goto _poll;
    }
    Socket *socket = (Socket *) conn->object;
    socket->setTimeout((double) timeout / 1000);
    if (fds[0].events & POLLIN)
    {
        fds[0].revents |= POLLIN;
    }
    if (fds[0].events & POLLOUT)
    {
        fds[0].revents |= POLLOUT;
    }
    return 1;
}

static void handler_access(swAio_event *event)
{
    event->ret = access((const char*) event->buf, event->offset);
    event->error = errno;
}

static void handler_open(swAio_event *event)
{
    event->ret = open((const char*) event->buf, event->flags, event->offset);
    event->error = errno;
}

static void handler_read(swAio_event *event)
{
    event->ret = read(event->fd, event->buf, event->nbytes);
    event->error = errno;
}

static void handler_write(swAio_event *event)
{
    event->ret = write(event->fd, event->buf, event->nbytes);
    event->error = errno;
}

static void handler_lseek(swAio_event *event)
{
    event->ret = lseek(event->fd, event->offset, event->flags);
    event->error = errno;
}

static void handler_fstat(swAio_event *event)
{
    event->ret = fstat(event->fd, (struct stat *) event->buf);
    event->error = errno;
}

static void handler_unlink(swAio_event *event)
{
    event->ret = unlink((const char*) event->buf);
    event->error = errno;
}

static void handler_mkdir(swAio_event *event)
{
    event->ret = mkdir((const char*) event->buf, event->offset);
    event->error = errno;
}

static void handler_rmdir(swAio_event *event)
{
    event->ret = rmdir((const char*) event->buf);
    event->error = errno;
}

static void handler_rename(swAio_event *event)
{
    event->ret = rename((const char*) event->buf, (const char*) event->offset);
    event->error = errno;
}

static void aio_onCompleted(swAio_event *event)
{
    swAio_event *ev = (swAio_event *) event->req;
    ev->ret = event->ret;
    errno = event->error;
    coroutine_resume((coroutine_t *) event->object);
}

static void sleep_timeout(swTimer *timer, swTimer_node *tnode)
{
    coroutine_resume((coroutine_t *) tnode->data);
}

int swoole_coroutine_open(const char *pathname, int flags, mode_t mode)
{
    if (SwooleG.main_reactor == nullptr || coroutine_get_current_cid() == -1)
    {
        return open(pathname, flags, mode);
    }

    swAio_event ev;
    bzero(&ev, sizeof(ev));
    ev.buf = (void*) pathname;
    ev.offset = mode;
    ev.flags = flags;
    ev.handler = handler_open;
    ev.callback = aio_onCompleted;
    ev.object = coroutine_get_current();
    ev.req = &ev;

    int ret = swAio_dispatch(&ev);
    if (ret < 0)
    {
        return SW_ERR;
    }
    coroutine_yield((coroutine_t *) ev.object);
    return ev.ret;
}

ssize_t swoole_coroutine_read(int fd, void *buf, size_t count)
{
    if (SwooleG.main_reactor == nullptr || coroutine_get_current_cid() == -1)
    {
        return read(fd, buf, count);
    }

    swAio_event ev;
    bzero(&ev, sizeof(ev));
    ev.fd = fd;
    ev.buf = buf;
    ev.nbytes = count;
    ev.handler = handler_read;
    ev.callback = aio_onCompleted;
    ev.object = coroutine_get_current();
    ev.req = &ev;

    int ret = swAio_dispatch(&ev);
    if (ret < 0)
    {
        return SW_ERR;
    }
    coroutine_yield((coroutine_t *) ev.object);
    return ev.ret;
}

ssize_t swoole_coroutine_write(int fd, const void *buf, size_t count)
{
    if (SwooleG.main_reactor == nullptr || coroutine_get_current_cid() == -1)
    {
        return write(fd, buf, count);
    }

    swAio_event ev;
    bzero(&ev, sizeof(ev));
    ev.fd = fd;
    ev.buf = (void*) buf;
    ev.nbytes = count;
    ev.handler = handler_write;
    ev.callback = aio_onCompleted;
    ev.object = coroutine_get_current();
    ev.req = &ev;

    int ret = swAio_dispatch(&ev);
    if (ret < 0)
    {
        return SW_ERR;
    }
    coroutine_yield((coroutine_t *) ev.object);
    return ev.ret;
}

off_t swoole_coroutine_lseek(int fd, off_t offset, int whence)
{
    if (SwooleG.main_reactor == nullptr || coroutine_get_current_cid() == -1)
    {
        return lseek(fd, offset, whence);
    }

    swAio_event ev;
    bzero(&ev, sizeof(ev));
    ev.fd = fd;
    ev.offset = offset;
    ev.flags = whence;
    ev.handler = handler_lseek;
    ev.callback = aio_onCompleted;
    ev.object = coroutine_get_current();
    ev.req = &ev;

    int ret = swAio_dispatch(&ev);
    if (ret < 0)
    {
        return SW_ERR;
    }
    coroutine_yield((coroutine_t *) ev.object);
    return ev.ret;
}

int swoole_coroutine_fstat(int fd, struct stat *statbuf)
{
    if (SwooleG.main_reactor == nullptr || coroutine_get_current_cid() == -1)
    {
        return fstat(fd, statbuf);
    }

    swAio_event ev;
    bzero(&ev, sizeof(ev));
    ev.fd = fd;
    ev.buf = (void*) statbuf;
    ev.handler = handler_fstat;
    ev.callback = aio_onCompleted;
    ev.object = coroutine_get_current();
    ev.req = &ev;

    int ret = swAio_dispatch(&ev);
    if (ret < 0)
    {
        return SW_ERR;
    }
    coroutine_yield((coroutine_t *) ev.object);
    return ev.ret;
}

int swoole_coroutine_unlink(const char *pathname)
{
    if (SwooleG.main_reactor == nullptr || coroutine_get_current_cid() == -1)
    {
        return unlink(pathname);
    }

    swAio_event ev;
    bzero(&ev, sizeof(ev));
    ev.buf = (void*) pathname;
    ev.handler = handler_unlink;
    ev.callback = aio_onCompleted;
    ev.object = coroutine_get_current();
    ev.req = &ev;

    int ret = swAio_dispatch(&ev);
    if (ret < 0)
    {
        return SW_ERR;
    }
    coroutine_yield((coroutine_t *) ev.object);
    return ev.ret;
}

int swoole_coroutine_mkdir(const char *pathname, mode_t mode)
{
    if (SwooleG.main_reactor == nullptr || coroutine_get_current_cid() == -1)
    {
        return mkdir(pathname, mode);
    }

    swAio_event ev;
    bzero(&ev, sizeof(ev));
    ev.buf = (void*) pathname;
    ev.offset = mode;
    ev.handler = handler_mkdir;
    ev.callback = aio_onCompleted;
    ev.object = coroutine_get_current();
    ev.req = &ev;

    int ret = swAio_dispatch(&ev);
    if (ret < 0)
    {
        return SW_ERR;
    }
    coroutine_yield((coroutine_t *) ev.object);
    return ev.ret;
}

int swoole_coroutine_rmdir(const char *pathname)
{
    if (SwooleG.main_reactor == nullptr || coroutine_get_current_cid() == -1)
    {
        return rmdir(pathname);
    }

    swAio_event ev;
    bzero(&ev, sizeof(ev));
    ev.buf = (void*) pathname;
    ev.handler = handler_rmdir;
    ev.callback = aio_onCompleted;
    ev.object = coroutine_get_current();
    ev.req = &ev;

    int ret = swAio_dispatch(&ev);
    if (ret < 0)
    {
        return SW_ERR;
    }
    coroutine_yield((coroutine_t *) ev.object);
    return ev.ret;
}

int swoole_coroutine_rename(const char *oldpath, const char *newpath)
{
    if (SwooleG.main_reactor == nullptr || coroutine_get_current_cid() == -1)
    {
        return rename(oldpath, newpath);
    }

    swAio_event ev;
    bzero(&ev, sizeof(ev));
    ev.buf = (void*) oldpath;
    ev.offset = (off_t) newpath;
    ev.handler = handler_rename;
    ev.callback = aio_onCompleted;
    ev.object = coroutine_get_current();
    ev.req = &ev;

    int ret = swAio_dispatch(&ev);
    if (ret < 0)
    {
        return SW_ERR;
    }
    coroutine_yield((coroutine_t *) ev.object);
    return ev.ret;
}

int swoole_coroutine_access(const char *pathname, int mode)
{
    if (SwooleG.main_reactor == nullptr || coroutine_get_current_cid() == -1)
    {
        return access(pathname, mode);
    }

    swAio_event ev;
    bzero(&ev, sizeof(ev));
    ev.buf = (void*) pathname;
    ev.offset = mode;
    ev.handler = handler_access;
    ev.callback = aio_onCompleted;
    ev.object = coroutine_get_current();
    ev.req = &ev;

    int ret = swAio_dispatch(&ev);
    if (ret < 0)
    {
        return SW_ERR;
    }
    coroutine_yield((coroutine_t *) ev.object);
    return ev.ret;
}

int swoole_coroutine_sleep(double sec)
{
    coroutine_t* co = coroutine_get_current();
    if (SwooleG.timer.add(&SwooleG.timer, sec * 1000, 0, co, sleep_timeout) == NULL)
    {
        return -1;
    }
    coroutine_yield(co);
    return 0;
}

}

