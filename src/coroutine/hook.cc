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

#include "swoole_cxx.h"
#include "coroutine_cxx_api.h"

#include <sys/file.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <poll.h>
#include <dirent.h>
#include <string>
#include <iostream>
#include <unordered_map>

using swoole::Coroutine;
using swoole::coroutine::Socket;
using swoole::coroutine::System;
using std::unordered_map;

static unordered_map<int, Socket *> socket_map;

Socket* swoole_coroutine_get_socket_object(int sockfd)
{
    return socket_map[sockfd];
}

SW_EXTERN_C_BEGIN

int swoole_coroutine_socket(int domain, int type, int protocol)
{
    if (sw_unlikely(SwooleTG.reactor == nullptr || !Coroutine::get_current()))
    {
        return socket(domain, type, protocol);
    }
    Socket *socket = new Socket(domain, type, protocol);
    int fd = socket->get_fd();
    if (sw_unlikely(fd < 0))
    {
        delete socket;
    }
    else
    {
        socket_map[fd] = socket;
    }
    return fd;
}

ssize_t swoole_coroutine_send(int sockfd, const void *buf, size_t len, int flags)
{
    if (sw_unlikely(SwooleTG.reactor == nullptr || !Coroutine::get_current()))
    {
        _no_coro: return ::send(sockfd, buf, len, flags);
    }
    Socket *socket = socket_map[sockfd];
    if (socket == nullptr)
    {
        goto _no_coro;
    }
    return socket->send(buf, len);
}

ssize_t swoole_coroutine_sendmsg(int sockfd, const struct msghdr *msg, int flags)
{
    if (sw_unlikely(SwooleTG.reactor == nullptr || !Coroutine::get_current()))
    {
        _no_coro: return ::sendmsg(sockfd, msg, flags);
    }
    Socket *socket = socket_map[sockfd];
    if (socket == nullptr)
    {
        goto _no_coro;
    }
    return socket->sendmsg(msg, flags);
}

ssize_t swoole_coroutine_recvmsg(int sockfd, struct msghdr *msg, int flags)
{
    if (sw_unlikely(SwooleTG.reactor == nullptr || !Coroutine::get_current()))
    {
        _no_coro: return ::recvmsg(sockfd, msg, flags);
    }
    Socket *socket = socket_map[sockfd];
    if (socket == nullptr)
    {
        goto _no_coro;
    }
    return socket->recvmsg(msg, flags);
}

ssize_t swoole_coroutine_recv(int sockfd, void *buf, size_t len, int flags)
{
    if (sw_unlikely(SwooleTG.reactor == nullptr || !Coroutine::get_current()))
    {
        _no_coro: return ::recv(sockfd, buf, len, flags);
    }
    Socket *socket = socket_map[sockfd];
    if (socket == nullptr)
    {
        goto _no_coro;
    }
    if (flags & MSG_PEEK)
    {
        return socket->peek(buf, len);
    }
    else
    {
        return socket->recv(buf, len);
    }
}

int swoole_coroutine_close(int sockfd)
{
    Socket *socket = socket_map[sockfd];
    if (socket == nullptr)
    {
        errno = EBADFD;
        return SW_ERR;
    }
    if (socket->close())
    {
        delete socket;
        socket_map.erase(sockfd);
        return 0;
    }
    else
    {
        return -1;
    }
}

int swoole_coroutine_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    if (sw_unlikely(SwooleTG.reactor == nullptr || !Coroutine::get_current()))
    {
        _no_coro: return connect(sockfd, addr, addrlen);
    }
    Socket *socket = socket_map[sockfd];
    if (socket == nullptr)
    {
        goto _no_coro;
    }
    return socket->connect(addr, addrlen) ? 0 : -1;
}

#if 1
int swoole_coroutine_poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
    if (sw_unlikely(SwooleTG.reactor == nullptr || !Coroutine::get_current() || nfds != 1 || timeout == 0))
    {
        _poll: return poll(fds, nfds, timeout);
    }
    Socket *socket = socket_map[fds[0].fd];
    if (socket == nullptr)
    {
        goto _poll;
    }
    socket->set_timeout((double) timeout / 1000);
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
#else
int swoole_coroutine_poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
    if (sw_unlikely(SwooleTG.reactor == nullptr || !Coroutine::get_current() || nfds != 1 || timeout == 0))
    {
        return poll(fds, nfds, timeout);
    }

    std::unordered_map<int, swoole::socket_poll_fd> _fds;
    for(int i = 0; i< nfds; i++)
    {
        _fds.emplace(std::make_pair(fds[i].fd, swoole::socket_poll_fd(fds[i].events, &fds[i])));
    }

    if (!System::socket_poll(_fds, (double)timeout / 1000))
    {
        return -1;
    }

    int retval;
    for (auto &i : _fds)
    {
        int revents = i.second.revents;
        struct pollfd *_fd = (struct pollfd *) i.second.ptr;
        _fd->revents = revents;
        if (revents > 0)
        {
            retval++;
        }
    }

    return retval;
}
#endif

static void handler_access(swAio_event *event)
{
    event->ret = access((const char*) event->buf, event->offset);
    event->error = errno;
}

static void handler_flock(swAio_event *event)
{
    event->ret = ::flock(event->fd, (int) event->flags);
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

static void handler_statvfs(swAio_event *event)
{
    event->ret = statvfs((const char *) event->buf, (struct statvfs *) event->offset);
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
    ((Coroutine *) event->object)->resume();
}

int swoole_coroutine_open(const char *pathname, int flags, mode_t mode)
{
    if (sw_unlikely(SwooleTG.reactor == nullptr || !Coroutine::get_current()))
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
    ev.object = Coroutine::get_current();
    ev.req = &ev;

    ssize_t ret = swAio_dispatch(&ev);
    if (ret < 0)
    {
        return -1;
    }
    ((Coroutine *) ev.object)->yield();
    return ev.ret;
}

ssize_t swoole_coroutine_read(int sockfd, void *buf, size_t count)
{
    if (sw_unlikely(SwooleTG.reactor == nullptr || !Coroutine::get_current()))
    {
        return read(sockfd, buf, count);
    }

    Socket *socket = socket_map[sockfd];
    if (socket && socket->socket->fdtype == SW_FD_CORO_SOCKET)
    {
        return socket->read(buf, count);
    }

    swAio_event ev;
    bzero(&ev, sizeof(ev));
    ev.fd = sockfd;
    ev.buf = buf;
    ev.nbytes = count;
    ev.handler = handler_read;
    ev.callback = aio_onCompleted;
    ev.object = Coroutine::get_current();
    ev.req = &ev;

    ssize_t ret = swAio_dispatch(&ev);
    if (ret < 0)
    {
        return -1;
    }
    ((Coroutine *) ev.object)->yield();
    return ev.ret;
}

ssize_t swoole_coroutine_write(int sockfd, const void *buf, size_t count)
{
    if (sw_unlikely(SwooleTG.reactor == nullptr || !Coroutine::get_current()))
    {
        return write(sockfd, buf, count);
    }

    Socket *socket = socket_map[sockfd];
    if (socket && socket->socket->fdtype == SW_FD_CORO_SOCKET)
    {
        return socket->write(buf, count);
    }

    swAio_event ev;
    bzero(&ev, sizeof(ev));
    ev.fd = sockfd;
    ev.buf = (void*) buf;
    ev.nbytes = count;
    ev.handler = handler_write;
    ev.callback = aio_onCompleted;
    ev.object = Coroutine::get_current();
    ev.req = &ev;

    ssize_t ret = swAio_dispatch(&ev);
    if (ret < 0)
    {
        return -1;
    }
    ((Coroutine *) ev.object)->yield();
    return ev.ret;
}

off_t swoole_coroutine_lseek(int fd, off_t offset, int whence)
{
    if (sw_unlikely(SwooleTG.reactor == nullptr || !Coroutine::get_current()))
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
    ev.object = Coroutine::get_current();
    ev.req = &ev;

    ssize_t ret = swAio_dispatch(&ev);
    if (ret < 0)
    {
        return -1;
    }
    ((Coroutine *) ev.object)->yield();
    return ev.ret;
}

int swoole_coroutine_fstat(int fd, struct stat *statbuf)
{
    if (sw_unlikely(SwooleTG.reactor == nullptr || !Coroutine::get_current()))
    {
        return fstat(fd, statbuf);
    }

    swAio_event ev;
    bzero(&ev, sizeof(ev));
    ev.fd = fd;
    ev.buf = (void*) statbuf;
    ev.handler = handler_fstat;
    ev.callback = aio_onCompleted;
    ev.object = Coroutine::get_current();
    ev.req = &ev;

    ssize_t ret = swAio_dispatch(&ev);
    if (ret < 0)
    {
        return -1;
    }
    ((Coroutine *) ev.object)->yield();
    return ev.ret;
}

int swoole_coroutine_unlink(const char *pathname)
{
    if (sw_unlikely(SwooleTG.reactor == nullptr || !Coroutine::get_current()))
    {
        return unlink(pathname);
    }

    swAio_event ev;
    bzero(&ev, sizeof(ev));
    ev.buf = (void*) pathname;
    ev.handler = handler_unlink;
    ev.callback = aio_onCompleted;
    ev.object = Coroutine::get_current();
    ev.req = &ev;

    ssize_t ret = swAio_dispatch(&ev);
    if (ret < 0)
    {
        return -1;
    }
    ((Coroutine *) ev.object)->yield();
    return ev.ret;
}

int swoole_coroutine_statvfs(const char *path, struct statvfs *buf)
{
    if (sw_unlikely(SwooleTG.reactor == nullptr || !Coroutine::get_current()))
    {
        return statvfs(path, buf);
    }

    swAio_event ev;
    bzero(&ev, sizeof(ev));
    ev.buf = (void*) path;
    ev.offset = (off_t) buf;
    ev.handler = handler_statvfs;
    ev.callback = aio_onCompleted;
    ev.object = Coroutine::get_current();
    ev.req = &ev;

    ssize_t ret = swAio_dispatch(&ev);
    if (ret < 0)
    {
        return -1;
    }
    ((Coroutine *) ev.object)->yield();
    return ev.ret;
}

int swoole_coroutine_mkdir(const char *pathname, mode_t mode)
{
    if (sw_unlikely(SwooleTG.reactor == nullptr || !Coroutine::get_current()))
    {
        return mkdir(pathname, mode);
    }

    swAio_event ev;
    bzero(&ev, sizeof(ev));
    ev.buf = (void*) pathname;
    ev.offset = mode;
    ev.handler = handler_mkdir;
    ev.callback = aio_onCompleted;
    ev.object = Coroutine::get_current();
    ev.req = &ev;

    ssize_t ret = swAio_dispatch(&ev);
    if (ret < 0)
    {
        return -1;
    }
    ((Coroutine *) ev.object)->yield();
    return ev.ret;
}

int swoole_coroutine_rmdir(const char *pathname)
{
    if (sw_unlikely(SwooleTG.reactor == nullptr || !Coroutine::get_current()))
    {
        return rmdir(pathname);
    }

    swAio_event ev;
    bzero(&ev, sizeof(ev));
    ev.buf = (void*) pathname;
    ev.handler = handler_rmdir;
    ev.callback = aio_onCompleted;
    ev.object = Coroutine::get_current();
    ev.req = &ev;

    ssize_t ret = swAio_dispatch(&ev);
    if (ret < 0)
    {
        return -1;
    }
    ((Coroutine *) ev.object)->yield();
    return ev.ret;
}

int swoole_coroutine_rename(const char *oldpath, const char *newpath)
{
    if (sw_unlikely(SwooleTG.reactor == nullptr || !Coroutine::get_current()))
    {
        return rename(oldpath, newpath);
    }

    swAio_event ev;
    bzero(&ev, sizeof(ev));
    ev.buf = (void*) oldpath;
    ev.offset = (off_t) newpath;
    ev.handler = handler_rename;
    ev.callback = aio_onCompleted;
    ev.object = Coroutine::get_current();
    ev.req = &ev;

    ssize_t ret = swAio_dispatch(&ev);
    if (ret < 0)
    {
        return -1;
    }
    ((Coroutine *) ev.object)->yield();
    return ev.ret;
}

int swoole_coroutine_access(const char *pathname, int mode)
{
    if (sw_unlikely(SwooleTG.reactor == nullptr || !Coroutine::get_current()))
    {
        return access(pathname, mode);
    }

    swAio_event ev;
    bzero(&ev, sizeof(ev));
    ev.buf = (void*) pathname;
    ev.offset = mode;
    ev.handler = handler_access;
    ev.callback = aio_onCompleted;
    ev.object = Coroutine::get_current();
    ev.req = &ev;

    ssize_t ret = swAio_dispatch(&ev);
    if (ret < 0)
    {
        return -1;
    }
    ((Coroutine *) ev.object)->yield();
    return ev.ret;
}

int swoole_coroutine_flock(int fd, int operation)
{
    if (sw_unlikely(SwooleTG.reactor == nullptr || !Coroutine::get_current()))
    {
        return flock(fd, operation);
    }

    swAio_event ev;
    bzero(&ev, sizeof(ev));
    ev.fd = fd;
    ev.flags = operation;
    ev.handler = handler_flock;
    ev.callback = aio_onCompleted;
    ev.object = Coroutine::get_current();
    ev.req = &ev;

    ssize_t ret = swAio_dispatch(&ev);
    if (ret < 0)
    {
        return -1;
    }
    ((Coroutine *) ev.object)->yield();
    return ev.ret;
}

#if 0
static void handler_opendir(swAio_event *event)
{
    swAio_event *req = (swAio_event *) event->object;
    req->buf = opendir((const char*) event->buf);
    event->error = errno;
}

static void handler_readdir(swAio_event *event)
{
    swAio_event *req = (swAio_event *) event->object;
    req->buf = (void*) opendir((const char*) event->buf);
    event->error = errno;
}

DIR *swoole_coroutine_opendir(const char *name)
{
    if (sw_unlikely(SwooleTG.reactor == nullptr || !Coroutine::get_current()))
    {
        return opendir(name);
    }

    swAio_event ev;
    bzero(&ev, sizeof(ev));
    ev.buf = (void*) name;
    ev.handler = handler_opendir;
    ev.callback = aio_onCompleted;
    ev.object = Coroutine::get_current();
    ev.req = &ev;

    ssize_t ret = swAio_dispatch(&ev);
    if (ret < 0)
    {
        return nullptr;
    }
    coroutine_yield((coroutine_t *) ev.object);
    return (DIR*) ev.buf;
}

struct dirent *swoole_coroutine_readdir(DIR *dirp)
{
    if (sw_unlikely(SwooleTG.reactor == nullptr || !Coroutine::get_current()))
    {
        return readdir(dirp);
    }

    swAio_event ev;
    bzero(&ev, sizeof(ev));
    ev.buf = (void*) dirp;
    ev.handler = handler_readdir;
    ev.callback = aio_onCompleted;
    ev.object = Coroutine::get_current();
    ev.req = &ev;

    ssize_t ret = swAio_dispatch(&ev);
    if (ret < 0)
    {
        return nullptr;
    }
    coroutine_yield((coroutine_t *) ev.object);
    return (struct dirent *) ev.buf;
}
#endif

void swoole_coroutine_sleep(int sec)
{
    System::sleep((double) sec);
}

void swoole_coroutine_usleep(int usec)
{
    System::sleep((double) usec / 1024 / 1024);
}

int swoole_coroutine_socket_set_timeout(int sockfd, int which, double timeout)
{
    if (sw_unlikely(SwooleTG.reactor == nullptr || !Coroutine::get_current()))
    {
        _error: errno = EINVAL;
        return SW_ERR;
    }
    Socket *socket = socket_map[sockfd];
    if (socket == nullptr)
    {
        goto _error;
    }
    if (which == SO_RCVTIMEO)
    {
        socket->set_timeout(timeout, swoole::SW_TIMEOUT_READ);
        return SW_OK;
    }
    else if (which == SO_SNDTIMEO)
    {
        socket->set_timeout(timeout, swoole::SW_TIMEOUT_WRITE);
        return SW_OK;
    }
    else
    {
        goto _error;
    }
}

int swoole_coroutine_socket_wait_event(int sockfd, int event, double timeout)
{
    if (sw_unlikely(SwooleTG.reactor == nullptr || !Coroutine::get_current()))
    {
        _error: errno = EINVAL;
        return SW_ERR;
    }
    Socket *socket = socket_map[sockfd];
    if (socket == nullptr)
    {
        goto _error;
    }
    double ori_timeout = socket->get_timeout(event == SW_EVENT_READ ? swoole::SW_TIMEOUT_READ : swoole::SW_TIMEOUT_WRITE);
    socket->set_timeout(timeout);
    bool retval = socket->poll((enum swEvent_type) event);
    socket->set_timeout(ori_timeout);
    return retval ? SW_OK : SW_ERR;
}

SW_EXTERN_C_END
