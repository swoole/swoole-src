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

#ifndef _WIN32

#include <sys/file.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <poll.h>
#include <dirent.h>
#include <string>
#include <iostream>

using namespace swoole;
using namespace std;

extern "C"
{
struct aio_task
{
    Coroutine *co;
    swAio_event *event;
};

int swoole_coroutine_socket(int domain, int type, int protocol)
{
    if (unlikely(SwooleG.main_reactor == nullptr || !Coroutine::get_current()))
    {
        return socket(domain, type, protocol);
    }
    enum swSocket_type sock_type = get_socket_type(domain, type, protocol);
    Socket *sock = new Socket(sock_type);
    if (sock->socket == nullptr)
    {
        delete sock;
        return -1;
    }
    return sock->socket->fd;
}

ssize_t swoole_coroutine_send(int sockfd, const void *buf, size_t len, int flags)
{
    if (unlikely(SwooleG.main_reactor == nullptr || !Coroutine::get_current()))
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
        return -1;
    }
    else
    {
        return retval;
    }
}

ssize_t swoole_coroutine_sendmsg(int sockfd, const struct msghdr *msg, int flags)
{
    if (unlikely(SwooleG.main_reactor == nullptr || !Coroutine::get_current()))
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
        return -1;
    }
    else
    {
        return retval;
    }
}

ssize_t swoole_coroutine_recvmsg(int sockfd, struct msghdr *msg, int flags)
{
    if (unlikely(SwooleG.main_reactor == nullptr || !Coroutine::get_current()))
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
        return -1;
    }
    else
    {
        return retval;
    }
}

ssize_t swoole_coroutine_recv(int sockfd, void *buf, size_t len, int flags)
{
    if (unlikely(SwooleG.main_reactor == nullptr || !Coroutine::get_current()))
    {
        _no_coro: return ::recv(sockfd, buf, len, flags);
    }
    swConnection *conn = swReactor_get(SwooleG.main_reactor, sockfd);
    if (conn == nullptr)
    {
        goto _no_coro;
    }
    Socket *socket = (Socket *) conn->object;
    ssize_t retval;
    if (flags & MSG_PEEK)
    {
        retval = socket->peek(buf, len);
    }
    else
    {
        retval = socket->recv(buf, len);
    }
    if (retval < 0)
    {
        return -1;
    }
    else
    {
        return retval;
    }
}

int swoole_coroutine_close(int fd)
{
    if (unlikely(SwooleG.main_reactor == nullptr || !Coroutine::get_current()))
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
    if (unlikely(SwooleG.main_reactor == nullptr || !Coroutine::get_current()))
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
        return -1;
    }
    else
    {
        return 0;
    }
}

int swoole_coroutine_poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
    if (unlikely(SwooleG.main_reactor == nullptr || !Coroutine::get_current() || nfds != 1))
    {
        _poll: return poll(fds, nfds, timeout);
    }
    swConnection *conn = swReactor_get(SwooleG.main_reactor, fds[0].fd);
    if (conn == nullptr)
    {
        goto _poll;
    }
    Socket *socket = (Socket *) conn->object;
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

static void aio_onReadFileCompleted(swAio_event *event)
{
    aio_task *task = (aio_task *) event->object;
    task->event->buf = event->buf;
    task->event->nbytes = event->ret;
    task->event->error = event->error;
    ((Coroutine *) task->co)->resume();
}

static void aio_onWriteFileCompleted(swAio_event *event)
{
    aio_task *task = (aio_task *) event->object;
    task->event->ret = event->ret;
    task->event->error = event->error;
    ((Coroutine *) task->co)->resume();
}

static void aio_onDNSCompleted(swAio_event *event)
{
    aio_task *task = (aio_task *) event->object;
    task->event->ret = event->ret;
    task->event->error = event->error;
    ((Coroutine *) task->co)->resume();
}

int swoole_coroutine_open(const char *pathname, int flags, mode_t mode)
{
    if (unlikely(SwooleG.main_reactor == nullptr || !Coroutine::get_current()))
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

    int ret = swAio_dispatch(&ev);
    if (ret < 0)
    {
        return SW_ERR;
    }
    ((Coroutine *) ev.object)->yield();
    return ev.ret;
}

ssize_t swoole_coroutine_read(int fd, void *buf, size_t count)
{
    if (unlikely(SwooleG.main_reactor == nullptr || !Coroutine::get_current()))
    {
        return read(fd, buf, count);
    }

    swConnection *conn = swReactor_get(SwooleG.main_reactor, fd);
    if (conn && conn->fdtype == SW_FD_CORO_SOCKET)
    {
        Socket *socket = (Socket *) conn->object;
        return socket->read(buf, count);
    }

    swAio_event ev;
    bzero(&ev, sizeof(ev));
    ev.fd = fd;
    ev.buf = buf;
    ev.nbytes = count;
    ev.handler = handler_read;
    ev.callback = aio_onCompleted;
    ev.object = Coroutine::get_current();
    ev.req = &ev;

    int ret = swAio_dispatch(&ev);
    if (ret < 0)
    {
        return SW_ERR;
    }
    ((Coroutine *) ev.object)->yield();
    return ev.ret;
}

ssize_t swoole_coroutine_write(int fd, const void *buf, size_t count)
{
    if (unlikely(SwooleG.main_reactor == nullptr || !Coroutine::get_current()))
    {
        return write(fd, buf, count);
    }

    swConnection *conn = swReactor_get(SwooleG.main_reactor, fd);
    if (conn && conn->fdtype == SW_FD_CORO_SOCKET)
    {
        Socket *socket = (Socket *) conn->object;
        return socket->write(buf, count);
    }

    swAio_event ev;
    bzero(&ev, sizeof(ev));
    ev.fd = fd;
    ev.buf = (void*) buf;
    ev.nbytes = count;
    ev.handler = handler_write;
    ev.callback = aio_onCompleted;
    ev.object = Coroutine::get_current();
    ev.req = &ev;

    int ret = swAio_dispatch(&ev);
    if (ret < 0)
    {
        return SW_ERR;
    }
    ((Coroutine *) ev.object)->yield();
    return ev.ret;
}

off_t swoole_coroutine_lseek(int fd, off_t offset, int whence)
{
    if (unlikely(SwooleG.main_reactor == nullptr || !Coroutine::get_current()))
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

    int ret = swAio_dispatch(&ev);
    if (ret < 0)
    {
        return SW_ERR;
    }
    ((Coroutine *) ev.object)->yield();
    return ev.ret;
}

int swoole_coroutine_fstat(int fd, struct stat *statbuf)
{
    if (unlikely(SwooleG.main_reactor == nullptr || !Coroutine::get_current()))
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

    int ret = swAio_dispatch(&ev);
    if (ret < 0)
    {
        return SW_ERR;
    }
    ((Coroutine *) ev.object)->yield();
    return ev.ret;
}

int swoole_coroutine_unlink(const char *pathname)
{
    if (unlikely(SwooleG.main_reactor == nullptr || !Coroutine::get_current()))
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

    int ret = swAio_dispatch(&ev);
    if (ret < 0)
    {
        return SW_ERR;
    }
    ((Coroutine *) ev.object)->yield();
    return ev.ret;
}

int swoole_coroutine_statvfs(const char *path, struct statvfs *buf)
{
    if (unlikely(SwooleG.main_reactor == nullptr || !Coroutine::get_current()))
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

    int ret = swAio_dispatch(&ev);
    if (ret < 0)
    {
        return SW_ERR;
    }
    ((Coroutine *) ev.object)->yield();
    return ev.ret;
}

int swoole_coroutine_mkdir(const char *pathname, mode_t mode)
{
    if (unlikely(SwooleG.main_reactor == nullptr || !Coroutine::get_current()))
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

    int ret = swAio_dispatch(&ev);
    if (ret < 0)
    {
        return SW_ERR;
    }
    ((Coroutine *) ev.object)->yield();
    return ev.ret;
}

int swoole_coroutine_rmdir(const char *pathname)
{
    if (unlikely(SwooleG.main_reactor == nullptr || !Coroutine::get_current()))
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

    int ret = swAio_dispatch(&ev);
    if (ret < 0)
    {
        return SW_ERR;
    }
    ((Coroutine *) ev.object)->yield();
    return ev.ret;
}

int swoole_coroutine_rename(const char *oldpath, const char *newpath)
{
    if (unlikely(SwooleG.main_reactor == nullptr || !Coroutine::get_current()))
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

    int ret = swAio_dispatch(&ev);
    if (ret < 0)
    {
        return SW_ERR;
    }
    ((Coroutine *) ev.object)->yield();
    return ev.ret;
}

int swoole_coroutine_access(const char *pathname, int mode)
{
    if (unlikely(SwooleG.main_reactor == nullptr || !Coroutine::get_current()))
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

    int ret = swAio_dispatch(&ev);
    if (ret < 0)
    {
        return SW_ERR;
    }
    ((Coroutine *) ev.object)->yield();
    return ev.ret;
}

int swoole_coroutine_flock(int fd, int operation)
{
    if (unlikely(SwooleG.main_reactor == nullptr || !Coroutine::get_current()))
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

    int ret = swAio_dispatch(&ev);
    if (ret < 0)
    {
        return SW_ERR;
    }
    ((Coroutine *) ev.object)->yield();
    return ev.ret;
}

static void sleep_timeout(swTimer *timer, swTimer_node *tnode)
{
    ((Coroutine *) tnode->data)->resume();
}

int Coroutine::sleep(double sec)
{
    Coroutine* co = Coroutine::get_current();
    if (swTimer_add(&SwooleG.timer, (long) (sec * 1000), 0, co, sleep_timeout) == NULL)
    {
        return -1;
    }
    co->yield();
    return 0;
}

swString* Coroutine::read_file(const char *file, int lock)
{
    aio_task task;

    swAio_event ev;
    bzero(&ev, sizeof(swAio_event));

    task.co = Coroutine::get_current();
    task.event = &ev;

    ev.lock = lock ? 1 : 0;
    ev.type = SW_AIO_READ_FILE;
    ev.object = (void*) &task;
    ev.handler = swAio_handler_read_file;
    ev.callback = aio_onReadFileCompleted;
    ev.req = (void*) file;

    int ret = swAio_dispatch(&ev);
    if (ret < 0)
    {
        return NULL;
    }
    task.co->yield();
    if (ev.error == 0)
    {
        swString *str = (swString *) sw_malloc(sizeof(swString));
        str->str = (char*) ev.buf;
        str->length = ev.nbytes;
        return str;
    }
    else
    {
        SwooleG.error = ev.error;
        return NULL;
    }
}

ssize_t Coroutine::write_file(const char *file, char *buf, size_t length, int lock, int flags)
{
    aio_task task;

    swAio_event ev;
    bzero(&ev, sizeof(swAio_event));

    task.co = Coroutine::get_current();
    task.event = &ev;

    ev.lock = lock ? 1 : 0;
    ev.type = SW_AIO_WRITE_FILE;
    ev.buf = buf;
    ev.nbytes = length;
    ev.object = (void*) &task;
    ev.handler = swAio_handler_write_file;
    ev.callback = aio_onWriteFileCompleted;
    ev.req = (void*) file;
    ev.flags = flags;

    int ret = swAio_dispatch(&ev);
    if (ret < 0)
    {
        return -1;
    }
    task.co->yield();
    if (ev.error != 0)
    {
        SwooleG.error = ev.error;
    }
    return ev.ret;
}

string Coroutine::gethostbyname(const string &hostname, int domain, float timeout)
{
    swAio_event ev;
    aio_task task;

    bzero(&ev, sizeof(swAio_event));
    if (hostname.size() < SW_IP_MAX_LENGTH)
    {
        ev.nbytes = SW_IP_MAX_LENGTH + 1;
    }
    else
    {
        ev.nbytes = hostname.size() + 1;
    }
    ev.buf = sw_malloc(ev.nbytes);
    if (!ev.buf)
    {
        return "";
    }

    task.co = coroutine_get_current();
    task.event = &ev;

    memcpy(ev.buf, hostname.c_str(), hostname.size());
    ((char *) ev.buf)[hostname.size()] = 0;
    ev.flags = domain;
    ev.type = SW_AIO_GETHOSTBYNAME;
    ev.object = (void*) &task;
    ev.handler = swAio_handler_gethostbyname;
    ev.callback = aio_onDNSCompleted;

    if (SwooleAIO.init == 0)
    {
        swAio_init();
    }

    if (swAio_dispatch(&ev) < 0)
    {
        sw_free(ev.buf);
        return "";
    }

    task.co->yield();

    if (ev.ret == -1)
    {
        SwooleG.error = ev.error;
        return "";
    }
    else
    {
        string addr((char *) ev.buf);
        sw_free(ev.buf);
        return addr;
    }
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
    if (unlikely(SwooleG.main_reactor == nullptr || !Coroutine::get_current()))
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

    int ret = swAio_dispatch(&ev);
    if (ret < 0)
    {
        return nullptr;
    }
    coroutine_yield((coroutine_t *) ev.object);
    return (DIR*) ev.buf;
}

struct dirent *swoole_coroutine_readdir(DIR *dirp)
{
    if (unlikely(SwooleG.main_reactor == nullptr || !Coroutine::get_current()))
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

    int ret = swAio_dispatch(&ev);
    if (ret < 0)
    {
        return nullptr;
    }
    coroutine_yield((coroutine_t *) ev.object);
    return (struct dirent *) ev.buf;
}
#endif
}

#endif
