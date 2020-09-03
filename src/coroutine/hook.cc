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

#include <sys/file.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <netdb.h>
#include <poll.h>
#include <dirent.h>

#include <string>
#include <iostream>
#include <unordered_map>

#include "swoole_coroutine_socket.h"
#include "swoole_coroutine_system.h"

using std::unordered_map;
using swoole::Coroutine;
using swoole::async::dispatch;
using swoole::async::Event;
using swoole::coroutine::Socket;
using swoole::coroutine::System;

static unordered_map<int, Socket *> socket_map;

static sw_inline bool is_no_coro() {
    return SwooleTG.reactor == nullptr || !Coroutine::get_current();
}

static sw_inline Socket *get_socket(int sockfd) {
    auto socket_iterator = socket_map.find(sockfd);
    if (socket_iterator == socket_map.end()) {
        return nullptr;
    }
    return socket_iterator->second;
}

static sw_inline Socket *get_socket_ex(int sockfd) {
    if (sw_unlikely(is_no_coro())) {
        return nullptr;
    }
    return get_socket(sockfd);
}

Socket *swoole_coroutine_get_socket_object(int sockfd) {
    return get_socket(sockfd);
}

SW_EXTERN_C_BEGIN

int swoole_coroutine_socket(int domain, int type, int protocol) {
    if (sw_unlikely(is_no_coro())) {
        return ::socket(domain, type, protocol);
    }
    Socket *socket = new Socket(domain, type, protocol);
    int fd = socket->get_fd();
    if (sw_unlikely(fd < 0)) {
        delete socket;
    } else {
        socket_map[fd] = socket;
    }
    return fd;
}

ssize_t swoole_coroutine_send(int sockfd, const void *buf, size_t len, int flags) {
    Socket *socket = get_socket_ex(sockfd);
    if (sw_unlikely(socket == NULL)) {
        return ::send(sockfd, buf, len, flags);
    }
    return socket->send(buf, len);
}

ssize_t swoole_coroutine_sendmsg(int sockfd, const struct msghdr *msg, int flags) {
    Socket *socket = get_socket_ex(sockfd);
    if (sw_unlikely(socket == NULL)) {
        return ::sendmsg(sockfd, msg, flags);
    }
    return socket->sendmsg(msg, flags);
}

ssize_t swoole_coroutine_recvmsg(int sockfd, struct msghdr *msg, int flags) {
    Socket *socket = get_socket_ex(sockfd);
    if (sw_unlikely(socket == NULL)) {
        return ::recvmsg(sockfd, msg, flags);
    }
    return socket->recvmsg(msg, flags);
}

ssize_t swoole_coroutine_recv(int sockfd, void *buf, size_t len, int flags) {
    Socket *socket = get_socket_ex(sockfd);
    if (sw_unlikely(socket == NULL)) {
        return ::recv(sockfd, buf, len, flags);
    }
    if (flags & MSG_PEEK) {
        return socket->peek(buf, len);
    } else {
        return socket->recv(buf, len);
    }
}

int swoole_coroutine_close(int sockfd) {
    Socket *socket = get_socket(sockfd);
    if (socket == NULL) {
        return ::close(sockfd);
    }
    if (socket->close()) {
        delete socket;
        socket_map.erase(sockfd);
    }
    return 0;
}

int swoole_coroutine_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    Socket *socket = get_socket_ex(sockfd);
    if (sw_unlikely(socket == NULL)) {
        return ::connect(sockfd, addr, addrlen);
    }
    return socket->connect(addr, addrlen) ? 0 : -1;
}

#if 1
int swoole_coroutine_poll(struct pollfd *fds, nfds_t nfds, int timeout) {
    Socket *socket;
    if (sw_unlikely(nfds != 1 || timeout == 0 || (socket = get_socket_ex(fds[0].fd)) == NULL)) {
        return poll(fds, nfds, timeout);
    }
    socket->set_timeout((double) timeout / 1000);
    if (fds[0].events & POLLIN) {
        fds[0].revents |= POLLIN;
    }
    if (fds[0].events & POLLOUT) {
        fds[0].revents |= POLLOUT;
    }
    return 1;
}
#else
int swoole_coroutine_poll(struct pollfd *fds, nfds_t nfds, int timeout) {
    if (sw_unlikely(is_no_coro() || nfds != 1 || timeout == 0)) {
        return poll(fds, nfds, timeout);
    }

    std::unordered_map<int, swoole::socket_poll_fd> _fds;
    for (int i = 0; i < nfds; i++) {
        _fds.emplace(std::make_pair(fds[i].fd, swoole::socket_poll_fd(fds[i].events, &fds[i])));
    }

    if (!System::socket_poll(_fds, (double) timeout / 1000)) {
        return -1;
    }

    int retval;
    for (auto &i : _fds) {
        int revents = i.second.revents;
        struct pollfd *_fd = (struct pollfd *) i.second.ptr;
        _fd->revents = revents;
        if (revents > 0) {
            retval++;
        }
    }

    return retval;
}
#endif

static void handler_access(Event *event) {
    event->ret = access((const char *) event->buf, event->offset);
    event->error = errno;
}

static void handler_flock(Event *event) {
    event->ret = ::flock(event->fd, (int) event->flags);
    event->error = errno;
}

static void handler_open(Event *event) {
    event->ret = open((const char *) event->buf, event->flags, event->offset);
    event->error = errno;
}

static void handler_read(Event *event) {
    event->ret = read(event->fd, event->buf, event->nbytes);
    event->error = errno;
}

static void handler_write(Event *event) {
    event->ret = write(event->fd, event->buf, event->nbytes);
    event->error = errno;
}

static void handler_fstat(Event *event) {
    event->ret = fstat(event->fd, (struct stat *) event->buf);
    event->error = errno;
}

static void handler_unlink(Event *event) {
    event->ret = unlink((const char *) event->buf);
    event->error = errno;
}

static void handler_mkdir(Event *event) {
    event->ret = mkdir((const char *) event->buf, event->offset);
    event->error = errno;
}

static void handler_rmdir(Event *event) {
    event->ret = rmdir((const char *) event->buf);
    event->error = errno;
}

static void handler_statvfs(Event *event) {
    event->ret = statvfs((const char *) event->buf, (struct statvfs *) event->offset);
    event->error = errno;
}

static void handler_rename(Event *event) {
    event->ret = rename((const char *) event->buf, (const char *) event->offset);
    event->error = errno;
}

static void aio_onCompleted(Event *event) {
    Event *ev = (Event *) event->req;
    ev->ret = event->ret;
    errno = event->error;
    ((Coroutine *) event->object)->resume();
}

int swoole_coroutine_open(const char *pathname, int flags, mode_t mode) {
    if (sw_unlikely(is_no_coro())) {
        return open(pathname, flags, mode);
    }

    Event ev;
    sw_memset_zero(&ev, sizeof(ev));
    ev.buf = (void *) pathname;
    ev.offset = mode;
    ev.flags = flags;
    ev.handler = handler_open;
    ev.callback = aio_onCompleted;
    ev.object = Coroutine::get_current();
    ev.req = &ev;

    ssize_t ret = dispatch(&ev);
    if (ret < 0) {
        return -1;
    }
    ((Coroutine *) ev.object)->yield();
    return ev.ret;
}

ssize_t swoole_coroutine_read(int sockfd, void *buf, size_t count) {
    if (sw_unlikely(is_no_coro())) {
        return read(sockfd, buf, count);
    }

    Socket *socket = get_socket(sockfd);
    if (socket && socket->socket->fdtype == SW_FD_CORO_SOCKET) {
        return socket->read(buf, count);
    }

    Event ev;
    sw_memset_zero(&ev, sizeof(ev));
    ev.fd = sockfd;
    ev.buf = buf;
    ev.nbytes = count;
    ev.handler = handler_read;
    ev.callback = aio_onCompleted;
    ev.object = Coroutine::get_current();
    ev.req = &ev;

    ssize_t ret = dispatch(&ev);
    if (ret < 0) {
        return -1;
    }
    ((Coroutine *) ev.object)->yield();
    return ev.ret;
}

ssize_t swoole_coroutine_write(int sockfd, const void *buf, size_t count) {
    if (sw_unlikely(is_no_coro())) {
        return write(sockfd, buf, count);
    }

    Socket *socket = get_socket(sockfd);
    if (socket && socket->socket->fdtype == SW_FD_CORO_SOCKET) {
        return socket->write(buf, count);
    }

    Event ev;
    sw_memset_zero(&ev, sizeof(ev));
    ev.fd = sockfd;
    ev.buf = (void *) buf;
    ev.nbytes = count;
    ev.handler = handler_write;
    ev.callback = aio_onCompleted;
    ev.object = Coroutine::get_current();
    ev.req = &ev;

    ssize_t ret = dispatch(&ev);
    if (ret < 0) {
        return -1;
    }
    ((Coroutine *) ev.object)->yield();
    return ev.ret;
}

off_t swoole_coroutine_lseek(int fd, off_t offset, int whence) {
    if (sw_unlikely(is_no_coro())) {
        return lseek(fd, offset, whence);
    }

    off_t retval = -1;
    int _tmp_errno = 0;
    swoole::coroutine::async([&]() {
        retval = lseek(fd, offset, whence);
        _tmp_errno = errno;
    });
    errno = _tmp_errno;
    return retval;
}

int swoole_coroutine_fstat(int fd, struct stat *statbuf) {
    if (sw_unlikely(is_no_coro())) {
        return fstat(fd, statbuf);
    }

    Event ev;
    sw_memset_zero(&ev, sizeof(ev));
    ev.fd = fd;
    ev.buf = (void *) statbuf;
    ev.handler = handler_fstat;
    ev.callback = aio_onCompleted;
    ev.object = Coroutine::get_current();
    ev.req = &ev;

    ssize_t ret = dispatch(&ev);
    if (ret < 0) {
        return -1;
    }
    ((Coroutine *) ev.object)->yield();
    return ev.ret;
}

int swoole_coroutine_unlink(const char *pathname) {
    if (sw_unlikely(is_no_coro())) {
        return unlink(pathname);
    }

    Event ev;
    sw_memset_zero(&ev, sizeof(ev));
    ev.buf = (void *) pathname;
    ev.handler = handler_unlink;
    ev.callback = aio_onCompleted;
    ev.object = Coroutine::get_current();
    ev.req = &ev;

    ssize_t ret = dispatch(&ev);
    if (ret < 0) {
        return -1;
    }
    ((Coroutine *) ev.object)->yield();
    return ev.ret;
}

int swoole_coroutine_statvfs(const char *path, struct statvfs *buf) {
    if (sw_unlikely(is_no_coro())) {
        return statvfs(path, buf);
    }

    Event ev;
    sw_memset_zero(&ev, sizeof(ev));
    ev.buf = (void *) path;
    ev.offset = (off_t) buf;
    ev.handler = handler_statvfs;
    ev.callback = aio_onCompleted;
    ev.object = Coroutine::get_current();
    ev.req = &ev;

    ssize_t ret = dispatch(&ev);
    if (ret < 0) {
        return -1;
    }
    ((Coroutine *) ev.object)->yield();
    return ev.ret;
}

int swoole_coroutine_mkdir(const char *pathname, mode_t mode) {
    if (sw_unlikely(is_no_coro())) {
        return mkdir(pathname, mode);
    }

    Event ev;
    sw_memset_zero(&ev, sizeof(ev));
    ev.buf = (void *) pathname;
    ev.offset = mode;
    ev.handler = handler_mkdir;
    ev.callback = aio_onCompleted;
    ev.object = Coroutine::get_current();
    ev.req = &ev;

    ssize_t ret = dispatch(&ev);
    if (ret < 0) {
        return -1;
    }
    ((Coroutine *) ev.object)->yield();
    return ev.ret;
}

int swoole_coroutine_rmdir(const char *pathname) {
    if (sw_unlikely(is_no_coro())) {
        return rmdir(pathname);
    }

    Event ev;
    sw_memset_zero(&ev, sizeof(ev));
    ev.buf = (void *) pathname;
    ev.handler = handler_rmdir;
    ev.callback = aio_onCompleted;
    ev.object = Coroutine::get_current();
    ev.req = &ev;

    ssize_t ret = dispatch(&ev);
    if (ret < 0) {
        return -1;
    }
    ((Coroutine *) ev.object)->yield();
    return ev.ret;
}

int swoole_coroutine_rename(const char *oldpath, const char *newpath) {
    if (sw_unlikely(is_no_coro())) {
        return rename(oldpath, newpath);
    }

    Event ev;
    sw_memset_zero(&ev, sizeof(ev));
    ev.buf = (void *) oldpath;
    ev.offset = (off_t) newpath;
    ev.handler = handler_rename;
    ev.callback = aio_onCompleted;
    ev.object = Coroutine::get_current();
    ev.req = &ev;

    ssize_t ret = dispatch(&ev);
    if (ret < 0) {
        return -1;
    }
    ((Coroutine *) ev.object)->yield();
    return ev.ret;
}

int swoole_coroutine_access(const char *pathname, int mode) {
    if (sw_unlikely(is_no_coro())) {
        return access(pathname, mode);
    }

    Event ev;
    sw_memset_zero(&ev, sizeof(ev));
    ev.buf = (void *) pathname;
    ev.offset = mode;
    ev.handler = handler_access;
    ev.callback = aio_onCompleted;
    ev.object = Coroutine::get_current();
    ev.req = &ev;

    ssize_t ret = dispatch(&ev);
    if (ret < 0) {
        return -1;
    }
    ((Coroutine *) ev.object)->yield();
    return ev.ret;
}

int swoole_coroutine_flock(int fd, int operation) {
    if (sw_unlikely(is_no_coro())) {
        return flock(fd, operation);
    }

    Event ev;
    sw_memset_zero(&ev, sizeof(ev));
    ev.fd = fd;
    ev.flags = operation;
    ev.handler = handler_flock;
    ev.callback = aio_onCompleted;
    ev.object = Coroutine::get_current();
    ev.req = &ev;

    ssize_t ret = dispatch(&ev);
    if (ret < 0) {
        return -1;
    }
    ((Coroutine *) ev.object)->yield();
    return ev.ret;
}

#if 0
static void handler_opendir(Event *event)
{
    Event *req = (Event *) event->object;
    req->buf = opendir((const char*) event->buf);
    event->error = errno;
}

static void handler_readdir(Event *event)
{
    Event *req = (Event *) event->object;
    req->buf = (void*) opendir((const char*) event->buf);
    event->error = errno;
}

DIR *swoole_coroutine_opendir(const char *name)
{
    if (sw_unlikely(is_no_coro()))
    {
        return opendir(name);
    }

    Event ev;
    sw_memset_zero(&ev, sizeof(ev));
    ev.buf = (void*) name;
    ev.handler = handler_opendir;
    ev.callback = aio_onCompleted;
    ev.object = Coroutine::get_current();
    ev.req = &ev;

    ssize_t ret = dispatch(&ev);
    if (ret < 0)
    {
        return NULL;
    }
    coroutine_yield((coroutine_t *) ev.object);
    return (DIR*) ev.buf;
}

struct dirent *swoole_coroutine_readdir(DIR *dirp)
{
    if (sw_unlikely(is_no_coro()))
    {
        return readdir(dirp);
    }

    Event ev;
    sw_memset_zero(&ev, sizeof(ev));
    ev.buf = (void*) dirp;
    ev.handler = handler_readdir;
    ev.callback = aio_onCompleted;
    ev.object = Coroutine::get_current();
    ev.req = &ev;

    ssize_t ret = dispatch(&ev);
    if (ret < 0)
    {
        return NULL;
    }
    coroutine_yield((coroutine_t *) ev.object);
    return (struct dirent *) ev.buf;
}
#endif

void swoole_coroutine_sleep(int sec) {
    System::sleep((double) sec);
}

void swoole_coroutine_usleep(int usec) {
    System::sleep((double) usec / 1024 / 1024);
}

int swoole_coroutine_socket_set_timeout(int sockfd, int which, double timeout) {
    Socket *socket = get_socket_ex(sockfd);
    if (sw_unlikely(socket == NULL)) {
        errno = EINVAL;
        return -1;
    }
    if (which == SO_RCVTIMEO) {
        socket->set_timeout(timeout, swoole::SW_TIMEOUT_READ);
        return 0;
    } else if (which == SO_SNDTIMEO) {
        socket->set_timeout(timeout, swoole::SW_TIMEOUT_WRITE);
        return 0;
    } else {
        errno = EINVAL;
        return -1;
    }
}

int swoole_coroutine_socket_wait_event(int sockfd, int event, double timeout) {
    Socket *socket = get_socket_ex(sockfd);
    if (sw_unlikely(socket == NULL)) {
        errno = EINVAL;
        return -1;
    }
    double ori_timeout =
        socket->get_timeout(event == SW_EVENT_READ ? swoole::SW_TIMEOUT_READ : swoole::SW_TIMEOUT_WRITE);
    socket->set_timeout(timeout);
    bool retval = socket->poll((enum swEvent_type) event);
    socket->set_timeout(ori_timeout);
    return retval ? SW_OK : SW_ERR;
}

int swoole_coroutine_getaddrinfo(const char *name,
                                 const char *service,
                                 const struct addrinfo *req,
                                 struct addrinfo **pai) {
    int retval = -1;
    int _tmp_errno = 0;
    swoole::coroutine::async([&]() {
        retval = getaddrinfo(name, service, req, pai);
        _tmp_errno = errno;
    });
    errno = _tmp_errno;
    return retval;
}

struct hostent *swoole_coroutine_gethostbyname(const char *name) {
    struct hostent *retval = nullptr;
    int _tmp_errno = 0, _tmp_h_errno;
    swoole::coroutine::async([&]() {
        retval = gethostbyname(name);
        _tmp_errno = errno;
        _tmp_h_errno = h_errno;
    });
    errno = _tmp_errno;
    h_errno = _tmp_h_errno;
    return retval;
}

SW_EXTERN_C_END
