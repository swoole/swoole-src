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
  | Author: Tianfeng Han  <rango@swoole.com>                             |
  +----------------------------------------------------------------------+
*/

#ifndef _WIN32
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <netdb.h>
#include <poll.h>
#include <dirent.h>
#else
#include <sys/stat.h>
#include <io.h>
#endif

#include <mutex>
#include <unordered_map>

#include "swoole_coroutine_system.h"
#include "swoole_socket_impl.h"
#ifndef _WIN32
#include "swoole_iouring.h"
#else
#include "swoole_iocp.h"
#endif

using swoole::AsyncEvent;
using swoole::Coroutine;
using swoole::EventType;
using swoole::translate_events_from_poll;
using swoole::translate_events_to_poll;
using swoole::async::dispatch;
using swoole::coroutine::async;
using swoole::coroutine::PollSocket;
using swoole::coroutine::System;

#ifdef SW_USE_IOURING
using swoole::Iouring;
#elif defined(_WIN32) && defined(SW_USE_IOCP)
using swoole::Iocp;
#define SW_USE_IOCP_FILE 1
#define SW_USE_ASYNC 1
#else
#define SW_USE_ASYNC 1
#endif

static std::unordered_map<swSocketFd, std::shared_ptr<SocketImpl>> socket_map;
static std::mutex socket_map_lock;

#if defined(__APPLE__) || defined(__MACH__)
static int fdatasync(int fd) {
    return fcntl(fd, F_FULLFSYNC);
}
#endif

static sw_inline bool is_no_coro() {
    return SwooleTG.reactor == nullptr || !Coroutine::get_current();
}

static sw_inline std::shared_ptr<SocketImpl> get_socket(swSocketFd sockfd) {
    std::unique_lock<std::mutex> _lock(socket_map_lock);
    auto socket_iterator = socket_map.find(sockfd);
    if (socket_iterator == socket_map.end()) {
        errno = ENOTSOCK;
        return nullptr;
    }
    return socket_iterator->second;
}

static sw_inline std::shared_ptr<SocketImpl> get_socket_ex(swSocketFd sockfd) {
    if (sw_unlikely(is_no_coro())) {
        errno = EWOULDBLOCK;
        return nullptr;
    }
    return get_socket(sockfd);
}

std::shared_ptr<SocketImpl> swoole_coroutine_get_socket_object(swSocketFd sockfd) {
    return get_socket(sockfd);
}

std::shared_ptr<SocketImpl> swoole_coroutine_get_socket_object_ex(swSocketFd sockfd) {
    return get_socket_ex(sockfd);
}

SW_EXTERN_C_BEGIN
int swoole_coroutine_socket(int domain, int type, int protocol) {
    if (sw_unlikely(is_no_coro())) {
        return (int)::socket(domain, type, protocol);
    }
    auto socket = std::make_shared<SocketImpl>(domain, type, protocol);
    swSocketFd fd = socket->get_fd();
    if (sw_unlikely(fd == SW_BAD_SOCKET)) {
        return -1;
    } else {
        std::unique_lock<std::mutex> _lock(socket_map_lock);
        socket_map[fd] = socket;
    }
    return (int)fd;
}

ssize_t swoole_coroutine_send(int sockfd, const void *buf, size_t len, int flags) {
    auto socket = get_socket_ex(sockfd);
    if (sw_unlikely(socket == nullptr)) {
#ifdef _WIN32
        return ::send(sockfd, static_cast<const char *>(buf), static_cast<int>(len), flags);
#else
        return ::send(sockfd, buf, len, flags);
#endif
    }
    return socket->send(buf, len);
}

ssize_t swoole_coroutine_sendmsg(int sockfd, const struct msghdr *msg, int flags) {
    auto socket = get_socket_ex(sockfd);
    if (sw_unlikely(socket == nullptr)) {
#ifndef _WIN32
        return ::sendmsg(sockfd, msg, flags);
#else
        // Windows does not have sendmsg; return error
        errno = ENOSYS;
        return -1;
#endif
    }
    return socket->sendmsg(msg, flags);
}

ssize_t swoole_coroutine_recvmsg(int sockfd, struct msghdr *msg, int flags) {
    auto socket = get_socket_ex(sockfd);
    if (sw_unlikely(socket == nullptr)) {
#ifndef _WIN32
        return ::recvmsg(sockfd, msg, flags);
#else
        // Windows does not have recvmsg; return error
        errno = ENOSYS;
        return -1;
#endif
    }
    return socket->recvmsg(msg, flags);
}

ssize_t swoole_coroutine_recv(int sockfd, void *buf, size_t len, int flags) {
    auto socket = get_socket_ex(sockfd);
    if (sw_unlikely(socket == nullptr)) {
#ifdef _WIN32
        return ::recv(sockfd, static_cast<char *>(buf), static_cast<int>(len), flags);
#else
        return ::recv(sockfd, buf, len, flags);
#endif
    }
    if (flags & MSG_PEEK) {
        return socket->peek(buf, len);
    } else {
        return socket->recv(buf, len);
    }
}

int swoole_coroutine_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    auto socket = get_socket_ex(sockfd);
    if (sw_unlikely(socket == nullptr)) {
        return ::connect(sockfd, addr, addrlen);
    }
    return socket->connect(addr, addrlen) ? 0 : -1;
}

int swoole_coroutine_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    auto socket = get_socket_ex(sockfd);
    if (sw_unlikely(socket == nullptr)) {
        return ::accept(sockfd, addr, addrlen);
    }

    auto conn = socket->accept(0);
    if (!conn) {
        return -1;
    }

    *addrlen = conn->get_socket()->info.len;
    memcpy(addr, &conn->get_socket()->info.addr.ss, *addrlen);

    std::unique_lock<std::mutex> _lock(socket_map_lock);
    socket_map.emplace(conn->get_fd(), std::shared_ptr<SocketImpl>(conn));
    return conn->get_fd();
}

int swoole_coroutine_poll_fake(struct pollfd *fds, nfds_t nfds, int timeout) {
    if (nfds != 1) {
        swoole_set_last_error(SW_ERROR_INVALID_PARAMS);
        swoole_warning("fake poll() implementation, only supports one fd");
        return -1;
    }
    auto socket = get_socket_ex(fds[0].fd);
    if (sw_unlikely(timeout == 0 || socket == nullptr)) {
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

int swoole_coroutine_poll(struct pollfd *fds, nfds_t nfds, int timeout) {
    if (sw_unlikely(is_no_coro() || timeout == 0)) {
        return poll(fds, nfds, timeout);
    }

#ifdef SW_USE_IOURING
    if (nfds == 1) {
        return Iouring::poll(fds, nfds, timeout);
    }
#endif

    std::unordered_map<swSocketFd, PollSocket> _fds;
    for (nfds_t i = 0; i < nfds; i++) {
        _fds.emplace(static_cast<swSocketFd>(fds[i].fd), PollSocket(translate_events_from_poll(fds[i].events), &fds[i]));
    }

    if (!System::socket_poll(_fds, (double) timeout / 1000)) {
        return -1;
    }

    int retval = 0;
    for (auto &i : _fds) {
        int revents = i.second.revents;
        auto *_fd = static_cast<struct pollfd *>(i.second.ptr);
        _fd->revents = translate_events_to_poll(revents);
        if (revents > 0) {
            retval++;
        }
    }

    return retval;
}

int swoole_coroutine_socket_create(int fd) {
    if (sw_unlikely(is_no_coro())) {
        return -1;
    }
    auto socket = std::make_shared<SocketImpl>((swSocketFd)fd, SW_SOCK_RAW);
    swSocketFd _fd = socket->get_fd();
    if (sw_unlikely(_fd == SW_BAD_SOCKET)) {
        return -1;
    }
    socket->get_socket()->set_nonblock();
    std::unique_lock<std::mutex> _lock(socket_map_lock);
    socket_map[(swSocketFd)fd] = socket;
    return 0;
}

int swoole_coroutine_socket_unwrap(int fd) {
    if (sw_unlikely(is_no_coro())) {
        return -1;
    }
    auto socket = get_socket((swSocketFd)fd);
    if (socket == nullptr) {
        return -1;
    }
    std::unique_lock<std::mutex> _lock(socket_map_lock);
    socket->move_fd();
    socket_map.erase((swSocketFd)fd);
    return 0;
}

uint8_t swoole_coroutine_socket_exists(int fd) {
    return socket_map.find((swSocketFd)fd) != socket_map.end();
}

FILE *swoole_coroutine_fopen(const char *pathname, const char *mode) {
    if (sw_unlikely(is_no_coro())) {
        return fopen(pathname, mode);
    }

    FILE *retval = nullptr;
    async([&]() { retval = fopen(pathname, mode); });
    return retval;
}

FILE *swoole_coroutine_fdopen(int fd, const char *mode) {
    if (sw_unlikely(is_no_coro())) {
        return fdopen(fd, mode);
    }

    FILE *retval = nullptr;
    async([&]() { retval = fdopen(fd, mode); });
    return retval;
}

FILE *swoole_coroutine_freopen(const char *pathname, const char *mode, FILE *stream) {
    if (sw_unlikely(is_no_coro())) {
        return freopen(pathname, mode, stream);
    }

    FILE *retval = nullptr;
    async([&]() { retval = freopen(pathname, mode, stream); });
    return retval;
}

size_t swoole_coroutine_fread(void *ptr, size_t size, size_t nmemb, FILE *stream) {
    if (sw_unlikely(is_no_coro())) {
        return fread(ptr, size, nmemb, stream);
    }

    size_t retval = 0;
    async([&]() { retval = fread(ptr, size, nmemb, stream); });
    return retval;
}

size_t swoole_coroutine_fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) {
    if (sw_unlikely(is_no_coro())) {
        return fwrite(ptr, size, nmemb, stream);
    }

    size_t retval = 0;
    async([&]() { retval = fwrite(ptr, size, nmemb, stream); });
    return retval;
}

char *swoole_coroutine_fgets(char *s, int size, FILE *stream) {
    if (sw_unlikely(is_no_coro())) {
        return fgets(s, size, stream);
    }

    char *retval = nullptr;
    async([&]() { retval = fgets(s, size, stream); });
    return retval;
}

int swoole_coroutine_fputs(const char *s, FILE *stream) {
    if (sw_unlikely(is_no_coro())) {
        return fputs(s, stream);
    }

    int retval = -1;
    async([&]() { retval = fputs(s, stream); });
    return retval;
}

int swoole_coroutine_feof(FILE *stream) {
    if (sw_unlikely(is_no_coro())) {
        return feof(stream);
    }

    int retval = -1;
    async([&]() { retval = feof(stream); });
    return retval;
}

int swoole_coroutine_fflush(FILE *stream) {
    if (sw_unlikely(is_no_coro())) {
        return fflush(stream);
    }

    int retval = -1;
    async([&]() { retval = fflush(stream); });
    return retval;
}

int swoole_coroutine_fclose(FILE *stream) {
    if (sw_unlikely(is_no_coro())) {
        return fclose(stream);
    }

    int retval = -1;
    async([&]() { retval = fclose(stream); });
    return retval;
}

DIR *swoole_coroutine_opendir(const char *name) {
    if (sw_unlikely(is_no_coro())) {
        return sw_opendir(name);
    }

    DIR *retval = nullptr;
    async([&]() { retval = sw_opendir(name); });
    return retval;
}

struct dirent *swoole_coroutine_readdir(DIR *dirp) {
    if (sw_unlikely(is_no_coro())) {
        return sw_readdir(dirp);
    }

    struct dirent *retval;
    async([&retval, dirp]() { retval = sw_readdir(dirp); });
    return retval;
}

int swoole_coroutine_closedir(DIR *dirp) {
    if (sw_unlikely(is_no_coro())) {
        return sw_closedir(dirp);
    }

    int retval = -1;
    async([&]() { retval = sw_closedir(dirp); });
    return retval;
}

void swoole_coroutine_sleep(int sec) {
    System::sleep((double) sec);
}

void swoole_coroutine_usleep(int usec) {
    System::sleep((double) usec / 1000000);
}

int swoole_coroutine_socket_set_timeout(int sockfd, int which, double timeout) {
    auto socket = get_socket_ex(sockfd);
    if (sw_unlikely(socket == nullptr)) {
        errno = EINVAL;
        return -1;
    }
    if (which == SO_RCVTIMEO) {
        socket->set_timeout(timeout, SW_TIMEOUT_READ);
        return 0;
    } else if (which == SO_SNDTIMEO) {
        socket->set_timeout(timeout, SW_TIMEOUT_WRITE);
        return 0;
    } else {
        errno = EINVAL;
        return -1;
    }
}

int swoole_coroutine_socket_set_connect_timeout(int sockfd, double timeout) {
    auto socket = get_socket_ex(sockfd);
    if (sw_unlikely(socket == nullptr)) {
        errno = EINVAL;
        return -1;
    }
    socket->set_timeout(timeout, SW_TIMEOUT_DNS | SW_TIMEOUT_CONNECT);
    return 0;
}

int swoole_coroutine_socket_wait_event(int sockfd, int event, double timeout) {
    auto socket = get_socket_ex(sockfd);
    if (sw_unlikely(socket == nullptr)) {
        pollfd poll_ev{};
        poll_ev.fd = sockfd;
        poll_ev.events = translate_events_to_poll(event);
        return poll(&poll_ev, 1, (int) (timeout * 1000)) == 1 ? SW_OK : SW_ERR;
    }
    double ori_timeout = socket->get_timeout(event == SW_EVENT_READ ? SW_TIMEOUT_READ : SW_TIMEOUT_WRITE);
    socket->set_timeout(timeout);
    bool retval = socket->poll(static_cast<EventType>(event));
    socket->set_timeout(ori_timeout);
    return retval ? SW_OK : SW_ERR;
}

int swoole_coroutine_getaddrinfo(const char *name, const char *service, const addrinfo *req, addrinfo **pai) {
    int retval = -1;
    async([&]() { retval = getaddrinfo(name, service, req, pai); });
    return retval;
}

hostent *swoole_coroutine_gethostbyname(const char *name) {
    hostent *retval = nullptr;
    int _tmp_h_errno = 0;
    async([&]() {
        retval = gethostbyname(name);
        _tmp_h_errno = h_errno;
    });
#ifdef _WIN32
    // On Windows, h_errno is a macro that expands to a function call, not an lvalue
    // We cannot assign to it, so skip the assignment
#else
    h_errno = _tmp_h_errno;
#endif
    return retval;
}

int swoole_coroutine_open(const char *pathname, int flags, mode_t mode) {
    if (sw_unlikely(is_no_coro())) {
        return open(pathname, flags, mode);
    }

#if defined(_WIN32) && defined(SW_USE_IOCP)
    return Iocp::open_file(pathname, flags, mode);
#else
#ifdef SW_USE_ASYNC
    int ret = -1;
    async([&]() { ret = open(pathname, flags, mode); });
    return ret;
#else
    return Iouring::open(pathname, flags, mode);
#endif
#endif
}

int swoole_coroutine_close(int sockfd) {
    if (sw_unlikely(is_no_coro())) {
        return close(sockfd);
    }

    auto socket = get_socket((swSocketFd)sockfd);
    if (socket != nullptr) {
        if (socket->close()) {
            std::unique_lock<std::mutex> _lock(socket_map_lock);
            socket_map.erase((swSocketFd)sockfd);
            return 0;
        }
        return -1;
    }

#ifdef SW_USE_IOCP_FILE
    return Iocp::close_file(sockfd);
#elif defined(SW_USE_ASYNC)
    int ret = -1;
    async([&]() { ret = close(sockfd); });
    return ret;
#else
    return Iouring::close(sockfd);
#endif
}

ssize_t swoole_coroutine_read(int sockfd, void *buf, size_t count) {
    if (sw_unlikely(is_no_coro())) {
        return read(sockfd, buf, count);
    }

    auto socket = get_socket(sockfd);
    if (socket != nullptr) {
        return socket->read(buf, count);
    }

#ifdef SW_USE_IOCP_FILE
    return Iocp::read_file(sockfd, buf, count);
#elif defined(SW_USE_ASYNC)
    ssize_t ret = -1;
    NetSocket sock = {};
    sock.fd = sockfd;
    sock.nonblock = 1;
    sock.read_timeout = -1;
    async([&]() { ret = sock.read_sync(buf, count); });
    return ret;
#else
    return Iouring::read(sockfd, buf, count);
#endif
}

ssize_t swoole_coroutine_write(int sockfd, const void *buf, size_t count) {
    if (sw_unlikely(is_no_coro())) {
        return write(sockfd, buf, count);
    }

    auto socket = get_socket(sockfd);
    if (socket != nullptr) {
        return socket->write(buf, count);
    }

#ifdef SW_USE_IOCP_FILE
    return Iocp::write_file(sockfd, buf, count);
#elif defined(SW_USE_ASYNC)
    ssize_t ret = -1;
    NetSocket sock = {};
    sock.fd = sockfd;
    sock.nonblock = 1;
    sock.write_timeout = -1;
    async([&]() { ret = sock.write_sync(buf, count); });
    return ret;
#else
    return Iouring::write(sockfd, buf, count);
#endif
}

int swoole_coroutine_fstat(int fd, struct stat *statbuf) {
    if (sw_unlikely(is_no_coro())) {
        return fstat(fd, statbuf);
    }

#if defined(SW_USE_ASYNC) || !defined(HAVE_IOURING_STATX)
    int ret = -1;
    async([&]() { ret = fstat(fd, statbuf); });
    return ret;
#else
    return Iouring::fstat(fd, statbuf);
#endif
}

int swoole_coroutine_stat(const char *path, struct stat *statbuf) {
    if (sw_unlikely(is_no_coro())) {
        return stat(path, statbuf);
    }

#if defined(SW_USE_ASYNC) || !defined(HAVE_IOURING_STATX)
    int ret = -1;
    async([&]() { ret = stat(path, statbuf); });
    return ret;
#else
    return Iouring::stat(path, statbuf);
#endif
}

int swoole_coroutine_lstat(const char *path, struct stat *statbuf) {
    if (sw_unlikely(is_no_coro())) {
        return lstat(path, statbuf);
    }

#if defined(SW_USE_ASYNC) || !defined(HAVE_IOURING_STATX)
    int ret = -1;
    async([&]() { ret = lstat(path, statbuf); });
    return ret;
#else
    return Iouring::stat(path, statbuf);
#endif
}

int swoole_coroutine_unlink(const char *pathname) {
    if (sw_unlikely(is_no_coro())) {
        return unlink(pathname);
    }

#ifdef SW_USE_ASYNC
    int ret = -1;
    async([&]() { ret = unlink(pathname); });
    return ret;
#else
    return Iouring::unlink(pathname);
#endif
}

int swoole_coroutine_mkdir(const char *pathname, mode_t mode) {
    if (sw_unlikely(is_no_coro())) {
#ifdef _WIN32
        return mkdir(pathname);
#else
        return mkdir(pathname, mode);
#endif
    }

#ifdef SW_USE_ASYNC
    int ret = -1;
#ifdef _WIN32
    async([&]() { ret = mkdir(pathname); });
#else
    async([&]() { ret = mkdir(pathname, mode); });
#endif
    return ret;
#else
    return Iouring::mkdir(pathname, mode);
#endif
}

int swoole_coroutine_rmdir(const char *pathname) {
    if (sw_unlikely(is_no_coro())) {
        return rmdir(pathname);
    }

#ifdef SW_USE_ASYNC
    int ret = -1;
    async([&]() { ret = rmdir(pathname); });
    return ret;
#else
    return Iouring::rmdir(pathname);
#endif
}

int swoole_coroutine_rename(const char *oldpath, const char *newpath) {
    if (sw_unlikely(is_no_coro())) {
        return rename(oldpath, newpath);
    }

#ifdef SW_USE_ASYNC
    int ret = -1;
    async([&]() { ret = rename(oldpath, newpath); });
    return ret;
#else
    return Iouring::rename(oldpath, newpath);
#endif
}

int swoole_coroutine_fsync(int fd) {
    if (sw_unlikely(is_no_coro())) {
        return sw_fsync(fd);
    }

#ifdef SW_USE_ASYNC
    int ret = -1;
    async([&]() { ret = sw_fsync(fd); });
    return ret;
#else
    return Iouring::fsync(fd);
#endif
}

int swoole_coroutine_fdatasync(int fd) {
    if (sw_unlikely(is_no_coro())) {
#ifdef HAVE_FDATASYNC
        return fdatasync(fd);
#else
        return sw_fsync(fd);
#endif
    }

#ifdef SW_USE_ASYNC
    int ret = -1;
#ifdef HAVE_FDATASYNC
    async([&]() { ret = fdatasync(fd); });
#else
    async([&]() { ret = sw_fsync(fd); });
#endif
    return ret;
#else
    return Iouring::fdatasync(fd);
#endif
}

int swoole_coroutine_ftruncate(int fd, off_t length) {
    if (sw_unlikely(is_no_coro())) {
        return sw_ftruncate(fd, length);
    }

#if defined(SW_USE_ASYNC) || !defined(HAVE_IOURING_FTRUNCATE)
    int ret = -1;
    async([&]() { ret = sw_ftruncate(fd, length); });
    return ret;
#else
    return Iouring::ftruncate(fd, length);
#endif
}

off_t swoole_coroutine_lseek(int fd, off_t offset, int whence) {
    if (sw_unlikely(is_no_coro())) {
        return lseek(fd, offset, whence);
    }

    off_t ret = -1;
    async([&]() { ret = lseek(fd, offset, whence); });
    return ret;
}

ssize_t swoole_coroutine_readlink(const char *pathname, char *buf, size_t len) {
    if (sw_unlikely(is_no_coro())) {
#ifdef _WIN32
        errno = ENOSYS;
        return -1;
#else
        return readlink(pathname, buf, len);
#endif
    }

    ssize_t ret = -1;
#ifdef _WIN32
    errno = ENOSYS;
    ret = -1;
#else
    async([&]() { ret = readlink(pathname, buf, len); });
#endif
    return ret;
}

int swoole_coroutine_statvfs(const char *path, struct statvfs *buf) {
    if (sw_unlikely(is_no_coro())) {
#ifdef _WIN32
        errno = ENOSYS;
        return -1;
#else
        return statvfs(path, buf);
#endif
    }

    int ret = -1;
#ifdef _WIN32
    errno = ENOSYS;
    ret = -1;
#else
    async([&]() { ret = statvfs(path, buf); });
#endif
    return ret;
}

int swoole_coroutine_access(const char *pathname, int mode) {
    if (sw_unlikely(is_no_coro())) {
        return sw_access(pathname, mode);
    }

    int ret = -1;
    async([&]() { ret = sw_access(pathname, mode); });
    return ret;
}
SW_EXTERN_C_END
