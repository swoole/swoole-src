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

#include <sys/file.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <netdb.h>
#include <poll.h>
#include <dirent.h>

#include <mutex>
#include <unordered_map>

#include "swoole_coroutine_socket.h"
#include "swoole_coroutine_system.h"

using swoole::AsyncEvent;
using swoole::Coroutine;
using swoole::async::dispatch;
using swoole::coroutine::Socket;
using swoole::coroutine::System;
using swoole::coroutine::async;

static std::unordered_map<int, Socket *> socket_map;
static std::mutex socket_map_lock;

static sw_inline bool is_no_coro() {
    return SwooleTG.reactor == nullptr || !Coroutine::get_current();
}

static sw_inline Socket *get_socket(int sockfd) {
    std::unique_lock<std::mutex> _lock(socket_map_lock);
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
        std::unique_lock<std::mutex> _lock(socket_map_lock);
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
        std::unique_lock<std::mutex> _lock(socket_map_lock);
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

int swoole_coroutine_open(const char *pathname, int flags, mode_t mode) {
    if (sw_unlikely(is_no_coro())) {
        return open(pathname, flags, mode);
    }

    int ret = -1;
    async([&]() { ret = open(pathname, flags, mode); });
    return ret;
}

int swoole_coroutine_socket_create(int fd) {
    if (sw_unlikely(is_no_coro())) {
        return -1;
    }
    Socket *socket = new Socket(fd, SW_SOCK_RAW);
    int _fd = socket->get_fd();
    if (sw_unlikely(_fd < 0)) {
        delete socket;
    } else {
        std::unique_lock<std::mutex> _lock(socket_map_lock);
        socket_map[fd] = socket;
    }
    return 0;
}

uint8_t swoole_coroutine_socket_exists(int fd) {
    return socket_map.find(fd) != socket_map.end();
}

ssize_t swoole_coroutine_read(int sockfd, void *buf, size_t count) {
    if (sw_unlikely(is_no_coro())) {
        return read(sockfd, buf, count);
    }

    Socket *socket = get_socket(sockfd);
    if (socket) {
        return socket->read(buf, count);
    }

    ssize_t ret = -1;
    async([&]() { ret = read(sockfd, buf, count); });
    return ret;
}

ssize_t swoole_coroutine_write(int sockfd, const void *buf, size_t count) {
    if (sw_unlikely(is_no_coro())) {
        return write(sockfd, buf, count);
    }

    Socket *socket = get_socket(sockfd);
    if (socket) {
        return socket->write(buf, count);
    }

    ssize_t ret = -1;
    async([&]() { ret = write(sockfd, buf, count); });
    return ret;
}

off_t swoole_coroutine_lseek(int fd, off_t offset, int whence) {
    if (sw_unlikely(is_no_coro())) {
        return lseek(fd, offset, whence);
    }

    off_t retval = -1;
    async([&]() { retval = lseek(fd, offset, whence); });
    return retval;
}

int swoole_coroutine_fstat(int fd, struct stat *statbuf) {
    if (sw_unlikely(is_no_coro())) {
        return fstat(fd, statbuf);
    }

    int retval = -1;
    async([&]() { retval = fstat(fd, statbuf); });
    return retval;
}

int swoole_coroutine_readlink(const char *pathname, char *buf, size_t len) {
    if (sw_unlikely(is_no_coro())) {
        return readlink(pathname, buf, len);
    }

    int retval = -1;
    async([&]() { retval = readlink(pathname, buf, len); });
    return retval;
}

int swoole_coroutine_unlink(const char *pathname) {
    if (sw_unlikely(is_no_coro())) {
        return unlink(pathname);
    }

    int retval = -1;
    async([&]() { retval = unlink(pathname); });
    return retval;
}

int swoole_coroutine_statvfs(const char *path, struct statvfs *buf) {
    if (sw_unlikely(is_no_coro())) {
        return statvfs(path, buf);
    }

    int retval = -1;
    async([&]() { retval = statvfs(path, buf); });
    return retval;
}

int swoole_coroutine_mkdir(const char *pathname, mode_t mode) {
    if (sw_unlikely(is_no_coro())) {
        return mkdir(pathname, mode);
    }

    int retval = -1;
    async([&]() { retval = mkdir(pathname, mode); });
    return retval;
}

int swoole_coroutine_rmdir(const char *pathname) {
    if (sw_unlikely(is_no_coro())) {
        return rmdir(pathname);
    }

    int retval = -1;
    async([&]() { retval = rmdir(pathname); });
    return retval;
}

int swoole_coroutine_rename(const char *oldpath, const char *newpath) {
    if (sw_unlikely(is_no_coro())) {
        return rename(oldpath, newpath);
    }

    int retval = -1;
    async([&]() { retval = rename(oldpath, newpath); });
    return retval;
}

int swoole_coroutine_access(const char *pathname, int mode) {
    if (sw_unlikely(is_no_coro())) {
        return access(pathname, mode);
    }

    int retval = -1;
    async([&]() { retval = access(pathname, mode); });
    return retval;
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

int swoole_coroutine_fclose(FILE *stream) {
    if (sw_unlikely(is_no_coro())) {
        return fclose(stream);
    }

    int retval = -1;
    async([&]() { retval = fclose(stream); });
    return retval;
}

int swoole_coroutine_flock(int fd, int operation) {
    if (sw_unlikely(is_no_coro())) {
        return flock(fd, operation);
    }

    int retval = -1;
    async([&]() { retval = flock(fd, operation); });
    return retval;
}

DIR *swoole_coroutine_opendir(const char *name) {
    if (sw_unlikely(is_no_coro())) {
        return opendir(name);
    }

    DIR *retval = nullptr;
    async([&]() { retval = opendir(name); });
    return retval;
}

struct dirent *swoole_coroutine_readdir(DIR *dirp) {
    if (sw_unlikely(is_no_coro())) {
        return readdir(dirp);
    }

    struct dirent *retval;

    async([&retval, dirp]() {
        retval = readdir(dirp);
    });

    return retval;
}

int swoole_coroutine_closedir(DIR *dirp) {
    if (sw_unlikely(is_no_coro())) {
        return closedir(dirp);
    }

    int retval = -1;
    async([&]() { retval = closedir(dirp); });
    return retval;
}

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
        socket->set_timeout(timeout, Socket::TIMEOUT_READ);
        return 0;
    } else if (which == SO_SNDTIMEO) {
        socket->set_timeout(timeout, Socket::TIMEOUT_WRITE);
        return 0;
    } else {
        errno = EINVAL;
        return -1;
    }
}

int swoole_coroutine_socket_set_connect_timeout(int sockfd, double timeout) {
    Socket *socket = get_socket_ex(sockfd);
    if (sw_unlikely(socket == NULL)) {
        errno = EINVAL;
        return -1;
    }
    socket->set_timeout(timeout, Socket::TIMEOUT_DNS | Socket::TIMEOUT_CONNECT);
    return 0;
}

int swoole_coroutine_socket_wait_event(int sockfd, int event, double timeout) {
    Socket *socket = get_socket_ex(sockfd);
    if (sw_unlikely(socket == NULL)) {
        errno = EINVAL;
        return -1;
    }
    double ori_timeout = socket->get_timeout(event == SW_EVENT_READ ? Socket::TIMEOUT_READ : Socket::TIMEOUT_WRITE);
    socket->set_timeout(timeout);
    bool retval = socket->poll((enum swEventType) event);
    socket->set_timeout(ori_timeout);
    return retval ? SW_OK : SW_ERR;
}

int swoole_coroutine_getaddrinfo(const char *name,
                                 const char *service,
                                 const struct addrinfo *req,
                                 struct addrinfo **pai) {
    if (sw_unlikely(is_no_coro())) {
        return getaddrinfo(name, service, req, pai);
    }

    int retval = -1;
    async([&]() { retval = getaddrinfo(name, service, req, pai); });
    return retval;
}

struct hostent *swoole_coroutine_gethostbyname(const char *name) {
    if (sw_unlikely(is_no_coro())) {
        return gethostbyname(name);
    }

    struct hostent *retval = nullptr;
    int _tmp_h_errno;
    async([&]() {
        retval = gethostbyname(name);
        _tmp_h_errno = h_errno;
    });
    h_errno = _tmp_h_errno;
    return retval;
}

SW_EXTERN_C_END
