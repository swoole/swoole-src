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
  | Author: NathanFreeman  <mariasocute@163.com>                         |
  +----------------------------------------------------------------------+
*/

#pragma once

#include "swoole_coroutine.h"

#ifdef SW_USE_IOURING
#include <liburing.h>

using swoole::Coroutine;

enum swIouringFlag {
    SW_IOURING_DEFAULT = 0,
    SW_IOURING_SQPOLL = IORING_SETUP_SQPOLL,
};

namespace swoole {

struct IouringEvent;

struct IouringTimeout {
    int64_t tv_sec;
    int64_t tv_nsec;
};

class Iouring {
    uint64_t task_num = 0;
    uint64_t entries = SW_IOURING_QUEUE_SIZE;
    io_uring ring;
    std::queue<IouringEvent *> waiting_tasks;
    network::Socket *ring_socket = nullptr;
    Reactor *reactor = nullptr;

    explicit Iouring(Reactor *reactor_);
    bool ready() const;
    bool submit(IouringEvent *event);
    bool dispatch(IouringEvent *event);
    bool wakeup();

    static Iouring *get_instance();
    static ssize_t execute(IouringEvent *event);

  public:
    ~Iouring();

    bool is_empty_waiting_tasks() const {
        return waiting_tasks.empty();
    }

    uint64_t get_task_num() const {
        return task_num;
    }

    uint32_t get_sq_space_left() const {
        return io_uring_sq_space_left(&ring);
    }

    uint32_t get_sq_capacity() const {
        return ring.sq.ring_entries;
    }

    unsigned int get_sq_used() const {
        return get_sq_capacity() - get_sq_space_left();
    }

    float get_sq_usage_percent() const {
        return (float) get_sq_used() / get_sq_capacity() * 100.0f;
    }

    static int socket(int domain, int type, int protocol = 0, int flags = 0);
    static int open(const char *pathname, int flags, mode_t mode);
    static int connect(int fd, const struct sockaddr *addr, socklen_t len, double timeout = -1);
    static int accept(int fd, struct sockaddr *addr, socklen_t *len, int flags = 0, double timeout = -1);
    static int bind(int fd, const struct sockaddr *addr, socklen_t len);
    static int listen(int fd, int backlog);
    static int sleep(int tv_sec, int tv_nsec, int flags = 0);
    static int sleep(double seconds);
    static ssize_t recv(int fd, void *buf, size_t len, int flags, double timeout = -1);
    static ssize_t send(int fd, const void *buf, size_t len, int flags, double timeout = -1);
    static ssize_t recvmsg(int fd, struct msghdr *message, int flags, double timeout = -1);
    static ssize_t sendmsg(int fd, const struct msghdr *message, int flags, double timeout = -1);
    static ssize_t sendfile(int out_fd, int in_fd, off_t *offset, size_t size, double timeout = -1);
    static ssize_t recvfrom(int fd, void *_buf, size_t _n, sockaddr *_addr, socklen_t *_socklen, double timeout = -1);
    static ssize_t readv(int fd, const struct iovec *iovec, int count, double timeout = -1);
    static ssize_t writev(int fd, const struct iovec *iovec, int count, double timeout = -1);

    static int close(int fd);
    static ssize_t read(int fd, void *buf, size_t size, double timeout = -1);
    static ssize_t write(int fd, const void *buf, size_t size, double timeout = -1);
    static int rename(const char *oldpath, const char *newpath);
    static int mkdir(const char *pathname, mode_t mode);
    static int unlink(const char *pathname);
#ifdef HAVE_IOURING_STATX
    static int fstat(int fd, struct stat *statbuf);
    static int stat(const char *path, struct stat *statbuf);
#endif
    static int rmdir(const char *pathname);
    static int fsync(int fd);
    static int fdatasync(int fd);
    static pid_t wait(int *stat_loc, double timeout = -1);
    static pid_t waitpid(pid_t pid, int *stat_loc, int options, double timeout = -1);
    /**
     * Only supports listening to the readable and writable events of a single fd; nfds must be 1.
     */
    static int poll(struct pollfd *fds, nfds_t nfds, int timeout);
#ifdef HAVE_IOURING_FUTEX
    static int futex_wait(uint32_t *futex);
    static int futex_wakeup(uint32_t *futex);
#endif
#ifdef HAVE_IOURING_FTRUNCATE
    static int ftruncate(int fd, off_t length);
#endif

    static std::unordered_map<std::string, int> list_all_opcode();
    static int callback(Reactor *reactor, Event *event);
};
};  // namespace swoole
#endif
