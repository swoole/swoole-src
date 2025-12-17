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
    uint64_t entries = 8192;
    io_uring ring;
    std::queue<IouringEvent *> waiting_tasks;
    network::Socket *ring_socket = nullptr;
    Reactor *reactor = nullptr;

    explicit Iouring(Reactor *reactor_);
    bool ready() const;
    bool submit(IouringEvent *event);
    bool dispatch(IouringEvent *event, IouringTimeout *timeout);
    bool wakeup();

    static ssize_t execute(IouringEvent *event, IouringTimeout *timeout = nullptr);

  public:
    ~Iouring();

    bool is_empty_waiting_tasks() const {
        return waiting_tasks.empty();
    }

    uint64_t get_task_num() const {
        return task_num;
    }

    static int socket(int domain, int type, int protocol = 0, int flags = 0);
    static int open(const char *pathname, int flags, mode_t mode);
    static int connect(int fd, const struct sockaddr *addr, socklen_t len);
    static int accept(int fd, struct sockaddr *addr, socklen_t *len, int flags = 0);
    static int bind(int fd, const struct sockaddr *addr, socklen_t len);
    static int listen(int fd, int backlog);
    static int sleep(int tv_sec, int tv_nsec, int flags = 0);
    static ssize_t recv(int fd, char *buf, size_t len, int flags);
    static ssize_t send(int fd, const char *buf, size_t len, int flags);
    static int close(int fd);
    static ssize_t read(int fd, void *buf, size_t size);
    static ssize_t write(int fd, const void *buf, size_t size);
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
