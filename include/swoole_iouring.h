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
    bool dispatch(IouringEvent *event);
    bool wakeup();

    io_uring_sqe *get_iouring_sqe() {
        struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
        // We need to reset the values of each sqe structure so that they can be used in a loop.
        if (sqe) {
            memset(sqe, 0, sizeof(struct io_uring_sqe));
        }
        return sqe;
    }

    static ssize_t execute(IouringEvent *event);

  public:
    ~Iouring();

    bool is_empty_waiting_tasks() {
        return waiting_tasks.size() == 0;
    }

    uint64_t get_task_num() {
        return task_num;
    }

    static int open(const char *pathname, int flags, mode_t mode);
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
