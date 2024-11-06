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

#ifndef SWOOLE_SRC_SWOOLE_IOURING_H
#define SWOOLE_SRC_SWOOLE_IOURING_H

#include "swoole_coroutine.h"

#ifdef SW_USE_IOURING
#include <liburing.h>

#ifdef HAVE_IOURING_FUTEX
#ifndef FUTEX2_SIZE_U32
#define FUTEX2_SIZE_U32 0x02
#endif
#endif

using swoole::Coroutine;

enum swIouringFlag {
    SW_IOURING_DEFAULT = 0,
    SW_IOURING_SQPOLL = IORING_SETUP_SQPOLL,
};

namespace swoole {

struct IouringEvent;

class Iouring {
  private:
    uint64_t task_num = 0;
    uint64_t entries = 8192;
    struct io_uring ring;
    std::queue<IouringEvent *> waiting_tasks;
    network::Socket *ring_socket = nullptr;
    Reactor *reactor = nullptr;

    Iouring(Reactor *reactor_);
    bool ready();
    bool submit(IouringEvent *event);
    bool dispatch(IouringEvent *event);
    bool wakeup();

    struct io_uring_sqe *get_iouring_sqe() {
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

    static int open(const char *pathname, int flags, int mode);
    static int close(int fd);
    static ssize_t read(int fd, void *buf, size_t size);
    static ssize_t write(int fd, const void *buf, size_t size);
    static ssize_t rename(const char *oldpath, const char *newpath);
    static int mkdir(const char *pathname, mode_t mode);
    static int unlink(const char *pathname);
    static int fstat(int fd, struct stat *statbuf);
    static int stat(const char *path, struct stat *statbuf);
    static int rmdir(const char *pathname);
    static int fsync(int fd);
    static int fdatasync(int fd);
#ifdef HAVE_IOURING_FUTEX
    static int futex_wait(uint32_t *futex);
    static int futex_wakeup(uint32_t *futex);
#endif

    static int callback(Reactor *reactor, Event *event);
};
};  // namespace swoole
#endif
#endif
