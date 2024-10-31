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

using swoole::Coroutine;

enum Opcodes {
    SW_IORING_OP_OPENAT = IORING_OP_OPENAT,
    SW_IORING_OP_CLOSE = IORING_OP_CLOSE,
    SW_IORING_OP_STATX = IORING_OP_STATX,
    SW_IORING_OP_READ = IORING_OP_READ,
    SW_IORING_OP_WRITE = IORING_OP_WRITE,
    SW_IORING_OP_RENAMEAT = IORING_OP_RENAMEAT,
    SW_IORING_OP_UNLINKAT = IORING_OP_UNLINKAT,
    SW_IORING_OP_MKDIRAT = IORING_OP_MKDIRAT,

    SW_IORING_OP_FSTAT = 1000,
    SW_IORING_OP_LSTAT = 1001,
    SW_IORING_OP_UNLINK_FILE = 1002,
    SW_IORING_OP_UNLINK_DIR = 1003,
    SW_IORING_OP_FSYNC = 1004,
    SW_IORING_OP_FDATASYNC = 1005,
};

namespace swoole {
struct IouringEvent {
    int fd;
    int flags;
    int opcode;
    mode_t mode;
    uint64_t count;  // share with offset
    ssize_t result;
    void *rbuf;
    Coroutine *coroutine;
    const void *wbuf;
    const char *pathname;
    const char *pathname2;
    struct statx *statxbuf;
    uint8_t canceled = 0;
};

class Iouring {
  private:
    int ring_fd;
    uint64_t task_num = 0;
    uint64_t entries = 8192;
    struct io_uring ring;
    std::queue<IouringEvent *> waiting_tasks;
    network::Socket *iou_socket = nullptr;
    Reactor *reactor = nullptr;

    void add_event();
    void delete_event();
    bool wakeup();
    bool open(IouringEvent *event);
    bool close(IouringEvent *event);
    bool wr(IouringEvent *event);
    bool statx(IouringEvent *event);
    bool mkdir(IouringEvent *event);
    bool unlink(IouringEvent *event);
    bool rename(IouringEvent *event);
    bool fsync(IouringEvent *event);
    int dispatch(IouringEvent *event);

    inline struct io_uring_sqe *get_iouring_sqe() {
        struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
        // We need to reset the values of each sqe structure so that they can be used in a loop.
        if (sqe) {
            memset(sqe, 0, sizeof(struct io_uring_sqe));
        }
        return sqe;
    }

    inline bool submit_iouring_sqe(IouringEvent *event) {
        int ret = io_uring_submit(&ring);

        if (ret < 0) {
            errno = -ret;
            if (ret == -EAGAIN) {
                waiting_tasks.push(event);
                return true;
            }
            return false;
        }

        task_num++;
        return true;
    }

    static Iouring *create_iouring();

  public:
    Iouring(Reactor *reactor_);
    ~Iouring();

    enum flags {
        SW_IOURING_DEFAULT = 0,
        SW_IOURING_SQPOLL = IORING_SETUP_SQPOLL,
    };

    inline bool is_empty_waiting_tasks() {
        return waiting_tasks.size() == 0;
    }

    inline uint64_t get_task_num() {
        return task_num;
    }

    static int async(Opcodes type,
                     int fd = 0,
                     uint64_t count = 0,
                     void *rbuf = nullptr,
                     const void *wbuf = nullptr,
                     struct statx *statxbuf = nullptr);
    static int async(Opcodes type,
                     const char *pathname = nullptr,
                     const char *pathname2 = nullptr,
                     struct statx *statxbuf = nullptr,
                     int flags = 0,
                     mode_t mode = 0);
    static int callback(Reactor *reactor, Event *event);
};
};  // namespace swoole
#endif
#endif
