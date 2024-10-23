/*
 +----------------------------------------------------------------------+
 | Swoole                                                               |
 +----------------------------------------------------------------------+
 | Copyright (c) 2012-2018 The Swoole Group                             |
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

#pragma once

#include <vector>
#include <string>
#include <mutex>
#include <atomic>
#include <queue>

#ifndef O_DIRECT
#define O_DIRECT 040000
#endif

#ifdef SW_USE_IOURING
#include <liburing.h>
#include <linux/version.h>

#define SW_CHECK_IOURING_VERSION(major, minor)                                                                         \
    ((IO_URING_VERSION_MAJOR > major) || (IO_URING_VERSION_MAJOR == major && IO_URING_VERSION_MINOR >= minor))

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 7, 0) && SW_CHECK_IOURING_VERSION(2, 6)
#define HAVE_IOURING_FUTEX 1  // futex lock available since kernel 6.7 and liburing >= 2.6.
#endif
#endif

namespace swoole {

enum AsyncFlag {
    SW_AIO_WRITE_FSYNC = 1u << 1,
    SW_AIO_EOF = 1u << 2,
};

struct AsyncEvent {
#ifdef SW_USE_IOURING
    size_t count;
    const char *pathname;
    const char *pathname2;
    struct statx *statxbuf;
    void *rbuf;
    const void *wbuf;
    int fd;  // alias futex_flags
    uint32_t flags;
    int opcode;
    mode_t mode;
#ifdef HAVE_IOURING_FUTEX
    uint32_t *futex;
    uint64_t value;
    uint64_t mask;
#endif
#endif

    // internal use only
    network::Socket *pipe_socket;
    double timestamp;
    void *object;
    void (*handler)(AsyncEvent *event);
    void (*callback)(AsyncEvent *event);

    size_t task_id;
    ssize_t retval;  // output
    void *data;      // input & output
    uint8_t canceled;
    int error;

    bool catch_error() {
        return (error == SW_ERROR_AIO_TIMEOUT || error == SW_ERROR_AIO_CANCELED);
    }
};

struct GethostbynameRequest {
    const char *name;
    int family;
    char *addr;
    size_t addr_len;

    GethostbynameRequest(const char *_name, int _family) : name(_name), family(_family) {
        addr_len = _family == AF_INET6 ? INET6_ADDRSTRLEN : INET_ADDRSTRLEN;
        addr = new char[addr_len];
    }

    ~GethostbynameRequest() {
        delete[] addr;
    }
};

class AsyncThreads {
  public:
    size_t task_num = 0;
    Pipe *pipe = nullptr;
    std::shared_ptr<async::ThreadPool> pool;
    network::Socket *read_socket = nullptr;
    network::Socket *write_socket = nullptr;

    AsyncThreads();
    ~AsyncThreads();

    size_t get_task_num() {
        return task_num;
    }

    size_t get_queue_size();
    size_t get_worker_num();
    void notify_one();

    static int callback(Reactor *reactor, Event *event);
};

#ifdef SW_USE_IOURING
class AsyncIouring {
  private:
    int ring_fd;
    uint64_t task_num = 0;
    uint64_t entries = 8192;
    struct io_uring ring;
    std::queue<AsyncEvent *> waiting_tasks;
    network::Socket *iou_socket = nullptr;
    Reactor *reactor = nullptr;

    inline struct io_uring_sqe *get_iouring_sqe() {
        struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
        // We need to reset the values of each sqe structure so that they can be used in a loop.
        if (sqe) {
            memset(sqe, 0, sizeof(struct io_uring_sqe));
        }
        return sqe;
    }

    inline bool submit_iouring_sqe(AsyncEvent *event) {
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

  public:
    AsyncIouring(Reactor *reactor_);
    ~AsyncIouring();

    enum opcodes {
        SW_IORING_OP_OPENAT = IORING_OP_OPENAT,
        SW_IORING_OP_CLOSE = IORING_OP_CLOSE,
        SW_IORING_OP_STATX = IORING_OP_STATX,
        SW_IORING_OP_READ = IORING_OP_READ,
        SW_IORING_OP_WRITE = IORING_OP_WRITE,
        SW_IORING_OP_RENAMEAT = IORING_OP_RENAMEAT,
        SW_IORING_OP_UNLINKAT = IORING_OP_UNLINKAT,
        SW_IORING_OP_MKDIRAT = IORING_OP_MKDIRAT,
#ifdef HAVE_IOURING_FUTEX
        SW_IORING_OP_FUTEX_WAIT = IORING_OP_FUTEX_WAIT,
        SW_IORING_OP_FUTEX_WAKE = IORING_OP_FUTEX_WAKE,
#endif

        SW_IORING_OP_FSTAT = 1000,
        SW_IORING_OP_LSTAT = 1001,
        SW_IORING_OP_UNLINK_FILE = 1002,
        SW_IORING_OP_UNLINK_DIR = 1003,
        SW_IORING_OP_FSYNC = 1004,
        SW_IORING_OP_FDATASYNC = 1005,
    };

    enum flags {
        SW_IOURING_DEFAULT = 0,
        SW_IOURING_SQPOLL = IORING_SETUP_SQPOLL,
    };

    void add_event();
    void delete_event();
    bool wakeup();
    bool open(AsyncEvent *event);
    bool close(AsyncEvent *event);
    bool wr(AsyncEvent *event);
    bool statx(AsyncEvent *event);
    bool mkdir(AsyncEvent *event);
    bool unlink(AsyncEvent *event);
    bool rename(AsyncEvent *event);
    bool fsync(AsyncEvent *event);
#ifdef HAVE_IOURING_FUTEX
    bool futex(AsyncEvent *event);
#endif
    inline bool is_empty_waiting_tasks() {
        return waiting_tasks.size() == 0;
    }

    inline uint64_t get_task_num() {
        return task_num;
    }

    static int callback(Reactor *reactor, Event *event);
};
#endif

namespace async {

typedef void (*Handler)(AsyncEvent *event);

AsyncEvent *dispatch(const AsyncEvent *request);

void handler_gethostbyname(AsyncEvent *event);
void handler_getaddrinfo(AsyncEvent *event);

}  // namespace async
};  // namespace swoole
