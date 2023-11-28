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

namespace swoole {

enum AsyncFlag {
    SW_AIO_WRITE_FSYNC = 1u << 1,
    SW_AIO_EOF = 1u << 2,
};

struct AsyncEvent {
    size_t task_id;
#if defined(__linux__) && defined(SW_USE_IOURING)
    size_t count;
#endif
    uint8_t canceled;
    int error;
    /**
     * input & output
     */
    void *data;
#if defined(__linux__) && defined(SW_USE_IOURING)
    const char *pathname;
    const char *pathname2;
    struct statx *statxbuf;
    void *rbuf;
    const void *wbuf;
#endif
    /**
     * output
     */
    ssize_t retval;
#if defined(__linux__) && defined(SW_USE_IOURING)
    int fd;
    int flags;
    int opcode;
    mode_t mode;
#endif
    /**
     * internal use only
     */
    network::Socket *pipe_socket;
    double timestamp;
    void *object;
    void (*handler)(AsyncEvent *event);
    void (*callback)(AsyncEvent *event);

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
    bool schedule = false;
    size_t task_num = 0;
    Pipe *pipe = nullptr;
    async::ThreadPool *pool = nullptr;
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

  private:
    std::mutex init_lock;
};

#if defined(__linux__) && defined(SW_USE_IOURING)
class AsyncIOUring {
  private:
    int ring_fd;
    uint32_t entries = 8192;
    struct io_uring ring;
    network::Socket *iou_socket = nullptr;
    Reactor *reactor = nullptr;

    struct io_uring_sqe *get_iouring_sqe();
    bool store_events(AsyncEvent *event);
    void set_iouring_sqe_data(struct io_uring_sqe *sqe, void *data);
    void *get_iouring_cqe_data(struct io_uring_cqe *cqe);
    int get_iouring_cqe(struct io_uring_cqe **cqe_ptr);
    void finish_iouring_cqe(struct io_uring_cqe *cqe);
    bool submit_iouring_sqe();

  public:
    uint64_t task_num = 0;
    std::queue<AsyncEvent *> waitEvents;
    AsyncIOUring(Reactor *reactor_);
    ~AsyncIOUring();

    enum opcodes {
        SW_IORING_OP_OPENAT = 18,
        SW_IORING_OP_CLOSE = 19,
        SW_IORING_OP_STATX = 21,
        SW_IORING_OP_READ = 22,
        SW_IORING_OP_WRITE = 23,
        SW_IORING_OP_RENAMEAT = 35,
        SW_IORING_OP_UNLINKAT = 36,
        SW_IORING_OP_MKDIRAT = 37,
        SW_IORING_OP_FSTAT = 1000,
        SW_IORING_OP_LSTAT = 1001,
        SW_IORING_OP_UNLINK_FILE = 1002,
        SW_IORING_OP_UNLINK_DIR = 1003,
    };

    void add_event();
    void delete_event();
    bool open(AsyncEvent *event);
    bool close(AsyncEvent *event);
    bool wr(AsyncEvent *event);
    bool statx(AsyncEvent *event);
    bool mkdir(AsyncEvent *event);
    bool unlink(AsyncEvent *event);
    bool rename(AsyncEvent *event);
    inline bool is_empty_wait_events() {
        return waitEvents.size() == 0;
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
