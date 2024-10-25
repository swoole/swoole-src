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

#include "swoole.h"
#include "swoole_api.h"
#include "swoole_socket.h"
#include "swoole_reactor.h"
#include "swoole_string.h"
#include "swoole_signal.h"
#include "swoole_pipe.h"
#include "swoole_async.h"
#include "swoole_util.h"
#include "swoole_coroutine.h"

#ifdef SW_USE_IOURING
namespace swoole {
//-------------------------------------------------------------------------------
AsyncIouring::AsyncIouring(Reactor *reactor_) {
    if (!SwooleTG.reactor) {
        swoole_warning("no event loop, cannot initialized");
        throw swoole::Exception(SW_ERROR_WRONG_OPERATION);
    }

    reactor = reactor_;
    if (SwooleG.iouring_entries > 0) {
        uint32_t i = 6;
        while ((1U << i) < SwooleG.iouring_entries) {
            i++;
        }
        entries = 1 << i;
    }

    int ret =
        io_uring_queue_init(entries, &ring, (SwooleG.iouring_flag == IORING_SETUP_SQPOLL ? IORING_SETUP_SQPOLL : 0));
    if (ret < 0) {
        swoole_warning("Create io_uring failed, the error code is %d", -ret);
        throw swoole::Exception(SW_ERROR_WRONG_OPERATION);
        return;
    }

    if (SwooleG.iouring_workers > 0) {
        unsigned int workers[2] = {SwooleG.iouring_workers, SwooleG.iouring_workers};
        ret = io_uring_register_iowq_max_workers(&ring, workers);

        if (ret < 0) {
            swoole_warning("Failed to increase io_uring async workers, the error code is %d", -ret);
            throw swoole::Exception(SW_ERROR_WRONG_OPERATION);
            return;
        }
    }

    ring_fd = ring.ring_fd;

    iou_socket = make_socket(ring_fd, SW_FD_IOURING);
    if (!iou_socket) {
        swoole_sys_warning("create io_uring socket failed");
        return;
    }

    reactor->set_exit_condition(Reactor::EXIT_CONDITION_IOURING, [](Reactor *reactor, size_t &event_num) -> bool {
        if (SwooleTG.async_iouring && SwooleTG.async_iouring->get_task_num() == 0 &&
            SwooleTG.async_iouring->is_empty_waiting_tasks()) {
            event_num--;
        }
        return true;
    });

    reactor->add_destroy_callback([](void *data) {
        if (!SwooleTG.async_iouring) {
            return;
        }
        SwooleTG.async_iouring->delete_event();
        delete SwooleTG.async_iouring;
        SwooleTG.async_iouring = nullptr;
    });
}

AsyncIouring::~AsyncIouring() {
    if (ring_fd >= 0) {
        ::close(ring_fd);
    }

    if (iou_socket) {
        delete iou_socket;
    }

    io_uring_queue_exit(&ring);
}

void AsyncIouring::add_event() {
    reactor->add(iou_socket, SW_EVENT_READ);
}

void AsyncIouring::delete_event() {
    reactor->del(iou_socket);
}

bool AsyncIouring::wakeup() {
    unsigned count = 0;
    unsigned num = 8192;
    void *data = nullptr;
    AsyncEvent *task = nullptr;
    AsyncEvent *waiting_task = nullptr;
    struct io_uring_cqe *cqe = nullptr;
    struct io_uring_cqe *cqes[num];

    while (true) {
        count = io_uring_peek_batch_cqe(&ring, cqes, num);
        if (count == 0) {
            return true;
        }

        for (unsigned i = 0; i < count; i++) {
            cqe = cqes[i];
            data = io_uring_cqe_get_data(cqe);
            task = reinterpret_cast<AsyncEvent *>(data);
            task_num--;
            if (cqe->res < 0) {
                errno = -(cqe->res);
                /**
                 * If the error code is EAGAIN, it indicates that the resource is temporarily unavailable,
                 * but it can be retried. However, for the fairness of the tasks, this task should be placed
                 * at the end of the queue.
                 */
                if (cqe->res == -EAGAIN) {
                    io_uring_cq_advance(&ring, 1);
                    waiting_tasks.push(task);
                    continue;
                }
            }

            task->retval = (cqe->res >= 0 ? cqe->res : -1);
            io_uring_cq_advance(&ring, 1);
            task->callback(task);

            if (!is_empty_waiting_tasks()) {
                waiting_task = waiting_tasks.front();
                waiting_tasks.pop();
                if (waiting_task->opcode == AsyncIouring::SW_IORING_OP_OPENAT) {
                    open(waiting_task);
                } else if (waiting_task->opcode == AsyncIouring::SW_IORING_OP_CLOSE) {
                    close(waiting_task);
                } else if (waiting_task->opcode == AsyncIouring::SW_IORING_OP_FSTAT ||
                           waiting_task->opcode == AsyncIouring::SW_IORING_OP_LSTAT) {
                    statx(waiting_task);
                } else if (waiting_task->opcode == AsyncIouring::SW_IORING_OP_READ ||
                           waiting_task->opcode == AsyncIouring::SW_IORING_OP_WRITE) {
                    wr(waiting_task);
                } else if (waiting_task->opcode == AsyncIouring::SW_IORING_OP_RENAMEAT) {
                    rename(waiting_task);
                } else if (waiting_task->opcode == AsyncIouring::SW_IORING_OP_UNLINK_FILE ||
                           waiting_task->opcode == AsyncIouring::SW_IORING_OP_UNLINK_DIR) {
                    unlink(waiting_task);
                } else if (waiting_task->opcode == AsyncIouring::SW_IORING_OP_MKDIRAT) {
                    mkdir(waiting_task);
                } else if (waiting_task->opcode == AsyncIouring::SW_IORING_OP_FSYNC ||
                           waiting_task->opcode == AsyncIouring::SW_IORING_OP_FDATASYNC) {
                    fsync(waiting_task);
                }
#ifdef HAVE_IOURING_FTRUNCATE
                else if (waiting_task->opcode == AsyncIouring::SW_IORING_OP_FTRUNCATE) {
                    ftruncate(waiting_task);
                }
#endif
            }
        }
    }

    return true;
}

bool AsyncIouring::open(AsyncEvent *event) {
    struct io_uring_sqe *sqe = get_iouring_sqe();
    if (!sqe) {
        waiting_tasks.push(event);
        return true;
    }

    io_uring_sqe_set_data(sqe, (void *) event);
    sqe->addr = (uintptr_t) event->pathname;
    sqe->fd = AT_FDCWD;
    sqe->len = event->mode;
    sqe->opcode = SW_IORING_OP_OPENAT;
    sqe->open_flags = event->flags | O_CLOEXEC;

    return submit_iouring_sqe(event);
}

bool AsyncIouring::close(AsyncEvent *event) {
    struct io_uring_sqe *sqe = get_iouring_sqe();
    if (!sqe) {
        waiting_tasks.push(event);
        return true;
    }

    io_uring_sqe_set_data(sqe, (void *) event);
    sqe->fd = event->fd;
    sqe->opcode = SW_IORING_OP_CLOSE;

    return submit_iouring_sqe(event);
}

bool AsyncIouring::wr(AsyncEvent *event) {
    struct io_uring_sqe *sqe = get_iouring_sqe();
    if (!sqe) {
        waiting_tasks.push(event);
        return true;
    }

    io_uring_sqe_set_data(sqe, (void *) event);
    sqe->fd = event->fd;
    sqe->addr = event->opcode == SW_IORING_OP_READ ? (uintptr_t) event->rbuf : (uintptr_t) event->wbuf;
    sqe->len = event->count;
    sqe->off = -1;
    sqe->opcode = event->opcode;

    return submit_iouring_sqe(event);
}

bool AsyncIouring::statx(AsyncEvent *event) {
    struct io_uring_sqe *sqe = get_iouring_sqe();
    if (!sqe) {
        waiting_tasks.push(event);
        return true;
    }

    io_uring_sqe_set_data(sqe, (void *) event);
    if (event->opcode == SW_IORING_OP_FSTAT) {
        sqe->addr = (uintptr_t) "";
        sqe->fd = event->fd;
        sqe->statx_flags |= AT_EMPTY_PATH;
    } else {
        sqe->addr = (uintptr_t) event->pathname;
        sqe->fd = AT_FDCWD;
        sqe->statx_flags |= AT_SYMLINK_NOFOLLOW;
    }
    //    sqe->len = 0xFFF;
    sqe->opcode = SW_IORING_OP_STATX;
    sqe->off = (uintptr_t) event->statxbuf;

    return submit_iouring_sqe(event);
}

bool AsyncIouring::mkdir(AsyncEvent *event) {
    struct io_uring_sqe *sqe = get_iouring_sqe();
    if (!sqe) {
        waiting_tasks.push(event);
        return true;
    }

    io_uring_sqe_set_data(sqe, (void *) event);
    sqe->addr = (uintptr_t) event->pathname;
    sqe->fd = AT_FDCWD;
    sqe->len = event->mode;
    sqe->opcode = SW_IORING_OP_MKDIRAT;

    return submit_iouring_sqe(event);
}

bool AsyncIouring::unlink(AsyncEvent *event) {
    struct io_uring_sqe *sqe = get_iouring_sqe();
    if (!sqe) {
        waiting_tasks.push(event);
        return true;
    }

    io_uring_sqe_set_data(sqe, (void *) event);

    sqe->addr = (uintptr_t) event->pathname;
    sqe->fd = AT_FDCWD;
    sqe->opcode = SW_IORING_OP_UNLINKAT;
    if (event->opcode == SW_IORING_OP_UNLINK_DIR) {
        sqe->unlink_flags |= AT_REMOVEDIR;
    }

    return submit_iouring_sqe(event);
}

bool AsyncIouring::rename(AsyncEvent *event) {
    struct io_uring_sqe *sqe = get_iouring_sqe();
    if (!sqe) {
        waiting_tasks.push(event);
        return true;
    }

    io_uring_sqe_set_data(sqe, (void *) event);

    sqe->addr = (uintptr_t) event->pathname;
    sqe->addr2 = (uintptr_t) event->pathname2;
    sqe->fd = AT_FDCWD;
    sqe->len = AT_FDCWD;
    sqe->opcode = SW_IORING_OP_RENAMEAT;

    return submit_iouring_sqe(event);
}

bool AsyncIouring::fsync(AsyncEvent *event) {
    struct io_uring_sqe *sqe = get_iouring_sqe();
    if (!sqe) {
        waiting_tasks.push(event);
        return true;
    }

    io_uring_sqe_set_data(sqe, (void *) event);
    sqe->fd = event->fd;
    sqe->addr = (unsigned long) nullptr;
    sqe->opcode = IORING_OP_FSYNC;
    sqe->len = 0;
    sqe->off = 0;
    sqe->fsync_flags = 0;

    if (event->opcode == SW_IORING_OP_FDATASYNC) {
        sqe->fsync_flags = IORING_FSYNC_DATASYNC;
    }

    return submit_iouring_sqe(event);
}

#ifdef HAVE_IOURING_FTRUNCATE
bool AsyncIouring::ftruncate(AsyncEvent *event) {
    struct io_uring_sqe *sqe = get_iouring_sqe();
    if (!sqe) {
        waiting_tasks.push(event);
        return true;
    }

    io_uring_sqe_set_data(sqe, (void *) event);
    sqe->opcode = IORING_OP_FTRUNCATE;
    sqe->fd = event->fd;
    sqe->off = event->offset;
    sqe->addr = (unsigned long) 0;
    sqe->len = 0;

    return submit_iouring_sqe(event);
}
#endif

int AsyncIouring::callback(Reactor *reactor, Event *event) {
    AsyncIouring *iouring = SwooleTG.async_iouring;
    return iouring->wakeup() ? 1 : 0;
}
}  // namespace swoole
#endif
