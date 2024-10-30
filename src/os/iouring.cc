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

#include "swoole_iouring.h"

#ifdef SW_USE_IOURING
using swoole::Coroutine;

namespace swoole {
//-------------------------------------------------------------------------------
Iouring::Iouring(Reactor *reactor_) {
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
        if (SwooleTG.iouring && SwooleTG.iouring->get_task_num() == 0 && SwooleTG.iouring->is_empty_waiting_tasks()) {
            event_num--;
        }
        return true;
    });

    reactor->add_destroy_callback([](void *data) {
        if (!SwooleTG.iouring) {
            return;
        }
        SwooleTG.iouring->delete_event();
        delete SwooleTG.iouring;
        SwooleTG.iouring = nullptr;
    });
}

Iouring::~Iouring() {
    if (ring_fd >= 0) {
        ::close(ring_fd);
    }

    if (iou_socket) {
        delete iou_socket;
    }

    io_uring_queue_exit(&ring);
}

void Iouring::add_event() {
    reactor->add(iou_socket, SW_EVENT_READ);
}

void Iouring::delete_event() {
    reactor->del(iou_socket);
}

bool Iouring::wakeup() {
    unsigned count = 0;
    unsigned num = 8192;
    void *data = nullptr;
    IouringEvent *task = nullptr;
    IouringEvent *waiting_task = nullptr;
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
            task = reinterpret_cast<IouringEvent *>(data);
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

            task->result = (cqe->res >= 0 ? cqe->res : -1);
            io_uring_cq_advance(&ring, 1);

            if (task->canceled == 1) {
                delete task;
                continue;
            }

            task->coroutine->resume();

            if (!is_empty_waiting_tasks()) {
                waiting_task = waiting_tasks.front();
                waiting_tasks.pop();
                if (waiting_task->opcode == SW_IORING_OP_OPENAT) {
                    open(waiting_task);
                } else if (waiting_task->opcode == SW_IORING_OP_CLOSE) {
                    close(waiting_task);
                } else if (waiting_task->opcode == SW_IORING_OP_FSTAT || waiting_task->opcode == SW_IORING_OP_LSTAT) {
                    statx(waiting_task);
                } else if (waiting_task->opcode == SW_IORING_OP_READ || waiting_task->opcode == SW_IORING_OP_WRITE) {
                    wr(waiting_task);
                } else if (waiting_task->opcode == SW_IORING_OP_RENAMEAT) {
                    rename(waiting_task);
                } else if (waiting_task->opcode == SW_IORING_OP_UNLINK_FILE ||
                           waiting_task->opcode == SW_IORING_OP_UNLINK_DIR) {
                    unlink(waiting_task);
                } else if (waiting_task->opcode == SW_IORING_OP_MKDIRAT) {
                    mkdir(waiting_task);
                } else if (waiting_task->opcode == SW_IORING_OP_FSYNC ||
                           waiting_task->opcode == SW_IORING_OP_FDATASYNC) {
                    fsync(waiting_task);
                }
            }
        }
    }

    return true;
}

bool Iouring::open(IouringEvent *event) {
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

bool Iouring::close(IouringEvent *event) {
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

bool Iouring::wr(IouringEvent *event) {
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

bool Iouring::statx(IouringEvent *event) {
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

bool Iouring::mkdir(IouringEvent *event) {
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

bool Iouring::unlink(IouringEvent *event) {
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

bool Iouring::rename(IouringEvent *event) {
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

bool Iouring::fsync(IouringEvent *event) {
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

int Iouring::dispatch(IouringEvent *event) {
    bool result = false;
    if (event->opcode == SW_IORING_OP_READ || event->opcode == SW_IORING_OP_WRITE) {
        result = wr(event);
    } else if (event->opcode == SW_IORING_OP_CLOSE) {
        result = close(event);
    } else if (event->opcode == SW_IORING_OP_FSTAT) {
        result = statx(event);
    } else if (event->opcode == SW_IORING_OP_FSYNC || event->opcode == SW_IORING_OP_FDATASYNC) {
        result = fsync(event);
    } else if (event->opcode == SW_IORING_OP_OPENAT) {
        result = open(event);
    } else if (event->opcode == SW_IORING_OP_MKDIRAT) {
        result = mkdir(event);
    } else if (event->opcode == SW_IORING_OP_UNLINK_FILE || event->opcode == SW_IORING_OP_UNLINK_DIR) {
        result = unlink(event);
    } else if (event->opcode == SW_IORING_OP_RENAMEAT) {
        result = rename(event);
    } else if (event->opcode == SW_IORING_OP_LSTAT) {
        result = statx(event);
    }

    if (!result) {
        delete event;
        return 0;
    }

    if (!event->coroutine->yield_ex()) {
        if (swoole_get_last_error() == SW_ERROR_CO_CANCELED) {
            event->canceled = 1;
        } else {
            delete event;
        }
        return 0;
    }

    ssize_t retval = event->result;
    delete event;
    return retval;
}

Iouring *Iouring::create_iouring() {
    if (SwooleTG.iouring == nullptr) {
        SwooleTG.iouring = new Iouring(SwooleTG.reactor);
        SwooleTG.iouring->add_event();
    }

    return SwooleTG.iouring;
}

int Iouring::async(Opcodes type, int fd, uint64_t count, void *rbuf, const void *wbuf, struct statx *statxbuf) {
    IouringEvent *event = new IouringEvent();
    event->fd = fd;
    event->rbuf = rbuf;
    event->wbuf = wbuf;
    event->count = count;
    event->opcode = type;
    event->statxbuf = statxbuf;
    event->coroutine = Coroutine::get_current_safe();

    Iouring *iouring = create_iouring();
    return iouring->dispatch(event);
}

int Iouring::async(
    Opcodes type, const char *pathname, const char *pathname2, struct statx *statxbuf, int flags, mode_t mode) {
    IouringEvent *event = new IouringEvent();
    event->mode = mode;
    event->flags = flags;
    event->opcode = type;
    event->pathname = pathname;
    event->pathname2 = pathname2;
    event->statxbuf = statxbuf;
    event->coroutine = Coroutine::get_current_safe();

    Iouring *iouring = create_iouring();
    return iouring->dispatch(event);
}

int Iouring::callback(Reactor *reactor, Event *event) {
    Iouring *iouring = SwooleTG.iouring;
    return iouring->wakeup() ? 1 : 0;
}
}  // namespace swoole
#endif
