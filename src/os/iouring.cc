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
AsyncIOUring::AsyncIOUring(Reactor *reactor_) {
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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 19, 0)
    int ret = io_uring_queue_init(entries, &ring, IORING_SETUP_COOP_TASKRUN | IORING_SETUP_SUBMIT_ALL);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
    int ret = io_uring_queue_init(
        entries, &ring, IORING_SETUP_COOP_TASKRUN | IORING_SETUP_SUBMIT_ALL | IORING_SETUP_SINGLE_ISSUER);
#else
    int ret = io_uring_queue_init(entries, &ring, 0);
#endif

    if (ret < 0) {
        swoole_warning("create io_uring failed");
        throw swoole::Exception(SW_ERROR_WRONG_OPERATION);
        return;
    }
    ring_fd = ring.ring_fd;

    iou_socket = make_socket(ring_fd, SW_FD_IOURING);
    if (!iou_socket) {
        swoole_sys_warning("create io_uring socket failed");
        return;
    }

    reactor->set_exit_condition(Reactor::EXIT_CONDITION_IOURING, [](Reactor *reactor, size_t &event_num) -> bool {
        if (SwooleTG.async_iouring && SwooleTG.async_iouring->get_task_num() == 0 &&
            SwooleTG.async_iouring->is_empty_wait_events()) {
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

AsyncIOUring::~AsyncIOUring() {
    if (ring_fd >= 0) {
        ::close(ring_fd);
    }

    if (iou_socket) {
        delete iou_socket;
    }

    io_uring_queue_exit(&ring);
}

void AsyncIOUring::add_event() {
    reactor->add(iou_socket, SW_EVENT_READ);
}

void AsyncIOUring::delete_event() {
    reactor->del(iou_socket);
}

bool AsyncIOUring::wakeup() {
    unsigned num = entries * 2;
    struct io_uring_cqe *cqes[num];
    unsigned count = get_iouring_cqes(cqes, num);
    if (count == 0) {
        return true;
    }
    if (count < 0) {
        return false;
    }

    unsigned i = 0;
    AsyncEvent *tasks[count];
    void *data = nullptr;
    AsyncEvent *task = nullptr;
    struct io_uring_cqe *cqe = nullptr;
    for (i = 0; i < count; i++) {
        cqe = cqes[i];
        data = get_iouring_cqe_data(cqe);
        task = reinterpret_cast<AsyncEvent *>(data);
        task->retval = (cqe->res >= 0 ? cqe->res : -1);
        if (cqe->res < 0) {
            errno = abs(cqe->res);
        }
        tasks[i] = task;
        task_num--;
    }
    finish_iouring_cqes(count);

    AsyncEvent *waitEvent = nullptr;
    for (i = 0; i < count; i++) {
        task = tasks[i];
        if (is_empty_wait_events()) {
            task->callback(task);
            continue;
        }

        waitEvent = waitEvents.front();
        waitEvents.pop();
        if (waitEvent->opcode == AsyncIOUring::SW_IORING_OP_OPENAT) {
            open(waitEvent);
        } else if (waitEvent->opcode == AsyncIOUring::SW_IORING_OP_CLOSE) {
            close(waitEvent);
        } else if (waitEvent->opcode == AsyncIOUring::SW_IORING_OP_FSTAT ||
                   waitEvent->opcode == AsyncIOUring::SW_IORING_OP_LSTAT) {
            statx(waitEvent);
        } else if (waitEvent->opcode == AsyncIOUring::SW_IORING_OP_READ ||
                   waitEvent->opcode == AsyncIOUring::SW_IORING_OP_WRITE) {
            wr(waitEvent);
        } else if (waitEvent->opcode == AsyncIOUring::SW_IORING_OP_RENAMEAT) {
            rename(waitEvent);
        } else if (waitEvent->opcode == AsyncIOUring::SW_IORING_OP_UNLINK_FILE ||
                   waitEvent->opcode == AsyncIOUring::SW_IORING_OP_UNLINK_DIR) {
            unlink(waitEvent);
        } else if (waitEvent->opcode == AsyncIOUring::SW_IORING_OP_MKDIRAT) {
            mkdir(waitEvent);
        } else if (waitEvent->opcode == AsyncIOUring::SW_IORING_OP_FSYNC ||
                   waitEvent->opcode == AsyncIOUring::SW_IORING_OP_FDATASYNC) {
            fsync(waitEvent);
        }

        task->callback(task);
    }

    return true;
}

bool AsyncIOUring::open(AsyncEvent *event) {
    struct io_uring_sqe *sqe = get_iouring_sqe();
    if (!sqe) {
        waitEvents.push(event);
        return true;
    }

    set_iouring_sqe_data(sqe, (void *) event);
    sqe->addr = (uintptr_t) event->pathname;
    sqe->fd = AT_FDCWD;
    sqe->len = event->mode;
    sqe->opcode = SW_IORING_OP_OPENAT;
    sqe->open_flags = event->flags | O_CLOEXEC;

    bool result = submit_iouring_sqe();

    if (!result) {
        return false;
    }

    task_num++;
    return true;
}

bool AsyncIOUring::close(AsyncEvent *event) {
    struct io_uring_sqe *sqe = get_iouring_sqe();
    if (!sqe) {
        waitEvents.push(event);
        return true;
    }

    set_iouring_sqe_data(sqe, (void *) event);
    sqe->fd = event->fd;
    sqe->opcode = SW_IORING_OP_CLOSE;

    bool result = submit_iouring_sqe();

    if (!result) {
        return false;
    }

    task_num++;
    return true;
}

bool AsyncIOUring::wr(AsyncEvent *event) {
    struct io_uring_sqe *sqe = get_iouring_sqe();
    if (!sqe) {
        waitEvents.push(event);
        return true;
    }

    set_iouring_sqe_data(sqe, (void *) event);
    sqe->fd = event->fd;
    sqe->addr = event->opcode == SW_IORING_OP_READ ? (uintptr_t) event->rbuf : (uintptr_t) event->wbuf;
    sqe->len = event->count;
    sqe->off = -1;
    sqe->opcode = event->opcode;

    bool result = submit_iouring_sqe();

    if (!result) {
        return false;
    }

    task_num++;
    return true;
}

bool AsyncIOUring::statx(AsyncEvent *event) {
    struct io_uring_sqe *sqe = get_iouring_sqe();
    if (!sqe) {
        waitEvents.push(event);
        return true;
    }

    set_iouring_sqe_data(sqe, (void *) event);
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

    bool result = submit_iouring_sqe();

    if (!result) {
        return false;
    }

    task_num++;
    return true;
}

bool AsyncIOUring::mkdir(AsyncEvent *event) {
    struct io_uring_sqe *sqe = get_iouring_sqe();
    if (!sqe) {
        waitEvents.push(event);
        return true;
    }

    set_iouring_sqe_data(sqe, (void *) event);
    sqe->addr = (uintptr_t) event->pathname;
    sqe->fd = AT_FDCWD;
    sqe->len = event->mode;
    sqe->opcode = SW_IORING_OP_MKDIRAT;
    bool result = submit_iouring_sqe();

    if (!result) {
        return false;
    }

    task_num++;
    return true;
}

bool AsyncIOUring::unlink(AsyncEvent *event) {
    struct io_uring_sqe *sqe = get_iouring_sqe();
    if (!sqe) {
        waitEvents.push(event);
        return true;
    }

    set_iouring_sqe_data(sqe, (void *) event);

    sqe->addr = (uintptr_t) event->pathname;
    sqe->fd = AT_FDCWD;
    sqe->opcode = SW_IORING_OP_UNLINKAT;
    if (event->opcode == SW_IORING_OP_UNLINK_DIR) {
        sqe->unlink_flags |= AT_REMOVEDIR;
    }
    bool result = submit_iouring_sqe();

    if (!result) {
        return false;
    }

    task_num++;
    return true;
}

bool AsyncIOUring::rename(AsyncEvent *event) {
    struct io_uring_sqe *sqe = get_iouring_sqe();
    if (!sqe) {
        waitEvents.push(event);
        return true;
    }

    set_iouring_sqe_data(sqe, (void *) event);

    sqe->addr = (uintptr_t) event->pathname;
    sqe->addr2 = (uintptr_t) event->pathname2;
    sqe->fd = AT_FDCWD;
    sqe->len = AT_FDCWD;
    sqe->opcode = SW_IORING_OP_RENAMEAT;
    bool result = submit_iouring_sqe();

    if (!result) {
        return false;
    }

    task_num++;
    return true;
}

bool AsyncIOUring::fsync(AsyncEvent *event) {
    struct io_uring_sqe *sqe = get_iouring_sqe();
    if (!sqe) {
        waitEvents.push(event);
        return true;
    }

    set_iouring_sqe_data(sqe, (void *) event);
    sqe->fd = event->fd;
    sqe->addr = (unsigned long) nullptr;
    sqe->opcode = IORING_OP_FSYNC;
    sqe->len = 0;
    sqe->off = 0;
    sqe->fsync_flags = 0;

    if (event->opcode == SW_IORING_OP_FDATASYNC) {
        sqe->fsync_flags = IORING_FSYNC_DATASYNC;
    }

    bool result = submit_iouring_sqe();

    if (!result) {
        return false;
    }

    task_num++;
    return true;
}

int AsyncIOUring::callback(Reactor *reactor, Event *event) {
    AsyncIOUring *iouring = SwooleTG.async_iouring;
    return iouring->wakeup() ? 1 : 0;
}
}  // namespace swoole
#endif
