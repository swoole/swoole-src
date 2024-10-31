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
  | @link     https://www.swoole.com/                                    |
  | @contact  team@swoole.com                                            |
  | @license  https://github.com/swoole/swoole-src/blob/master/LICENSE   |
  | @Author   NathanFreeman  <mariasocute@163.com>                       |
  +----------------------------------------------------------------------+
*/

#include "swoole_iouring.h"

#ifdef SW_USE_IOURING
using swoole::Coroutine;

namespace swoole {
//-------------------------------------------------------------------------------
enum IouringOpcode {
    SW_IORING_OP_OPENAT = IORING_OP_OPENAT,
    SW_IORING_OP_CLOSE = IORING_OP_CLOSE,
    SW_IORING_OP_STATX = IORING_OP_STATX,
    SW_IORING_OP_READ = IORING_OP_READ,
    SW_IORING_OP_WRITE = IORING_OP_WRITE,
    SW_IORING_OP_RENAMEAT = IORING_OP_RENAMEAT,
    SW_IORING_OP_MKDIRAT = IORING_OP_MKDIRAT,

    SW_IORING_OP_FSTAT = 1000,
    SW_IORING_OP_LSTAT = 1001,
    SW_IORING_OP_UNLINK_FILE = 1002,
    SW_IORING_OP_UNLINK_DIR = 1003,
    SW_IORING_OP_FSYNC = 1004,
    SW_IORING_OP_FDATASYNC = 1005,
};

struct IouringEvent {
    IouringOpcode opcode;
    Coroutine *coroutine;
    int fd;
    int flags;
    mode_t mode;
    size_t size;
    ssize_t result;
    void *rbuf;
    const void *wbuf;
    const char *pathname;
    const char *pathname2;
    struct statx *statxbuf;
};

Iouring::Iouring(Reactor *_reactor) {
    if (!SwooleTG.reactor) {
        swoole_warning("no event loop, cannot initialized");
        throw swoole::Exception(SW_ERROR_WRONG_OPERATION);
    }

    reactor = _reactor;
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
        swoole_error_log(
            SW_LOG_WARNING, SW_ERROR_SYSTEM_CALL_FAIL, "Create io_uring failed, the error code is %d", -ret);
        return;
    }

    if (SwooleG.iouring_workers > 0) {
        unsigned int workers[2] = {SwooleG.iouring_workers, SwooleG.iouring_workers};
        ret = io_uring_register_iowq_max_workers(&ring, workers);

        if (ret < 0) {
            swoole_error_log(SW_LOG_WARNING,
                             SW_ERROR_SYSTEM_CALL_FAIL,
                             "Failed to increase io_uring async workers, the error code is %d",
                             -ret);
            return;
        }
    }

    ring_socket = make_socket(ring.ring_fd, SW_FD_IOURING);
    if (!ring_socket) {
        swoole_error_log(SW_LOG_WARNING, SW_ERROR_SYSTEM_CALL_FAIL, "create io_uring socket failed");
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
        delete SwooleTG.iouring;
        SwooleTG.iouring = nullptr;
    });

    reactor->add(ring_socket, SW_EVENT_READ);
}

Iouring::~Iouring() {
    if (!ring_socket->removed) {
        reactor->del(ring_socket);
    }

    if (ring_socket) {
        delete ring_socket;
    }

    io_uring_queue_exit(&ring);
}

bool Iouring::ready() {
    return reactor->exists(ring_socket);
}

bool Iouring::wakeup() {
    unsigned count = 0;
    unsigned num = 8192;
    void *data = nullptr;
    IouringEvent *event = nullptr;
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
            event = static_cast<IouringEvent *>(data);
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
                    waiting_tasks.push(event);
                    continue;
                }
            }

            event->result = (cqe->res >= 0 ? cqe->res : -1);
            io_uring_cq_advance(&ring, 1);

            event->coroutine->resume();

            if (!is_empty_waiting_tasks()) {
                waiting_task = waiting_tasks.front();
                waiting_tasks.pop();
                if (!dispatch(waiting_task)) {
                    waiting_task->coroutine->resume();
                }
            }
        }
    }

    return true;
}

bool Iouring::submit(IouringEvent *event) {
    int ret = io_uring_submit(&ring);

    if (ret < 0) {
        if (-ret == EAGAIN) {
            waiting_tasks.push(event);
            return true;
        }
        swoole_set_last_error(-ret);
        event->result = -1;
        return false;
    }

    task_num++;
    return true;
}

ssize_t Iouring::execute(IouringEvent *event) {
    if (sw_unlikely(!SwooleTG.iouring)) {
        auto iouring = new Iouring(SwooleTG.reactor);
        if (!iouring->ready()) {
            delete iouring;
            return SW_ERR;
        }
        SwooleTG.iouring = iouring;
    }

    if (!SwooleTG.iouring->dispatch(event)) {
        return SW_ERR;
    }

    // File system operations cannot be canceled, must wait to be completed.
    event->coroutine->yield();

    return event->result;
}

bool Iouring::dispatch(IouringEvent *event) {
    struct io_uring_sqe *sqe = get_iouring_sqe();
    if (!sqe) {
        waiting_tasks.push(event);
        return true;
    }

    io_uring_sqe_set_data(sqe, (void *) event);

    switch (event->opcode) {
    case SW_IORING_OP_OPENAT:
        sqe->addr = (uintptr_t) event->pathname;
        sqe->fd = AT_FDCWD;
        sqe->len = event->mode;
        sqe->opcode = SW_IORING_OP_OPENAT;
        sqe->open_flags = event->flags | O_CLOEXEC;
        break;
    case SW_IORING_OP_READ:
    case SW_IORING_OP_WRITE:
        sqe->fd = event->fd;
        sqe->addr = (uintptr_t) (event->opcode == SW_IORING_OP_READ ? event->rbuf : event->wbuf);
        sqe->len = event->size;
        sqe->off = -1;
        sqe->opcode = event->opcode;
        break;
    case SW_IORING_OP_CLOSE:
        sqe->fd = event->fd;
        sqe->opcode = SW_IORING_OP_CLOSE;
        break;
    case SW_IORING_OP_FSTAT:
    case SW_IORING_OP_LSTAT:
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
        // sqe->len = 0xFFF;
        sqe->opcode = SW_IORING_OP_STATX;
        sqe->off = (uintptr_t) event->statxbuf;
        break;
    case SW_IORING_OP_MKDIRAT:
        sqe->addr = (uintptr_t) event->pathname;
        sqe->fd = AT_FDCWD;
        sqe->len = event->mode;
        sqe->opcode = SW_IORING_OP_MKDIRAT;
        break;

    case SW_IORING_OP_UNLINK_FILE:
    case SW_IORING_OP_UNLINK_DIR:
        sqe->addr = (uintptr_t) event->pathname;
        sqe->fd = AT_FDCWD;
        sqe->opcode = IORING_OP_UNLINKAT;
        if (event->opcode == SW_IORING_OP_UNLINK_DIR) {
            sqe->unlink_flags |= AT_REMOVEDIR;
        }
        break;
    case SW_IORING_OP_RENAMEAT:
        sqe->addr = (uintptr_t) event->pathname;
        sqe->addr2 = (uintptr_t) event->pathname2;
        sqe->fd = AT_FDCWD;
        sqe->len = AT_FDCWD;
        sqe->opcode = SW_IORING_OP_RENAMEAT;
        break;
    case SW_IORING_OP_FSYNC:
    case SW_IORING_OP_FDATASYNC:
        sqe->fd = event->fd;
        sqe->addr = (unsigned long) nullptr;
        sqe->opcode = IORING_OP_FSYNC;
        sqe->len = 0;
        sqe->off = 0;
        sqe->fsync_flags = 0;
        if (event->opcode == SW_IORING_OP_FDATASYNC) {
            sqe->fsync_flags = IORING_FSYNC_DATASYNC;
        }
        break;
    default:
        abort();
        return false;
    }

    return submit(event);
}

int Iouring::open(const char *pathname, int flags, int mode) {
    IouringEvent event{};
    event.coroutine = Coroutine::get_current_safe();
    event.opcode = SW_IORING_OP_OPENAT;
    event.mode = mode;
    event.flags = flags;
    event.pathname = pathname;

    return execute(&event);
}

int Iouring::close(int fd) {
    IouringEvent event{};
    event.coroutine = Coroutine::get_current_safe();
    event.opcode = SW_IORING_OP_CLOSE;
    event.fd = fd;

    return execute(&event);
}

ssize_t Iouring::read(int fd, void *buf, size_t size) {
    IouringEvent event{};
    event.coroutine = Coroutine::get_current_safe();
    event.opcode = SW_IORING_OP_READ;
    event.fd = fd;
    event.rbuf = buf;
    event.size = size;

    return execute(&event);
}

ssize_t Iouring::write(int fd, const void *buf, size_t size) {
    IouringEvent event{};
    event.coroutine = Coroutine::get_current_safe();
    event.opcode = SW_IORING_OP_WRITE;
    event.fd = fd;
    event.wbuf = buf;
    event.size = size;

    return execute(&event);
}

ssize_t Iouring::rename(const char *oldpath, const char *newpath) {
    IouringEvent event{};
    event.coroutine = Coroutine::get_current_safe();
    event.opcode = SW_IORING_OP_RENAMEAT;
    event.pathname = oldpath;
    event.pathname2 = newpath;

    return execute(&event);
}

int Iouring::mkdir(const char *pathname, mode_t mode) {
    IouringEvent event{};
    event.coroutine = Coroutine::get_current_safe();
    event.opcode = SW_IORING_OP_MKDIRAT;
    event.pathname = pathname;
    event.mode = mode;

    return execute(&event);
}

int Iouring::unlink(const char *pathname) {
    IouringEvent event{};
    event.coroutine = Coroutine::get_current_safe();
    event.opcode = SW_IORING_OP_UNLINK_FILE;
    event.pathname = pathname;

    return execute(&event);
}

int Iouring::rmdir(const char *pathname) {
    IouringEvent event{};
    event.coroutine = Coroutine::get_current_safe();
    event.opcode = SW_IORING_OP_UNLINK_DIR;
    event.pathname = pathname;

    return execute(&event);
}

int Iouring::fsync(int fd) {
    IouringEvent event{};
    event.coroutine = Coroutine::get_current_safe();
    event.opcode = SW_IORING_OP_FSYNC;
    event.fd = fd;

    return execute(&event);
}

int Iouring::fdatasync(int fd) {
    IouringEvent event{};
    event.coroutine = Coroutine::get_current_safe();
    event.opcode = SW_IORING_OP_FDATASYNC;
    event.fd = fd;

    return execute(&event);
}

static void swoole_statx_to_stat(const struct statx *statxbuf, struct stat *statbuf) {
    statbuf->st_dev = (((unsigned int) statxbuf->stx_dev_major) << 8) | (unsigned int) statxbuf->stx_dev_minor;
    statbuf->st_mode = statxbuf->stx_mode;
    statbuf->st_nlink = statxbuf->stx_nlink;
    statbuf->st_uid = statxbuf->stx_uid;
    statbuf->st_gid = statxbuf->stx_gid;
    statbuf->st_rdev = (((unsigned int) statxbuf->stx_rdev_major) << 8) | (unsigned int) statxbuf->stx_rdev_minor;
    statbuf->st_ino = statxbuf->stx_ino;
    statbuf->st_size = statxbuf->stx_size;
    statbuf->st_blksize = statxbuf->stx_blksize;
    statbuf->st_blocks = statxbuf->stx_blocks;
    statbuf->st_atim.tv_sec = statxbuf->stx_atime.tv_sec;
    statbuf->st_atim.tv_nsec = statxbuf->stx_atime.tv_nsec;
    statbuf->st_mtim.tv_sec = statxbuf->stx_mtime.tv_sec;
    statbuf->st_mtim.tv_nsec = statxbuf->stx_mtime.tv_nsec;
    statbuf->st_ctim.tv_sec = statxbuf->stx_ctime.tv_sec;
    statbuf->st_ctim.tv_nsec = statxbuf->stx_ctime.tv_nsec;
}

int Iouring::fstat(int fd, struct stat *statbuf) {
    IouringEvent event{};
    struct statx _statxbuf;
    event.coroutine = Coroutine::get_current_safe();
    event.opcode = SW_IORING_OP_FSTAT;
    event.fd = fd;
    event.statxbuf = &_statxbuf;

    auto retval = execute(&event);
    if (retval == 0) {
        swoole_statx_to_stat(&_statxbuf, statbuf);
    }
    return retval;
}

int Iouring::stat(const char *path, struct stat *statbuf) {
    IouringEvent event{};
    struct statx _statxbuf;
    event.coroutine = Coroutine::get_current_safe();
    event.opcode = SW_IORING_OP_LSTAT;
    event.pathname = path;
    event.statxbuf = &_statxbuf;

    auto retval = execute(&event);
    if (retval == 0) {
        swoole_statx_to_stat(&_statxbuf, statbuf);
    }
    return retval;
}

int Iouring::callback(Reactor *reactor, Event *event) {
    Iouring *iouring = SwooleTG.iouring;
    return iouring->wakeup() ? 1 : 0;
}
}  // namespace swoole
#endif
