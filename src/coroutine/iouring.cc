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

#ifdef HAVE_IOURING_FUTEX
#ifndef FUTEX2_SIZE_U32
#define FUTEX2_SIZE_U32 0x02
#endif
#include <linux/futex.h>
#endif

using swoole::Coroutine;

namespace swoole {
//-------------------------------------------------------------------------------
enum IouringOpcode {
    SW_IORING_OP_SOCKET = IORING_OP_SOCKET,
    SW_IORING_OP_OPENAT = IORING_OP_OPENAT,
    SW_IORING_OP_CONNECT = IORING_OP_CONNECT,
    SW_IORING_OP_ACCEPT = IORING_OP_ACCEPT,
    SW_IORING_OP_BIND = IORING_OP_BIND,
    SW_IORING_OP_LISTEN = IORING_OP_LISTEN,
    SW_IORING_OP_CLOSE = IORING_OP_CLOSE,
    SW_IORING_OP_STATX = IORING_OP_STATX,
    SW_IORING_OP_READ = IORING_OP_READ,
    SW_IORING_OP_WRITE = IORING_OP_WRITE,
    SW_IORING_OP_RECV = IORING_OP_RECV,
    SW_IORING_OP_SEND = IORING_OP_SEND,
    SW_IORING_OP_RENAMEAT = IORING_OP_RENAMEAT,
    SW_IORING_OP_MKDIRAT = IORING_OP_MKDIRAT,
#ifdef HAVE_IOURING_FUTEX
    SW_IORING_OP_FUTEX_WAIT = IORING_OP_FUTEX_WAIT,
    SW_IORING_OP_FUTEX_WAKE = IORING_OP_FUTEX_WAKE,
#endif
#ifdef HAVE_IOURING_FTRUNCATE
    SW_IORING_OP_FTRUNCATE = IORING_OP_FTRUNCATE,
#endif

    SW_IORING_OP_FSTAT = 100,
    SW_IORING_OP_LSTAT = 101,
    SW_IORING_OP_UNLINK_FILE = 102,
    SW_IORING_OP_UNLINK_DIR = 103,
    SW_IORING_OP_FSYNC = 104,
    SW_IORING_OP_FDATASYNC = 105,

    SW_IORING_OP_LAST = 128,
};

struct IouringEvent {
    // control
    IouringOpcode opcode;
    Coroutine *coroutine;
    // input
    int fd;
    int flags;
    union {
        mode_t mode;
        size_t size;
        socklen_t addr_len;
        socklen_t *addr_len_ptr;
        int backlog;
        struct {
            int sock_type;
            int sock_protocol;
        };
    };
    const char *pathname;
    union {
        void *rbuf;
        const void *wbuf;
        struct statx *statxbuf;
        const char *pathname2;
        const struct sockaddr *addr;
        struct sockaddr *addr_wr;
#ifdef HAVE_IOURING_FUTEX
        uint32_t *futex;
#endif
    };
    // output
    ssize_t result;
};

static void parse_kernel_version(const char *release, int *major, int *minor) {
    char copy[SW_STRUCT_MEMBER_SIZE(utsname, release)];
    strcpy(copy, release);

    char *token = strtok(copy, ".-");
    *major = token ? sw_atoi(token) : 0;

    token = strtok(nullptr, ".-");
    *minor = token ? sw_atoi(token) : 0;
}

Iouring::Iouring(Reactor *_reactor) {
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
        uint32_t workers[2] = {SwooleG.iouring_workers, SwooleG.iouring_workers};
        ret = io_uring_register_iowq_max_workers(&ring, workers);

        if (ret < 0) {
            swoole_error_log(SW_LOG_WARNING,
                             SW_ERROR_SYSTEM_CALL_FAIL,
                             "Failed to increase io_uring async workers, the error code is %d",
                             -ret);
            return;
        }
    }

    int major, minor;
    parse_kernel_version(SwooleG.uname.release, &major, &minor);

#ifdef HAVE_IOURING_FUTEX
    if (!(major >= 6 && minor >= 7)) {
        swoole_error_log(SW_LOG_WARNING,
                         SW_ERROR_OPERATION_NOT_SUPPORT,
                         "The Iouring::futex_wait()/Iouring::futex_wakeup() requires `6.7` or higher Linux kernel");
    }
#endif

#ifdef HAVE_IOURING_FTRUNCATE
    if (!(major >= 6 && minor >= 9)) {
        swoole_error_log(SW_LOG_WARNING,
                         SW_ERROR_OPERATION_NOT_SUPPORT,
                         "The Iouring::ftruncate() requires `6.9` or higher Linux kernel");
    }
#endif

    ring_socket = make_socket(ring.ring_fd, SW_FD_IOURING);
    ring_socket->object = this;

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
    if (!ring_socket) {
        return;
    }

    if (!ring_socket->removed) {
        reactor->del(ring_socket);
    }
    ring_socket->move_fd();
    ring_socket->free();
    ring_socket = nullptr;

    io_uring_queue_exit(&ring);
}

bool Iouring::ready() const {
    return ring_socket && reactor->exists(ring_socket);
}

bool Iouring::wakeup() {
    IouringEvent *waiting_task = nullptr;
    io_uring_cqe *cqes[SW_IOURING_CQES_SIZE];

    while (true) {
        auto count = io_uring_peek_batch_cqe(&ring, cqes, SW_IOURING_CQES_SIZE);
        if (count == 0) {
            return true;
        }

        for (decltype(count) i = 0; i < count; i++) {
            auto *cqe = cqes[i];
            auto *task = static_cast<IouringEvent *>(io_uring_cqe_get_data(cqe));
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

            task->coroutine->resume();

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

static const char *get_opcode_name(IouringOpcode opcode) {
    switch (opcode) {
    case SW_IORING_OP_SOCKET:
        return "SOCKET";
    case SW_IORING_OP_OPENAT:
        return "OPENAT";
    case SW_IORING_OP_ACCEPT:
        return "ACCEPT";
    case SW_IORING_OP_CONNECT:
        return "CONNECT";
    case SW_IORING_OP_BIND:
        return "BIND";
    case SW_IORING_OP_LISTEN:
        return "LISTEN";
    case SW_IORING_OP_SEND:
        return "SEND";
    case SW_IORING_OP_RECV:
        return "RECV";
    case SW_IORING_OP_CLOSE:
        return "CLOSE";
    case SW_IORING_OP_STATX:
        return "STATX";
    case SW_IORING_OP_READ:
        return "READ";
    case SW_IORING_OP_WRITE:
        return "WRITE";
    case SW_IORING_OP_RENAMEAT:
        return "RENAMEAT";
    case SW_IORING_OP_MKDIRAT:
        return "MKDIRAT";
    case SW_IORING_OP_FSTAT:
        return "FSTAT";
    case SW_IORING_OP_LSTAT:
        return "LSTAT";
    case SW_IORING_OP_UNLINK_FILE:
        return "UNLINK_FILE";
    case SW_IORING_OP_UNLINK_DIR:
        return "UNLINK_DIR";
    case SW_IORING_OP_FSYNC:
        return "FSYNC";
    case SW_IORING_OP_FDATASYNC:
        return "FDATASYNC";
#ifdef HAVE_IOURING_FUTEX
    case SW_IORING_OP_FUTEX_WAIT:
        return "FUTEX_WAIT";
    case SW_IORING_OP_FUTEX_WAKE:
        return "FUTEX_WAKE";
#endif
#ifdef HAVE_IOURING_FTRUNCATE
    case SW_IORING_OP_FTRUNCATE:
        return "FTRUNCATE";
#endif
    default:
        return "unknown";
    }
}

std::unordered_map<std::string, int> Iouring::list_all_opcode() {
    std::unordered_map<std::string, int> opcodes;
    for (int i = SW_IORING_OP_OPENAT; i < SW_IORING_OP_LAST; i++) {
        auto name = get_opcode_name((IouringOpcode) i);
        if (strcmp(name, "unknown") == 0) {
            continue;
        }
        opcodes[name] = i;
    }
    return opcodes;
}

bool Iouring::submit(IouringEvent *event) {
    swoole_trace("opcode=%s, fd=%d, path=%s", get_opcode_name(event->opcode), event->fd, event->pathname);

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
        if (!swoole_event_is_available()) {
            swoole_warning("no event loop, cannot initialized");
            throw Exception(SW_ERROR_WRONG_OPERATION);
        }
        auto iouring = new Iouring(sw_reactor());
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
    io_uring_sqe *sqe = get_iouring_sqe();
    if (!sqe) {
        waiting_tasks.push(event);
        return true;
    }

    io_uring_sqe_set_data(sqe, (void *) event);

    switch (event->opcode) {
    case SW_IORING_OP_OPENAT:
        io_uring_prep_open(sqe, event->pathname, event->flags | O_CLOEXEC, event->mode);
        break;
    case SW_IORING_OP_SOCKET:
        io_uring_prep_socket(sqe, event->fd, event->sock_type, event->sock_protocol, event->flags);
        break;
    case SW_IORING_OP_CONNECT:
        io_uring_prep_connect(sqe, event->fd, event->addr, event->addr_len);
        break;
    case SW_IORING_OP_ACCEPT:
        io_uring_prep_accept(sqe, event->fd, event->addr_wr, event->addr_len_ptr, event->flags);
        break;
    case SW_IORING_OP_BIND:
        io_uring_prep_bind(sqe, event->fd, (struct sockaddr *) event->addr, event->addr_len);
        break;
    case SW_IORING_OP_LISTEN:
        io_uring_prep_listen(sqe, event->fd, event->backlog);
        break;
    case SW_IORING_OP_READ:
        io_uring_prep_read(sqe, event->fd, event->rbuf, event->size, -1);
        break;
    case SW_IORING_OP_WRITE:
        io_uring_prep_write(sqe, event->fd, event->wbuf, event->size, -1);
        break;
    case SW_IORING_OP_RECV:
        io_uring_prep_recv(sqe, event->fd, event->rbuf, event->size, event->flags);
        break;
    case SW_IORING_OP_SEND:
        io_uring_prep_send(sqe, event->fd, event->wbuf, event->size, event->flags);
        break;
    case SW_IORING_OP_CLOSE:
        io_uring_prep_close(sqe, event->fd);
        break;
    case SW_IORING_OP_FSTAT:
    case SW_IORING_OP_LSTAT:
        if (event->opcode == SW_IORING_OP_FSTAT) {
            sqe->addr = (uintptr_t) "";
            sqe->fd = event->fd;
            sqe->statx_flags |= AT_EMPTY_PATH;
        } else {
            sqe->addr = (uintptr_t) event->pathname;
            sqe->fd = AT_FDCWD;
            sqe->statx_flags |= AT_SYMLINK_NOFOLLOW;
        }
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
        sqe->addr = (uintptr_t) nullptr;
        sqe->opcode = IORING_OP_FSYNC;
        sqe->len = 0;
        sqe->off = 0;
        sqe->fsync_flags = 0;
        if (event->opcode == SW_IORING_OP_FDATASYNC) {
            sqe->fsync_flags = IORING_FSYNC_DATASYNC;
        }
        break;
#ifdef HAVE_IOURING_FUTEX
    case SW_IORING_OP_FUTEX_WAIT:
        sqe->opcode = SW_IORING_OP_FUTEX_WAIT;
        sqe->fd = FUTEX2_SIZE_U32;
        sqe->off = 1;
        sqe->addr = (uintptr_t) event->futex;
        sqe->len = 0;
        sqe->futex_flags = 0;
        sqe->addr3 = FUTEX_BITSET_MATCH_ANY;
        break;
    case SW_IORING_OP_FUTEX_WAKE:
        sqe->opcode = SW_IORING_OP_FUTEX_WAKE;
        sqe->fd = FUTEX2_SIZE_U32;
        sqe->off = 1;
        sqe->addr = (uintptr_t) event->futex;
        sqe->len = 0;
        sqe->futex_flags = 0;
        sqe->addr3 = FUTEX_BITSET_MATCH_ANY;
        break;
#ifdef HAVE_IOURING_FTRUNCATE
    case SW_IORING_OP_FTRUNCATE:
        sqe->opcode = SW_IORING_OP_FTRUNCATE;
        sqe->fd = event->fd;
        sqe->off = event->size;
        sqe->addr = 0;
        sqe->len = 0;
        break;
#endif
#endif
    default:
        abort();
        return false;
    }

    return submit(event);
}

#define INIT_EVENT(op)                                                                                                 \
    IouringEvent event{};                                                                                              \
    event.coroutine = Coroutine::get_current_safe();                                                                   \
    event.opcode = op;

int Iouring::open(const char *pathname, int flags, mode_t mode) {
    INIT_EVENT(SW_IORING_OP_OPENAT);
    event.mode = mode;
    event.flags = flags;
    event.pathname = pathname;

    return static_cast<int>(execute(&event));
}

int Iouring::socket(int domain, int type, int protocol, int flags) {
    INIT_EVENT(SW_IORING_OP_SOCKET);
    event.fd = domain;
    event.sock_type = type;
    event.sock_protocol = protocol;
    event.flags = flags;

    return static_cast<int>(execute(&event));
}

int Iouring::connect(int fd, const struct sockaddr *addr, socklen_t len) {
    INIT_EVENT(SW_IORING_OP_CONNECT);
    event.fd = fd;
    event.addr = addr;
    event.addr_len = len;

    return static_cast<int>(execute(&event));
}

int Iouring::bind(int fd, const struct sockaddr *addr, socklen_t len) {
#if 1
    return ::bind(fd, addr, len);
#else
    INIT_EVENT(SW_IORING_OP_BIND);
    event.fd = fd;
    event.addr = addr;
    event.addr_len = len;

    return static_cast<int>(execute(&event));
#endif
}

int Iouring::listen(int fd, int backlog) {
#if 1
    return ::listen(fd, backlog);
#else
    INIT_EVENT(SW_IORING_OP_LISTEN);
    event.fd = fd;
    event.backlog = backlog;

    return static_cast<int>(execute(&event));
#endif
}

int Iouring::accept(int fd, struct sockaddr *addr, socklen_t *len, int flags) {
    INIT_EVENT(SW_IORING_OP_ACCEPT);
    event.fd = fd;
    event.addr_wr = addr;
    event.addr_len_ptr = len;
    event.flags = flags;

    return static_cast<int>(execute(&event));
}

int Iouring::recv(int fd, char *buf, size_t len, int flags) {
    INIT_EVENT(SW_IORING_OP_RECV);
    event.fd = fd;
    event.rbuf = buf;
    event.size = len;
    event.flags = flags;

    return static_cast<int>(execute(&event));
}

int Iouring::send(int fd, const char *buf, size_t len, int flags) {
    INIT_EVENT(SW_IORING_OP_SEND);
    event.fd = fd;
    event.wbuf = buf;
    event.size = len;
    event.flags = flags;

    return static_cast<int>(execute(&event));
}

int Iouring::close(int fd) {
    INIT_EVENT(SW_IORING_OP_CLOSE);
    event.fd = fd;

    return static_cast<int>(execute(&event));
}

ssize_t Iouring::read(int fd, void *buf, size_t size) {
    INIT_EVENT(SW_IORING_OP_READ);
    event.fd = fd;
    event.rbuf = buf;
    event.size = size;

    return execute(&event);
}

ssize_t Iouring::write(int fd, const void *buf, size_t size) {
    INIT_EVENT(SW_IORING_OP_WRITE);
    event.fd = fd;
    event.wbuf = buf;
    event.size = size;

    return execute(&event);
}

int Iouring::rename(const char *oldpath, const char *newpath) {
    INIT_EVENT(SW_IORING_OP_RENAMEAT);
    event.pathname = oldpath;
    event.pathname2 = newpath;

    return static_cast<int>(execute(&event));
}

int Iouring::mkdir(const char *pathname, mode_t mode) {
    INIT_EVENT(SW_IORING_OP_MKDIRAT);
    event.pathname = pathname;
    event.mode = mode;

    return static_cast<int>(execute(&event));
}

int Iouring::unlink(const char *pathname) {
    INIT_EVENT(SW_IORING_OP_UNLINK_FILE);
    event.pathname = pathname;

    return static_cast<int>(execute(&event));
}

int Iouring::rmdir(const char *pathname) {
    INIT_EVENT(SW_IORING_OP_UNLINK_DIR);
    event.pathname = pathname;

    return static_cast<int>(execute(&event));
}

int Iouring::fsync(int fd) {
    INIT_EVENT(SW_IORING_OP_FSYNC);
    event.fd = fd;

    return static_cast<int>(execute(&event));
}

int Iouring::fdatasync(int fd) {
    INIT_EVENT(SW_IORING_OP_FDATASYNC);
    event.fd = fd;

    return static_cast<int>(execute(&event));
}

#ifdef HAVE_IOURING_FTRUNCATE
int Iouring::ftruncate(int fd, off_t length) {
    INIT_EVENT(SW_IORING_OP_FTRUNCATE);
    event.fd = fd;
    event.size = length;

    return static_cast<int>(execute(&event));
}
#endif

#ifdef HAVE_IOURING_STATX
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
    struct statx _statxbuf;
    INIT_EVENT(SW_IORING_OP_FSTAT);
    event.fd = fd;
    event.statxbuf = &_statxbuf;

    auto retval = execute(&event);
    if (retval == 0) {
        swoole_statx_to_stat(&_statxbuf, statbuf);
    }
    return retval;
}

int Iouring::stat(const char *path, struct stat *statbuf) {
    struct statx _statxbuf;
    INIT_EVENT(SW_IORING_OP_LSTAT);
    event.pathname = path;
    event.statxbuf = &_statxbuf;

    auto retval = execute(&event);
    if (retval == 0) {
        swoole_statx_to_stat(&_statxbuf, statbuf);
    }
    return retval;
}
#endif

#ifdef HAVE_IOURING_FUTEX
int Iouring::futex_wait(uint32_t *futex) {
    INIT_EVENT(SW_IORING_OP_FUTEX_WAIT);
    event.futex = futex;

    return execute(&event);
}

int Iouring::futex_wakeup(uint32_t *futex) {
    INIT_EVENT(SW_IORING_OP_FUTEX_WAKE);
    event.futex = futex;

    return execute(&event);
}
#endif

int Iouring::callback(Reactor *reactor, Event *event) {
    auto *iouring = static_cast<Iouring *>(event->socket->object);
    return iouring->wakeup() ? SW_OK : SW_ERR;
}
}  // namespace swoole
#endif
