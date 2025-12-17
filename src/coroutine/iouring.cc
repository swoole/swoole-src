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
  |           Tianfeng Han   <rango@swoole.com>                          |
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

#include <cmath>

#define DOUBLE_TO_TIMESPEC(seconds, ts)                                                                                \
    do {                                                                                                               \
        double __int_part;                                                                                             \
        double __frac_part = modf((seconds), &__int_part);                                                             \
        (ts)->tv_sec = (__kernel_time64_t) __int_part;                                                                 \
        (ts)->tv_nsec = (long long) (__frac_part * 1000000000.0);                                                      \
        if ((ts)->tv_nsec >= 1000000000) {                                                                             \
            (ts)->tv_sec += 1;                                                                                         \
            (ts)->tv_nsec = 0;                                                                                         \
        }                                                                                                              \
    } while (0)

#define TIMEOUT_EVENT (-1)

using swoole::Coroutine;

namespace swoole {
//-------------------------------------------------------------------------------
struct IouringEvent {
    Coroutine *coroutine;
    io_uring_sqe data;
    ssize_t result;
    IouringTimeout timeout;
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
            // The user data for the timeout request is -1, this event should be ignored.
            if (task == reinterpret_cast<void *>(TIMEOUT_EVENT)) {
                io_uring_cq_advance(&ring, 1);
                continue;
            }

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
                if (!dispatch(waiting_task, &task->timeout)) {
                    waiting_task->coroutine->resume();
                }
            }
        }
    }

    return true;
}

static const char *get_opcode_name(io_uring_op opcode) {
    switch (opcode) {
    case IORING_OP_SOCKET:
        return "SOCKET";
    case IORING_OP_OPENAT:
        return "OPENAT";
    case IORING_OP_ACCEPT:
        return "ACCEPT";
    case IORING_OP_CONNECT:
        return "CONNECT";
    case IORING_OP_BIND:
        return "BIND";
    case IORING_OP_LISTEN:
        return "LISTEN";
    case IORING_OP_SEND:
        return "SEND";
    case IORING_OP_RECV:
        return "RECV";
    case IORING_OP_CLOSE:
        return "CLOSE";
    case IORING_OP_STATX:
        return "STATX";
    case IORING_OP_READ:
        return "READ";
    case IORING_OP_WRITE:
        return "WRITE";
    case IORING_OP_RENAMEAT:
        return "RENAMEAT";
    case IORING_OP_MKDIRAT:
        return "MKDIRAT";
    case IORING_OP_UNLINKAT:
        return "UNLINKAT";
    case IORING_OP_FSYNC:
        return "FSYNC";
#ifdef HAVE_IOURING_FUTEX
    case IORING_OP_FUTEX_WAIT:
        return "FUTEX_WAIT";
    case IORING_OP_FUTEX_WAKE:
        return "FUTEX_WAKE";
#endif
#ifdef HAVE_IOURING_FTRUNCATE
    case IORING_OP_FTRUNCATE:
        return "FTRUNCATE";
#endif
    default:
        return "unknown";
    }
}

std::unordered_map<std::string, int> Iouring::list_all_opcode() {
    std::unordered_map<std::string, int> opcodes;
    for (int i = IORING_OP_NOP; i < IORING_OP_LAST; i++) {
        auto name = get_opcode_name((io_uring_op) i);
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

ssize_t Iouring::execute(IouringEvent *event, IouringTimeout *timeout) {
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

    if (!SwooleTG.iouring->dispatch(event, timeout)) {
        return SW_ERR;
    }

    // File system operations cannot be canceled, must wait to be completed.
    event->coroutine->yield();

    return event->result;
}

bool Iouring::dispatch(IouringEvent *event, IouringTimeout *timeout) {
    io_uring_sqe *sqe = io_uring_get_sqe(&ring);
    if (!sqe) {
        waiting_tasks.push(event);
        return true;
    }

    memcpy(sqe, &event->data, sizeof(event->data));
    io_uring_sqe_set_data(sqe, (void *) event);

    if (timeout) {
        auto timeout_sqe = io_uring_get_sqe(&ring);
        if (!timeout_sqe) {
            swoole_warning("timeout setting failed, the iouring queue[%d] is full", ring.ring_fd);
        }
        memset(timeout_sqe, 0, sizeof(*timeout_sqe));
        io_uring_prep_link_timeout(timeout_sqe, reinterpret_cast<__kernel_timespec *>(timeout), 0);
        io_uring_sqe_set_data(timeout_sqe, reinterpret_cast<void *>(TIMEOUT_EVENT));
        sqe->flags |= IOSQE_IO_LINK;
    }

    return submit(event);
}

#define INIT_EVENT(op)                                                                                                 \
    IouringEvent event{};                                                                                              \
    event.coroutine = Coroutine::get_current_safe();

int Iouring::open(const char *pathname, int flags, mode_t mode) {
    INIT_EVENT(IORING_OP_OPENAT);
    io_uring_prep_open(&event.data, pathname, flags | O_CLOEXEC, mode);
    return static_cast<int>(execute(&event));
}

int Iouring::socket(int domain, int type, int protocol, int flags) {
    INIT_EVENT(IORING_OP_SOCKET);
    io_uring_prep_socket(&event.data, domain, type, protocol, flags);
    return static_cast<int>(execute(&event));
}

int Iouring::connect(int fd, const struct sockaddr *addr, socklen_t len) {
    INIT_EVENT(IORING_OP_CONNECT);
    io_uring_prep_connect(&event.data, fd, addr, len);
    return static_cast<int>(execute(&event));
}

int Iouring::bind(int fd, const struct sockaddr *addr, socklen_t len) {
#if 1
    return ::bind(fd, addr, len);
#else
    INIT_EVENT(IORING_OP_BIND);
    io_uring_prep_bind(&event.data, fd, (struct sockaddr *) addr, len);
    return static_cast<int>(execute(&event));
#endif
}

int Iouring::listen(int fd, int backlog) {
#if 1
    return ::listen(fd, backlog);
#else
    io_uring_prep_listen(sqe, fd, backlog);
#endif
}

int Iouring::sleep(int tv_sec, int tv_nsec, int flags) {
    struct __kernel_timespec ts {
        tv_sec, tv_nsec,
    };

    INIT_EVENT(IORING_OP_TIMEOUT);
    io_uring_prep_timeout(&event.data, &ts, 0, flags);
    return static_cast<int>(execute(&event));
}

int Iouring::accept(int fd, struct sockaddr *addr, socklen_t *len, int flags) {
    INIT_EVENT(IORING_OP_ACCEPT);
    io_uring_prep_accept(&event.data, fd, addr, len, flags);
    return static_cast<int>(execute(&event));
}

ssize_t Iouring::recv(int fd, char *buf, size_t len, int flags) {
    INIT_EVENT(IORING_OP_RECV);
    io_uring_prep_recv(&event.data, fd, buf, len, flags);
    return execute(&event);
}

ssize_t Iouring::send(int fd, const char *buf, size_t len, int flags) {
    INIT_EVENT(IORING_OP_SEND);
    io_uring_prep_send(&event.data, fd, buf, len, flags);
    return execute(&event);
}

int Iouring::close(int fd) {
    INIT_EVENT(IORING_OP_CLOSE);
    io_uring_prep_close(&event.data, fd);
    return static_cast<int>(execute(&event));
}

ssize_t Iouring::read(int fd, void *buf, size_t size) {
    INIT_EVENT(IORING_OP_READ);
    io_uring_prep_read(&event.data, fd, buf, size, -1);
    return execute(&event);
}

ssize_t Iouring::write(int fd, const void *buf, size_t size) {
    INIT_EVENT(IORING_OP_WRITE);
    io_uring_prep_write(&event.data, fd, buf, size, -1);
    return execute(&event);
}

int Iouring::rename(const char *oldpath, const char *newpath) {
    INIT_EVENT(IORING_OP_RENAMEAT);
    io_uring_prep_rename(&event.data, oldpath, newpath);
    return static_cast<int>(execute(&event));
}

int Iouring::mkdir(const char *pathname, mode_t mode) {
    INIT_EVENT(IORING_OP_MKDIRAT);
    io_uring_prep_mkdir(&event.data, pathname, mode);
    return static_cast<int>(execute(&event));
}

int Iouring::unlink(const char *pathname) {
    INIT_EVENT(IORING_OP_UNLINK_FILE);
    io_uring_prep_unlink(&event.data, pathname, 0);
    return static_cast<int>(execute(&event));
}

int Iouring::rmdir(const char *pathname) {
    INIT_EVENT(IORING_OP_UNLINK_DIR);
    io_uring_prep_unlink(&event.data, pathname, AT_REMOVEDIR);
    return static_cast<int>(execute(&event));
}

int Iouring::fsync(int fd) {
    INIT_EVENT(IORING_OP_FSYNC);
    io_uring_prep_fsync(&event.data, fd, 0);
    return static_cast<int>(execute(&event));
}

int Iouring::fdatasync(int fd) {
    INIT_EVENT(IORING_OP_FDATASYNC);
    io_uring_prep_fsync(&event.data, fd, IORING_FSYNC_DATASYNC);
    return static_cast<int>(execute(&event));
}

#ifdef HAVE_IOURING_FTRUNCATE
int Iouring::ftruncate(int fd, off_t length) {
    INIT_EVENT(IORING_OP_FTRUNCATE);
    io_uring_prep_ftruncate(&event.data, fd, length);
    return static_cast<int>(execute(&event));
}
#endif

static inline int siginfo_to_status(const siginfo_t *info) {
    int status = 0;

    switch (info->si_code) {
    case CLD_EXITED:
        status = (info->si_status & 0xFF) << 8;
        break;
    case CLD_KILLED:
        status = info->si_status & 0x7F;
        break;
    case CLD_DUMPED:
        status = (info->si_status & 0x7F) | 0x80;
        break;
    case CLD_STOPPED:
        status = ((info->si_status & 0xFF) << 8) | 0x7F;
        break;
    case CLD_CONTINUED:
        status = 0xFFFF;
        break;
    }

    return status;
}

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
    struct statx statxbuf;
    INIT_EVENT(IORING_OP_FSTAT);

    event.data.addr = (uintptr_t) "";
    event.data.fd = fd;
    event.data.statx_flags = AT_EMPTY_PATH;
    event.data.opcode = IORING_OP_STATX;
    event.data.off = (uintptr_t) &statxbuf;

    auto retval = execute(&event);
    if (retval == 0) {
        swoole_statx_to_stat(&statxbuf, statbuf);
    }
    return retval;
}

int Iouring::stat(const char *path, struct stat *statbuf) {
    struct statx statxbuf;
    INIT_EVENT(IORING_OP_FSTAT);

    event.data.addr = (uintptr_t) path;
    event.data.fd = AT_FDCWD;
    event.data.statx_flags = AT_SYMLINK_NOFOLLOW;
    event.data.opcode = IORING_OP_STATX;
    event.data.off = (uintptr_t) &statxbuf;

    auto retval = execute(&event);
    if (retval == 0) {
        swoole_statx_to_stat(&statxbuf, statbuf);
    }
    return retval;
}
#endif

#ifdef HAVE_IOURING_FUTEX
int Iouring::futex_wait(uint32_t *futex) {
    INIT_EVENT(IORING_OP_FUTEX_WAIT);

    event.data.opcode = IORING_FSYNC_DATASYNC;
    event.data.fd = FUTEX2_SIZE_U32;
    event.data.off = 1;
    event.data.addr = (uintptr_t) futex;
    event.data.len = 0;
    event.data.futex_flags = 0;
    event.data.addr3 = FUTEX_BITSET_MATCH_ANY;

    return static_cast<int>(execute(&event));
}

int Iouring::futex_wakeup(uint32_t *futex) {
    INIT_EVENT(IORING_OP_FUTEX_WAKE);

    event.data.opcode = IORING_OP_FUTEX_WAKE;
    event.data.fd = FUTEX2_SIZE_U32;
    event.data.off = 1;
    event.data.addr = (uintptr_t) futex;
    event.data.len = 0;
    event.data.futex_flags = 0;
    event.data.addr3 = FUTEX_BITSET_MATCH_ANY;

    return static_cast<int>(execute(&event));
}
#endif

pid_t Iouring::wait(int *stat_loc, double timeout) {
	return waitpid(-1, stat_loc, 0, timeout);
}

pid_t Iouring::waitpid(pid_t _pid, int *stat_loc, int options, double timeout) {
    if (options & WNOHANG) {
        return ::waitpid(_pid, stat_loc, options);
    }

    INIT_EVENT(IORING_OP_WAITID);
    siginfo_t info{};
    idtype_t idtype = _pid > 0 ? P_PID : P_ALL;
    id_t id = _pid > 0 ? _pid : 0;
    options = options == 0 ? WEXITED : options;
    io_uring_prep_waitid(&event.data, idtype, id, &info, options, 0);

    int rc;

    if (timeout > 0) {
        DOUBLE_TO_TIMESPEC(timeout, &event.timeout);
        rc = static_cast<int>(execute(&event, &event.timeout));
    } else {
        rc = static_cast<int>(execute(&event));
    }

    if (rc != -1) {
        *stat_loc = siginfo_to_status(&info);
        return info.si_pid;
    }

    /**
	 * After a timeout, iouring will set errno to `ECANCELED`, but in the async implementation,
	 * the errno after a timeout is `ETIMEDOUT`.
	 * To maintain compatibility, numerical conversion is necessary.
	 */
	errno = errno == ECANCELED ? ETIMEDOUT : errno;
	return rc;
}

int Iouring::callback(Reactor *reactor, Event *event) {
    auto *iouring = static_cast<Iouring *>(event->socket->object);
    return iouring->wakeup() ? SW_OK : SW_ERR;
}
}  // namespace swoole
#endif
