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

#pragma once

#include "swoole_coroutine.h"

#if defined(_WIN32) && defined(SW_USE_IOCP)

#include <vector>
#include <unordered_set>
#include <unordered_map>

namespace swoole {

struct IocpEvent;
typedef void (*IocpCallback)(IocpEvent *event, DWORD transferred, DWORD error);

enum IocpOpcode {
    SW_IOCP_CONNECT,
    SW_IOCP_ACCEPT,
    SW_IOCP_RECV,
    SW_IOCP_SEND,
    SW_IOCP_RECVFROM,
    SW_IOCP_SENDTO,
    SW_IOCP_RECVMSG,
    SW_IOCP_SENDMSG,
    SW_IOCP_READV,
    SW_IOCP_WRITEV,
    SW_IOCP_FILE_READ,
    SW_IOCP_FILE_WRITE,
    SW_IOCP_CUSTOM,
};

struct IocpEvent {
    OVERLAPPED overlapped;
    Coroutine *coroutine = nullptr;
    swSocketFd fd = SW_BAD_SOCKET;
    HANDLE handle = INVALID_HANDLE_VALUE;
    IocpOpcode opcode = SW_IOCP_RECV;
    ssize_t result = -1;
    int error = 0;
    bool completed = false;
    bool orphaned = false;
    bool socket_event = true;

    IocpCallback callback = nullptr;
    void *private_data = nullptr;

    WSABUF wsabuf = {};
    std::vector<WSABUF> wsabufs;
    DWORD flags = 0;
    DWORD bytes = 0;

    SOCKET accept_socket = INVALID_SOCKET;
    sockaddr *addr = nullptr;
    socklen_t *addrlen = nullptr;
    socklen_t *msg_namelen = nullptr;
    int addrlen_int = 0;

    IocpEvent(IocpOpcode opcode_, swSocketFd fd_);
    void set_result(DWORD transferred, DWORD err);
};

class Iocp {
    HANDLE port = INVALID_HANDLE_VALUE;
    Reactor *reactor = nullptr;
    uint32_t task_num = 0;
    std::unordered_set<swSocketFd> associated_sockets;
    std::unordered_set<int> associated_files;
    std::unordered_map<int, int> file_flags;

    explicit Iocp(Reactor *reactor_);
    bool associate(swSocketFd fd);
    bool associate(HANDLE handle, ULONG_PTR key);
    ssize_t execute(IocpEvent *event, double timeout);
    bool dispatch(DWORD transferred, ULONG_PTR key, OVERLAPPED *overlapped, DWORD error);

    static Iocp *get_instance();
    static bool get_extension_function(SOCKET fd, GUID guid, void **fn);

  public:
    ~Iocp();

    static bool init(Reactor *reactor = nullptr);
    static void set_error(DWORD error);
    static void set_file_error(DWORD error);

    bool ready() const {
        return port != INVALID_HANDLE_VALUE && port != nullptr;
    }

    uint64_t get_task_num() const {
        return task_num;
    }

    bool wakeup();
    int wait(int timeout_msec);

    bool associate_socket(swSocketFd fd) {
        return associate(fd);
    }

    void submit(IocpEvent *event) {
        event->completed = false;
        ++task_num;
    }

    void cancel_submission(IocpEvent *event) {
        event->orphaned = true;
        if (task_num > 0) {
            --task_num;
        }
    }

    static int connect(swSocketFd fd, const struct sockaddr *addr, socklen_t len, double timeout = -1);
    static int accept(swSocketFd fd, struct sockaddr *addr, socklen_t *len, int flags = 0, double timeout = -1);
    static ssize_t recv(swSocketFd fd, void *buf, size_t len, int flags, double timeout = -1);
    static ssize_t send(swSocketFd fd, const void *buf, size_t len, int flags, double timeout = -1);
    static ssize_t recvmsg(swSocketFd fd, struct msghdr *message, int flags, double timeout = -1);
    static ssize_t sendmsg(swSocketFd fd, const struct msghdr *message, int flags, double timeout = -1);
    static ssize_t sendto(
        swSocketFd fd, const void *buf, size_t n, int flags, const struct sockaddr *addr, socklen_t len, double timeout = -1);
    static ssize_t recvfrom(
        swSocketFd fd, void *buf, size_t n, sockaddr *addr, socklen_t *socklen, double timeout = -1);
    static ssize_t readv(swSocketFd fd, const struct iovec *iovec, int count, double timeout = -1);
    static ssize_t writev(swSocketFd fd, const struct iovec *iovec, int count, double timeout = -1);
    static ssize_t read(swSocketFd fd, void *buf, size_t size, double timeout = -1);
    static ssize_t write(swSocketFd fd, const void *buf, size_t size, double timeout = -1);
    static ssize_t sendfile(swSocketFd out_fd, int in_fd, off_t *offset, size_t size, double timeout = -1);
    static int shutdown(swSocketFd fd, int how);
    static int close(swSocketFd fd);
    static int poll(struct pollfd *fds, nfds_t nfds, int timeout);

    static int open_file(const char *pathname, int flags, mode_t mode);
    static int close_file(int fd);
    static ssize_t read_file(int fd, void *buf, size_t size, double timeout = -1);
    static ssize_t write_file(int fd, const void *buf, size_t size, double timeout = -1);
};

}  // namespace swoole

#endif
