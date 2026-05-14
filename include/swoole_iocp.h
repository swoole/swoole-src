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

class Iocp {
    HANDLE port = INVALID_HANDLE_VALUE;
    Reactor *reactor = nullptr;
    uint32_t task_num = 0;
    int original_timeout_msec = -1;
    std::unordered_set<sw_socket_t> associated_sockets;
    std::unordered_set<int> associated_files;
    std::unordered_map<int, int> file_flags;

    explicit Iocp(Reactor *reactor_);
    bool associate(sw_socket_t fd);
    bool associate(HANDLE handle, ULONG_PTR key);
    ssize_t execute(IocpEvent *event, double timeout);

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

    static int connect(sw_socket_t fd, const struct sockaddr *addr, socklen_t len, double timeout = -1);
    static int accept(sw_socket_t fd, struct sockaddr *addr, socklen_t *len, int flags = 0, double timeout = -1);
    static ssize_t recv(sw_socket_t fd, void *buf, size_t len, int flags, double timeout = -1);
    static ssize_t send(sw_socket_t fd, const void *buf, size_t len, int flags, double timeout = -1);
    static ssize_t recvmsg(sw_socket_t fd, struct msghdr *message, int flags, double timeout = -1);
    static ssize_t sendmsg(sw_socket_t fd, const struct msghdr *message, int flags, double timeout = -1);
    static ssize_t sendto(
        sw_socket_t fd, const void *buf, size_t n, int flags, const struct sockaddr *addr, socklen_t len, double timeout = -1);
    static ssize_t recvfrom(
        sw_socket_t fd, void *buf, size_t n, sockaddr *addr, socklen_t *socklen, double timeout = -1);
    static ssize_t readv(sw_socket_t fd, const struct iovec *iovec, int count, double timeout = -1);
    static ssize_t writev(sw_socket_t fd, const struct iovec *iovec, int count, double timeout = -1);
    static ssize_t read(sw_socket_t fd, void *buf, size_t size, double timeout = -1);
    static ssize_t write(sw_socket_t fd, const void *buf, size_t size, double timeout = -1);
    static ssize_t sendfile(sw_socket_t out_fd, int in_fd, off_t *offset, size_t size, double timeout = -1);
    static int shutdown(sw_socket_t fd, int how);
    static int close(sw_socket_t fd);
    static int poll(struct pollfd *fds, nfds_t nfds, int timeout);

    static int open_file(const char *pathname, int flags, mode_t mode);
    static int close_file(int fd);
    static ssize_t read_file(int fd, void *buf, size_t size, double timeout = -1);
    static ssize_t write_file(int fd, const void *buf, size_t size, double timeout = -1);
};

}  // namespace swoole

#endif
