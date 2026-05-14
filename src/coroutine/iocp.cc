/*
  +----------------------------------------------------------------------+
  | Swoole                                                               |
  +----------------------------------------------------------------------+
  | This source file is subject to version 2.0 of the Apache license,    |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.apache.org/licenses/LICENSE-2.0.html                      |
  | If you did not receive a copy of the Apache2 license and are unable  |
  | to obtain it through the world-wide-web, please send a note to       |
  | license@swoole.com so we can mail you a copy immediately.            |
  +----------------------------------------------------------------------+
  | Author: Tianfeng Han  <rango@swoole.com>                             |
  +----------------------------------------------------------------------+
*/

#include "swoole_iocp.h"
#include "swoole_coroutine_system.h"

#if defined(_WIN32) && defined(SW_USE_IOCP)

#include <algorithm>

using swoole::Coroutine;
using swoole::coroutine::System;

namespace swoole {

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
};

struct IocpEvent {
    OVERLAPPED overlapped;
    Coroutine *coroutine = nullptr;
    sw_socket_t fd = SW_BAD_SOCKET;
    IocpOpcode opcode = SW_IOCP_RECV;
    ssize_t result = -1;
    int error = 0;
    bool completed = false;
    bool orphaned = false;

    WSABUF wsabuf = {};
    std::vector<WSABUF> wsabufs;
    DWORD flags = 0;
    DWORD bytes = 0;

    SOCKET accept_socket = INVALID_SOCKET;
    char accept_buffer[(sizeof(sockaddr_storage) + 16) * 2] = {};
    sockaddr *addr = nullptr;
    socklen_t *addrlen = nullptr;
    socklen_t *msg_namelen = nullptr;
    int addrlen_int = 0;

    IocpEvent(IocpOpcode opcode_, sw_socket_t fd_) : fd(fd_), opcode(opcode_) {
        memset(&overlapped, 0, sizeof(overlapped));
    }

    void set_result(DWORD transferred, DWORD err) {
        completed = true;
        if (err == ERROR_SUCCESS) {
            result = static_cast<ssize_t>(transferred);
            error = 0;
        } else {
            result = -1;
            Iocp::set_error(err);
            error = errno;
        }
    }
};

static LPFN_CONNECTEX fn_connect_ex = nullptr;
static LPFN_ACCEPTEX fn_accept_ex = nullptr;
static LPFN_GETACCEPTEXSOCKADDRS fn_get_accept_ex_sockaddrs = nullptr;

static const char *get_opcode_name(IocpOpcode opcode) {
    switch (opcode) {
    case SW_IOCP_CONNECT:
        return "CONNECT";
    case SW_IOCP_ACCEPT:
        return "ACCEPT";
    case SW_IOCP_RECV:
        return "RECV";
    case SW_IOCP_SEND:
        return "SEND";
    case SW_IOCP_RECVFROM:
        return "RECVFROM";
    case SW_IOCP_SENDTO:
        return "SENDTO";
    case SW_IOCP_RECVMSG:
        return "RECVMSG";
    case SW_IOCP_SENDMSG:
        return "SENDMSG";
    case SW_IOCP_READV:
        return "READV";
    case SW_IOCP_WRITEV:
        return "WRITEV";
    default:
        return "UNKNOWN";
    }
}

static std::vector<WSABUF> make_wsabufs(const struct iovec *iov, int count) {
    std::vector<WSABUF> buffers;
    buffers.reserve(count);
    for (int i = 0; i < count; i++) {
        WSABUF buf;
        buf.buf = static_cast<CHAR *>(iov[i].iov_base);
        buf.len = static_cast<ULONG>(iov[i].iov_len);
        buffers.push_back(buf);
    }
    return buffers;
}

static bool bind_connect_ex_socket(sw_socket_t fd, const sockaddr *addr) {
    sockaddr_storage local_addr;
    socklen_t local_addr_len;
    memset(&local_addr, 0, sizeof(local_addr));

    if (addr->sa_family == AF_INET6) {
        auto *in6 = reinterpret_cast<sockaddr_in6 *>(&local_addr);
        in6->sin6_family = AF_INET6;
        in6->sin6_port = 0;
        local_addr_len = sizeof(sockaddr_in6);
    } else {
        auto *in = reinterpret_cast<sockaddr_in *>(&local_addr);
        in->sin_family = AF_INET;
        in->sin_addr.s_addr = htonl(INADDR_ANY);
        in->sin_port = 0;
        local_addr_len = sizeof(sockaddr_in);
    }

    if (::bind(fd, reinterpret_cast<sockaddr *>(&local_addr), local_addr_len) == SOCKET_ERROR) {
        const int err = WSAGetLastError();
        if (err != WSAEINVAL) {
            Iocp::set_error(err);
            return false;
        }
    }
    return true;
}

Iocp::Iocp(Reactor *reactor_) {
    reactor = reactor_;
    port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 0);
    if (port == nullptr) {
        set_error(GetLastError());
        swoole_sys_error("CreateIoCompletionPort() failed");
        return;
    }

    swoole_trace_log(SW_TRACE_EVENT, "IOCP created: port=%p", port);

    original_timeout_msec = reactor->timeout_msec;
    if (reactor->timeout_msec < 0) {
        reactor->set_timeout_msec(1);
    }

    reactor->set_exit_condition(Reactor::EXIT_CONDITION_IOCP, [](Reactor *reactor, size_t &event_num) -> bool {
        if (SwooleTG.iocp && SwooleTG.iocp->get_task_num() > 0) {
            return false;
        }
        return true;
    });

    reactor->set_end_callback(Reactor::PRIORITY_IOCP_WAKEUP, [](Reactor *reactor) {
        if (SwooleTG.iocp) {
            SwooleTG.iocp->wakeup();
        }
    });

    reactor->add_destroy_callback([](void *data) {
        if (!SwooleTG.iocp) {
            return;
        }
        delete SwooleTG.iocp;
        SwooleTG.iocp = nullptr;
    });
}

Iocp::~Iocp() {
    swoole_trace_log(SW_TRACE_EVENT, "IOCP destroyed: port=%p", port);
    if (reactor && !reactor->destroyed) {
        reactor->remove_exit_condition(Reactor::EXIT_CONDITION_IOCP);
        reactor->erase_end_callback(Reactor::PRIORITY_IOCP_WAKEUP);
        if (original_timeout_msec < 0 && reactor->timeout_msec == 1) {
            reactor->set_timeout_msec(original_timeout_msec);
        }
    }
    if (port != INVALID_HANDLE_VALUE && port != nullptr) {
        CloseHandle(port);
        port = INVALID_HANDLE_VALUE;
    }
}

void Iocp::set_error(DWORD error) {
    WSASetLastError(error);
    errno = sw_socket_errno();
    swoole_set_last_error(errno);
}

bool Iocp::get_extension_function(SOCKET fd, GUID guid, void **fn) {
    DWORD bytes = 0;
    if (WSAIoctl(fd,
                 SIO_GET_EXTENSION_FUNCTION_POINTER,
                 &guid,
                 sizeof(guid),
                 fn,
                 sizeof(*fn),
                 &bytes,
                 nullptr,
                 nullptr) == SOCKET_ERROR) {
        set_error(WSAGetLastError());
        return false;
    }
    return true;
}

Iocp *Iocp::get_instance() {
    if (sw_unlikely(!SwooleTG.iocp)) {
        if (!init(sw_reactor())) {
            swoole_error("The event loop is unavailable, unable to create IOCP instance.");
        }
    }
    return SwooleTG.iocp;
}

bool Iocp::init(Reactor *reactor) {
    if (SwooleTG.iocp) {
        return SwooleTG.iocp->ready();
    }
    if (!reactor) {
        reactor = sw_reactor();
    }
    if (!reactor || !swoole_event_is_available()) {
        swoole_error("The event loop is unavailable, unable to initialize IOCP.");
        return false;
    }

    SwooleTG.iocp = new Iocp(reactor);
    if (!SwooleTG.iocp->ready()) {
        delete SwooleTG.iocp;
        SwooleTG.iocp = nullptr;
        return false;
    }
    return true;
}

bool Iocp::associate(sw_socket_t fd) {
    if (associated_sockets.find(fd) != associated_sockets.end()) {
        return true;
    }
    HANDLE handle = reinterpret_cast<HANDLE>(fd);
    HANDLE retval = CreateIoCompletionPort(handle, port, static_cast<ULONG_PTR>(fd), 0);
    if (retval != port) {
        set_error(GetLastError());
        return false;
    }
    associated_sockets.insert(fd);
    swoole_trace_log(SW_TRACE_EVENT, "IOCP associate fd=%d", (int) fd);
    return true;
}

ssize_t Iocp::execute(IocpEvent *event, double timeout) {
    event->coroutine = Coroutine::get_current_safe();
    ++task_num;
    swoole_trace_log(SW_TRACE_SOCKET,
                     "IOCP submit opcode=%s, fd=%d, timeout=%f, task_num=%u",
                     get_opcode_name(event->opcode),
                     (int) event->fd,
                     timeout,
                     task_num);

    if (timeout > 0) {
        event->coroutine->yield_ex(timeout);
    } else {
        Coroutine::CancelFunc cancel_fn = [event](Coroutine *co) {
            CancelIoEx(reinterpret_cast<HANDLE>(event->fd), &event->overlapped);
            co->resume();
            return true;
        };
        event->coroutine->yield(&cancel_fn);
    }

    if (!event->completed) {
        event->orphaned = true;
        CancelIoEx(reinterpret_cast<HANDLE>(event->fd), &event->overlapped);
        if (event->coroutine->is_timedout()) {
            errno = ETIMEDOUT;
        } else if (event->coroutine->is_canceled()) {
            errno = ECANCELED;
        } else {
            errno = ECANCELED;
        }
        swoole_set_last_error(errno);
        swoole_trace_log(SW_TRACE_SOCKET,
                         "IOCP timeout/cancel opcode=%s, fd=%d, errno=%d",
                         get_opcode_name(event->opcode),
                         (int) event->fd,
                         errno);
        return -1;
    }

    ssize_t result = event->result;
    if (event->error) {
        errno = event->error;
        swoole_set_last_error(errno);
    }
    swoole_trace_log(SW_TRACE_SOCKET,
                     "IOCP done opcode=%s, fd=%d, result=%ld, errno=%d",
                     get_opcode_name(event->opcode),
                     (int) event->fd,
                     result,
                     event->error);
    delete event;
    return result;
}

bool Iocp::wakeup() {
    DWORD transferred = 0;
    ULONG_PTR key = 0;
    OVERLAPPED *overlapped = nullptr;

    while (true) {
        BOOL ok = GetQueuedCompletionStatus(port, &transferred, &key, &overlapped, 0);
        if (overlapped == nullptr) {
            break;
        }

        auto *event = reinterpret_cast<IocpEvent *>(overlapped);
        DWORD err = ok ? ERROR_SUCCESS : GetLastError();
        event->set_result(transferred, err);
        swoole_trace_log(SW_TRACE_EVENT,
                         "IOCP completion opcode=%s, fd=%d, bytes=%lu, error=%lu",
                         get_opcode_name(event->opcode),
                         (int) event->fd,
                         transferred,
                         err);

        if (task_num > 0) {
            --task_num;
        }

        if (event->opcode == SW_IOCP_RECVFROM && event->addrlen) {
            *event->addrlen = static_cast<socklen_t>(event->addrlen_int);
        } else if (event->opcode == SW_IOCP_RECVMSG && event->msg_namelen) {
            *event->msg_namelen = static_cast<socklen_t>(event->addrlen_int);
        }

        if (event->orphaned || event->coroutine == nullptr) {
            delete event;
            continue;
        }

        event->coroutine->resume();
    }

    return true;
}

int Iocp::connect(sw_socket_t fd, const struct sockaddr *addr, socklen_t len, double timeout) {
    auto iocp = get_instance();
    if (!iocp->associate(fd)) {
        return -1;
    }
    if (!fn_connect_ex) {
        GUID guid = WSAID_CONNECTEX;
        if (!get_extension_function(fd, guid, reinterpret_cast<void **>(&fn_connect_ex))) {
            return -1;
        }
    }
    if (!bind_connect_ex_socket(fd, addr)) {
        return -1;
    }

    auto *event = new IocpEvent(SW_IOCP_CONNECT, fd);
    BOOL ok = fn_connect_ex(fd, addr, len, nullptr, 0, nullptr, &event->overlapped);
    if (!ok && WSAGetLastError() != ERROR_IO_PENDING) {
        set_error(WSAGetLastError());
        delete event;
        return -1;
    }

    int retval = static_cast<int>(iocp->execute(event, timeout));
    if (retval == 0) {
        setsockopt(fd, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, nullptr, 0);
    }
    return retval;
}

int Iocp::accept(sw_socket_t fd, struct sockaddr *addr, socklen_t *len, int flags, double timeout) {
    auto iocp = get_instance();
    if (!iocp->associate(fd)) {
        return -1;
    }
    if (!fn_accept_ex) {
        GUID guid = WSAID_ACCEPTEX;
        if (!get_extension_function(fd, guid, reinterpret_cast<void **>(&fn_accept_ex))) {
            return -1;
        }
    }
    if (!fn_get_accept_ex_sockaddrs) {
        GUID guid = WSAID_GETACCEPTEXSOCKADDRS;
        if (!get_extension_function(fd, guid, reinterpret_cast<void **>(&fn_get_accept_ex_sockaddrs))) {
            return -1;
        }
    }

    sockaddr_storage sockname;
    int sockname_len = sizeof(sockname);
    int domain = AF_INET;
    if (getsockname(fd, reinterpret_cast<sockaddr *>(&sockname), &sockname_len) == 0) {
        domain = reinterpret_cast<sockaddr *>(&sockname)->sa_family;
    }

    SOCKET accept_fd = WSASocketW(domain, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, WSA_FLAG_OVERLAPPED);
    if (accept_fd == INVALID_SOCKET) {
        set_error(WSAGetLastError());
        return -1;
    }

    auto *event = new IocpEvent(SW_IOCP_ACCEPT, fd);
    event->accept_socket = accept_fd;
    DWORD bytes = 0;
    const DWORD address_length = sizeof(sockaddr_storage) + 16;
    BOOL ok = fn_accept_ex(fd, accept_fd, event->accept_buffer, 0, address_length, address_length, &bytes, &event->overlapped);
    if (!ok && WSAGetLastError() != ERROR_IO_PENDING) {
        set_error(WSAGetLastError());
        closesocket(accept_fd);
        delete event;
        return -1;
    }

    int retval = static_cast<int>(iocp->execute(event, timeout));
    if (retval < 0) {
        closesocket(accept_fd);
        return -1;
    }

    setsockopt(accept_fd, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, reinterpret_cast<const char *>(&fd), sizeof(fd));

    sockaddr *local_addr = nullptr;
    sockaddr *remote_addr = nullptr;
    int local_len = 0;
    int remote_len = 0;
    fn_get_accept_ex_sockaddrs(event->accept_buffer, 0, address_length, address_length, &local_addr, &local_len, &remote_addr, &remote_len);
    if (addr && len && remote_addr) {
        socklen_t copy_len = std::min(*len, static_cast<socklen_t>(remote_len));
        memcpy(addr, remote_addr, copy_len);
        *len = copy_len;
    }

    return static_cast<int>(accept_fd);
}

ssize_t Iocp::recv(sw_socket_t fd, void *buf, size_t len, int flags, double timeout) {
    auto iocp = get_instance();
    if (!iocp->associate(fd)) {
        return -1;
    }
    auto *event = new IocpEvent(SW_IOCP_RECV, fd);
    event->wsabuf.buf = static_cast<CHAR *>(buf);
    event->wsabuf.len = static_cast<ULONG>(len);
    event->flags = static_cast<DWORD>(flags);
    if (WSARecv(fd, &event->wsabuf, 1, nullptr, &event->flags, &event->overlapped, nullptr) == SOCKET_ERROR &&
        WSAGetLastError() != WSA_IO_PENDING) {
        set_error(WSAGetLastError());
        delete event;
        return -1;
    }
    return iocp->execute(event, timeout);
}

ssize_t Iocp::send(sw_socket_t fd, const void *buf, size_t len, int flags, double timeout) {
    auto iocp = get_instance();
    if (!iocp->associate(fd)) {
        return -1;
    }
    auto *event = new IocpEvent(SW_IOCP_SEND, fd);
    event->wsabuf.buf = const_cast<CHAR *>(static_cast<const CHAR *>(buf));
    event->wsabuf.len = static_cast<ULONG>(len);
    if (WSASend(fd, &event->wsabuf, 1, nullptr, static_cast<DWORD>(flags), &event->overlapped, nullptr) == SOCKET_ERROR &&
        WSAGetLastError() != WSA_IO_PENDING) {
        set_error(WSAGetLastError());
        delete event;
        return -1;
    }
    return iocp->execute(event, timeout);
}

ssize_t Iocp::recvmsg(sw_socket_t fd, struct msghdr *message, int flags, double timeout) {
    auto iocp = get_instance();
    if (!iocp->associate(fd)) {
        return -1;
    }
    auto *event = new IocpEvent(SW_IOCP_RECVMSG, fd);
    event->wsabufs = make_wsabufs(message->msg_iov, static_cast<int>(message->msg_iovlen));
    event->flags = static_cast<DWORD>(flags);
    event->addr = static_cast<sockaddr *>(message->msg_name);
    event->msg_namelen = &message->msg_namelen;
    event->addrlen_int = static_cast<int>(message->msg_namelen);

    int rc;
    if (message->msg_name) {
        rc = WSARecvFrom(fd,
                         event->wsabufs.data(),
                         static_cast<DWORD>(event->wsabufs.size()),
                         nullptr,
                         &event->flags,
                         event->addr,
                         &event->addrlen_int,
                         &event->overlapped,
                         nullptr);
    } else {
        rc = WSARecv(fd,
                     event->wsabufs.data(),
                     static_cast<DWORD>(event->wsabufs.size()),
                     nullptr,
                     &event->flags,
                     &event->overlapped,
                     nullptr);
    }
    if (rc == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
        set_error(WSAGetLastError());
        delete event;
        return -1;
    }
    return iocp->execute(event, timeout);
}

ssize_t Iocp::sendmsg(sw_socket_t fd, const struct msghdr *message, int flags, double timeout) {
    auto iocp = get_instance();
    if (!iocp->associate(fd)) {
        return -1;
    }
    auto *event = new IocpEvent(SW_IOCP_SENDMSG, fd);
    event->wsabufs = make_wsabufs(message->msg_iov, static_cast<int>(message->msg_iovlen));

    int rc;
    if (message->msg_name) {
        rc = WSASendTo(fd,
                       event->wsabufs.data(),
                       static_cast<DWORD>(event->wsabufs.size()),
                       nullptr,
                       static_cast<DWORD>(flags),
                       static_cast<const sockaddr *>(message->msg_name),
                       static_cast<int>(message->msg_namelen),
                       &event->overlapped,
                       nullptr);
    } else {
        rc = WSASend(fd,
                     event->wsabufs.data(),
                     static_cast<DWORD>(event->wsabufs.size()),
                     nullptr,
                     static_cast<DWORD>(flags),
                     &event->overlapped,
                     nullptr);
    }
    if (rc == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
        set_error(WSAGetLastError());
        delete event;
        return -1;
    }
    return iocp->execute(event, timeout);
}

ssize_t Iocp::sendto(
    sw_socket_t fd, const void *buf, size_t n, int flags, const struct sockaddr *addr, socklen_t len, double timeout) {
    auto iocp = get_instance();
    if (!iocp->associate(fd)) {
        return -1;
    }
    auto *event = new IocpEvent(SW_IOCP_SENDTO, fd);
    event->wsabuf.buf = const_cast<CHAR *>(static_cast<const CHAR *>(buf));
    event->wsabuf.len = static_cast<ULONG>(n);
    if (WSASendTo(fd, &event->wsabuf, 1, nullptr, static_cast<DWORD>(flags), addr, len, &event->overlapped, nullptr) ==
            SOCKET_ERROR &&
        WSAGetLastError() != WSA_IO_PENDING) {
        set_error(WSAGetLastError());
        delete event;
        return -1;
    }
    return iocp->execute(event, timeout);
}

ssize_t Iocp::recvfrom(sw_socket_t fd, void *buf, size_t n, sockaddr *addr, socklen_t *socklen, double timeout) {
    auto iocp = get_instance();
    if (!iocp->associate(fd)) {
        return -1;
    }
    auto *event = new IocpEvent(SW_IOCP_RECVFROM, fd);
    event->wsabuf.buf = static_cast<CHAR *>(buf);
    event->wsabuf.len = static_cast<ULONG>(n);
    event->addr = addr;
    event->addrlen = socklen;
    event->addrlen_int = static_cast<int>(*socklen);
    if (WSARecvFrom(fd,
                    &event->wsabuf,
                    1,
                    nullptr,
                    &event->flags,
                    event->addr,
                    &event->addrlen_int,
                    &event->overlapped,
                    nullptr) == SOCKET_ERROR &&
        WSAGetLastError() != WSA_IO_PENDING) {
        set_error(WSAGetLastError());
        delete event;
        return -1;
    }
    return iocp->execute(event, timeout);
}

ssize_t Iocp::readv(sw_socket_t fd, const struct iovec *iovec, int count, double timeout) {
    auto iocp = get_instance();
    if (!iocp->associate(fd)) {
        return -1;
    }
    auto *event = new IocpEvent(SW_IOCP_READV, fd);
    event->wsabufs = make_wsabufs(iovec, count);
    if (WSARecv(fd,
                event->wsabufs.data(),
                static_cast<DWORD>(event->wsabufs.size()),
                nullptr,
                &event->flags,
                &event->overlapped,
                nullptr) == SOCKET_ERROR &&
        WSAGetLastError() != WSA_IO_PENDING) {
        set_error(WSAGetLastError());
        delete event;
        return -1;
    }
    return iocp->execute(event, timeout);
}

ssize_t Iocp::writev(sw_socket_t fd, const struct iovec *iovec, int count, double timeout) {
    auto iocp = get_instance();
    if (!iocp->associate(fd)) {
        return -1;
    }
    auto *event = new IocpEvent(SW_IOCP_WRITEV, fd);
    event->wsabufs = make_wsabufs(iovec, count);
    if (WSASend(fd,
                event->wsabufs.data(),
                static_cast<DWORD>(event->wsabufs.size()),
                nullptr,
                0,
                &event->overlapped,
                nullptr) == SOCKET_ERROR &&
        WSAGetLastError() != WSA_IO_PENDING) {
        set_error(WSAGetLastError());
        delete event;
        return -1;
    }
    return iocp->execute(event, timeout);
}

ssize_t Iocp::read(sw_socket_t fd, void *buf, size_t size, double timeout) {
    return recv(fd, buf, size, 0, timeout);
}

ssize_t Iocp::write(sw_socket_t fd, const void *buf, size_t size, double timeout) {
    return send(fd, buf, size, 0, timeout);
}

ssize_t Iocp::sendfile(sw_socket_t out_fd, int in_fd, off_t *offset, size_t size, double timeout) {
    if (size == 0) {
        return 0;
    }

    char buffer[SW_BUFFER_SIZE_BIG];
    size_t total = 0;
    off_t current_offset = offset ? *offset : 0;
    while (total < size) {
        size_t read_size = std::min(size - total, sizeof(buffer));
        ssize_t n = pread(in_fd, buffer, read_size, current_offset + total);
        if (n <= 0) {
            return total > 0 ? static_cast<ssize_t>(total) : -1;
        }
        ssize_t written = send(out_fd, buffer, n, 0, timeout);
        if (written <= 0) {
            return total > 0 ? static_cast<ssize_t>(total) : written;
        }
        total += written;
    }
    if (offset) {
        *offset += total;
    }
    return static_cast<ssize_t>(total);
}

int Iocp::shutdown(sw_socket_t fd, int how) {
    return ::shutdown(fd, how);
}

int Iocp::close(sw_socket_t fd) {
    return closesocket(fd);
}

int Iocp::poll(struct pollfd *fds, nfds_t nfds, int timeout) {
    if (nfds != 1) {
        errno = EINVAL;
        swoole_set_last_error(errno);
        return -1;
    }

    const double timeout_sec = timeout > 0 ? static_cast<double>(timeout) / 1000 : timeout;
    const double started = microtime();
    while (true) {
        fds[0].revents = 0;
        int retval = WSAPoll(fds, nfds, 0);
        if (retval != 0 || timeout == 0) {
            if (retval < 0) {
                set_error(WSAGetLastError());
            }
            return retval;
        }
        if (timeout > 0 && microtime() - started >= timeout_sec) {
            errno = ETIMEDOUT;
            swoole_set_last_error(errno);
            return -1;
        }
        System::sleep(0.001);
    }
}

}  // namespace swoole

#endif
