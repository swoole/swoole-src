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
#include <io.h>
#include <fcntl.h>
#ifdef realpath
#undef realpath
#endif
#include "win32/ioutil.h"

using swoole::Coroutine;
using swoole::coroutine::System;

namespace swoole {

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
    case SW_IOCP_FILE_READ:
        return "FILE_READ";
    case SW_IOCP_FILE_WRITE:
        return "FILE_WRITE";
    case SW_IOCP_CUSTOM:
        return "CUSTOM";
    default:
        return "UNKNOWN";
    }
}

IocpEvent::IocpEvent(IocpOpcode opcode_, swSocketFd fd_) : fd(fd_), opcode(opcode_) {
    memset(&overlapped, 0, sizeof(overlapped));
    handle = reinterpret_cast<HANDLE>(fd_);
}

void IocpEvent::set_result(DWORD transferred, DWORD err) {
    completed = true;
    if (err == ERROR_SUCCESS) {
        result = static_cast<ssize_t>(transferred);
        error = 0;
    } else if (!socket_event && err == ERROR_HANDLE_EOF) {
        result = 0;
        error = 0;
    } else {
        result = -1;
        if (socket_event) {
            Iocp::set_error(err);
        } else {
            Iocp::set_file_error(err);
        }
        error = errno;
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

static bool bind_connect_ex_socket(swSocketFd fd, const sockaddr *addr) {
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

void Iocp::set_file_error(DWORD error) {
    SetLastError(error);
    switch (error) {
    case ERROR_SUCCESS:
        errno = 0;
        break;
    case ERROR_FILE_NOT_FOUND:
    case ERROR_PATH_NOT_FOUND:
        errno = ENOENT;
        break;
    case ERROR_ACCESS_DENIED:
    case ERROR_SHARING_VIOLATION:
    case ERROR_LOCK_VIOLATION:
        errno = EACCES;
        break;
    case ERROR_INVALID_HANDLE:
        errno = EBADF;
        break;
    case ERROR_ALREADY_EXISTS:
    case ERROR_FILE_EXISTS:
        errno = EEXIST;
        break;
    case ERROR_HANDLE_EOF:
        errno = 0;
        break;
    case ERROR_NOT_ENOUGH_MEMORY:
    case ERROR_OUTOFMEMORY:
        errno = ENOMEM;
        break;
    default:
        errno = EIO;
        break;
    }
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
    if (!reactor || reactor->destroyed) {
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

bool Iocp::associate(swSocketFd fd) {
    if (associated_sockets.find(fd) != associated_sockets.end()) {
        return true;
    }
    if (!associate(reinterpret_cast<HANDLE>(fd), static_cast<ULONG_PTR>(fd))) {
        return false;
    }
    associated_sockets.insert(fd);
    swoole_trace_log(SW_TRACE_EVENT, "IOCP associate fd=%d", (int) fd);
    return true;
}

bool Iocp::associate(HANDLE handle, ULONG_PTR key) {
    HANDLE retval = CreateIoCompletionPort(handle, port, key, 0);
    if (retval != port) {
        set_error(GetLastError());
        return false;
    }
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
            CancelIoEx(event->handle, &event->overlapped);
            co->resume();
            return true;
        };
        event->coroutine->yield(&cancel_fn);
    }

    if (!event->completed) {
        event->orphaned = true;
        CancelIoEx(event->handle, &event->overlapped);
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

bool Iocp::dispatch(DWORD transferred, ULONG_PTR key, OVERLAPPED *overlapped, DWORD error) {
    (void) key;
    if (overlapped == nullptr) {
        return false;
    }

    auto *event = reinterpret_cast<IocpEvent *>(overlapped);
    if (event->callback) {
        event->completed = true;
        if (task_num > 0) {
            --task_num;
        }
        event->callback(event, transferred, error);
        return true;
    }

    event->set_result(transferred, error);
    swoole_trace_log(SW_TRACE_EVENT,
                     "IOCP completion opcode=%s, fd=%d, bytes=%lu, error=%lu",
                     get_opcode_name(event->opcode),
                     (int) event->fd,
                     transferred,
                     error);

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
        return true;
    }

    event->coroutine->resume();
    return true;
}

bool Iocp::wakeup() {
    DWORD transferred = 0;
    ULONG_PTR key = 0;
    OVERLAPPED *overlapped = nullptr;

    while (true) {
        BOOL ok = GetQueuedCompletionStatus(port, &transferred, &key, &overlapped, 0);
        if (!dispatch(transferred, key, overlapped, ok ? ERROR_SUCCESS : GetLastError())) {
            break;
        }
    }

    return true;
}

int Iocp::wait(int timeout_msec) {
    DWORD transferred = 0;
    ULONG_PTR key = 0;
    OVERLAPPED *overlapped = nullptr;
    DWORD timeout = timeout_msec < 0 ? INFINITE : static_cast<DWORD>(timeout_msec);
    BOOL ok = GetQueuedCompletionStatus(port, &transferred, &key, &overlapped, timeout);
    if (!ok && overlapped == nullptr) {
        DWORD error = GetLastError();
        if (error == WAIT_TIMEOUT) {
            return 0;
        }
        set_error(error);
        return -1;
    }

    return dispatch(transferred, key, overlapped, ok ? ERROR_SUCCESS : GetLastError()) ? 1 : 0;
}

int Iocp::connect(swSocketFd fd, const struct sockaddr *addr, socklen_t len, double timeout) {
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

int Iocp::accept(swSocketFd fd, struct sockaddr *addr, socklen_t *len, int flags, double timeout) {
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
    char accept_buffer[(sizeof(sockaddr_storage) + 16) * 2] = {};
    DWORD bytes = 0;
    const DWORD address_length = sizeof(sockaddr_storage) + 16;
    BOOL ok = fn_accept_ex(fd, accept_fd, accept_buffer, 0, address_length, address_length, &bytes, &event->overlapped);
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
    fn_get_accept_ex_sockaddrs(accept_buffer, 0, address_length, address_length, &local_addr, &local_len, &remote_addr, &remote_len);
    if (addr && len && remote_addr) {
        socklen_t copy_len = std::min(*len, static_cast<socklen_t>(remote_len));
        memcpy(addr, remote_addr, copy_len);
        *len = copy_len;
    }

    return static_cast<int>(accept_fd);
}

ssize_t Iocp::recv(swSocketFd fd, void *buf, size_t len, int flags, double timeout) {
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

ssize_t Iocp::send(swSocketFd fd, const void *buf, size_t len, int flags, double timeout) {
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

ssize_t Iocp::recvmsg(swSocketFd fd, struct msghdr *message, int flags, double timeout) {
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

ssize_t Iocp::sendmsg(swSocketFd fd, const struct msghdr *message, int flags, double timeout) {
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
    swSocketFd fd, const void *buf, size_t n, int flags, const struct sockaddr *addr, socklen_t len, double timeout) {
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

ssize_t Iocp::recvfrom(swSocketFd fd, void *buf, size_t n, sockaddr *addr, socklen_t *socklen, double timeout) {
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

ssize_t Iocp::readv(swSocketFd fd, const struct iovec *iovec, int count, double timeout) {
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

ssize_t Iocp::writev(swSocketFd fd, const struct iovec *iovec, int count, double timeout) {
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

ssize_t Iocp::read(swSocketFd fd, void *buf, size_t size, double timeout) {
    return recv(fd, buf, size, 0, timeout);
}

ssize_t Iocp::write(swSocketFd fd, const void *buf, size_t size, double timeout) {
    return send(fd, buf, size, 0, timeout);
}

static bool get_file_handle(int fd, HANDLE *handle) {
    auto h = reinterpret_cast<HANDLE>(_get_osfhandle(fd));
    if (h == INVALID_HANDLE_VALUE) {
        errno = EBADF;
        swoole_set_last_error(errno);
        return false;
    }
    *handle = h;
    return true;
}

static bool get_file_offset(HANDLE handle, uint64_t *offset, bool append) {
    LARGE_INTEGER pos = {};
    if (append) {
        if (!GetFileSizeEx(handle, &pos)) {
            Iocp::set_file_error(GetLastError());
            return false;
        }
    } else {
        LARGE_INTEGER zero = {};
        if (!SetFilePointerEx(handle, zero, &pos, FILE_CURRENT)) {
            Iocp::set_file_error(GetLastError());
            return false;
        }
    }
    *offset = static_cast<uint64_t>(pos.QuadPart);
    return true;
}

static void set_file_offset(HANDLE handle, uint64_t offset) {
    LARGE_INTEGER pos = {};
    pos.QuadPart = static_cast<LONGLONG>(offset);
    if (!SetFilePointerEx(handle, pos, nullptr, FILE_BEGIN)) {
        Iocp::set_file_error(GetLastError());
    }
}

int Iocp::open_file(const char *pathname, int flags, mode_t mode) {
    php_ioutil_open_opts open_opts;
    if (!php_win32_ioutil_posix_to_open_opts(flags, mode, &open_opts)) {
        return -1;
    }

    wchar_t *pathw = php_win32_ioutil_any_to_w(pathname);
    if (!pathw) {
        set_file_error(ERROR_INVALID_PARAMETER);
        return -1;
    }
    if (!PHP_WIN32_IOUTIL_PATH_IS_OK_W(pathw, wcslen(pathw))) {
        free(pathw);
        set_file_error(ERROR_ACCESS_DENIED);
        return -1;
    }

    open_opts.attributes |= FILE_FLAG_OVERLAPPED;
    HANDLE file = CreateFileW(pathw, open_opts.access, open_opts.share, nullptr, open_opts.disposition, open_opts.attributes, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        free(pathw);
        if (error == ERROR_FILE_EXISTS && (flags & _O_CREAT) && !(flags & _O_EXCL)) {
            errno = EISDIR;
            swoole_set_last_error(errno);
        } else {
            set_file_error(error);
        }
        return -1;
    }
    free(pathw);

    int fd = _open_osfhandle(reinterpret_cast<intptr_t>(file), flags);
    if (fd < 0) {
        CloseHandle(file);
        swoole_set_last_error(errno);
        return -1;
    }
    if (flags & _O_TEXT) {
        _setmode(fd, _O_TEXT);
    } else if (flags & _O_BINARY) {
        _setmode(fd, _O_BINARY);
    }

    auto iocp = get_instance();
    if (!iocp) {
        _close(fd);
        return -1;
    }
    iocp->file_flags[fd] = flags;
    swoole_trace_log(SW_TRACE_AIO, "IOCP file open fd=%d, path=%s, flags=%d", fd, pathname, flags);
    return fd;
}

int Iocp::close_file(int fd) {
    if (SwooleTG.iocp) {
        SwooleTG.iocp->associated_files.erase(fd);
        SwooleTG.iocp->file_flags.erase(fd);
    }
    swoole_trace_log(SW_TRACE_AIO, "IOCP file close fd=%d", fd);
    return _close(fd);
}

ssize_t Iocp::read_file(int fd, void *buf, size_t size, double timeout) {
    if (size == 0) {
        return 0;
    }
    if (size > UINT_MAX) {
        size = UINT_MAX;
    }

    auto iocp = get_instance();
    if (!iocp) {
        return -1;
    }

    HANDLE handle;
    if (!get_file_handle(fd, &handle)) {
        return -1;
    }
    if (iocp->associated_files.find(fd) == iocp->associated_files.end()) {
        if (!iocp->associate(handle, static_cast<ULONG_PTR>(fd))) {
            set_file_error(GetLastError());
            return -1;
        }
        iocp->associated_files.insert(fd);
        swoole_trace_log(SW_TRACE_AIO, "IOCP associate file fd=%d", fd);
    }

    uint64_t offset = 0;
    if (!get_file_offset(handle, &offset, false)) {
        return -1;
    }

    auto *event = new IocpEvent(SW_IOCP_FILE_READ, static_cast<swSocketFd>(fd));
    event->socket_event = false;
    event->handle = handle;
    event->overlapped.Offset = static_cast<DWORD>(offset & 0xffffffff);
    event->overlapped.OffsetHigh = static_cast<DWORD>(offset >> 32);

    if (!ReadFile(handle, buf, static_cast<DWORD>(size), nullptr, &event->overlapped)) {
        DWORD error = GetLastError();
        if (error == ERROR_HANDLE_EOF) {
            delete event;
            return 0;
        }
        if (error != ERROR_IO_PENDING) {
            set_file_error(error);
            delete event;
            return -1;
        }
    }

    ssize_t n = iocp->execute(event, timeout);
    if (n >= 0) {
        set_file_offset(handle, offset + static_cast<uint64_t>(n));
    }
    return n;
}

ssize_t Iocp::write_file(int fd, const void *buf, size_t size, double timeout) {
    if (size == 0) {
        return 0;
    }
    if (size > UINT_MAX) {
        size = UINT_MAX;
    }

    auto iocp = get_instance();
    if (!iocp) {
        return -1;
    }

    HANDLE handle;
    if (!get_file_handle(fd, &handle)) {
        return -1;
    }
    if (iocp->associated_files.find(fd) == iocp->associated_files.end()) {
        if (!iocp->associate(handle, static_cast<ULONG_PTR>(fd))) {
            set_file_error(GetLastError());
            return -1;
        }
        iocp->associated_files.insert(fd);
        swoole_trace_log(SW_TRACE_AIO, "IOCP associate file fd=%d", fd);
    }

    const auto flags_iter = iocp->file_flags.find(fd);
    const bool append = flags_iter != iocp->file_flags.end() && (flags_iter->second & _O_APPEND);
    uint64_t offset = 0;
    if (!get_file_offset(handle, &offset, append)) {
        return -1;
    }

    auto *event = new IocpEvent(SW_IOCP_FILE_WRITE, static_cast<swSocketFd>(fd));
    event->socket_event = false;
    event->handle = handle;
    event->overlapped.Offset = static_cast<DWORD>(offset & 0xffffffff);
    event->overlapped.OffsetHigh = static_cast<DWORD>(offset >> 32);

    if (!WriteFile(handle, buf, static_cast<DWORD>(size), nullptr, &event->overlapped)) {
        DWORD error = GetLastError();
        if (error != ERROR_IO_PENDING) {
            set_file_error(error);
            delete event;
            return -1;
        }
    }

    ssize_t n = iocp->execute(event, timeout);
    if (n >= 0) {
        set_file_offset(handle, offset + static_cast<uint64_t>(n));
    }
    return n;
}

ssize_t Iocp::sendfile(swSocketFd out_fd, int in_fd, off_t *offset, size_t size, double timeout) {
    if (size == 0) {
        return 0;
    }

    char buffer[SW_BUFFER_SIZE_BIG];
    size_t total = 0;
    off_t current_offset = offset ? *offset : 0;
    while (total < size) {
        size_t read_size = std::min(size - total, sizeof(buffer));
        ssize_t n = sw_pread(in_fd, buffer, read_size, current_offset + total);
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

int Iocp::shutdown(swSocketFd fd, int how) {
    return ::shutdown(fd, how);
}

int Iocp::close(swSocketFd fd) {
    if (SwooleTG.iocp) {
        SwooleTG.iocp->associated_sockets.erase(fd);
    }
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
