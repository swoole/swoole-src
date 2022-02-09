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
  | @author   Tianfeng Han  <mikan.tenny@gmail.com>                      |
  +----------------------------------------------------------------------+
*/

#include "swoole_string.h"
#include "swoole_util.h"
#include "swoole_reactor.h"
#include "swoole_buffer.h"
#include "swoole_base64.h"

#include "swoole_coroutine_socket.h"
#include "swoole_coroutine_system.h"

namespace swoole {
namespace coroutine {

enum Socket::TimeoutType Socket::timeout_type_list[4] = {TIMEOUT_DNS, TIMEOUT_CONNECT, TIMEOUT_READ, TIMEOUT_WRITE};

void Socket::timer_callback(Timer *timer, TimerNode *tnode) {
    Socket *socket = (Socket *) tnode->data;
    socket->set_err(ETIMEDOUT);
    if (sw_likely(tnode == socket->read_timer)) {
        socket->read_timer = nullptr;
        socket->read_co->resume();
    } else if (tnode == socket->write_timer) {
        socket->write_timer = nullptr;
        socket->write_co->resume();
    } else {
        abort();
    }
}

int Socket::readable_event_callback(Reactor *reactor, Event *event) {
    Socket *socket = (Socket *) event->socket->object;
    socket->set_err(0);
#ifdef SW_USE_OPENSSL
    if (sw_unlikely(socket->want_event != SW_EVENT_NULL)) {
        if (socket->want_event == SW_EVENT_READ) {
            socket->write_co->resume();
        }
    } else
#endif
    {
        if (socket->recv_barrier && (*socket->recv_barrier)() && !event->socket->event_hup) {
            return SW_OK;
        }
        socket->read_co->resume();
    }

    return SW_OK;
}

int Socket::writable_event_callback(Reactor *reactor, Event *event) {
    Socket *socket = (Socket *) event->socket->object;
    socket->set_err(0);
#ifdef SW_USE_OPENSSL
    if (sw_unlikely(socket->want_event != SW_EVENT_NULL)) {
        if (socket->want_event == SW_EVENT_WRITE) {
            socket->read_co->resume();
        }
    } else
#endif
    {
        if (socket->send_barrier && (*socket->send_barrier)() && !event->socket->event_hup) {
            return SW_OK;
        }
        socket->write_co->resume();
    }

    return SW_OK;
}

int Socket::error_event_callback(Reactor *reactor, Event *event) {
    Socket *socket = (Socket *) event->socket->object;
    if (socket->write_co) {
        socket->set_err(0);
        socket->write_co->resume();
    }
    // Notice: socket maybe deleted in write coroutine
    if (event->socket->object == socket && !event->socket->removed && socket->read_co) {
        socket->set_err(0);
        socket->read_co->resume();
    }
    return SW_OK;
}

bool Socket::add_event(const EventType event) {
    bool ret = true;
    if (sw_likely(!(socket->events & event))) {
        if (socket->removed) {
            ret = swoole_event_add(socket, event) == SW_OK;
        } else {
            ret = swoole_event_set(socket, socket->events | event) == SW_OK;
        }
    }
    set_err(ret ? 0 : errno);
    return ret;
}

/**
 * If an exception occurs while waiting for an event, false is returned.
 * For example, when waiting for a read event, timeout, connection closed, are exceptions to the interrupt event.
 * And these exceptions will actively set the errCode, We don't need to set the exception's errCode ourselves.
 * We only need to set the errCode for the socket operation when wait_event returns true,
 * which means that the exception's error code priority is greater than the current event error priority.
 */
bool Socket::wait_event(const EventType event, const void **__buf, size_t __n) {
    EventType added_event = event;
    Coroutine *co = Coroutine::get_current_safe();
    if (!co) {
        return false;
    }

    // clear the last errCode
    set_err(0);
#ifdef SW_USE_OPENSSL
    if (sw_unlikely(socket->ssl && ((event == SW_EVENT_READ && socket->ssl_want_write) ||
                                    (event == SW_EVENT_WRITE && socket->ssl_want_read)))) {
        if (sw_likely(socket->ssl_want_write && add_event(SW_EVENT_WRITE))) {
            want_event = SW_EVENT_WRITE;
        } else if (socket->ssl_want_read && add_event(SW_EVENT_READ)) {
            want_event = SW_EVENT_READ;
        } else {
            return false;
        }
        added_event = want_event;
    } else
#endif
        if (sw_unlikely(!add_event(event))) {
        return false;
    }
    swoole_trace_log(SW_TRACE_SOCKET,
                     "socket#%d blongs to cid#%ld is waiting for %s event",
                     sock_fd,
                     co->get_cid(),
#ifdef SW_USE_OPENSSL
                     socket->ssl_want_read ? "SSL READ"
                                           : socket->ssl_want_write ? "SSL WRITE" :
#endif
                                                                    event == SW_EVENT_READ ? "READ" : "WRITE");

    Coroutine::CancelFunc cancel_fn = [this, event](Coroutine *co) { return cancel(event); };

    if (sw_likely(event == SW_EVENT_READ)) {
        read_co = co;
        read_co->yield(&cancel_fn);
        read_co = nullptr;
    } else if (event == SW_EVENT_WRITE) {
        if (sw_unlikely(!zero_copy && __n > 0 && *__buf != get_write_buffer()->str)) {
            write_buffer->clear();
            if (write_buffer->append((const char *) *__buf, __n) != SW_OK) {
                set_err(ENOMEM);
                goto _failed;
            }
            *__buf = write_buffer->str;
        }
        write_co = co;
        write_co->yield(&cancel_fn);
        write_co = nullptr;
    } else {
        assert(0);
        return false;
    }
_failed:
#ifdef SW_USE_OPENSSL
    // maybe read_co and write_co are all waiting for the same event when we use SSL
    if (sw_likely(want_event == SW_EVENT_NULL || !has_bound()))
#endif
    {
        Reactor *reactor = SwooleTG.reactor;
        if (sw_likely(added_event == SW_EVENT_READ)) {
            reactor->remove_read_event(socket);
        } else {
            reactor->remove_write_event(socket);
        }
    }
#ifdef SW_USE_OPENSSL
    want_event = SW_EVENT_NULL;
#endif
    swoole_trace_log(SW_TRACE_SOCKET,
                     "socket#%d blongs to cid#%ld trigger %s event",
                     sock_fd,
                     co->get_cid(),
                     closed ? "CLOSE"
                            : errCode ? errCode == ETIMEDOUT ? "TIMEOUT" : "ERROR"
                                      : added_event == SW_EVENT_READ ? "READ" : "WRITE");
    return !closed && !errCode;
}

bool Socket::socks5_handshake() {
    Socks5Proxy *ctx = socks5_proxy;
    char *p;
    ssize_t n;
    uchar version, method, result;

    Socks5Proxy::pack(ctx->buf, !socks5_proxy->username.empty() ? 0x02 : 0x00);
    socks5_proxy->state = SW_SOCKS5_STATE_HANDSHAKE;
    if (send(ctx->buf, 3) != 3) {
        return false;
    }
    n = recv(ctx->buf, sizeof(ctx->buf));
    if (n <= 0) {
        return false;
    }
    version = ctx->buf[0];
    method = ctx->buf[1];
    if (version != SW_SOCKS5_VERSION_CODE) {
        swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SOCKS5_UNSUPPORT_VERSION, "SOCKS version is not supported");
        return false;
    }
    if (method != ctx->method) {
        swoole_error_log(
            SW_LOG_NOTICE, SW_ERROR_SOCKS5_UNSUPPORT_METHOD, "SOCKS authentication method is not supported");
        return false;
    }
    // authentication
    if (method == SW_SOCKS5_METHOD_AUTH) {
        p = ctx->buf;
        // username
        p[0] = 0x01;
        p[1] = ctx->username.length();
        p += 2;
        if (!ctx->username.empty()) {
            memcpy(p, ctx->username.c_str(), ctx->username.length());
            p += ctx->username.length();
        }
        // password
        p[0] = ctx->password.length();
        p += 1;
        if (!ctx->password.empty()) {
            memcpy(p, ctx->password.c_str(), ctx->password.length());
            p += ctx->password.length();
        }
        // auth request
        ctx->state = SW_SOCKS5_STATE_AUTH;
        if (send(ctx->buf, p - ctx->buf) != p - ctx->buf) {
            return false;
        }
        // auth response
        n = recv(ctx->buf, sizeof(ctx->buf));
        if (n <= 0) {
            return false;
        }
        uchar version = ctx->buf[0];
        uchar status = ctx->buf[1];
        if (version != 0x01) {
            swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SOCKS5_UNSUPPORT_VERSION, "SOCKS version is not supported");
            return false;
        }
        if (status != 0x00) {
            swoole_error_log(
                SW_LOG_NOTICE, SW_ERROR_SOCKS5_AUTH_FAILED, "SOCKS username/password authentication failed");
            return false;
        }
    }

    // send connect request
    ctx->state = SW_SOCKS5_STATE_CONNECT;
    p = ctx->buf;
    p[0] = SW_SOCKS5_VERSION_CODE;
    p[1] = 0x01;
    p[2] = 0x00;
    p += 3;
    if (ctx->dns_tunnel) {
        p[0] = 0x03;
        p[1] = ctx->target_host.length();
        p += 2;
        memcpy(p, ctx->target_host.c_str(), ctx->target_host.length());
        p += ctx->target_host.length();
        *(uint16_t *) p = htons(ctx->target_port);
        p += 2;
        if (send(ctx->buf, p - ctx->buf) != p - ctx->buf) {
            return false;
        }
    } else {
        p[0] = 0x01;
        p += 1;
        *(uint32_t *) p = htons(ctx->target_host.length());
        p += 4;
        *(uint16_t *) p = htons(ctx->target_port);
        p += 2;
        if (send(ctx->buf, p - ctx->buf) != p - ctx->buf) {
            return false;
        }
    }
    // recv response
    n = recv(ctx->buf, sizeof(ctx->buf));
    if (n <= 0) {
        return false;
    }
    version = ctx->buf[0];
    if (version != SW_SOCKS5_VERSION_CODE) {
        swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SOCKS5_UNSUPPORT_VERSION, "SOCKS version is not supported");
        return false;
    }
    result = ctx->buf[1];
#if 0
    uchar reg = buf[2];
    uchar type = buf[3];
    uint32_t ip = *(uint32_t *) (buf + 4);
    uint16_t port = *(uint16_t *) (buf + 8);
#endif
    if (result == 0) {
        ctx->state = SW_SOCKS5_STATE_READY;
        return true;
    } else {
        swoole_error_log(SW_LOG_NOTICE,
                         SW_ERROR_SOCKS5_SERVER_ERROR,
                         "Socks5 server error, reason: %s",
                         Socks5Proxy::strerror(result));
        return false;
    }
}

bool Socket::http_proxy_handshake() {
#define HTTP_PROXY_FMT                                                                                                 \
    "CONNECT %.*s:%d HTTP/1.1\r\n"                                                                                     \
    "Host: %.*s:%d\r\n"                                                                                                \
    "User-Agent: Swoole/" SWOOLE_VERSION "\r\n"                                                                        \
    "Proxy-Connection: Keep-Alive\r\n"

    // CONNECT
    int n;
    const char *host = http_proxy->target_host.c_str();
    int host_len = http_proxy->target_host.length();
#ifdef SW_USE_OPENSSL
    if (ssl_context && !ssl_context->tls_host_name.empty()) {
        host = ssl_context->tls_host_name.c_str();
        host_len = ssl_context->tls_host_name.length();
    }
#endif

    String *send_buffer = get_write_buffer();
    ON_SCOPE_EXIT {
        send_buffer->clear();
    };

    if (!http_proxy->password.empty()) {
        auto auth_str = http_proxy->get_auth_str();
        n = sw_snprintf(send_buffer->str,
                        send_buffer->size,
                        HTTP_PROXY_FMT "Proxy-Authorization: Basic %s\r\n\r\n",
                        (int) http_proxy->target_host.length(),
                        http_proxy->target_host.c_str(),
                        http_proxy->target_port,
                        host_len,
                        host,
                        http_proxy->target_port,
                        auth_str.c_str());
    } else {
        n = sw_snprintf(send_buffer->str,
                        send_buffer->size,
                        HTTP_PROXY_FMT "\r\n",
                        (int) http_proxy->target_host.length(),
                        http_proxy->target_host.c_str(),
                        http_proxy->target_port,
                        host_len,
                        host,
                        http_proxy->target_port);
    }

    swoole_trace_log(SW_TRACE_HTTP_CLIENT, "proxy request: <<EOF\n%.*sEOF", n, send_buffer->str);

    send_buffer->length = n;
    if (send(send_buffer->str, n) != n) {
        return false;
    }

    String *recv_buffer = get_read_buffer();
    ON_SCOPE_EXIT {
        recv_buffer->clear();
    };

    ProtocolSwitch ps(this);
    open_eof_check = true;
    open_length_check = false;
    protocol.package_eof_len = sizeof("\r\n\r\n") - 1;
    memcpy(protocol.package_eof, SW_STRS("\r\n\r\n"));

    n = recv_packet();
    if (n <= 0) {
        return false;
    }

    swoole_trace_log(SW_TRACE_HTTP_CLIENT, "proxy response: <<EOF\n%.*sEOF", n, recv_buffer->str);

    bool ret = false;
    char *buf = recv_buffer->str;
    int len = n;
    int state = 0;
    char *p = buf;
    char *pe = buf + len;
    for (; p < buf + len; p++) {
        if (state == 0) {
            if (SW_STRCASECT(p, pe - p, "HTTP/1.1") || SW_STRCASECT(p, pe - p, "HTTP/1.0")) {
                state = 1;
                p += sizeof("HTTP/1.x") - 1;
            } else {
                break;
            }
        } else if (state == 1) {
            if (isspace(*p)) {
                continue;
            } else {
                if (SW_STRCASECT(p, pe - p, "200")) {
                    state = 2;
                    p += sizeof("200") - 1;
                } else {
                    break;
                }
            }
        } else if (state == 2) {
            ret = true;
            break;
#if 0
            if (isspace(*p)) {
                continue;
            } else {
                if (SW_STRCASECT(p, pe - p, "Connection established")) {
                    ret = true;
                }
                break;
            }
#endif
        }
    }

    if (!ret) {
        set_err(SW_ERROR_HTTP_PROXY_BAD_RESPONSE,
                std::string("wrong http_proxy response received, \n[Request]: ") + send_buffer->to_std_string() +
                    "\n[Response]: " + std::string(buf, len));
    }

    return ret;
}

void Socket::init_sock_type(SocketType _sw_type) {
    type = _sw_type;
    network::Socket::get_domain_and_type(_sw_type, &sock_domain, &sock_type);
}

bool Socket::init_sock() {
    socket = make_socket(type, SW_FD_CO_SOCKET, SW_SOCK_CLOEXEC | SW_SOCK_NONBLOCK);
    if (socket == nullptr) {
        return false;
    }
    sock_fd = socket->fd;
    socket->object = this;
    socket->info.type = type;
    return true;
}

bool Socket::init_reactor_socket(int _fd) {
    socket = swoole::make_socket(_fd, SW_FD_CO_SOCKET);
    sock_fd = _fd;
    socket->object = this;
    socket->socket_type = type;
    socket->nonblock = 1;
    socket->cloexec = 1;
    socket->info.type = type;
    return true;
}

Socket::Socket(int _domain, int _type, int _protocol)
    : sock_domain(_domain), sock_type(_type), sock_protocol(_protocol) {
    type = network::Socket::convert_to_type(_domain, _type, _protocol);
    if (sw_unlikely(!init_sock())) {
        return;
    }
    init_options();
}

Socket::Socket(SocketType _type) {
    init_sock_type(_type);
    if (sw_unlikely(!init_sock())) {
        return;
    }
    init_options();
}

Socket::Socket(int _fd, SocketType _type) {
    init_sock_type(_type);
    if (sw_unlikely(!init_reactor_socket(_fd))) {
        return;
    }
    socket->set_nonblock();
    init_options();
}

Socket::Socket(int _fd, int _domain, int _type, int _protocol)
    : sock_domain(_domain), sock_type(_type), sock_protocol(_protocol) {
    type = network::Socket::convert_to_type(_domain, _type, _protocol);
    if (sw_unlikely(!init_reactor_socket(_fd))) {
        return;
    }
    socket->set_nonblock();
    init_options();
}

/**
 * Only used as accept member method
 */
Socket::Socket(network::Socket *sock, Socket *server_sock) {
    type = server_sock->type;
    sock_domain = server_sock->sock_domain;
    sock_type = server_sock->sock_type;
    sock_protocol = server_sock->sock_protocol;
    sock_fd = sock->fd;
    socket = sock;
    socket->object = this;
    socket->socket_type = type;
    socket->fd_type = SW_FD_CO_SOCKET;
    init_options();
    /* inherits server socket options */
    dns_timeout = server_sock->dns_timeout;
    connect_timeout = server_sock->connect_timeout;
    read_timeout = server_sock->read_timeout;
    write_timeout = server_sock->write_timeout;
    open_length_check = server_sock->open_length_check;
    open_eof_check = server_sock->open_eof_check;
    http2 = server_sock->http2;
    protocol = server_sock->protocol;
    connected = true;
#ifdef SW_USE_OPENSSL
    ssl_context = server_sock->ssl_context;
    ssl_is_server = server_sock->ssl_is_server;
    if (server_sock->ssl_is_enable() && !ssl_create(server_sock->get_ssl_context())) {
        close();
    }
#endif
}

bool Socket::getsockname(network::Address *sa) {
    sa->len = sizeof(sa->addr);
    if (::getsockname(sock_fd, (struct sockaddr *) &sa->addr, &sa->len) != 0) {
        set_err(errno);
        return false;
    }
    sa->type = type;
    return true;
}

bool Socket::getpeername(network::Address *sa) {
    sa->len = sizeof(sa->addr);
    if (::getpeername(sock_fd, (struct sockaddr *) &sa->addr, &sa->len) != 0) {
        set_err(errno);
        return false;
    }
    sa->type = type;
    return true;
}

bool Socket::connect(const struct sockaddr *addr, socklen_t addrlen) {
    if (sw_unlikely(!is_available(SW_EVENT_RDWR))) {
        return false;
    }
    int retval;
    do {
        retval = ::connect(sock_fd, addr, addrlen);
    } while (retval < 0 && errno == EINTR);
    if (retval < 0) {
        if (errno != EINPROGRESS) {
            set_err(errno);
            return false;
        } else {
            TimerController timer(&write_timer, connect_timeout, this, timer_callback);
            if (!timer.start() || !wait_event(SW_EVENT_WRITE)) {
                if (closed) {
                    set_err(ECONNABORTED);
                }
                return false;
            } else {
                if (socket->get_option(SOL_SOCKET, SO_ERROR, &errCode) < 0 || errCode != 0) {
                    set_err(errCode);
                    return false;
                }
            }
        }
    }
    connected = true;
    set_err(0);
    return true;
}

bool Socket::connect(std::string _host, int _port, int flags) {
    if (sw_unlikely(!is_available(SW_EVENT_RDWR))) {
        return false;
    }

#ifdef SW_USE_OPENSSL
    if (ssl_context && (socks5_proxy || http_proxy)) {
        /* If the proxy is enabled, the host will be replaced with the proxy ip,
         * so we have to handle the host first,
         * if the host is not a ip, assign it to ssl_host_name
         */
        union {
            struct in_addr sin;
            struct in6_addr sin6;
        } addr;
        if ((sock_domain == AF_INET && !inet_pton(AF_INET, _host.c_str(), &addr.sin)) ||
            (sock_domain == AF_INET6 && !inet_pton(AF_INET6, _host.c_str(), &addr.sin6))) {
            ssl_host_name = _host;
        }
    }
#endif
    if (socks5_proxy) {
        socks5_proxy->target_host = _host;
        socks5_proxy->target_port = _port;

        _host = socks5_proxy->host;
        _port = socks5_proxy->port;
    } else if (http_proxy) {
        http_proxy->target_host = _host;
        http_proxy->target_port = _port;

        _host = http_proxy->proxy_host;
        _port = http_proxy->proxy_port;
    }

    if (sock_domain == AF_INET6 || sock_domain == AF_INET) {
        if (_port == -1) {
            set_err(EINVAL, "Socket of type AF_INET/AF_INET6 requires port argument");
            return false;
        } else if (_port == 0 || _port >= 65536) {
            set_err(EINVAL, std_string::format("Invalid port [%d]", _port));
            return false;
        }
    }

    connect_host = _host;
    connect_port = _port;

    struct sockaddr *_target_addr = nullptr;

    for (int i = 0; i < 2; i++) {
        if (sock_domain == AF_INET) {
            socket->info.addr.inet_v4.sin_family = AF_INET;
            socket->info.addr.inet_v4.sin_port = htons(_port);

            if (!inet_pton(AF_INET, connect_host.c_str(), &socket->info.addr.inet_v4.sin_addr)) {
#ifdef SW_USE_OPENSSL
                if (ssl_context && !(socks5_proxy || http_proxy)) {
                    ssl_host_name = connect_host;
                }
#endif
                /* locked like wait_event */
                read_co = write_co = Coroutine::get_current_safe();
                connect_host = System::gethostbyname(connect_host, AF_INET, dns_timeout);
                read_co = write_co = nullptr;
                if (connect_host.empty()) {
                    set_err(swoole_get_last_error(), swoole_strerror(swoole_get_last_error()));
                    return false;
                }
                continue;
            } else {
                socket->info.len = sizeof(socket->info.addr.inet_v4);
                _target_addr = (struct sockaddr *) &socket->info.addr.inet_v4;
                break;
            }
        } else if (sock_domain == AF_INET6) {
            socket->info.addr.inet_v6.sin6_family = AF_INET6;
            socket->info.addr.inet_v6.sin6_port = htons(_port);

            if (!inet_pton(AF_INET6, connect_host.c_str(), &socket->info.addr.inet_v6.sin6_addr)) {
#ifdef SW_USE_OPENSSL
                if (ssl_context && !(socks5_proxy || http_proxy)) {
                    ssl_host_name = connect_host;
                }
#endif
                connect_host = System::gethostbyname(connect_host, AF_INET6, dns_timeout);
                if (connect_host.empty()) {
                    set_err(swoole_get_last_error());
                    return false;
                }
                continue;
            } else {
                socket->info.len = sizeof(socket->info.addr.inet_v6);
                _target_addr = (struct sockaddr *) &socket->info.addr.inet_v6;
                break;
            }
        } else if (sock_domain == AF_UNIX) {
            if (connect_host.size() >= sizeof(socket->info.addr.un.sun_path)) {
                set_err(EINVAL, "unix socket file is too large");
                return false;
            }
            socket->info.addr.un.sun_family = AF_UNIX;
            memcpy(&socket->info.addr.un.sun_path, connect_host.c_str(), connect_host.size());
            socket->info.len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + connect_host.size());
            _target_addr = (struct sockaddr *) &socket->info.addr.un;
            break;
        } else {
            set_err(EINVAL, "unknown protocol[%d]");
            return false;
        }
    }
    if (_target_addr == nullptr) {
        set_err(EINVAL, "bad target host");
        return false;
    }
    if (connect(_target_addr, socket->info.len) == false) {
        return false;
    }

    // socks5 proxy
    if (socks5_proxy && socks5_handshake() == false) {
        if (errCode == 0) {
            set_err(SW_ERROR_SOCKS5_HANDSHAKE_FAILED);
        }
        return false;
    }
    // http proxy
    if (http_proxy && !http_proxy->dont_handshake && http_proxy_handshake() == false) {
        if (errCode == 0) {
            set_err(SW_ERROR_HTTP_PROXY_HANDSHAKE_FAILED);
        }
        return false;
    }
#ifdef SW_USE_OPENSSL
    ssl_is_server = false;
    if (ssl_context) {
        if (!ssl_handshake()) {
            if (errCode == 0) {
                set_err(SW_ERROR_SSL_HANDSHAKE_FAILED);
            }
            return false;
        }
    }
#endif
    return true;
}

bool Socket::check_liveness() {
    if (closed) {
        set_err(ECONNRESET);
        return false;
    }
    if (!socket->check_liveness()) {
        set_err(errno ? errno : ECONNRESET);
        return false;
    }
    set_err(0);
    return true;
}

ssize_t Socket::peek(void *__buf, size_t __n) {
    ssize_t retval = socket->peek(__buf, __n, 0);
    check_return_value(retval);
    return retval;
}

bool Socket::poll(EventType type) {
    if (sw_unlikely(!is_available(type))) {
        return -1;
    }
    TimerController timer(&read_timer, read_timeout, this, timer_callback);
    if (timer.start() && wait_event(type)) {
        return true;
    } else {
        return false;
    }
}

ssize_t Socket::recv(void *__buf, size_t __n) {
    if (sw_unlikely(!is_available(SW_EVENT_READ))) {
        return -1;
    }
    ssize_t retval;
    TimerController timer(&read_timer, read_timeout, this, timer_callback);
    do {
        retval = socket->recv(__buf, __n, 0);
    } while (retval < 0 && socket->catch_read_error(errno) == SW_WAIT && timer.start() && wait_event(SW_EVENT_READ));
    check_return_value(retval);
    return retval;
}

ssize_t Socket::send(const void *__buf, size_t __n) {
    if (sw_unlikely(!is_available(SW_EVENT_WRITE))) {
        return -1;
    }
    ssize_t retval;
    TimerController timer(&write_timer, write_timeout, this, timer_callback);
    do {
        retval = socket->send(__buf, __n, 0);
    } while (retval < 0 && socket->catch_write_error(errno) == SW_WAIT && timer.start() &&
             wait_event(SW_EVENT_WRITE, &__buf, __n));
    check_return_value(retval);
    return retval;
}

ssize_t Socket::read(void *__buf, size_t __n) {
    if (sw_unlikely(!is_available(SW_EVENT_READ))) {
        return -1;
    }
    ssize_t retval;
    TimerController timer(&read_timer, read_timeout, this, timer_callback);
    do {
        retval = socket->read(__buf, __n);
    } while (retval < 0 && socket->catch_read_error(errno) == SW_WAIT && timer.start() && wait_event(SW_EVENT_READ));
    check_return_value(retval);
    return retval;
}

ssize_t Socket::recv_line(void *__buf, size_t maxlen) {
    size_t n = 0;
    ssize_t m = 0;
    char *t = (char *) __buf;

    *t = '\0';
    while (*t != '\n' && *t != '\r' && n < maxlen) {
        if (m > 0) {
            t++;
            n++;
        }
        if (n < maxlen) {
            m = recv_with_buffer((void *) t, 1);
            if (m < 0) {
                return -1;
            } else if (m == 0) {
                return n > 0 ? n : 0;
            }
        }
    }
    if (n < maxlen) {
        n++;
    }
    return n;
}

ssize_t Socket::recv_with_buffer(void *__buf, size_t __n) {
    if (sw_unlikely(!is_available(SW_EVENT_READ))) {
        return -1;
    }

    String *buffer = get_read_buffer();
    size_t buffer_bytes = buffer->length - buffer->offset;

    if (__n <= buffer_bytes) {
        memcpy(__buf, buffer->str + buffer->offset, __n);
        buffer->offset += __n;
        return __n;
    }

    if (buffer_bytes > 0) {
        memcpy(__buf, buffer->str + buffer->offset, buffer_bytes);
        buffer->offset += buffer_bytes;
    }

    if ((size_t) buffer->offset >= buffer->size / 2) {
        buffer->reduce(buffer->offset);
    }

    ssize_t retval = recv(buffer->str + buffer->length, buffer->size - buffer->length);
    if (retval <= 0) {
        return buffer_bytes > 0 ? buffer_bytes : retval;
    }

    buffer->length += retval;
    size_t copy_bytes = SW_MIN(__n - buffer_bytes, buffer->length - buffer->offset);
    memcpy((char *) __buf + buffer_bytes, buffer->str + buffer->offset, copy_bytes);
    buffer->offset += copy_bytes;

    return buffer_bytes + copy_bytes;
}

ssize_t Socket::write(const void *__buf, size_t __n) {
    if (sw_unlikely(!is_available(SW_EVENT_WRITE))) {
        return -1;
    }
    ssize_t retval;
    TimerController timer(&write_timer, write_timeout, this, timer_callback);
    do {
        retval = socket->write((void *) __buf, __n);
    } while (retval < 0 && socket->catch_write_error(errno) == SW_WAIT && timer.start() &&
             wait_event(SW_EVENT_WRITE, &__buf, __n));
    check_return_value(retval);
    return retval;
}

ssize_t Socket::readv(network::IOVector *io_vector) {
    if (sw_unlikely(!is_available(SW_EVENT_READ))) {
        return -1;
    }
    ssize_t retval;
    TimerController timer(&read_timer, read_timeout, this, timer_callback);
    do {
        retval = socket->readv(io_vector);
    } while (retval < 0 && socket->catch_read_error(errno) == SW_WAIT && timer.start() && wait_event(SW_EVENT_READ));
    check_return_value(retval);

    return retval;
}

ssize_t Socket::readv_all(network::IOVector *io_vector) {
    if (sw_unlikely(!is_available(SW_EVENT_READ))) {
        return -1;
    }
    ssize_t retval, total_bytes = 0;
    TimerController timer(&read_timer, read_timeout, this, timer_callback);

    retval = socket->readv(io_vector);
    swoole_trace_log(SW_TRACE_SOCKET, "readv %ld bytes, errno=%d", retval, errno);

    if (retval < 0 && socket->catch_read_error(errno) != SW_WAIT) {
        set_err(errno);
        return retval;
    }

    if (retval == 0) {
        return retval;
    }

    total_bytes += retval > 0 ? retval : 0;
    if (io_vector->get_remain_count() == 0) {
        // iov should not be modified, prevent valgrind from checking for invalid read
        return retval;
    }

    EventBarrier barrier = [&io_vector, &total_bytes, &retval, this]() -> bool {
        do {
            retval = socket->readv(io_vector);

            if (retval <= 0) {
                break;
            }

            total_bytes += retval;
        } while (retval > 0 && io_vector->get_remain_count() > 0);

        return retval < 0 && socket->catch_read_error(errno) == SW_WAIT;
    };

    recv_barrier = &barrier;
    if (timer.start() && wait_event(SW_EVENT_READ)) {
        check_return_value(retval);
    }
    recv_barrier = nullptr;

    return total_bytes;
}

ssize_t Socket::writev(network::IOVector *io_vector) {
    if (sw_unlikely(!is_available(SW_EVENT_WRITE))) {
        return -1;
    }
    ssize_t retval;
    TimerController timer(&write_timer, write_timeout, this, timer_callback);
    do {
        retval = socket->writev(io_vector);
    } while (retval < 0 && socket->catch_write_error(errno) == SW_WAIT && timer.start() && wait_event(SW_EVENT_WRITE));
    check_return_value(retval);

    return retval;
}

ssize_t Socket::writev_all(network::IOVector *io_vector) {
    if (sw_unlikely(!is_available(SW_EVENT_WRITE))) {
        return -1;
    }
    ssize_t retval, total_bytes = 0;
    TimerController timer(&write_timer, write_timeout, this, timer_callback);

    retval = socket->writev(io_vector);
    swoole_trace_log(SW_TRACE_SOCKET, "writev %ld bytes, errno=%d", retval, errno);

    if (retval < 0 && socket->catch_write_error(errno) != SW_WAIT) {
        set_err(errno);
        return retval;
    }

    if (retval == 0) {
        return retval;
    }

    total_bytes += retval > 0 ? retval : 0;
    if (io_vector->get_remain_count() == 0) {
        // iov should not be modified, prevent valgrind from checking for invalid read
        return retval;
    }

    EventBarrier barrier = [&io_vector, &total_bytes, &retval, this]() -> bool {
        do {
            retval = socket->writev(io_vector);

            if (retval <= 0) {
                break;
            }

            total_bytes += retval;
        } while (retval > 0 && io_vector->get_remain_count() > 0);

        return retval < 0 && socket->catch_write_error(errno) == SW_WAIT;
    };

    send_barrier = &barrier;
    if (timer.start() && wait_event(SW_EVENT_WRITE)) {
        check_return_value(retval);
    }
    send_barrier = nullptr;

    return total_bytes;
}

ssize_t Socket::recv_all(void *__buf, size_t __n) {
    if (sw_unlikely(!is_available(SW_EVENT_READ))) {
        return -1;
    }
    ssize_t retval = 0;
    size_t total_bytes = 0;
    TimerController timer(&read_timer, read_timeout, this, timer_callback);

    retval = socket->recv(__buf, __n, 0);

    if (retval == 0 || retval == (ssize_t) __n) {
        return retval;
    }
    if (retval < 0 && socket->catch_read_error(errno) != SW_WAIT) {
        set_err(errno);
        return retval;
    }
    total_bytes = retval > 0 ? retval : 0;

    retval = -1;

    EventBarrier barrier = [&__n, &total_bytes, &retval, &__buf, this]() -> bool {
        retval = socket->recv((char *) __buf + total_bytes, __n - total_bytes, 0);
        return (retval < 0 && socket->catch_read_error(errno) == SW_WAIT) ||
               (retval > 0 && (total_bytes += retval) < __n);
    };

    recv_barrier = &barrier;
    if (timer.start() && wait_event(SW_EVENT_READ)) {
        check_return_value(retval);
    }
    recv_barrier = nullptr;

    return retval < 0 && total_bytes == 0 ? -1 : total_bytes;
}

ssize_t Socket::send_all(const void *__buf, size_t __n) {
    if (sw_unlikely(!is_available(SW_EVENT_WRITE))) {
        return -1;
    }
    ssize_t retval = 0;
    size_t total_bytes = 0;
    TimerController timer(&write_timer, write_timeout, this, timer_callback);

    retval = socket->send(__buf, __n, 0);

    if (retval == 0 || retval == (ssize_t) __n) {
        return retval;
    }
    if (retval < 0 && socket->catch_write_error(errno) != SW_WAIT) {
        set_err(errno);
        return retval;
    }
    total_bytes = retval > 0 ? retval : 0;

    retval = -1;

    EventBarrier barrier = [&__n, &total_bytes, &retval, &__buf, this]() -> bool {
        retval = socket->send((char *) __buf + total_bytes, __n - total_bytes, 0);
        return (retval < 0 && socket->catch_write_error(errno) == SW_WAIT) ||
               (retval > 0 && (total_bytes += retval) < __n);
    };

    send_barrier = &barrier;
    if (timer.start() && wait_event(SW_EVENT_WRITE)) {
        check_return_value(retval);
    }
    send_barrier = nullptr;

    return retval < 0 && total_bytes == 0 ? -1 : total_bytes;
}

ssize_t Socket::recvmsg(struct msghdr *msg, int flags) {
    if (sw_unlikely(!is_available(SW_EVENT_READ))) {
        return -1;
    }
    ssize_t retval;
    TimerController timer(&read_timer, read_timeout, this, timer_callback);
    do {
        retval = ::recvmsg(sock_fd, msg, flags);
    } while (retval < 0 && socket->catch_read_error(errno) == SW_WAIT && timer.start() && wait_event(SW_EVENT_READ));
    check_return_value(retval);
    return retval;
}

/**
 * Notice: you must use non-global buffer here (or else it may be changed after yield)
 */
ssize_t Socket::sendmsg(const struct msghdr *msg, int flags) {
    if (sw_unlikely(!is_available(SW_EVENT_WRITE))) {
        return -1;
    }
    ssize_t retval;
    TimerController timer(&write_timer, write_timeout, this, timer_callback);
    do {
        retval = ::sendmsg(sock_fd, msg, flags);
    } while (retval < 0 && socket->catch_write_error(errno) == SW_WAIT && timer.start() && wait_event(SW_EVENT_WRITE));
    check_return_value(retval);
    return retval;
}

bool Socket::bind(const struct sockaddr *sa, socklen_t len) {
    return ::bind(sock_fd, (struct sockaddr *) sa, len) == 0;
}

bool Socket::bind(std::string address, int port) {
    if (sw_unlikely(!is_available(SW_EVENT_NULL))) {
        return false;
    }
    if ((sock_domain == AF_INET || sock_domain == AF_INET6) && (port < 0 || port > 65535)) {
        set_err(EINVAL, std_string::format("Invalid port [%d]", port));
        return false;
    }

    bind_address = address;
    bind_port = port;
    bind_address_info.type = type;

    if (socket->bind(address, &bind_port) != 0) {
        set_err(errno);
        return false;
    }

    return true;
}

bool Socket::listen(int backlog) {
    if (sw_unlikely(!is_available(SW_EVENT_NULL))) {
        return false;
    }
    this->backlog = backlog <= 0 ? SW_BACKLOG : backlog;
    if (socket->listen(this->backlog) < 0) {
        set_err(errno);
        return false;
    }
    if (socket->get_name(&socket->info) < 0) {
        set_err(errno);
        return false;
    }
#ifdef SW_USE_OPENSSL
    ssl_is_server = true;
#endif
    return true;
}

Socket *Socket::accept(double timeout) {
    if (sw_unlikely(!is_available(SW_EVENT_READ))) {
        return nullptr;
    }
    network::Socket *conn = socket->accept();
    if (conn == nullptr && errno == EAGAIN) {
        TimerController timer(&read_timer, timeout == 0 ? read_timeout : timeout, this, timer_callback);
        if (!timer.start() || !wait_event(SW_EVENT_READ)) {
            return nullptr;
        }
        conn = socket->accept();
    }
    if (conn == nullptr) {
        set_err(errno);
        return nullptr;
    }

    Socket *client_sock = new Socket(conn, this);
    if (sw_unlikely(client_sock->get_fd() < 0)) {
        swoole_sys_warning("new Socket() failed");
        set_err(errno);
        delete client_sock;
        return nullptr;
    }

    return client_sock;
}

#ifdef SW_USE_OPENSSL
bool Socket::ssl_check_context() {
    if (socket->ssl || (get_ssl_context() && get_ssl_context()->get_context())) {
        return true;
    }
    if (socket->is_dgram()) {
#ifdef SW_SUPPORT_DTLS
        socket->dtls = 1;
        ssl_context->protocols = SW_SSL_DTLS;
        socket->chunk_size = SW_SSL_BUFFER_SIZE;
#else
        swoole_warning("DTLS support require openssl-1.1 or later");
        return false;
#endif
    }
    ssl_context->http_v2 = http2;
    if (!ssl_context->create()) {
        swoole_warning("swSSL_get_context() error");
        return false;
    }
    socket->ssl_send_ = 1;
    return true;
}

bool Socket::ssl_create(SSLContext *ssl_context) {
    if (socket->ssl) {
        return true;
    }
    if (socket->ssl_create(ssl_context, 0) < 0) {
        return false;
    }
#ifdef SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER
    SSL_set_mode(socket->ssl, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
#endif
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
    if (!ssl_context->tls_host_name.empty()) {
        SSL_set_tlsext_host_name(socket->ssl, ssl_context->tls_host_name.c_str());
    } else if (!ssl_context->disable_tls_host_name && !ssl_host_name.empty()) {
        SSL_set_tlsext_host_name(socket->ssl, ssl_host_name.c_str());
    }
#endif
    return true;
}

bool Socket::ssl_handshake() {
    if (ssl_handshaked) {
        return false;
    }
    if (sw_unlikely(!is_available(SW_EVENT_RDWR))) {
        return false;
    }
    if (!ssl_check_context()) {
        return false;
    }
    if (!ssl_create(get_ssl_context())) {
        return false;
    }
    if (!ssl_is_server) {
        while (true) {
            if (socket->ssl_connect() < 0) {
                set_err(errno);
                return false;
            }
            if (socket->ssl_state == SW_SSL_STATE_WAIT_STREAM) {
                TimerController timer(&read_timer, read_timeout, this, timer_callback);
                if (!timer.start() || !wait_event(SW_EVENT_READ)) {
                    return false;
                }
            } else if (socket->ssl_state == SW_SSL_STATE_READY) {
                break;
            }
        }
    } else {
        ReturnCode retval;
        TimerController timer(&read_timer, read_timeout, this, timer_callback);

        do {
            retval = socket->ssl_accept();
        } while (retval == SW_WAIT && timer.start() && wait_event(SW_EVENT_READ));

        if (retval != SW_READY) {
            set_err(SW_ERROR_SSL_BAD_CLIENT);
            return false;
        }
    }
    if (ssl_context->verify_peer) {
        if (!ssl_verify(ssl_context->allow_self_signed)) {
            return false;
        }
    }
    ssl_handshaked = true;

    return true;
}

bool Socket::ssl_verify(bool allow_self_signed) {
    if (!socket->ssl_verify(allow_self_signed)) {
        set_err(SW_ERROR_SSL_VERIFY_FAILED);
        return false;
    }
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
    if (!ssl_context->tls_host_name.empty() && !socket->ssl_check_host(ssl_context->tls_host_name.c_str())) {
        set_err(SW_ERROR_SSL_VERIFY_FAILED);
        return false;
    }
#endif
    return true;
}

std::string Socket::ssl_get_peer_cert() {
    if (!socket->ssl_get_peer_certificate(sw_tg_buffer())) {
        return "";
    } else {
        return sw_tg_buffer()->to_std_string();
    }
}
#endif

bool Socket::sendfile(const char *filename, off_t offset, size_t length) {
    if (sw_unlikely(!is_available(SW_EVENT_WRITE))) {
        return false;
    }

    File file(filename, O_RDONLY);
    if (!file.ready()) {
        set_err(errno, std_string::format("open(%s) failed, %s", filename, strerror(errno)));
        return false;
    }

    if (length == 0) {
        FileStatus file_stat;
        if (!file.stat(&file_stat)) {
            set_err(errno, std_string::format("fstat(%s) failed, %s", filename, strerror(errno)));
            return false;
        }
        length = file_stat.st_size;
    } else {
        // total length of the file
        length = offset + length;
    }

    TimerController timer(&write_timer, write_timeout, this, timer_callback);
    int n, sendn;
    while ((size_t) offset < length) {
        sendn = (length - offset > SW_SENDFILE_CHUNK_SIZE) ? SW_SENDFILE_CHUNK_SIZE : length - offset;
#ifdef SW_USE_OPENSSL
        if (socket->ssl) {
            n = socket->ssl_sendfile(file, &offset, sendn);
        } else
#endif
        {
            n = ::swoole_sendfile(sock_fd, file.get_fd(), &offset, sendn);
        }
        if (n > 0) {
            continue;
        } else if (n == 0) {
            set_err(SW_ERROR_SYSTEM_CALL_FAIL, "sendfile return zero");
            return false;
        } else if (errno != EAGAIN) {
            set_err(errno, std_string::format("sendfile(%d, %s) failed, %s", sock_fd, filename, strerror(errno)));
            return false;
        }
        if (!timer.start() || !wait_event(SW_EVENT_WRITE)) {
            return false;
        }
    }
    return true;
}

ssize_t Socket::sendto(const std::string &host, int port, const void *__buf, size_t __n) {
    if (sw_unlikely(!is_available(SW_EVENT_WRITE))) {
        return -1;
    }

    ssize_t retval = 0;
    union {
        struct sockaddr_in in;
        struct sockaddr_in6 in6;
        struct sockaddr_un un;
    } addr = {};
    size_t addr_size = 0;

    std::string ip = host;

    for (size_t i = 0; i < 2; i++) {
        if (type == SW_SOCK_UDP) {
            if (::inet_pton(AF_INET, ip.c_str(), &addr.in.sin_addr) == 0) {
                read_co = write_co = Coroutine::get_current_safe();
                ip = System::gethostbyname(host, sock_domain, dns_timeout);
                read_co = write_co = nullptr;
                if (ip.empty()) {
                    set_err(swoole_get_last_error(), swoole_strerror(swoole_get_last_error()));
                    return -1;
                }
                continue;
            } else {
                addr.in.sin_family = AF_INET;
                addr.in.sin_port = htons(port);
                addr_size = sizeof(addr.in);
                break;
            }
        } else if (type == SW_SOCK_UDP6) {
            if (::inet_pton(AF_INET6, ip.c_str(), &addr.in6.sin6_addr) == 0) {
                read_co = write_co = Coroutine::get_current_safe();
                ip = System::gethostbyname(host, sock_domain, dns_timeout);
                read_co = write_co = nullptr;
                if (ip.empty()) {
                    set_err(swoole_get_last_error(), swoole_strerror(swoole_get_last_error()));
                    return -1;
                }
                continue;
            } else {
                addr.in6.sin6_port = (uint16_t) htons(port);
                addr.in6.sin6_family = AF_INET6;
                addr_size = sizeof(addr.in6);
                break;
            }
        } else if (type == SW_SOCK_UNIX_DGRAM) {
            addr.un.sun_family = AF_UNIX;
            swoole_strlcpy(addr.un.sun_path, host.c_str(), sizeof(addr.un.sun_path));
            addr_size = sizeof(addr.un);
            break;
        } else {
            set_err(EPROTONOSUPPORT);
            retval = -1;
            break;
        }
    }

    if (addr_size > 0) {
        TimerController timer(&write_timer, write_timeout, this, timer_callback);
        do {
            retval = ::sendto(sock_fd, __buf, __n, 0, (struct sockaddr *) &addr, addr_size);
            swoole_trace_log(SW_TRACE_SOCKET, "sendto %ld/%ld bytes, errno=%d", retval, __n, errno);
        } while (retval < 0 && (errno == EINTR || (socket->catch_write_error(errno) == SW_WAIT && timer.start() &&
                                                   wait_event(SW_EVENT_WRITE, &__buf, __n))));
        check_return_value(retval);
    }

    return retval;
}

ssize_t Socket::recvfrom(void *__buf, size_t __n) {
    if (sw_unlikely(!is_available(SW_EVENT_READ))) {
        return -1;
    }
    socket->info.len = sizeof(socket->info.addr);
    return recvfrom(__buf, __n, (struct sockaddr *) &socket->info.addr, &socket->info.len);
}

ssize_t Socket::recvfrom(void *__buf, size_t __n, struct sockaddr *_addr, socklen_t *_socklen) {
    if (sw_unlikely(!is_available(SW_EVENT_READ))) {
        return -1;
    }
    ssize_t retval;
    TimerController timer(&read_timer, read_timeout, this, timer_callback);
    do {
        retval = ::recvfrom(sock_fd, __buf, __n, 0, _addr, _socklen);
        swoole_trace_log(SW_TRACE_SOCKET, "recvfrom %ld/%ld bytes, errno=%d", retval, __n, errno);
    } while (retval < 0 && ((errno == EINTR) || (socket->catch_read_error(errno) == SW_WAIT && timer.start() &&
                                                 wait_event(SW_EVENT_READ))));
    check_return_value(retval);
    return retval;
}

ssize_t Socket::recv_packet_with_length_protocol() {
    ssize_t packet_len = SW_BUFFER_SIZE_STD;
    ssize_t retval;
    PacketLength pl;
    uint32_t header_len = protocol.package_length_offset + protocol.package_length_size;

    if (read_buffer->length > 0) {
        if (read_buffer->length >= header_len ||
            (protocol.package_length_size == 0 && protocol.package_length_type == '\0')  // custom package_length_func
        ) {
            goto _get_length;
        } else {
            goto _recv_header;
        }
    }

_recv_header:
    retval = recv(read_buffer->str + read_buffer->length, header_len - read_buffer->length);
    if (retval <= 0) {
        return retval;
    } else {
        read_buffer->length += retval;
    }

_get_length:
    pl.header_len = 0;
    pl.buf = read_buffer->str;
    pl.buf_size = (uint32_t) read_buffer->length;
    packet_len = protocol.get_package_length(&protocol, socket, &pl);
    swoole_trace_log(SW_TRACE_SOCKET, "packet_len=%ld, length=%ld", packet_len, read_buffer->length);
    if (packet_len < 0) {
        set_err(SW_ERROR_PACKAGE_LENGTH_NOT_FOUND, "get package length failed");
        return 0;
    } else if (packet_len == 0) {
        if (pl.header_len != 0) {
            header_len = pl.header_len;
        }
        goto _recv_header;
    } else if (packet_len > protocol.package_max_length) {
        read_buffer->clear();
        swoole_error_log(SW_LOG_WARNING,
                         SW_ERROR_PACKAGE_LENGTH_TOO_LARGE,
                         "packet length is too big, remote_addr=%s:%d, length=%zu",
                         socket->info.get_ip(),
                         socket->info.get_port(),
                         packet_len);
        set_err(SW_ERROR_PACKAGE_LENGTH_TOO_LARGE, sw_error);
        return -1;
    }

    read_buffer->offset = packet_len;

    if ((size_t) packet_len <= read_buffer->length) {
        return packet_len;
    }

    if ((size_t) packet_len > read_buffer->size) {
        if (!read_buffer->extend(packet_len)) {
            read_buffer->clear();
            set_err(ENOMEM);
            return -1;
        }
    }

    retval = recv_all(read_buffer->str + read_buffer->length, packet_len - read_buffer->length);
    if (retval > 0) {
        read_buffer->length += retval;
        if (read_buffer->length != (size_t) packet_len) {
            retval = 0;
        } else {
            return packet_len;
        }
    }

    return retval;
}

ssize_t Socket::recv_packet_with_eof_protocol() {
    ssize_t retval, eof = -1;
    char *buf = nullptr;
    size_t l_buf = 0;

    if (read_buffer->length > 0) {
        goto _find_eof;
    }

    while (1) {
        buf = read_buffer->str + read_buffer->length;
        l_buf = read_buffer->size - read_buffer->length;

        if (l_buf > SW_BUFFER_SIZE_BIG) {
            l_buf = SW_BUFFER_SIZE_BIG;
        }

        retval = recv(buf, l_buf);
        if (retval <= 0) {
            read_buffer->clear();
            return retval;
        }

        read_buffer->length += retval;

        if (read_buffer->length < protocol.package_eof_len) {
            continue;
        }

    _find_eof:
        eof = swoole_strnpos(read_buffer->str, read_buffer->length, protocol.package_eof, protocol.package_eof_len);
        if (eof >= 0) {
            return (read_buffer->offset = eof + protocol.package_eof_len);
        }
        if (read_buffer->length == protocol.package_max_length) {
            read_buffer->clear();
            set_err(SW_ERROR_PACKAGE_LENGTH_TOO_LARGE, "no package eof, package_max_length exceeded");
            return -1;
        }
        if (read_buffer->length == read_buffer->size && read_buffer->size < protocol.package_max_length) {
            size_t new_size = read_buffer->size * 2;
            if (new_size > protocol.package_max_length) {
                new_size = protocol.package_max_length;
            }
            if (!read_buffer->extend(new_size)) {
                read_buffer->clear();
                set_err(ENOMEM);
                return -1;
            }
        }
    }
    assert(0);
    return -1;
}

/**
 * Recv packet with protocol
 * Returns the length of the packet, [return value == read_buffer->offset]
 * ---------------------------------------Usage---------------------------------------------
 * ssize_t l = sock.recv_packet();
 * String *pkt = sock.get_read_buffer();
 * a) memcpy(result_buf, pkt->str, l); //copy data to new buffer
 * b) result_buf = sock.pop_packet();  //pop packet data, create a new buffer memory
 * ---------------------------------------read_buffer---------------------------------------
 * [read_buffer->length > read_buffer->offset] : may be unprocessed data in the buffer
 * [read_buffer->length == read_buffer->offset] : no data in the buffer
 */
ssize_t Socket::recv_packet(double timeout) {
    if (sw_unlikely(!is_available(SW_EVENT_READ))) {
        return -1;
    }

    TimerController timer(&read_timer, timeout == 0 ? read_timeout : timeout, this, timer_callback);
    if (sw_unlikely(!timer.start())) {
        return 0;
    }

    get_read_buffer();

    // unprocessed data
    if (read_buffer->offset > 0) {
        read_buffer->reduce(read_buffer->offset);
    }

    ssize_t recv_bytes;

    if (open_length_check) {
        recv_bytes = recv_packet_with_length_protocol();
    } else if (open_eof_check) {
        recv_bytes = recv_packet_with_eof_protocol();
    } else {
        recv_bytes = recv(read_buffer->str, read_buffer->size);
        if (recv_bytes > 0) {
            read_buffer->length = read_buffer->offset = recv_bytes;
        }
    }
    if (recv_bytes <= 0) {
        read_buffer->clear();
    }
    return recv_bytes;
}

bool Socket::shutdown(int __how) {
    set_err(0);
    if (!is_connected() || (__how == SHUT_RD && shutdown_read) || (__how == SHUT_WR && shutdown_write)) {
        errno = ENOTCONN;
    } else {
#ifdef SW_USE_OPENSSL
        if (socket->ssl) {
            socket->ssl_shutdown();
        }
#endif
        if (::shutdown(sock_fd, __how) == 0 || errno == ENOTCONN) {
            if (errno == ENOTCONN) {
                // connection reset by server side
                __how = SHUT_RDWR;
            }
            switch (__how) {
            case SHUT_RD:
                shutdown_read = true;
                break;
            case SHUT_WR:
                shutdown_write = true;
                break;
            default:
                shutdown_read = shutdown_write = true;
                break;
            }
            if (shutdown_read && shutdown_write) {
                connected = false;
            }
            return true;
        }
    }
    set_err(errno);
    return false;
}

#ifdef SW_USE_OPENSSL
bool Socket::ssl_shutdown() {
    if (socket->ssl) {
        socket->ssl_close();
    }
    return true;
}
#endif

bool Socket::cancel(const EventType event) {
    if (!has_bound(event)) {
        return false;
    }
    if (event == SW_EVENT_READ) {
        set_err(ECANCELED);
        read_co->resume();
        return true;
    } else if (event == SW_EVENT_WRITE) {
        set_err(ECANCELED);
        write_co->resume();
        return true;
    } else {
        return false;
    }
}

/**
 * @return bool (whether it can be freed)
 * you can access errCode member to get error information
 */
bool Socket::close() {
    if (sock_fd < 0) {
        set_err(EBADF);
        return true;
    }
    if (connected) {
        shutdown();
    }
    if (sw_unlikely(has_bound())) {
        if (closed) {
            // close operation is in processing
            set_err(EINPROGRESS);
            return false;
        }
        closed = true;
        if (write_co) {
            set_err(ECONNRESET);
            write_co->resume();
        }
        if (read_co) {
            set_err(ECONNRESET);
            read_co->resume();
        }
        return false;
    } else {
        sock_fd = -1;
        closed = true;
        return true;
    }
}

/**
 * Warn:
 * the destructor should only be called in following two cases:
 * 1. construct failed
 * 2. called close() and it return true
 * 3. called close() and it return false but it will not be accessed anywhere else
 */
Socket::~Socket() {
#ifdef SW_DEBUG
    if (SwooleG.running) {
        SW_ASSERT(!has_bound() && socket->removed);
    }
#endif
    if (read_buffer) {
        delete read_buffer;
    }
    if (write_buffer) {
        delete write_buffer;
    }
    if (socks5_proxy) {
        delete socks5_proxy;
    }
    if (http_proxy) {
        delete http_proxy;
    }
    if (socket == nullptr) {
        return;
    }
    /* {{{ release socket resources */
#ifdef SW_USE_OPENSSL
    ssl_shutdown();
#endif
    if (sock_domain == AF_UNIX && !bind_address.empty()) {
        ::unlink(bind_address_info.addr.un.sun_path);
        bind_address_info = {};
    }
    if (socket->socket_type == SW_SOCK_UNIX_DGRAM) {
        ::unlink(socket->info.addr.un.sun_path);
    }
    socket->free();
}

}  // namespace coroutine

std::string HttpProxy::get_auth_str() {
    char auth_buf[256];
    char encode_buf[512];
    size_t n = sw_snprintf(auth_buf,
                           sizeof(auth_buf),
                           "%.*s:%.*s",
                           (int) username.length(),
                           username.c_str(),
                           (int) password.length(),
                           password.c_str());
    base64_encode((unsigned char *) auth_buf, n, encode_buf);
    return std::string(encode_buf);
}

}  // namespace swoole
