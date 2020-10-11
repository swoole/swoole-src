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

#include "swoole_coroutine_socket.h"

#include <string>
#include <iostream>

#include "swoole_util.h"
#include "swoole_socket.h"
#include "swoole_coroutine_system.h"
#include "swoole_buffer.h"
#include "swoole_base64.h"

namespace swoole {
namespace coroutine {

#ifdef SW_USE_OPENSSL
#ifndef OPENSSL_NO_NEXTPROTONEG

const std::string HTTP2_H2_ALPN("\x2h2");
const std::string HTTP2_H2_16_ALPN("\x5h2-16");
const std::string HTTP2_H2_14_ALPN("\x5h2-14");

static bool ssl_select_proto(const uchar **out, uchar *outlen, const uchar *in, uint inlen, const std::string &key) {
    for (auto p = in, end = in + inlen; p + key.size() <= end; p += *p + 1) {
        if (std::equal(std::begin(key), std::end(key), p)) {
            *out = p + 1;
            *outlen = *p;
            return true;
        }
    }
    return false;
}

static bool ssl_select_h2(const uchar **out, uchar *outlen, const uchar *in, uint inlen) {
    return ssl_select_proto(out, outlen, in, inlen, HTTP2_H2_ALPN) ||
           ssl_select_proto(out, outlen, in, inlen, HTTP2_H2_16_ALPN) ||
           ssl_select_proto(out, outlen, in, inlen, HTTP2_H2_14_ALPN);
}

static int ssl_select_next_proto_cb(SSL *ssl, uchar **out, uchar *outlen, const uchar *in, uint inlen, void *arg) {
#ifdef SW_LOG_TRACE_OPEN
    std::string info("[NPN] server offers:\n");
    for (unsigned int i = 0; i < inlen; i += in[i] + 1) {
        info += "        * " + std::string(reinterpret_cast<const char *>(&in[i + 1]), in[i]);
    }
    swTraceLog(SW_TRACE_HTTP2, "[NPN] server offers: %s", info.c_str());
#endif
    if (!ssl_select_h2(const_cast<const unsigned char **>(out), outlen, in, inlen)) {
        swWarn("HTTP/2 protocol was not selected, expects [h2]");
        return SSL_TLSEXT_ERR_NOACK;
    } else {
        return SSL_TLSEXT_ERR_OK;
    }
}
#endif
#endif

enum Socket::TimeoutType Socket::timeout_type_list[4] = { TIMEOUT_DNS, TIMEOUT_CONNECT, TIMEOUT_READ, TIMEOUT_WRITE };

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
        EventBarrier &barrier = socket->recv_barrier;
        if (barrier.hold) {
            barrier.retval = socket->socket->recv(barrier.buf + barrier.total_bytes, barrier.n - barrier.total_bytes, 0);
            if ((barrier.retval < 0 && socket->socket->catch_error(errno) == SW_WAIT)
                    || (barrier.retval > 0 && (barrier.total_bytes += barrier.retval) < barrier.n)) {
                return SW_OK;
            }
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
        EventBarrier &barrier = socket->send_barrier;
        if (barrier.hold) {
            barrier.retval = socket->socket->send(barrier.buf + barrier.total_bytes, barrier.n - barrier.total_bytes, 0);
            if ((barrier.retval < 0 && socket->socket->catch_error(errno) == SW_WAIT)
                    || (barrier.retval > 0 && (barrier.total_bytes += barrier.retval) < barrier.n)) {
                return SW_OK;
            }
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

bool Socket::add_event(const enum swEvent_type event) {
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

bool Socket::wait_event(const enum swEvent_type event, const void **__buf, size_t __n) {
    enum swEvent_type added_event = event;
    Coroutine *co = Coroutine::get_current_safe();
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
    swTraceLog(SW_TRACE_SOCKET,
               "socket#%d blongs to cid#%ld is waiting for %s event",
               sock_fd,
               co->get_cid(),
#ifdef SW_USE_OPENSSL
               socket->ssl_want_read ? "SSL READ"
                                     : socket->ssl_want_write ? "SSL WRITE" :
#endif
                                                              event == SW_EVENT_READ ? "READ" : "WRITE");
    if (sw_likely(event == SW_EVENT_READ)) {
        read_co = co;
        read_co->yield();
        read_co = nullptr;
    } else  // if (event == SW_EVENT_WRITE)
    {
        if (sw_unlikely(!zero_copy && __n > 0 && *__buf != get_write_buffer()->str)) {
            swString_clear(write_buffer);
            if (write_buffer->append((const char *) *__buf, __n) != SW_OK) {
                set_err(ENOMEM);
                goto _failed;
            }
            *__buf = write_buffer->str;
            if (send_barrier.hold) {
                send_barrier.buf = (char *) write_buffer->str;
            }
        }
        write_co = co;
        write_co->yield();
        write_co = nullptr;
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
    swTraceLog(SW_TRACE_SOCKET,
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

    swSocks5_pack(ctx->buf, !socks5_proxy->username.empty() ? 0x02 : 0x00);
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
        swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SOCKS5_UNSUPPORT_METHOD, "SOCKS authentication method is not supported");
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
        swoole_error_log(
            SW_LOG_NOTICE, SW_ERROR_SOCKS5_SERVER_ERROR, "Socks5 server error, reason: %s", swSocks5_strerror(result));
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
    if (open_ssl && ssl_option.tls_host_name) {
        host = ssl_option.tls_host_name;
        host_len = strlen(ssl_option.tls_host_name);
    }
#endif

    String *send_buffer = get_write_buffer();
    DeferFn _1([send_buffer](){
        send_buffer->clear();
    });

    if (!http_proxy->password.empty()) {
        char auth_buf[256];
        char encode_buf[512];
        n = sw_snprintf(auth_buf,
                        sizeof(auth_buf),
                        "%.*s:%.*s",
                        http_proxy->username.length(),
                        http_proxy->username.c_str(),
                        http_proxy->password.length(),
                        http_proxy->password.c_str());
        swBase64_encode((unsigned char *) auth_buf, n, encode_buf);
        n = sw_snprintf(send_buffer->str,
                        send_buffer->size,
                        HTTP_PROXY_FMT "Proxy-Authorization: Basic %s\r\n\r\n",
                        http_proxy->target_host.length(),
                        http_proxy->target_host.c_str(),
                        http_proxy->target_port,
                        host_len,
                        host,
                        http_proxy->target_port,
                        encode_buf);
    } else {
        n = sw_snprintf(send_buffer->str,
                        send_buffer->size,
                        HTTP_PROXY_FMT "\r\n",
                        http_proxy->target_host.length(),
                        http_proxy->target_host.c_str(),
                        http_proxy->target_port,
                        host_len,
                        host,
                        http_proxy->target_port);
    }

    swTraceLog(SW_TRACE_HTTP_CLIENT, "proxy request: <<EOF\n%.*sEOF", n, send_buffer->str);

    send_buffer->length = n;
    if (send(send_buffer->str, n) != n) {
        return false;
    }

    String *recv_buffer = get_read_buffer();
    DeferFn _2([recv_buffer](){
        recv_buffer->clear();
    });

    ProtocolSwitch ps(this);
    open_eof_check = true;
    open_length_check = false;
    protocol.package_eof_len = sizeof("\r\n\r\n") - 1;
    memcpy(protocol.package_eof, SW_STRS("\r\n\r\n"));

    n = recv_packet();
    if (n <= 0) {
        return false;
    }

    swTraceLog(SW_TRACE_HTTP_CLIENT, "proxy response: <<EOF\n%.*sEOF", n, recv_buffer->str);

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
                std::string("wrong http_proxy response received, \n[Request]: ") + send_buffer->to_std_string() + "\n[Response]: "
                        + std::string(buf, len));
    }

    return ret;
}

void Socket::init_sock_type(enum swSocket_type _sw_type) {
    type = _sw_type;
    network::Socket::get_domain_and_type(_sw_type, &sock_domain, &sock_type);
}

bool Socket::init_sock() {
    socket = make_socket(type, SW_FD_CORO_SOCKET, SW_SOCK_CLOEXEC | SW_SOCK_NONBLOCK);
    if (socket == nullptr) {
        return false;
    }
    sock_fd = socket->fd;
    socket->object = this;
    socket->info.type = type;
    return true;
}

bool Socket::init_reactor_socket(int _fd) {
    socket = swoole::make_socket(_fd, SW_FD_CORO_SOCKET);
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

Socket::Socket(enum swSocket_type _type) {
    init_sock_type(_type);
    if (sw_unlikely(!init_sock())) {
        return;
    }
    init_options();
}

Socket::Socket(int _fd, enum swSocket_type _type) {
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
    socket->fd_type = SW_FD_CORO_SOCKET;
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
    open_ssl = server_sock->open_ssl;
    ssl_is_server = server_sock->ssl_is_server;
    if (open_ssl) {
        if (server_sock->ssl_context) {
            if (!ssl_create(server_sock->ssl_context)) {
                close();
            }
        }
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
    if (open_ssl && (socks5_proxy || http_proxy)) {
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
                if (open_ssl && !(socks5_proxy || http_proxy)) {
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
                if (open_ssl && !(socks5_proxy || http_proxy)) {
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
            set_err(EINVAL, "unknow protocol[%d]");
            return false;
        }
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
    if (open_ssl) {
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
    } else {
        char buf;
        errno = 0;
        ssize_t retval = socket->peek(&buf, sizeof(buf), 0);
        if (retval == 0 || (retval < 0 && socket->catch_error(errno) != SW_WAIT)) {
            set_err(errno ? errno : ECONNRESET);
            return false;
        }
    }
    set_err(0);
    return true;
}

ssize_t Socket::peek(void *__buf, size_t __n) {
    ssize_t retval = socket->peek(__buf, __n, 0);
    set_err(retval < 0 ? errno : 0);
    return retval;
}

bool Socket::poll(enum swEvent_type type) {
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
    } while (retval < 0 && socket->catch_error(errno) == SW_WAIT && timer.start() && wait_event(SW_EVENT_READ));
    set_err(retval < 0 ? errno : 0);
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
    } while (retval < 0 && socket->catch_error(errno) == SW_WAIT && timer.start() &&
             wait_event(SW_EVENT_WRITE, &__buf, __n));
    set_err(retval < 0 ? errno : 0);
    return retval;
}

ssize_t Socket::read(void *__buf, size_t __n) {
    if (sw_unlikely(!is_available(SW_EVENT_READ))) {
        return -1;
    }
    ssize_t retval;
    TimerController timer(&read_timer, read_timeout, this, timer_callback);
    do {
        retval = ::read(sock_fd, __buf, __n);
    } while (retval < 0 && socket->catch_error(errno) == SW_WAIT && timer.start() && wait_event(SW_EVENT_READ));
    set_err(retval < 0 ? errno : 0);
    return retval;
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
        retval = ::write(sock_fd, (void *) __buf, __n);
    } while (retval < 0 && socket->catch_error(errno) == SW_WAIT && timer.start() &&
             wait_event(SW_EVENT_WRITE, &__buf, __n));
    set_err(retval < 0 ? errno : 0);
    return retval;
}

ssize_t Socket::recv_all(void *__buf, size_t __n) {
    if (sw_unlikely(!is_available(SW_EVENT_READ))) {
        return -1;
    }
    ssize_t retval, total_bytes = 0;
    TimerController timer(&read_timer, read_timeout, this, timer_callback);

    retval = socket->recv(__buf, __n, 0);
    if (retval == 0 || retval == (ssize_t) __n) {
        return retval;
    }
    if (retval < 0 && socket->catch_error(errno) != SW_WAIT) {
        set_err(errno);
        return retval;
    }
    total_bytes = retval > 0 ? retval : 0;

    recv_barrier.hold = true;
    recv_barrier.n = __n;
    recv_barrier.total_bytes = total_bytes;
    recv_barrier.buf = (char *) __buf;
    retval = -1;

    if (timer.start() && wait_event(SW_EVENT_READ)) {
        retval = recv_barrier.retval;
    }

    total_bytes = recv_barrier.total_bytes;
    recv_barrier.hold = false;
    set_err(retval < 0 ? errno : 0);

    return retval < 0 && total_bytes == 0 ? -1 : total_bytes;
}

ssize_t Socket::send_all(const void *__buf, size_t __n) {
    if (sw_unlikely(!is_available(SW_EVENT_WRITE))) {
        return -1;
    }
    ssize_t retval, total_bytes = 0;
    TimerController timer(&write_timer, write_timeout, this, timer_callback);

    retval = socket->send(__buf, __n, 0);
    if (retval == 0 || retval == (ssize_t) __n) {
        return retval;
    }
    if (retval < 0 && socket->catch_error(errno) != SW_WAIT) {
        set_err(errno);
        return retval;
    }
    total_bytes = retval > 0 ? retval : 0;

    send_barrier.hold = true;
    send_barrier.n = __n;
    send_barrier.total_bytes = total_bytes;
    send_barrier.buf = (char *) __buf;
    retval = -1;

    if (timer.start() && wait_event(SW_EVENT_WRITE, &__buf, __n)) {
        retval = send_barrier.retval;
    }

    total_bytes = send_barrier.total_bytes;
    send_barrier.hold = false;
    set_err(retval < 0 ? errno : 0);

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
    } while (retval < 0 && socket->catch_error(errno) == SW_WAIT && timer.start() && wait_event(SW_EVENT_READ));
    set_err(retval < 0 ? errno : 0);
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
    } while (retval < 0 && socket->catch_error(errno) == SW_WAIT && timer.start() && wait_event(SW_EVENT_WRITE));
    set_err(retval < 0 ? errno : 0);
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

    if (socket->bind(address.c_str(), &bind_port) != 0) {
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
    if (socket->listen(this->backlog) != 0) {
        set_err(errno);
        return false;
    }
#ifdef SW_USE_OPENSSL
    ssl_is_server = true;
    if (open_ssl) {
        return ssl_check_context();
    }
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
        swSysWarn("new Socket() failed");
        set_err(errno);
        delete client_sock;
        return nullptr;
    }

    return client_sock;
}

#ifdef SW_USE_OPENSSL
bool Socket::ssl_check_context() {
    if (socket->ssl || ssl_context) {
        return true;
    }
    if (socket->is_dgram()) {
#ifdef SW_SUPPORT_DTLS
        socket->dtls = 1;
        ssl_option.protocols = SW_SSL_DTLS;
        ssl_option.create_flag = SW_SSL_CLIENT;
#else
        swWarn("DTLS support require openssl-1.1 or later");
        return false;
#endif
    }
    ssl_context = swSSL_get_context(&ssl_option);
    if (ssl_context == nullptr) {
        swWarn("swSSL_get_context() error");
        return false;
    }
    if (ssl_option.verify_peer) {
        if (swSSL_set_capath(&ssl_option, ssl_context) < 0) {
            return false;
        }
    }
    socket->ssl_send = 1;
#if defined(SW_USE_HTTP2) && defined(SW_USE_OPENSSL) && OPENSSL_VERSION_NUMBER >= 0x10002000L
    if (http2) {
#ifndef OPENSSL_NO_NEXTPROTONEG
        SSL_CTX_set_next_proto_select_cb(ssl_context, ssl_select_next_proto_cb, nullptr);
#endif
        if (SSL_CTX_set_alpn_protos(ssl_context, (const unsigned char *) SW_STRL(SW_SSL_HTTP2_NPN_ADVERTISE)) < 0) {
            return false;
        }
    }
#endif
    return true;
}

bool Socket::ssl_create(SSL_CTX *ssl_context) {
    if (socket->ssl) {
        return true;
    }
    if (swSSL_create(socket, ssl_context, 0) < 0) {
        return false;
    }
#ifdef SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER
    SSL_set_mode(socket->ssl, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
#endif
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
    if (ssl_option.tls_host_name) {
        SSL_set_tlsext_host_name(socket->ssl, ssl_option.tls_host_name);
    } else if (!ssl_option.disable_tls_host_name && !ssl_host_name.empty()) {
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
    if (!ssl_create(ssl_context)) {
        return false;
    }
    if (!ssl_is_server) {
        while (true) {
            if (swSSL_connect(socket) < 0) {
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
        enum swReturn_code retval;
        TimerController timer(&read_timer, read_timeout, this, timer_callback);

        do {
            retval = swSSL_accept(socket);
        } while (retval == SW_WAIT && timer.start() && wait_event(SW_EVENT_READ));

        if (retval != SW_READY) {
            set_err(SW_ERROR_SSL_BAD_CLIENT);
            return false;
        }
    }
    if (ssl_option.verify_peer) {
        if (!ssl_verify(ssl_option.allow_self_signed)) {
            return false;
        }
    }
    open_ssl = true;
    ssl_handshaked = true;

    return true;
}

bool Socket::ssl_verify(bool allow_self_signed) {
    if (swSSL_verify(socket, allow_self_signed) < 0) {
        set_err(SW_ERROR_SSL_VERIFY_FAILED);
        return false;
    }
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
    if (ssl_option.tls_host_name && swSSL_check_host(socket, ssl_option.tls_host_name) < 0) {
        set_err(SW_ERROR_SSL_VERIFY_FAILED);
        return false;
    }
#endif
    return true;
}

std::string Socket::ssl_get_peer_cert() {
    if (!socket->ssl) {
        return "";
    }
    int n = swSSL_get_peer_cert(socket->ssl, SwooleTG.buffer_stack->str, SwooleTG.buffer_stack->size);
    if (n <= 0) {
        return "";
    } else {
        return std::string(SwooleTG.buffer_stack->str, n);
    }
}
#endif

bool Socket::sendfile(const char *filename, off_t offset, size_t length) {
    if (sw_unlikely(!is_available(SW_EVENT_WRITE))) {
        return false;
    }
    int file_fd = ::open(filename, O_RDONLY);
    if (file_fd < 0) {
        set_err(errno, std_string::format("open(%s) failed, %s", filename, strerror(errno)));
        return false;
    }

    FileDescriptor _(file_fd);
    if (length == 0) {
        struct stat file_stat;
        if (::fstat(file_fd, &file_stat) < 0) {
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
            n = swSSL_sendfile(socket, file_fd, &offset, sendn);
        } else
#endif
        {
            n = ::swoole_sendfile(sock_fd, file_fd, &offset, sendn);
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
            if (::inet_aton(ip.c_str(), &addr.in.sin_addr) == 0) {
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
            strncpy(addr.un.sun_path, host.c_str(), sizeof(addr.un.sun_path) - 1);
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
            swTraceLog(SW_TRACE_SOCKET, "sendto %ld/%ld bytes, errno=%d", retval, __n, errno);
        } while (retval < 0 && (errno == EINTR || (socket->catch_error(errno) == SW_WAIT && timer.start() &&
                                                   wait_event(SW_EVENT_WRITE, &__buf, __n))));
        set_err(retval < 0 ? errno : 0);
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
        swTraceLog(SW_TRACE_SOCKET, "recvfrom %ld/%ld bytes, errno=%d", retval, __n, errno);
    } while (retval < 0 && ((errno == EINTR) ||
                            (socket->catch_error(errno) == SW_WAIT && timer.start() && wait_event(SW_EVENT_READ))));
    set_err(retval < 0 ? errno : 0);
    return retval;
}

ssize_t Socket::recv_packet_with_length_protocol() {
    ssize_t packet_len = SW_BUFFER_SIZE_STD;
    ssize_t retval;
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
    protocol.real_header_length = 0;
    packet_len = protocol.get_package_length(&protocol, socket, read_buffer->str, (uint32_t) read_buffer->length);
    swTraceLog(SW_TRACE_SOCKET, "packet_len=%ld, length=%ld", packet_len, read_buffer->length);
    if (packet_len < 0) {
        set_err(SW_ERROR_PACKAGE_LENGTH_NOT_FOUND, "get package length failed");
        return 0;
    } else if (packet_len == 0) {
        if (protocol.real_header_length != 0) {
            header_len = protocol.real_header_length;
        }
        goto _recv_header;
    } else if (packet_len > protocol.package_max_length) {
        swString_clear(read_buffer);
        set_err(SW_ERROR_PACKAGE_LENGTH_TOO_LARGE, "remote packet is too big");
        return -1;
    }

    read_buffer->offset = packet_len;

    if ((size_t) packet_len <= read_buffer->length) {
        return packet_len;
    }

    if ((size_t) packet_len > read_buffer->size) {
        if (!read_buffer->extend(packet_len)) {
            swString_clear(read_buffer);
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
            swString_clear(read_buffer);
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
            swString_clear(read_buffer);
            set_err(SW_ERROR_PACKAGE_LENGTH_TOO_LARGE, "no package eof, package_max_length exceeded");
            return -1;
        }
        if (read_buffer->length == read_buffer->size && read_buffer->size < protocol.package_max_length) {
            size_t new_size = read_buffer->size * 2;
            if (new_size > protocol.package_max_length) {
                new_size = protocol.package_max_length;
            }
            if (!read_buffer->extend(new_size)) {
                swString_clear(read_buffer);
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
        swString_clear(read_buffer);
    }
    return recv_bytes;
}

bool Socket::shutdown(int __how) {
    set_err(0);
    if (!is_connect() || (__how == SHUT_RD && shutdown_read) || (__how == SHUT_WR && shutdown_write)) {
        errno = ENOTCONN;
    } else {
#ifdef SW_USE_OPENSSL
        if (socket->ssl) {
            SSL_set_quiet_shutdown(socket->ssl, 0);
            SSL_shutdown(socket->ssl);
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
        swSSL_close(socket);
    }
    if (ssl_context) {
        swSSL_free_context(ssl_context);
        ssl_context = nullptr;
    }
    return true;
}
#endif

bool Socket::cancel(const enum swEvent_type event) {
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
    if (socket == nullptr) {
        return;
    }
#ifdef SW_DEBUG
    if (SwooleG.running) {
        SW_ASSERT(!has_bound() && socket->removed);
    }
#endif
    if (read_buffer) {
        swString_free(read_buffer);
    }
    if (write_buffer) {
        swString_free(write_buffer);
    }
    /* {{{ release socket resources */
#ifdef SW_USE_OPENSSL
    ssl_shutdown();
    if (ssl_option.cert_file) {
        sw_free(ssl_option.cert_file);
    }
    if (ssl_option.key_file) {
        sw_free(ssl_option.key_file);
    }
    if (ssl_option.passphrase) {
        sw_free(ssl_option.passphrase);
    }
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
    if (ssl_option.tls_host_name) {
        sw_free(ssl_option.tls_host_name);
    }
#endif
    if (ssl_option.cafile) {
        sw_free(ssl_option.cafile);
    }
    if (ssl_option.capath) {
        sw_free(ssl_option.capath);
    }
    ssl_option = {};
#endif
    if (socket->in_buffer) {
        delete socket->in_buffer;
    }
    if (socket->out_buffer) {
        delete socket->out_buffer;
    }
    if (sock_domain == AF_UNIX && !bind_address.empty()) {
        ::unlink(bind_address_info.addr.un.sun_path);
        bind_address_info = {};
    }
    if (socket->socket_type == SW_SOCK_UNIX_DGRAM) {
        ::unlink(socket->info.addr.un.sun_path);
    }
    if (socks5_proxy) {
        delete socks5_proxy;
    }
    if (http_proxy) {
        delete http_proxy;
    }
    socket->free();
}

}  // namespace coroutine
}  // namespace swoole
