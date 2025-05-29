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
  | @Author   Tianfeng Han  <rango@swoole.com>                           |
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
Socket::TimeoutType Socket::timeout_type_list[4] = {TIMEOUT_DNS, TIMEOUT_CONNECT, TIMEOUT_READ, TIMEOUT_WRITE};

void Socket::timer_callback(Timer *timer, TimerNode *tnode) {
    auto *socket = static_cast<Socket *>(tnode->data);
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
    auto *socket = static_cast<Socket *>(event->socket->object);
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
    auto *socket = static_cast<Socket *>(event->socket->object);
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
    auto *socket = static_cast<Socket *>(event->socket->object);
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

#ifdef SW_LOG_TRACE_OPEN
static const char *get_trigger_event_name(Socket *socket, EventType added_event) {
    if (socket->is_closed()) {
        return "CLOSE";
    }
    if (socket->errCode) {
        return socket->errCode == ETIMEDOUT ? "TIMEOUT" : "ERROR";
    }
    return added_event == SW_EVENT_READ ? "READ" : "WRITE";
}

static const char *get_wait_event_name(Socket *socket, EventType event) {
#ifdef SW_USE_OPENSSL
    if (socket->get_socket()->ssl_want_read) {
        return "SSL READ";
    } else if (socket->get_socket()->ssl_want_write) {
        return "SSL WRITE";
    } else
#endif
    {
        return event == SW_EVENT_READ ? "READ" : "WRITE";
    }
}
#endif

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
    if (sw_unlikely(socket->close_wait)) {
        set_err(SW_ERROR_CO_SOCKET_CLOSE_WAIT);
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
                     get_wait_event_name(this, event));

    Coroutine::CancelFunc cancel_fn = [this, event](Coroutine *co) { return cancel(event); };

    if (sw_likely(event == SW_EVENT_READ)) {
        read_co = co;
        read_co->yield(&cancel_fn);
        read_co = nullptr;
    } else if (event == SW_EVENT_WRITE) {
        if (sw_unlikely(!zero_copy && __n > 0 && *__buf != get_write_buffer()->str)) {
            write_buffer->clear();
            if (write_buffer->append(static_cast<const char *>(*__buf), __n) != SW_OK) {
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
                     get_trigger_event_name(this, added_event));
    return !is_closed() && !errCode;
}

bool Socket::socks5_handshake() {
    Socks5Proxy *ctx = socks5_proxy.get();
    const auto len = ctx->pack_negotiate_request();
    if (send(ctx->buf, len) < 0) {
        return false;
    }

    auto send_fn = [this](const char *buf, size_t len) { return send(buf, len); };
    char recv_buf[512];
    ctx->state = SW_SOCKS5_STATE_HANDSHAKE;
    while (true) {
        const ssize_t n = recv(recv_buf, sizeof(recv_buf));
        if (n > 0 && ctx->handshake(recv_buf, n, send_fn)) {
            if (ctx->state == SW_SOCKS5_STATE_READY) {
                return true;
            }
            continue;
        }
        break;
    }
    return false;
}

bool Socket::http_proxy_handshake() {
    auto target_host = get_http_proxy_host_name();

    String *send_buffer = get_write_buffer();
    ON_SCOPE_EXIT {
        send_buffer->clear();
    };

    size_t n = http_proxy->pack(send_buffer, target_host);
    send_buffer->length = n;
    swoole_trace_log(SW_TRACE_HTTP_CLIENT, "proxy request: <<EOF\n%.*sEOF", (int) n, send_buffer->str);

    if (send(send_buffer->str, n) != (ssize_t) n) {
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

    if (recv_packet() <= 0) {
        return false;
    }

    swoole_trace_log(SW_TRACE_HTTP_CLIENT, "proxy response: <<EOF\n%.*sEOF", (int) n, recv_buffer->str);

    if (!http_proxy->handshake(recv_buffer)) {
        set_err(SW_ERROR_HTTP_PROXY_BAD_RESPONSE,
                std::string("wrong http_proxy response received, \n[Request]: ") + send_buffer->to_std_string() +
                    "\n[Response]: " + send_buffer->to_std_string());
        return false;
    }

    return true;
}

void Socket::init_sock_type(SocketType _type) {
    type = _type;
    network::Socket::get_domain_and_type(_type, &sock_domain, &sock_type);
}

bool Socket::init_sock() {
    socket =
        make_socket(type, SW_FD_CO_SOCKET, sock_domain, sock_type, sock_protocol, SW_SOCK_NONBLOCK | SW_SOCK_CLOEXEC);
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
    type = network::Socket::convert_to_type(_domain, _type);
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
    if (sw_unlikely(!init_reactor_socket(_fd))) {
        return;
    }
    if (_type == SW_SOCK_RAW) {
        return;
    }
    init_sock_type(_type);
    socket->set_nonblock();
    init_options();
}

Socket::Socket(int _fd, int _domain, int _type, int _protocol)
    : sock_domain(_domain), sock_type(_type), sock_protocol(_protocol) {
    type = network::Socket::convert_to_type(_domain, _type);
    if (sw_unlikely(!init_reactor_socket(_fd))) {
        return;
    }
    socket->set_nonblock();
    init_options();
}

/**
 * Only used as accept member method
 */
Socket::Socket(network::Socket *sock, const Socket *server_sock) {
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

bool Socket::getsockname() const {
    return socket->get_name() == SW_OK;
}

bool Socket::getpeername(network::Address *sa) {
    sa->len = sizeof(sa->addr);
    if (::getpeername(sock_fd, reinterpret_cast<sockaddr *>(&sa->addr), &sa->len) != 0) {
        set_err(errno);
        return false;
    }
    sa->type = type;
    return true;
}

double Socket::get_timeout(const TimeoutType type) const {
    SW_ASSERT_1BYTE(type);
    if (type == TIMEOUT_DNS) {
        return dns_timeout;
    } else if (type == TIMEOUT_CONNECT) {
        return connect_timeout;
    } else if (type == TIMEOUT_READ) {
        return read_timeout;
    } else if (type == TIMEOUT_WRITE) {
        return write_timeout;
    } else {
        assert(0);
        return -1;
    }
}

String *Socket::get_read_buffer() {
    if (sw_unlikely(!read_buffer)) {
        read_buffer = make_string(SW_BUFFER_SIZE_BIG, buffer_allocator);
        if (!read_buffer) {
            throw std::bad_alloc();
        }
    }
    return read_buffer;
}

String *Socket::get_write_buffer() {
    if (sw_unlikely(!write_buffer)) {
        write_buffer = make_string(SW_BUFFER_SIZE_BIG, buffer_allocator);
        if (!write_buffer) {
            throw std::bad_alloc();
        }
    }
    return write_buffer;
}

String *Socket::pop_read_buffer() {
    if (sw_unlikely(!read_buffer)) {
        return nullptr;
    }
    auto tmp = read_buffer;
    read_buffer = nullptr;
    return tmp;
}

String *Socket::pop_write_buffer() {
    if (sw_unlikely(!write_buffer)) {
        return nullptr;
    }
    auto tmp = write_buffer;
    write_buffer = nullptr;
    return tmp;
}

void Socket::set_timeout(double timeout, int type) {
    if (timeout == 0) {
        return;
    }
    if (type & TIMEOUT_DNS) {
        dns_timeout = timeout;
    }
    if (type & TIMEOUT_CONNECT) {
        connect_timeout = timeout;
    }
    if (type & TIMEOUT_READ) {
        read_timeout = timeout;
    }
    if (type & TIMEOUT_WRITE) {
        write_timeout = timeout;
    }
}

const char *Socket::get_event_str(const EventType event) const {
    if (event == SW_EVENT_READ) {
        return "reading";
    } else if (event == SW_EVENT_WRITE) {
        return "writing";
    } else {
        return read_co && write_co ? "reading or writing" : (read_co ? "reading" : "writing");
    }
}

bool Socket::set_option(int level, int optname, int optval) const {
    return set_option(level, optname, &optval, sizeof(optval));
}

bool Socket::get_option(int level, int optname, int *optval) const {
    socklen_t optval_size = sizeof(*optval);
    return get_option(level, optname, optval, &optval_size);
}

bool Socket::set_option(int level, int optname, const void *optval, socklen_t optlen) const {
    if (socket->set_option(level, optname, optval, optlen) < 0) {
        swoole_sys_warning("setsockopt(%d, %d, %d, %u) failed", sock_fd, level, optname, optlen);
        return false;
    }
    return true;
}

bool Socket::get_option(int level, int optname, void *optval, socklen_t *optlen) const {
    if (socket->get_option(level, optname, optval, optlen) < 0) {
        swoole_sys_warning("getsockopt(%d, %d, %d) failed", sock_fd, level, optname);
        return false;
    }
    return true;
}

void Socket::set_socks5_proxy(const std::string &host, int port, const std::string &user, const std::string &pwd) {
    socks5_proxy.reset(Socks5Proxy::create(type, host, port, user, pwd));
}

void Socket::set_http_proxy(const std::string &host, int port, const std::string &user, const std::string &pwd) {
    http_proxy.reset(HttpProxy::create(host, port, user, pwd));
}

bool Socket::connect(const sockaddr *addr, socklen_t addrlen) {
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
                if (is_closed()) {
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
    socket->get_name();
    set_err(0);
    return true;
}

bool Socket::connect(const std::string &_host, int _port, int flags) {
    if (sw_unlikely(!is_available(SW_EVENT_RDWR))) {
        return false;
    }

#ifdef SW_USE_OPENSSL
    if (ssl_context && (socks5_proxy || http_proxy)) {
        /* If the proxy is enabled, the host will be replaced with the proxy ip,
         * so we have to handle the host first,
         * if the host is not an ip, assign it to ssl_host_name
         */
        if (!network::Address::verify_ip(sock_domain, _host)) {
            ssl_host_name = _host;
        }
    }
#endif
    if (socks5_proxy) {
        socks5_proxy->target_host = _host;
        socks5_proxy->target_port = _port;

        connect_host = socks5_proxy->host;
        connect_port = socks5_proxy->port;
    } else if (http_proxy) {
        http_proxy->target_host = _host;
        http_proxy->target_port = _port;

        connect_host = http_proxy->host;
        connect_port = http_proxy->port;
    } else {
        connect_host = _host;
        connect_port = _port;
    }

    NameResolver::Context *ctx = resolve_context_;

    NameResolver::Context _ctx{};
    if (ctx == nullptr) {
        ctx = &_ctx;
    }
    ctx->timeout = dns_timeout;

    std::once_flag oc;
    auto name_resolve_fn = [ctx, &oc, this](int type) -> bool {
        ctx->type = type;
#ifdef SW_USE_OPENSSL
        std::call_once(oc, [this]() {
            if (ssl_context && !(socks5_proxy || http_proxy)) {
                ssl_host_name = connect_host;
            }
        });
#endif
        /* locked like wait_event */
        read_co = write_co = Coroutine::get_current_safe();
        ON_SCOPE_EXIT {
            read_co = write_co = nullptr;
        };
        std::string addr = swoole_name_resolver_lookup(connect_host, ctx);
        if (addr.empty()) {
            set_err(swoole_get_last_error());
            return false;
        }
        if (ctx->with_port) {
            char delimiter = type == AF_INET6 ? '@' : ':';
            auto port_pos = addr.find_first_of(delimiter);
            if (port_pos != addr.npos) {
                connect_port = std::stoi(addr.substr(port_pos + 1));
                connect_host = addr.substr(0, port_pos);
                return true;
            }
        }
        connect_host = addr;
        return true;
    };

    network::Address server_addr;

    for (int i = 0; i < 2; i++) {
        if (!server_addr.assign(type, connect_host, connect_port, false)) {
            if (swoole_get_last_error() != SW_ERROR_BAD_HOST_ADDR) {
                set_err(swoole_get_last_error(), swoole_strerror(swoole_get_last_error()));
                return false;
            }
            if (!name_resolve_fn(sock_domain)) {
                set_err(swoole_get_last_error(), swoole_strerror(swoole_get_last_error()));
                return false;
            }
            continue;
        }
        break;
    }

    if (connect(&server_addr.addr.ss, server_addr.len) == false) {
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
    if (is_closed()) {
        set_err(EBADF);
        return false;
    }
    if (!socket->check_liveness()) {
        set_err(errno ? errno : ECONNRESET);
        return false;
    }
    set_err(0);
    return true;
}

ssize_t Socket::peek(void *_buf, size_t _n) {
    ssize_t retval = socket->peek(_buf, _n, 0);
    check_return_value(retval);
    return retval;
}

bool Socket::poll(EventType type, double timeout) {
    if (sw_unlikely(!is_available(type))) {
        return false;
    }
    TimerNode **timer_pp = type == SW_EVENT_READ ? &read_timer : &write_timer;
    if (timeout == 0) {
        timeout = type == SW_EVENT_READ ? read_timeout : write_timeout;
    }
    TimerController timer(timer_pp, timeout, this, timer_callback);
    if (timer.start() && wait_event(type)) {
        return true;
    } else {
        return false;
    }
}

ssize_t Socket::recv(void *_buf, size_t _n) {
    if (sw_unlikely(!is_available(SW_EVENT_READ))) {
        return -1;
    }
    ssize_t retval;
    TimerController timer(&read_timer, read_timeout, this, timer_callback);
    do {
        retval = socket->recv(_buf, _n, 0);
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

ssize_t Socket::read(void *_buf, size_t _n) {
    if (sw_unlikely(!is_available(SW_EVENT_READ))) {
        return -1;
    }
    ssize_t retval;
    TimerController timer(&read_timer, read_timeout, this, timer_callback);
    do {
        retval = socket->read(_buf, _n);
    } while (retval < 0 && socket->catch_read_error(errno) == SW_WAIT && timer.start() && wait_event(SW_EVENT_READ));
    check_return_value(retval);
    return retval;
}

ssize_t Socket::recv_line(void *_buf, size_t maxlen) {
    size_t n = 0;
    ssize_t m = 0;
    auto t = static_cast<char *>(_buf);

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
    ssize_t total_bytes = 0;
    TimerController timer(&read_timer, read_timeout, this, timer_callback);

    ssize_t retval = socket->readv(io_vector);
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
    ssize_t total_bytes = 0;
    TimerController timer(&write_timer, write_timeout, this, timer_callback);

    ssize_t retval = socket->writev(io_vector);
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

bool Socket::bind(const sockaddr *sa, socklen_t len) const {
    return socket->bind(sa, len) == 0;
}

bool Socket::bind(const std::string &address, const int port) {
    if (sw_unlikely(!is_available(SW_EVENT_NULL))) {
        return false;
    }

    if (socket->set_reuse_addr() < 0) {
        swoole_sys_warning("setsockopt(%d, SO_REUSEADDR) failed", get_fd());
    }

    if (socket->bind(address, port) < 0) {
        set_err(errno);
        return false;
    }

    if (socket->get_name() < 0) {
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
#ifdef SW_USE_OPENSSL
    ssl_is_server = true;
#endif
    return true;
}

Socket *Socket::accept(double timeout) {
    if (sw_unlikely(!is_available(SW_EVENT_READ))) {
        return nullptr;
    }
#ifdef SW_USE_OPENSSL
    if (ssl_is_enable() && sw_unlikely(ssl_context->context == nullptr) && !ssl_context_create()) {
        return nullptr;
    }
#endif
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

    auto *client_sock = new Socket(conn, this);
    if (sw_unlikely(client_sock->get_fd() < 0)) {
        swoole_sys_warning("new Socket() failed");
        set_err(errno);
        delete client_sock;
        return nullptr;
    }

    return client_sock;
}

#ifdef SW_USE_OPENSSL
bool Socket::ssl_context_create() const {
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
        return false;
    }
    socket->ssl_send_ = 1;
    return true;
}

bool Socket::ssl_create(SSLContext *ssl_context) const {
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
    /**
     * If the ssl_context is empty, it indicates that this socket was not a connection
     * returned by a server socket accept, and a new ssl_context needs to be created.
     */
    if (ssl_context->context == nullptr && !ssl_context_create()) {
        return false;
    }
    if (!ssl_create(get_ssl_context())) {
        return false;
    }
    /**
     * The server will use ssl_accept to complete the SSL handshake,
     * while the client will use ssl_connect.
     */
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
        set_err(SW_ERROR_SSL_EMPTY_PEER_CERTIFICATE);
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
    while ((size_t) offset < length) {
        ssize_t sent_bytes = (length - offset > SW_SENDFILE_CHUNK_SIZE) ? SW_SENDFILE_CHUNK_SIZE : length - offset;
        ssize_t n = socket->sendfile(file, &offset, sent_bytes);
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

ssize_t Socket::sendto(std::string host, int port, const void *__buf, size_t __n) {
    if (sw_unlikely(!is_available(SW_EVENT_WRITE))) {
        return -1;
    }

    ssize_t retval = 0;
    network::Address addr;

    if (!socket->is_dgram()) {
        set_err(EPROTONOSUPPORT);
        return -1;
    }

    SW_LOOP_N(2) {
        if (!addr.assign(type, host, port, false)) {
            if (swoole_get_last_error() == SW_ERROR_BAD_HOST_ADDR) {
                host = System::gethostbyname(host, sock_domain, dns_timeout);
                if (!host.empty()) {
                    continue;
                }
            }
            set_err();
            return -1;
        }
        break;
    }

    TimerController timer(&write_timer, write_timeout, this, timer_callback);
    do {
        retval = socket->sendto(addr, __buf, __n, 0);
        swoole_trace_log(SW_TRACE_SOCKET, "sendto %ld/%ld bytes, errno=%d", retval, __n, errno);
    } while (retval < 0 && (errno == EINTR || (socket->catch_write_error(errno) == SW_WAIT && timer.start() &&
                                               wait_event(SW_EVENT_WRITE, &__buf, __n))));
    check_return_value(retval);

    return retval;
}

ssize_t Socket::recvfrom(void *__buf, size_t __n) {
    if (sw_unlikely(!is_available(SW_EVENT_READ))) {
        return -1;
    }
    socket->info.len = sizeof(socket->info.addr);
    return recvfrom(__buf, __n, reinterpret_cast<sockaddr *>(&socket->info.addr), &socket->info.len);
}

ssize_t Socket::recvfrom(void *__buf, size_t __n, sockaddr *_addr, socklen_t *_socklen) {
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
                         socket->get_addr(),
                         socket->get_port(),
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

    while (true) {
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
bool Socket::ssl_shutdown() const {
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
        set_err(EINVAL);
        return false;
    }
}

/**
 * @return bool
 * If true is returned, the related resources of this socket can be released
 * If false is returned, it means that other coroutines are still referencing this socket,
 * and need to wait for the coroutine bound to readable or writable event to execute close,
 * and release when all references are 0
 */
bool Socket::close() {
    if (is_closed()) {
        set_err(EBADF);
        return false;
    }
    if (connected) {
        shutdown();
    }
    if (sw_unlikely(has_bound())) {
        socket->close_wait = 1;
        cancel(SW_EVENT_WRITE);
        cancel(SW_EVENT_READ);
        set_err(SW_ERROR_CO_SOCKET_CLOSE_WAIT);
        return false;
    } else {
        sock_fd = SW_BAD_SOCKET;
        if (dtor_ != nullptr) {
            auto dtor = dtor_;
            dtor_ = nullptr;
            dtor(this);
        }
        return true;
    }
}

/**
 * Warn:
 * the destructor should only be called in following two cases:
 * 1. construct failed
 * 2. called close() and it returns true
 * 3. called close() and it returns false, but it will not be accessed anywhere else
 */
Socket::~Socket() {
#ifdef SW_DEBUG
    if (SwooleG.running) {
        SW_ASSERT(!has_bound() && socket->removed);
    }
#endif
    delete read_buffer;
    delete write_buffer;
    if (socket == nullptr) {
        return;
    }
    /* {{{ release socket resources */
#ifdef SW_USE_OPENSSL
    ssl_shutdown();
#endif
    if (dtor_ != nullptr) {
        dtor_(this);
    }
    socket->free();
}

bool Socket::TimerController::start() {
    if (timeout != 0 && !*timer_pp) {
        enabled = true;
        if (timeout > 0) {
            *timer_pp = swoole_timer_add(timeout, false, callback, socket_);
            return *timer_pp != nullptr;
        }
        *timer_pp = reinterpret_cast<TimerNode *>(-1);
    }
    return true;
}

Socket::TimerController::~TimerController() {
    if (enabled && *timer_pp) {
        if (*timer_pp != reinterpret_cast<TimerNode *>(-1)) {
            swoole_timer_del(*timer_pp);
        }
        *timer_pp = nullptr;
    }
}

Socket::TimeoutSetter::TimeoutSetter(Socket *socket, double _timeout, const enum TimeoutType _type)
    : socket_(socket), timeout(_timeout), type(_type) {
    if (_timeout == 0) {
        return;
    }
    for (uint8_t i = 0; i < SW_ARRAY_SIZE(timeout_type_list); i++) {
        if (_type & timeout_type_list[i]) {
            original_timeout[i] = socket->get_timeout(timeout_type_list[i]);
            if (_timeout != original_timeout[i]) {
                socket->set_timeout(_timeout, timeout_type_list[i]);
            }
        }
    }
}

Socket::TimeoutSetter::~TimeoutSetter() {
    if (timeout == 0) {
        return;
    }
    for (uint8_t i = 0; i < SW_ARRAY_SIZE(timeout_type_list); i++) {
        if (type & timeout_type_list[i]) {
            if (timeout != original_timeout[i]) {
                socket_->set_timeout(original_timeout[i], timeout_type_list[i]);
            }
        }
    }
}

bool Socket::TimeoutController::has_timedout(const enum TimeoutType _type) {
    SW_ASSERT_1BYTE(_type);
    if (timeout > 0) {
        if (sw_unlikely(startup_time == 0)) {
            startup_time = microtime();
        } else {
            double used_time = microtime() - startup_time;
            if (sw_unlikely(timeout - used_time < SW_TIMER_MIN_SEC)) {
                socket_->set_err(ETIMEDOUT);
                return true;
            }
            socket_->set_timeout(timeout - used_time, _type);
        }
    }
    return false;
}

}  // namespace coroutine
}  // namespace swoole
