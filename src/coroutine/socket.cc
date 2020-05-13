#include "swoole_cxx.h"
#include "coroutine.h"
#include "coroutine_socket.h"
#include "coroutine_system.h"
#include "buffer.h"
#include "base64.h"

#include <string>
#include <iostream>
#include <sys/stat.h>

using namespace swoole;
using namespace std;
using swoole::coroutine::System;
using swoole::coroutine::Socket;

double Socket::default_dns_timeout     = SW_DEFAULT_SOCKET_DNS_TIMEOUT;
double Socket::default_connect_timeout = SW_DEFAULT_SOCKET_CONNECT_TIMEOUT;
double Socket::default_read_timeout    = SW_DEFAULT_SOCKET_READ_TIMEOUT;
double Socket::default_write_timeout   = SW_DEFAULT_SOCKET_WRITE_TIMEOUT;
static thread_local char tmp_address[INET6_ADDRSTRLEN + 1];

#ifdef SW_USE_OPENSSL
#ifndef OPENSSL_NO_NEXTPROTONEG

const string HTTP2_H2_ALPN("\x2h2");
const string HTTP2_H2_16_ALPN("\x5h2-16");
const string HTTP2_H2_14_ALPN("\x5h2-14");

static bool ssl_select_proto(const uchar **out, uchar *outlen, const uchar *in, uint inlen, const string &key)
{
    for (auto p = in, end = in + inlen; p + key.size() <= end; p += *p + 1)
    {
        if (std::equal(std::begin(key), std::end(key), p))
        {
            *out = p + 1;
            *outlen = *p;
            return true;
        }
    }
    return false;
}

static bool ssl_select_h2(const uchar **out, uchar *outlen, const uchar *in, uint inlen)
{
    return ssl_select_proto(out, outlen, in, inlen, HTTP2_H2_ALPN) ||
           ssl_select_proto(out, outlen, in, inlen, HTTP2_H2_16_ALPN) ||
           ssl_select_proto(out, outlen, in, inlen, HTTP2_H2_14_ALPN);
}

static int ssl_select_next_proto_cb(SSL *ssl, uchar **out, uchar *outlen, const uchar *in, uint inlen, void *arg)
{
#ifdef SW_LOG_TRACE_OPEN
    string info("[NPN] server offers:\n");
    for (unsigned int i = 0; i < inlen; i += in[i] + 1)
    {
        info += "        * " + string(reinterpret_cast<const char *>(&in[i + 1]), in[i]);
    }
    swTraceLog(SW_TRACE_HTTP2, "[NPN] server offers: %s", info.c_str());
#endif
    if (!ssl_select_h2(const_cast<const unsigned char **>(out), outlen, in, inlen))
    {
        swWarn("HTTP/2 protocol was not selected, expects [h2]");
        return SSL_TLSEXT_ERR_NOACK;
    }
    else
    {
        return SSL_TLSEXT_ERR_OK;
    }
}
#endif
#endif

void Socket::timer_callback(swTimer *timer, swTimer_node *tnode)
{
    Socket *socket = (Socket *) tnode->data;
    socket->set_err(ETIMEDOUT);
    if (sw_likely(tnode == socket->read_timer))
    {
        socket->read_timer = nullptr;
        socket->read_co->resume();
    }
    else if (tnode == socket->write_timer)
    {
        socket->write_timer = nullptr;
        socket->write_co->resume();
    }
    else
    {
        abort();
    }
}

int Socket::readable_event_callback(swReactor *reactor, swEvent *event)
{
    Socket *socket = (Socket *) event->socket->object;
    socket->set_err(0);
#ifdef SW_USE_OPENSSL
    if (sw_unlikely(socket->want_event != SW_EVENT_NULL))
    {
        if (socket->want_event == SW_EVENT_READ)
        {
            socket->write_co->resume();
        }
    }
    else
#endif
    {
        socket->read_co->resume();
    }
    return SW_OK;
}

int Socket::writable_event_callback(swReactor *reactor, swEvent *event)
{
    Socket *socket = (Socket *) event->socket->object;
    socket->set_err(0);
#ifdef SW_USE_OPENSSL
    if (sw_unlikely(socket->want_event != SW_EVENT_NULL))
    {
        if (socket->want_event == SW_EVENT_WRITE)
        {
            socket->read_co->resume();
        }
    }
    else
#endif
    {
        socket->write_co->resume();
    }
    return SW_OK;
}

int Socket::error_event_callback(swReactor *reactor, swEvent *event)
{
    Socket *socket = (Socket *) event->socket->object;
    if (socket->write_co)
    {
        socket->set_err(0);
        socket->write_co->resume();
    }
    // Notice: socket maybe deleted in write coroutine
    if (event->socket->object == socket && !event->socket->removed && socket->read_co)
    {
        socket->set_err(0);
        socket->read_co->resume();
    }
    return SW_OK;
}

bool Socket::add_event(const enum swEvent_type event)
{
    bool ret = true;
    if (sw_likely(!(socket->events & event)))
    {
        if (socket->removed)
        {
            ret = swoole_event_add(socket, event) == SW_OK;
        }
        else
        {
            ret = swoole_event_set(socket, socket->events | event) == SW_OK;
        }
    }
    set_err(ret ? 0 : errno);
    return ret;
}

bool Socket::wait_event(const enum swEvent_type event, const void **__buf, size_t __n)
{
    enum swEvent_type added_event = event;
    Coroutine *co = Coroutine::get_current_safe();
#ifdef SW_USE_OPENSSL
    if (sw_unlikely(socket->ssl && ((event == SW_EVENT_READ && socket->ssl_want_write) || (event == SW_EVENT_WRITE && socket->ssl_want_read))))
    {
        if (sw_likely(socket->ssl_want_write && add_event(SW_EVENT_WRITE)))
        {
            want_event = SW_EVENT_WRITE;
        }
        else if (socket->ssl_want_read && add_event(SW_EVENT_READ))
        {
            want_event = SW_EVENT_READ;
        }
        else
        {
            return false;
        }
        added_event = want_event;
    }
    else
#endif
    if (sw_unlikely(!add_event(event)))
    {
        return false;
    }
    swTraceLog(
        SW_TRACE_SOCKET, "socket#%d blongs to cid#%ld is waiting for %s event",
        sock_fd, co->get_cid(),
#ifdef SW_USE_OPENSSL
        socket->ssl_want_read ? "SSL READ" : socket->ssl_want_write ? "SSL WRITE" :
#endif
        event == SW_EVENT_READ ? "READ" : "WRITE"
    );
    if (sw_likely(event == SW_EVENT_READ))
    {
        read_co = co;
        read_co->yield();
        read_co = nullptr;
    }
    else // if (event == SW_EVENT_WRITE)
    {
        if (sw_unlikely(__n > 0 && *__buf != get_write_buffer()->str))
        {
            swString_clear(write_buffer);
            if (swString_append_ptr(write_buffer, (const char *) *__buf, __n) != SW_OK)
            {
                set_err(ENOMEM);
                goto _failed;
            }
            *__buf = write_buffer->str;
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
        swReactor *reactor = SwooleTG.reactor;
        if (sw_likely(added_event == SW_EVENT_READ))
        {
            swReactor_remove_read_event(reactor, socket);
        }
        else // if (added_event == SW_EVENT_WRITE)
        {
            swReactor_remove_write_event(reactor, socket);
        }
    }
#ifdef SW_USE_OPENSSL
    want_event = SW_EVENT_NULL;
#endif
    swTraceLog(
        SW_TRACE_SOCKET, "socket#%d blongs to cid#%ld trigger %s event",
        sock_fd, co->get_cid(), closed ? "CLOSE" :
        errCode ? errCode == ETIMEDOUT ? "TIMEOUT" : "ERROR" :
        added_event == SW_EVENT_READ ? "READ" : "WRITE"
    );
    return !closed && !errCode;
}

bool Socket::socks5_handshake()
{
    swSocks5 *ctx = socks5_proxy;
    char *p;
    ssize_t n;
    uchar version, method, result;

    swSocks5_pack(ctx->buf, socks5_proxy->l_username > 0 ? 0x02 : 0x00);
    socks5_proxy->state = SW_SOCKS5_STATE_HANDSHAKE;
    if (send(ctx->buf, 3) != 3)
    {
        return false;
    }
    n = recv(ctx->buf, sizeof(ctx->buf));
    if (n <= 0)
    {
        return false;
    }
    version = ctx->buf[0];
    method = ctx->buf[1];
    if (version != SW_SOCKS5_VERSION_CODE)
    {
        swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SOCKS5_UNSUPPORT_VERSION, "SOCKS version is not supported");
        return false;
    }
    if (method != ctx->method)
    {
        swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SOCKS5_UNSUPPORT_METHOD, "SOCKS authentication method not supported");
        return false;
    }
    // authentication
    if (method == SW_SOCKS5_METHOD_AUTH)
    {
        p = ctx->buf;
        // username
        p[0] = 0x01;
        p[1] = ctx->l_username;
        p += 2;
        if (ctx->l_username > 0)
        {
            memcpy(p, ctx->username, ctx->l_username);
            p += ctx->l_username;
        }
        // password
        p[0] = ctx->l_password;
        p += 1;
        if (ctx->l_password > 0)
        {
            memcpy(p, ctx->password, ctx->l_password);
            p += ctx->l_password;
        }
        // auth request
        ctx->state = SW_SOCKS5_STATE_AUTH;
        if (send(ctx->buf, p - ctx->buf) != p - ctx->buf)
        {
            return false;
        }
        // auth response
        n = recv(ctx->buf, sizeof(ctx->buf));
        if (n <= 0)
        {
            return false;
        }
        uchar version = ctx->buf[0];
        uchar status = ctx->buf[1];
        if (version != 0x01)
        {
            swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SOCKS5_UNSUPPORT_VERSION, "SOCKS version is not supported");
            return false;
        }
        if (status != 0x00)
        {
            swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SOCKS5_AUTH_FAILED, "SOCKS username/password authentication failed");
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
    if (ctx->dns_tunnel)
    {
        p[0] = 0x03;
        p[1] = ctx->l_target_host;
        p += 2;
        memcpy(p, ctx->target_host, ctx->l_target_host);
        sw_free((void *) ctx->target_host);
        ctx->target_host = nullptr;
        p += ctx->l_target_host;
        *(uint16_t *) p = htons(ctx->target_port);
        p += 2;
        if (send(ctx->buf, p - ctx->buf) != p - ctx->buf)
        {
            return false;
        }
    }
    else
    {
        p[0] = 0x01;
        p += 1;
        *(uint32_t *) p = htons(ctx->l_target_host);
        p += 4;
        *(uint16_t *) p = htons(ctx->target_port);
        p += 2;
        if (send(ctx->buf, p - ctx->buf) != p - ctx->buf)
        {
            return false;
        }
    }
    // recv response
    n = recv(ctx->buf, sizeof(ctx->buf));
    if (n <= 0)
    {
        return false;
    }
    version = ctx->buf[0];
    if (version != SW_SOCKS5_VERSION_CODE)
    {
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
    if (result == 0)
    {
        ctx->state = SW_SOCKS5_STATE_READY;
        return true;
    }
    else
    {
        swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SOCKS5_SERVER_ERROR, "Socks5 server error, reason: %s", swSocks5_strerror(result));
        return false;
    }
}

bool Socket::http_proxy_handshake()
{
#define HTTP_PROXY_FMT \
    "CONNECT %.*s:%d HTTP/1.1\r\n" \
    "Host: %.*s:%d\r\n" \
    "User-Agent: Swoole/" SWOOLE_VERSION "\r\n" \
    "Proxy-Connection: Keep-Alive\r\n" \

    swString *buffer = get_read_buffer();

    if (!buffer)
    {
        return false;
    }

    //CONNECT
    int n;
    if (http_proxy->password)
    {
        char auth_buf[256];
        char encode_buf[512];
        n = sw_snprintf(
            auth_buf, sizeof(auth_buf), "%.*s:%.*s",
            http_proxy->l_user, http_proxy->user,
            http_proxy->l_password, http_proxy->password
        );
        swBase64_encode((unsigned char *) auth_buf, n, encode_buf);
        n = sw_snprintf(
            buffer->str, buffer->size,
            HTTP_PROXY_FMT "Proxy-Authorization:Basic %s\r\n\r\n",
            http_proxy->l_target_host, http_proxy->target_host, http_proxy->target_port,
            http_proxy->l_target_host, http_proxy->target_host, http_proxy->target_port,
            encode_buf
        );
    }
    else
    {
        n = sw_snprintf(
            buffer->str, buffer->size,
            HTTP_PROXY_FMT "\r\n",
            http_proxy->l_target_host, http_proxy->target_host, http_proxy->target_port,
            http_proxy->l_target_host, http_proxy->target_host, http_proxy->target_port
        );
    }

    swTraceLog(SW_TRACE_HTTP_CLIENT, "proxy request: <<EOF\n%.*sEOF", n, buffer->str);

    if (send(buffer->str, n) != n)
    {
        return false;
    }

    /* use eof protocol (provisional) */
    bool ori_open_eof_check = open_eof_check;
    uint8_t ori_package_eof_len = protocol.package_eof_len;
    char ori_package_eof[SW_DATA_EOF_MAXLEN];
    memcpy(ori_package_eof, SW_STRS(protocol.package_eof));
    open_eof_check = true;
    protocol.package_eof_len = sizeof("\r\n\r\n") - 1;
    memcpy(protocol.package_eof, SW_STRS("\r\n\r\n"));

    n = recv_packet();
    if (n <= 0)
    {
        return false;
    }

    swTraceLog(SW_TRACE_HTTP_CLIENT, "proxy response: <<EOF\n%.*sEOF", n, buffer->str);

    bool ret = false;
    char *buf = buffer->str;
    int len = n;
    int state = 0;
    char *p = buf;
    char *pe = buf + len;
    for (; p < buf + len; p++)
    {
        if (state == 0)
        {
            if (SW_STRCASECT(p, pe - p, "HTTP/1.1") || SW_STRCASECT(p, pe - p, "HTTP/1.0"))
            {
                state = 1;
                p += sizeof("HTTP/1.x") - 1;
            }
            else
            {
                break;
            }
        }
        else if (state == 1)
        {
            if (isspace(*p))
            {
                continue;
            }
            else
            {
                if (SW_STRCASECT(p, pe - p, "200"))
                {
                    state = 2;
                    p += sizeof("200") - 1;
                }
                else
                {
                    break;
                }
            }
        }
        else if (state == 2)
        {
            if (isspace(*p))
            {
                continue;
            }
            else
            {
                if (SW_STRCASECT(p, pe - p, "Connection established"))
                {
                    ret = true;
                }
                break;
            }
        }
    }

    /* revert protocol settings */
    open_eof_check = ori_open_eof_check;
    protocol.package_eof_len = ori_package_eof_len;
    memcpy(protocol.package_eof, SW_STRS(ori_package_eof));

    return ret;
}

void Socket::init_sock_type(enum swSocket_type _sw_type)
{
    type = _sw_type;
    swSocket_get_domain_and_type(_sw_type, &sock_domain, &sock_type);
}

bool Socket::init_sock()
{
    int _fd = swSocket_create(type, 1, 1);
    if (sw_unlikely(_fd < 0))
    {
        return false;
    }
    return init_reactor_socket(_fd);
}

bool Socket::init_reactor_socket(int _fd)
{
    swReactor *reactor = SwooleTG.reactor;
    if (sw_unlikely(!reactor))
    {
        swFatalError(SW_ERROR_OPERATION_NOT_SUPPORT, "operation not support (reactor is not ready)");
    }
    socket = swSocket_new(_fd, SW_FD_CORO_SOCKET);
    if (socket == nullptr)
    {
        return false;
    }

    sock_fd = _fd;
    socket->object = this;
    socket->socket_type = type;
    socket->nonblock = 1;
    socket->cloexec = 1;

    return true;
}

Socket::Socket(int _domain, int _type, int _protocol) :
        sock_domain(_domain), sock_type(_type), sock_protocol(_protocol)
{
    type = convert_to_type(_domain, _type, _protocol);
    if (sw_unlikely(!init_sock()))
    {
        return;
    }
    init_options();
}

Socket::Socket(enum swSocket_type _type)
{
    init_sock_type(_type);
    if (sw_unlikely(!init_sock()))
    {
        return;
    }
    init_options();
}

Socket::Socket(int _fd, enum swSocket_type _type)
{
    init_sock_type(_type);
    if (sw_unlikely(!init_reactor_socket(_fd)))
    {
        return;
    }
    swSocket_set_nonblock(socket);
    init_options();
}

Socket::Socket(int _fd, int _domain, int _type, int _protocol) :
        sock_domain(_domain), sock_type(_type), sock_protocol(_protocol)
{
    type = convert_to_type(_domain, _type, _protocol);
    if (sw_unlikely(!init_reactor_socket(_fd)))
    {
        return;
    }
    swSocket_set_nonblock(socket);
    init_options();
}

Socket::Socket(swSocket *sock, Socket *server_sock)
{
    type = server_sock->type;
    sock_domain = server_sock->sock_domain;
    sock_type = server_sock->sock_type;
    sock_protocol = server_sock->sock_protocol;
    sock_fd = sock->fd;
    socket = sock;
    socket->object = this;
    socket->socket_type = type;
    socket->fdtype = SW_FD_CORO_SOCKET;
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
#ifdef SW_USE_OPENSSL
    open_ssl = server_sock->open_ssl;
    ssl_is_server = server_sock->ssl_is_server;
    if (open_ssl)
    {
        if (server_sock->ssl_context)
        {
            if (!ssl_create(server_sock->ssl_context))
            {
                close();
            }
        }
    }
#endif
}

bool Socket::getsockname(swSocketAddress *sa)
{
    sa->len = sizeof(sa->addr);
    if (::getsockname(sock_fd, (struct sockaddr *) &sa->addr, &sa->len) != 0)
    {
        set_err(errno);
        return false;
    }
    return true;
}

bool Socket::getpeername(swSocketAddress *sa)
{
    sa->len = sizeof(sa->addr);
    if (::getpeername(sock_fd, (struct sockaddr *) &sa->addr, &sa->len) != 0)
    {
        set_err(errno);
        return false;
    }
    return true;
}

const char* Socket::get_ip()
{
    if (type == SW_SOCK_TCP || type == SW_SOCK_UDP)
    {
        if (inet_ntop(AF_INET, &socket->info.addr.inet_v4.sin_addr, tmp_address, sizeof(tmp_address)))
        {
            return tmp_address;
        }
    }
    else if (type == SW_SOCK_TCP6 || type == SW_SOCK_UDP6)
    {
        if (inet_ntop(AF_INET6, &socket->info.addr.inet_v6.sin6_addr, tmp_address, sizeof(tmp_address)))
        {
            return tmp_address;
        }
    }
    else if (type == SW_SOCK_UNIX_STREAM || type == SW_SOCK_UNIX_DGRAM)
    {
        return socket->info.addr.un.sun_path;
    }
    return "unknown";
}

int Socket::get_port()
{
    if (type == SW_SOCK_TCP || type == SW_SOCK_UDP)
    {
        return ntohs(socket->info.addr.inet_v4.sin_port);
    }
    else if (type == SW_SOCK_TCP6 || type == SW_SOCK_UDP6)
    {
        return ntohs(socket->info.addr.inet_v6.sin6_port);
    }
    else
    {
        return 0;
    }
}

bool Socket::connect(const struct sockaddr *addr, socklen_t addrlen)
{
    if (sw_unlikely(!is_available(SW_EVENT_RDWR)))
    {
        return false;
    }
    int retval;
    do
    {
        retval = ::connect(sock_fd, addr, addrlen);
    } while (retval < 0 && errno == EINTR);
    if (retval < 0)
    {
        if (errno != EINPROGRESS)
        {
            set_err(errno);
            return false;
        }
        else
        {
            timer_controller timer(&write_timer, connect_timeout, this, timer_callback);
            if (!timer.start() || !wait_event(SW_EVENT_WRITE))
            {
                if (closed)
                {
                    set_err(ECONNABORTED);
                }
                return false;
            }
            else
            {
                socklen_t len = sizeof(errCode);
                if (getsockopt(sock_fd, SOL_SOCKET, SO_ERROR, &errCode, &len) < 0 || errCode != 0)
                {
                    set_err(errCode);
                    return false;
                }
            }
        }
    }
    set_err(0);
    return true;
}

bool Socket::connect(string _host, int _port, int flags)
{
    if (sw_unlikely(!is_available(SW_EVENT_RDWR)))
    {
        return false;
    }

#ifdef SW_USE_OPENSSL
    if (open_ssl && (socks5_proxy || http_proxy))
    {
        /* If the proxy is enabled, the host will be replaced with the proxy ip,
         * so we have to handle the host first,
         * if the host is not a ip, assign it to ssl_host_name
         */
        union { struct in_addr sin; struct in6_addr sin6; } addr;
        if ((sock_domain == AF_INET && !inet_pton(AF_INET, _host.c_str(), &addr.sin)) ||
                (sock_domain == AF_INET6 && !inet_pton(AF_INET6, _host.c_str(), &addr.sin6)))
        {
            ssl_host_name = _host;
        }
    }
#endif
    if (socks5_proxy)
    {
        //enable socks5 proxy
        socks5_proxy->target_host = sw_strndup((char *) _host.c_str(), _host.size());
        socks5_proxy->l_target_host = _host.size();
        socks5_proxy->target_port = _port;

        _host = socks5_proxy->host;
        _port = socks5_proxy->port;
    }
    else if (http_proxy)
    {
        //enable http proxy
        http_proxy->target_host = sw_strndup((char *) _host.c_str(), _host.size());
        http_proxy->l_target_host = _host.size();
        http_proxy->target_port = _port;

        _host = http_proxy->proxy_host;
        _port = http_proxy->proxy_port;
    }

    if (sock_domain == AF_INET6 || sock_domain == AF_INET)
    {
        if (_port == -1)
        {
            set_err(EINVAL, "Socket of type AF_INET/AF_INET6 requires port argument");
            return false;
        }
        else if (_port == 0 || _port >= 65536)
        {
            set_err(EINVAL, cpp_string::format("Invalid port [%d]", _port));
            return false;
        }
    }

    connect_host = _host;
    connect_port = _port;

    struct sockaddr *_target_addr = nullptr;

    for (int i = 0; i < 2; i++)
    {
        if (sock_domain == AF_INET)
        {
            socket->info.addr.inet_v4.sin_family = AF_INET;
            socket->info.addr.inet_v4.sin_port = htons(_port);

            if (!inet_pton(AF_INET, connect_host.c_str(), &socket->info.addr.inet_v4.sin_addr))
            {
#ifdef SW_USE_OPENSSL
                if (open_ssl)
                {
                    ssl_host_name = connect_host;
                }
#endif
                /* locked like wait_event */
                read_co = write_co = Coroutine::get_current_safe();
                connect_host = System::gethostbyname(connect_host, AF_INET, dns_timeout);
                read_co = write_co = nullptr;
                if (connect_host.empty())
                {
                    set_err(swoole_get_last_error(), swoole_strerror(swoole_get_last_error()));
                    return false;
                }
                continue;
            }
            else
            {
                socket->info.len = sizeof(socket->info.addr.inet_v4);
                _target_addr = (struct sockaddr *) &socket->info.addr.inet_v4;
                break;
            }
        }
        else if (sock_domain == AF_INET6)
        {
            socket->info.addr.inet_v6.sin6_family = AF_INET6;
            socket->info.addr.inet_v6.sin6_port = htons(_port);

            if (!inet_pton(AF_INET6, connect_host.c_str(), &socket->info.addr.inet_v6.sin6_addr))
            {
#ifdef SW_USE_OPENSSL
                if (open_ssl)
                {
                    ssl_host_name = connect_host;
                }
#endif
                connect_host = System::gethostbyname(connect_host, AF_INET6, dns_timeout);
                if (connect_host.empty())
                {
                    set_err(swoole_get_last_error());
                    return false;
                }
                continue;
            }
            else
            {
                socket->info.len = sizeof(socket->info.addr.inet_v6);
                _target_addr = (struct sockaddr *) &socket->info.addr.inet_v6;
                break;
            }
        }
        else if (sock_domain == AF_UNIX)
        {
            if (connect_host.size() >= sizeof(socket->info.addr.un.sun_path))
            {
                return false;
            }
            socket->info.addr.un.sun_family = AF_UNIX;
            memcpy(&socket->info.addr.un.sun_path, connect_host.c_str(), connect_host.size());
            socket->info.len = (socklen_t) (offsetof(struct sockaddr_un, sun_path) + connect_host.size());
            _target_addr = (struct sockaddr *) &socket->info.addr.un;
            break;
        }
        else
        {
            return false;
        }
    }
    if (connect(_target_addr, socket->info.len) == false)
    {
        return false;
    }
    //socks5 proxy
    if (socks5_proxy && socks5_handshake() == false)
    {
        return false;
    }
    //http proxy
    if (http_proxy && !http_proxy->dont_handshake && http_proxy_handshake() == false)
    {
        return false;
    }
#ifdef SW_USE_OPENSSL
    ssl_is_server = false;
    if (open_ssl)
    {
        if (!ssl_handshake())
        {
            return false;
        }
    }
#endif
    return true;
}

bool Socket::check_liveness()
{
    if (!is_connect())
    {
        set_err(ECONNRESET);
        return false;
    }
    else
    {
        char buf;
        errno = 0;
        ssize_t retval = swSocket_peek(socket, &buf, sizeof(buf), 0);
        if (retval == 0 || (retval < 0 && swSocket_error(errno) != SW_WAIT)) {
            set_err(errno ? errno : ECONNRESET);
            return false;
        }
    }
    set_err(0);
    return true;
}

ssize_t Socket::peek(void *__buf, size_t __n)
{
    ssize_t retval = swSocket_peek(socket, __buf, __n, 0);
    set_err(retval < 0 ? errno : 0);
    return retval;
}

bool Socket::poll(enum swEvent_type type)
{
    if (sw_unlikely(!is_available(type)))
    {
        return -1;
    }
    timer_controller timer(&read_timer, read_timeout, this, timer_callback);
    if (timer.start() && wait_event(type))
    {
        return true;
    }
    else
    {
        return false;
    }
}

ssize_t Socket::recv(void *__buf, size_t __n)
{
    if (sw_unlikely(!is_available(SW_EVENT_READ)))
    {
        return -1;
    }
    ssize_t retval;
    timer_controller timer(&read_timer, read_timeout, this, timer_callback);
    do
    {
        retval = swSocket_recv(socket, __buf, __n, 0);
    } while (retval < 0 && swSocket_error(errno) == SW_WAIT && timer.start() && wait_event(SW_EVENT_READ));
    set_err(retval < 0 ? errno : 0);
    return retval;
}

ssize_t Socket::send(const void *__buf, size_t __n)
{
    if (sw_unlikely(!is_available(SW_EVENT_WRITE)))
    {
        return -1;
    }
    ssize_t retval;
    timer_controller timer(&write_timer, write_timeout, this, timer_callback);
    do {
        retval = swSocket_send(socket, __buf, __n, 0);
    } while (retval < 0 && swSocket_error(errno) == SW_WAIT && timer.start() && wait_event(SW_EVENT_WRITE, &__buf, __n));
    set_err(retval < 0 ? errno : 0);
    return retval;
}

ssize_t Socket::read(void *__buf, size_t __n)
{
    if (sw_unlikely(!is_available(SW_EVENT_READ)))
    {
        return -1;
    }
    ssize_t retval;
    timer_controller timer(&read_timer, read_timeout, this, timer_callback);
    do {
        retval = ::read(sock_fd, __buf, __n);
    } while (retval < 0 && swSocket_error(errno) == SW_WAIT && timer.start() && wait_event(SW_EVENT_READ));
    set_err(retval < 0 ? errno : 0);
    return retval;
}

ssize_t Socket::write(const void *__buf, size_t __n)
{
    if (sw_unlikely(!is_available(SW_EVENT_WRITE)))
    {
        return -1;
    }
    ssize_t retval;
    timer_controller timer(&write_timer, write_timeout, this, timer_callback);
    do {
        retval = ::write(sock_fd, (void *) __buf, __n);
    } while (retval < 0 && swSocket_error(errno) == SW_WAIT && timer.start() && wait_event(SW_EVENT_WRITE, &__buf, __n));
    set_err(retval < 0 ? errno : 0);
    return retval;
}

ssize_t Socket::recv_all(void *__buf, size_t __n)
{
    if (sw_unlikely(!is_available(SW_EVENT_READ)))
    {
        return -1;
    }
    ssize_t retval, total_bytes = 0;
    timer_controller timer(&read_timer, read_timeout, this, timer_callback);
    while (true)
    {
        do {
            retval = swSocket_recv(socket, (char *) __buf + total_bytes, __n - total_bytes, 0);
        } while (retval < 0 && swSocket_error(errno) == SW_WAIT && timer.start() && wait_event(SW_EVENT_READ));
        if (sw_unlikely(retval <= 0))
        {
            if (total_bytes == 0)
            {
                total_bytes = retval;
            }
            break;
        }
        total_bytes += retval;
        if ((size_t) total_bytes == __n)
        {
            break;
        }
    }
    set_err(retval < 0 ? errno : 0);
    return total_bytes;
}

ssize_t Socket::send_all(const void *__buf, size_t __n)
{
    if (sw_unlikely(!is_available(SW_EVENT_WRITE)))
    {
        return -1;
    }
    ssize_t retval, total_bytes = 0;
    timer_controller timer(&write_timer, write_timeout, this, timer_callback);
    while (true)
    {
        do
        {
            retval = swSocket_send(socket, (char *) __buf + total_bytes, __n - total_bytes, 0);
        }
        while (retval < 0 && swSocket_error(errno) == SW_WAIT && timer.start() && wait_event(SW_EVENT_WRITE, &__buf, __n));
        /**
         * failed to send
         */
        if (sw_unlikely(retval <= 0))
        {
            if (total_bytes == 0)
            {
                total_bytes = retval;
            }
            break;
        }
        total_bytes += retval;
        if ((size_t) total_bytes == __n)
        {
            break;
        }
    }
    set_err(retval < 0 ? errno : 0);
    return total_bytes;
}

ssize_t Socket::recvmsg(struct msghdr *msg, int flags)
{
    if (sw_unlikely(!is_available(SW_EVENT_READ)))
    {
        return -1;
    }
    ssize_t retval;
    timer_controller timer(&read_timer, read_timeout, this, timer_callback);
    do {
        retval = ::recvmsg(sock_fd, msg, flags);
    } while (retval < 0 && swSocket_error(errno) == SW_WAIT && timer.start() && wait_event(SW_EVENT_READ));
    set_err(retval < 0 ? errno : 0);
    return retval;
}

/**
 * Notice: you must use non-global buffer here (or else it may be changed after yield)
 */
ssize_t Socket::sendmsg(const struct msghdr *msg, int flags)
{
    if (sw_unlikely(!is_available(SW_EVENT_WRITE)))
    {
        return -1;
    }
    ssize_t retval;
    timer_controller timer(&write_timer, write_timeout, this, timer_callback);
    do {
        retval = ::sendmsg(sock_fd, msg, flags);
    } while (retval < 0 && swSocket_error(errno) == SW_WAIT && timer.start() && wait_event(SW_EVENT_WRITE));
    set_err(retval < 0 ? errno : 0);
    return retval;
}

bool Socket::bind(std::string address, int port)
{
    if (sw_unlikely(!is_available(SW_EVENT_NULL)))
    {
        return false;
    }
    if ((sock_domain == AF_INET || sock_domain == AF_INET6) && (port < 0 || port > 65535))
    {
        set_err(EINVAL, cpp_string::format("Invalid port [%d]", port));
        return false;
    }

    bind_address = address;
    bind_port = port;

    struct sockaddr *sock_addr = (struct sockaddr*) &bind_address_info.addr;

    int option = 1;
    if (::setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(int)) < 0)
    {
        swSysWarn("setsockopt(%d, SO_REUSEADDR) failed", sock_fd);
    }

    int retval;
    socklen_t len;
    switch (sock_domain)
    {
    case AF_UNIX:
    {
        struct sockaddr_un *sa = (struct sockaddr_un *) sock_addr;
        sa->sun_family = AF_UNIX;

        if (bind_address.size() >= sizeof(sa->sun_path))
        {
            set_err(
                EINVAL,
                cpp_string::format(
                    "UNIXSocket bind path(%s) is too long, the maxium limit of bytes number is %zu",
                    bind_address.c_str(), sizeof(sa->sun_path)
                )
            );
            return false;
        }
        memcpy(&sa->sun_path, bind_address.c_str(), bind_address.size());

        retval = ::bind(sock_fd, (struct sockaddr *) sa,
        offsetof(struct sockaddr_un, sun_path) + bind_address.size());
        break;
    }

    case AF_INET:
    {
        struct sockaddr_in *sa = (struct sockaddr_in *) sock_addr;
        sa->sin_family = AF_INET;
        sa->sin_port = htons((unsigned short) bind_port);
        if (!inet_aton(bind_address.c_str(), &sa->sin_addr))
        {
            set_err(EINVAL);
            return false;
        }
        retval = ::bind(sock_fd, (struct sockaddr *) sa, sizeof(struct sockaddr_in));
        if (retval == 0 && bind_port == 0)
        {
            len = sizeof(struct sockaddr_in);
            if (::getsockname(sock_fd, (struct sockaddr *) sa, &len) != -1)
            {
                bind_port = ntohs(sa->sin_port);
            }
        }
        break;
    }

    case AF_INET6:
    {
        struct sockaddr_in6 *sa = (struct sockaddr_in6 *) sock_addr;
        sa->sin6_family = AF_INET6;
        sa->sin6_port = htons((unsigned short) bind_port);

        if (!inet_pton(AF_INET6, bind_address.c_str(), &sa->sin6_addr))
        {
            return false;
        }
        retval = ::bind(sock_fd, (struct sockaddr *) sa, sizeof(struct sockaddr_in6));
        if (retval == 0 && bind_port == 0)
        {
            len = sizeof(struct sockaddr_in6);
            if (::getsockname(sock_fd, (struct sockaddr *) sa, &len) != -1)
            {
                bind_port = ntohs(sa->sin6_port);
            }
        }
        break;
    }
    default:
        set_err(EINVAL);
        return false;
    }

    if (retval != 0)
    {
        set_err(errno);
        return false;
    }

    return true;
}

bool Socket::listen(int backlog)
{
    if (sw_unlikely(!is_available(SW_EVENT_NULL)))
    {
        return false;
    }
    this->backlog = backlog <= 0 ? SW_BACKLOG : backlog;
    if (::listen(sock_fd, this->backlog) != 0)
    {
        set_err(errno);
        return false;
    }
#ifdef SW_USE_OPENSSL
    ssl_is_server = true;
    if (open_ssl)
    {
        return ssl_check_context();
    }
#endif
    return true;
}

Socket* Socket::accept(double timeout)
{
    if (sw_unlikely(!is_available(SW_EVENT_READ)))
    {
        return nullptr;
    }
    swSocketAddress client_addr;
    swSocket *conn = swSocket_accept(socket, &client_addr);
    if (conn == nullptr && errno == EAGAIN)
    {
        timer_controller timer(&read_timer, timeout == 0 ? read_timeout : timeout, this, timer_callback);
        if (!timer.start() || !wait_event(SW_EVENT_READ))
        {
            return nullptr;
        }
        conn = swSocket_accept(socket, &client_addr);
    }
    if (conn == nullptr)
    {
        set_err(errno);
        return nullptr;
    }

    Socket *client_sock = new Socket(conn, this);
    if (sw_unlikely(client_sock->get_fd() < 0))
    {
        swSysWarn("new Socket() failed");
        set_err(errno);
        delete client_sock;
        return nullptr;
    }

    return client_sock;
}

#ifdef SW_USE_OPENSSL
bool Socket::ssl_check_context()
{
    if (socket->ssl || ssl_context)
    {
        return true;
    }
    if (swSocket_is_dgram(sock_type))
    {
#ifdef SW_SUPPORT_DTLS
        socket->dtls = 1;
        ssl_option.dtls = 1;
        ssl_option.method = SW_DTLS_CLIENT_METHOD;
#else
        swWarn("DTLS support require openssl-1.1 or later");
        return false;
#endif
    }
    ssl_context = swSSL_get_context(&ssl_option);
    if (ssl_context == nullptr)
    {
        swWarn("swSSL_get_context() error");
        return false;
    }
    if (ssl_option.verify_peer)
    {
        if (swSSL_set_capath(&ssl_option, ssl_context) < 0)
        {
            return false;
        }
    }
    socket->ssl_send = 1;
#if defined(SW_USE_HTTP2) && defined(SW_USE_OPENSSL) && OPENSSL_VERSION_NUMBER >= 0x10002000L
    if (http2)
    {
#ifndef OPENSSL_NO_NEXTPROTONEG
        SSL_CTX_set_next_proto_select_cb(ssl_context, ssl_select_next_proto_cb, nullptr);
#endif
        if (SSL_CTX_set_alpn_protos(ssl_context, (const unsigned char *) SW_STRL(SW_SSL_HTTP2_NPN_ADVERTISE)) < 0)
        {
            return false;
        }
    }
#endif
    return true;
}

bool Socket::ssl_create(SSL_CTX *ssl_context)
{
    if (socket->ssl)
    {
        return true;
    }
    if (swSSL_create(socket, ssl_context, 0) < 0)
    {
        return false;
    }
#ifdef SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER
    SSL_set_mode(socket->ssl, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
#endif
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
    if (ssl_option.tls_host_name)
    {
        SSL_set_tlsext_host_name(socket->ssl, ssl_option.tls_host_name);
    }
    else if (!ssl_option.disable_tls_host_name && !ssl_host_name.empty())
    {
        SSL_set_tlsext_host_name(socket->ssl, ssl_host_name.c_str());
    }
#endif
    return true;
}

bool Socket::ssl_handshake()
{
    if (ssl_handshaked)
    {
        return false;
    }
    if (sw_unlikely(!is_available(SW_EVENT_RDWR)))
    {
        return false;
    }
    if (!ssl_check_context())
    {
        return false;
    }
    if (!ssl_create(ssl_context))
    {
        return false;
    }
    if (!ssl_is_server) {
        while (true)
        {
            if (swSSL_connect(socket) < 0)
            {
                set_err(errno);
                return false;
            }
            if (socket->ssl_state == SW_SSL_STATE_WAIT_STREAM)
            {
                timer_controller timer(&read_timer, read_timeout, this, timer_callback);
                if (!timer.start() || !wait_event(SW_EVENT_READ))
                {
                    return false;
                }
            }
            else if (socket->ssl_state == SW_SSL_STATE_READY)
            {
                break;
            }
        }
    }
    else
    {
        enum swReturn_code retval;
        timer_controller timer(&read_timer, read_timeout, this, timer_callback);

        do
        {
            retval = swSSL_accept(socket);
        }
        while (retval == SW_WAIT && timer.start() && wait_event(SW_EVENT_READ));

        if (retval != SW_READY)
        {
            set_err(SW_ERROR_SSL_BAD_CLIENT);
            return false;
        }
    }
    if (ssl_option.verify_peer)
    {
        if (!ssl_verify(ssl_option.allow_self_signed))
        {
            return false;
        }
    }
    open_ssl = true;
    ssl_handshaked = true;

    return true;
}

bool Socket::ssl_verify(bool allow_self_signed)
{
    if (swSSL_verify(socket, allow_self_signed) < 0)
    {
        set_err(SW_ERROR_SSL_VERIFY_FAILED);
        return false;
    }
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
    if (ssl_option.tls_host_name && swSSL_check_host(socket, ssl_option.tls_host_name) < 0)
    {
        return false;
    }
#endif
    return true;
}

std::string Socket::ssl_get_peer_cert()
{
    if (!socket->ssl)
    {
        return "";
    }
    int n = swSSL_get_peer_cert(socket->ssl, SwooleTG.buffer_stack->str, SwooleTG.buffer_stack->size);
    if (n <= 0)
    {
        return "";
    }
    else
    {
        return std::string(SwooleTG.buffer_stack->str, n);
    }
}
#endif

bool Socket::sendfile(const char *filename, off_t offset, size_t length)
{
    if (sw_unlikely(!is_available(SW_EVENT_WRITE)))
    {
        return false;
    }
    int file_fd = ::open(filename, O_RDONLY);
    if (file_fd < 0)
    {
        set_err(errno, cpp_string::format("open(%s) failed, %s", filename, strerror(errno)));
        return false;
    }

    if (length == 0)
    {
        struct stat file_stat;
        if (::fstat(file_fd, &file_stat) < 0)
        {
            set_err(errno, cpp_string::format("fstat(%s) failed, %s", filename, strerror(errno)));
            ::close(file_fd);
            return false;
        }
        length = file_stat.st_size;
    }
    else
    {
        // total length of the file
        length = offset + length;
    }

    timer_controller timer(&write_timer, write_timeout, this, timer_callback);
    int n, sendn;
    while ((size_t) offset < length)
    {
        sendn = (length - offset > SW_SENDFILE_CHUNK_SIZE) ? SW_SENDFILE_CHUNK_SIZE : length - offset;
#ifdef SW_USE_OPENSSL
        if (socket->ssl)
        {
            n = swSSL_sendfile(socket, file_fd, &offset, sendn);
        }
        else
#endif
        {
            n = ::swoole_sendfile(sock_fd, file_fd, &offset, sendn);
        }
        if (n > 0)
        {
            continue;
        }
        else if (n == 0)
        {
            set_err(SW_ERROR_SYSTEM_CALL_FAIL, "sendfile return zero");
            ::close(file_fd);
            return false;
        }
        else if (errno != EAGAIN)
        {
            set_err(errno, cpp_string::format("sendfile(%d, %s) failed, %s", sock_fd, filename, strerror(errno)));
            ::close(file_fd);
            return false;
        }
        if (!timer.start() || !wait_event(SW_EVENT_WRITE))
        {
            ::close(file_fd);
            return false;
        }
    }
    ::close(file_fd);
    return true;
}

ssize_t Socket::sendto(const string &host, int port, const void *__buf, size_t __n)
{
    if (sw_unlikely(!is_available(SW_EVENT_WRITE)))
    {
        return -1;
    }

    ssize_t retval = 0;
    union
    {
        struct sockaddr_in in;
        struct sockaddr_in6 in6;
        struct sockaddr_un un;
    } addr = {};
    size_t addr_size = 0;

    std::string ip = host;

    for (size_t i = 0; i < 2; i++)
    {
        if (type == SW_SOCK_UDP)
        {
            if (::inet_aton(ip.c_str(), &addr.in.sin_addr) == 0)
            {
                read_co = write_co = Coroutine::get_current_safe();
                ip = System::gethostbyname(host, sock_domain, dns_timeout);
                read_co = write_co = nullptr;
                if (ip.empty())
                {
                    set_err(swoole_get_last_error(), swoole_strerror(swoole_get_last_error()));
                    return -1;
                }
                continue;
            }
            else
            {
                addr.in.sin_family = AF_INET;
                addr.in.sin_port = htons(port);
                addr_size = sizeof(addr.in);
                break;
            }
        }
        else if (type == SW_SOCK_UDP6)
        {
            if (::inet_pton(AF_INET6, ip.c_str(), &addr.in6.sin6_addr) == 0)
            {
                read_co = write_co = Coroutine::get_current_safe();
                ip = System::gethostbyname(host, sock_domain, dns_timeout);
                read_co = write_co = nullptr;
                if (ip.empty())
                {
                    set_err(swoole_get_last_error(), swoole_strerror(swoole_get_last_error()));
                    return -1;
                }
                continue;
            }
            else
            {
                addr.in6.sin6_port = (uint16_t) htons(port);
                addr.in6.sin6_family = AF_INET6;
                addr_size = sizeof(addr.in6);
                break;
            }
        }
        else if (type == SW_SOCK_UNIX_DGRAM)
        {
            addr.un.sun_family = AF_UNIX;
            strncpy(addr.un.sun_path, host.c_str(), sizeof(addr.un.sun_path) - 1);
            addr_size = sizeof(addr.un);
            break;
        }
        else
        {
            set_err(EPROTONOSUPPORT);
            retval = -1;
            break;
        }
    }

    if (addr_size > 0)
    {
        timer_controller timer(&write_timer, write_timeout, this, timer_callback);
        do {
            retval = ::sendto(sock_fd, __buf, __n, 0, (struct sockaddr *) &addr, addr_size);
            swTraceLog(SW_TRACE_SOCKET, "sendto %ld/%ld bytes, errno=%d", retval, __n, errno);
        } while (retval < 0 && (errno == EINTR || (swSocket_error(errno) == SW_WAIT && timer.start() && wait_event(SW_EVENT_WRITE, &__buf, __n))));
        set_err(retval < 0 ? errno : 0);
    }

    return retval;
}

ssize_t Socket::recvfrom(void *__buf, size_t __n)
{
    if (sw_unlikely(!is_available(SW_EVENT_READ)))
    {
        return -1;
    }
    socket->info.len = sizeof(socket->info.addr);
    return recvfrom(__buf, __n, (struct sockaddr*) &socket->info.addr, &socket->info.len);
}

ssize_t Socket::recvfrom(void *__buf, size_t __n, struct sockaddr* _addr, socklen_t *_socklen)
{
    if (sw_unlikely(!is_available(SW_EVENT_READ)))
    {
        return -1;
    }
    ssize_t retval;
    timer_controller timer(&read_timer, read_timeout, this, timer_callback);
    do {
        retval = ::recvfrom(sock_fd, __buf, __n, 0, _addr, _socklen);
        swTraceLog(SW_TRACE_SOCKET, "recvfrom %ld/%ld bytes, errno=%d", retval, __n, errno);
    } while (retval < 0 && ((errno == EINTR) || (swSocket_error(errno) == SW_WAIT && timer.start() && wait_event(SW_EVENT_READ))));
    set_err(retval < 0 ? errno : 0);
    return retval;
}

/**
 * recv packet with protocol
 */
ssize_t Socket::recv_packet(double timeout)
{
    if (sw_unlikely(!is_available(SW_EVENT_READ)))
    {
        return -1;
    }

    ssize_t buf_len = SW_BUFFER_SIZE_STD;
    ssize_t retval;
    timer_controller timer(&read_timer, timeout == 0 ? read_timeout : timeout, this, timer_callback);

    if (sw_unlikely(!timer.start()))
    {
        return 0;
    }
    get_read_buffer();

    //unprocessed data
    if (read_buffer->offset > 0)
    {
        swString_sub(read_buffer, read_buffer->offset, read_buffer->length);
    }

    if (open_length_check)
    {
        uint32_t header_len = protocol.package_length_offset + protocol.package_length_size;
        if (read_buffer->length > 0)
        {
            if (
                read_buffer->length >= header_len ||
                (protocol.package_length_size == 0 && protocol.package_length_type == '\0') // custom package_length_func
            )
            {
                goto _get_length;
            }
            else
            {
                goto _recv_header;
            }
        }

        _recv_header:
        retval = recv(read_buffer->str + read_buffer->length, header_len - read_buffer->length);
        if (retval <= 0)
        {
            return retval;
        }
        else
        {
            read_buffer->length += retval;
        }

        _get_length:
        protocol.real_header_length = 0;
        buf_len = protocol.get_package_length(&protocol, socket, read_buffer->str, (uint32_t) read_buffer->length);
        swTraceLog(SW_TRACE_SOCKET, "packet_len=%ld, length=%ld", buf_len, read_buffer->length);
        if (buf_len < 0)
        {
            set_err(SW_ERROR_PACKAGE_LENGTH_NOT_FOUND, "get package length failed");
            return 0;
        }
        else if (buf_len == 0)
        {
            if (protocol.real_header_length != 0)
            {
                header_len = protocol.real_header_length;
            }
            goto _recv_header;
        }
        else if (buf_len > protocol.package_max_length)
        {
            set_err(SW_ERROR_PACKAGE_LENGTH_TOO_LARGE, "remote packet is too big");
            return 0;
        }

        if ((size_t) buf_len == read_buffer->length)
        {
            read_buffer->length = 0;
            return buf_len;
        }
        else if ((size_t) buf_len < read_buffer->length)
        {
            //unprocessed data (offset will always be zero)
            read_buffer->length -= buf_len;
            read_buffer->offset = buf_len;
            return buf_len;
        }

        if ((size_t) buf_len > read_buffer->size)
        {
            if (swString_extend(read_buffer, buf_len) < 0)
            {
                read_buffer->length = 0;
                set_err(ENOMEM);
                return -1;
            }
        }

        retval = recv_all(read_buffer->str + read_buffer->length, buf_len - read_buffer->length);
        if (retval > 0)
        {
            read_buffer->length += retval;
            if (read_buffer->length != (size_t) buf_len)
            {
                retval = 0;
            }
            else
            {
                read_buffer->length = 0;
                return buf_len;
            }
        }
    }
    else if (open_eof_check)
    {
        int eof = -1;
        char *buf;

        if (read_buffer->length > 0)
        {
            goto _find_eof;
        }

        while (1)
        {
            buf = read_buffer->str + read_buffer->length;
            buf_len = read_buffer->size - read_buffer->length;

            if (buf_len > SW_BUFFER_SIZE_BIG)
            {
                buf_len = SW_BUFFER_SIZE_BIG;
            }

            retval = recv(buf, buf_len);
            if (retval < 0)
            {
                read_buffer->length = 0;
                return -1;
            }
            else if (retval == 0)
            {
                read_buffer->length = 0;
                return 0;
            }

            read_buffer->length += retval;

            if (read_buffer->length < protocol.package_eof_len)
            {
                continue;
            }

            _find_eof:
            eof = swoole_strnpos(read_buffer->str, read_buffer->length, protocol.package_eof, protocol.package_eof_len);
            if (eof >= 0)
            {
                eof += protocol.package_eof_len;
                if (read_buffer->length > (uint32_t) eof)
                {
                    read_buffer->length -= eof;
                    read_buffer->offset += eof;
                }
                else
                {
                    read_buffer->length = 0;
                }
                return eof;
            }
            else
            {
                if (read_buffer->length == protocol.package_max_length)
                {
                    read_buffer->length = 0;
                    set_err(EPROTO, "no package eof");
                    return -1;
                }
                else if (read_buffer->length == read_buffer->size)
                {
                    if (read_buffer->size < protocol.package_max_length)
                    {
                        size_t new_size = read_buffer->size * 2;
                        if (new_size > protocol.package_max_length)
                        {
                            new_size = protocol.package_max_length;
                        }
                        if (swString_extend(read_buffer, new_size) < 0)
                        {
                            read_buffer->length = 0;
                            set_err(ENOMEM);
                            return -1;
                        }
                    }
                }
            }
        }
        read_buffer->length = 0;
    }
    else
    {
        retval = recv(read_buffer->str, read_buffer->size);
    }

    return retval;
}

bool Socket::shutdown(int __how)
{
    set_err(0);
    if (!is_connect() || (__how == SHUT_RD && shutdown_read) || (__how == SHUT_WR && shutdown_write))
    {
        errno = ENOTCONN;
    }
    else
    {
#ifdef SW_USE_OPENSSL
        if (socket->ssl)
        {
            SSL_set_quiet_shutdown(socket->ssl, 1);
            SSL_shutdown(socket->ssl);
        }
#endif
        if (::shutdown(sock_fd, __how) == 0 || errno == ENOTCONN)
        {
            if (errno == ENOTCONN)
            {
                // connection reset by server side
                __how = SHUT_RDWR;
            }
            switch (__how)
            {
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
            if (shutdown_read && shutdown_write)
            {
                activated = false;
            }
            return true;
        }
    }
    set_err(errno);
    return false;
}

#ifdef SW_USE_OPENSSL
bool Socket::ssl_shutdown()
{
    if (socket->ssl)
    {
        swSSL_close(socket);
    }
    if (ssl_context)
    {
        swSSL_free_context(ssl_context);
        ssl_context = nullptr;
    }
    return true;
}
#endif

bool Socket::cancel(const enum swEvent_type event)
{
    if (!has_bound(event))
    {
        return false;
    }
    if (event == SW_EVENT_READ)
    {
        set_err(ECANCELED);
        read_co->resume();
        return true;
    }
    else if (event == SW_EVENT_WRITE)
    {
        set_err(ECANCELED);
        write_co->resume();
        return true;
    }
    else
    {
        return false;
    }
}

/**
 * @return bool (whether it can be freed)
 * you can access errCode member to get error information
 */
bool Socket::close()
{
    if (sock_fd < 0)
    {
        set_err(EBADF);
        return true;
    }
    if (sw_unlikely(has_bound()))
    {
        if (closed)
        {
            // close operation is in processing
            set_err(EINPROGRESS);
            return false;
        }
        if (activated)
        {
            shutdown();
        }
        closed = true;
        if (write_co)
        {
            set_err(ECONNRESET);
            write_co->resume();
        }
        if (read_co)
        {
            set_err(ECONNRESET);
            read_co->resume();
        }
        return false;
    }
    else
    {
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
Socket::~Socket()
{
    if (socket == nullptr)
    {
        return;
    }
#ifdef SW_DEBUG
    if (SwooleG.running)
    {
        SW_ASSERT(!has_bound() && socket->removed);
    }
#endif
    if (read_buffer)
    {
        swString_free(read_buffer);
    }
    if (write_buffer)
    {
        swString_free(write_buffer);
    }
    /* {{{ release socket resources */
#ifdef SW_USE_OPENSSL
    ssl_shutdown();
    if (ssl_option.cert_file)
    {
        sw_free(ssl_option.cert_file);
    }
    if (ssl_option.key_file)
    {
        sw_free(ssl_option.key_file);
    }
    if (ssl_option.passphrase)
    {
        sw_free(ssl_option.passphrase);
    }
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
    if (ssl_option.tls_host_name)
    {
        sw_free(ssl_option.tls_host_name);
    }
#endif
    if (ssl_option.cafile)
    {
        sw_free(ssl_option.cafile);
    }
    if (ssl_option.capath)
    {
        sw_free(ssl_option.capath);
    }
    ssl_option = {};
#endif
    if (socket->in_buffer)
    {
        swBuffer_free(socket->in_buffer);
    }
    if (socket->out_buffer)
    {
        swBuffer_free(socket->out_buffer);
    }
    if (sock_domain == AF_UNIX && !bind_address.empty())
    {
        ::unlink(bind_address_info.addr.un.sun_path);
        bind_address_info = {};
    }
    if (sock_type == SW_SOCK_UNIX_DGRAM)
    {
        ::unlink(socket->info.addr.un.sun_path);
    }
    swSocket_free(socket);
}
