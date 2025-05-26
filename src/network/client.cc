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

#include "swoole.h"
#include "swoole_api.h"
#include "swoole_string.h"
#include "swoole_socket.h"
#include "swoole_timer.h"
#include "swoole_protocol.h"
#include "swoole_client.h"
#include "swoole_proxy.h"
#include "swoole_async.h"

#include <cassert>

namespace swoole {
namespace network {

static int Client_inet_addr(Client *cli, const char *host, int port);
static int Client_tcp_connect_sync(Client *cli, const char *host, int port, double _timeout, int nonblock);
static int Client_tcp_connect_async(Client *cli, const char *host, int port, double timeout, int nonblock);
static int Client_udp_connect(Client *cli, const char *host, int port, double _timeout, int udp_connect);

static ssize_t Client_tcp_send_sync(Client *cli, const char *data, size_t length, int flags);
static ssize_t Client_tcp_send_async(Client *cli, const char *data, size_t length, int flags);
static ssize_t Client_udp_send(Client *cli, const char *data, size_t length, int flags);

static int Client_tcp_sendfile_sync(Client *cli, const char *filename, off_t offset, size_t length);
static int Client_tcp_sendfile_async(Client *cli, const char *filename, off_t offset, size_t length);

static ssize_t Client_tcp_recv_sync(Client *cli, char *data, size_t len, int flags);
static ssize_t Client_udp_recv(Client *cli, char *data, size_t len, int flags);

static int Client_onDgramRead(Reactor *reactor, Event *event);
static int Client_onStreamRead(Reactor *reactor, Event *event);
static int Client_onWrite(Reactor *reactor, Event *event);
static int Client_onError(Reactor *reactor, Event *event);
static void Client_onTimeout(Timer *timer, TimerNode *tnode);
static void Client_onResolveCompleted(AsyncEvent *event);
static int Client_onPackage(const Protocol *proto, Socket *conn, const RecvData *rdata);

static sw_inline void execute_onConnect(Client *cli) {
    if (cli->timer) {
        swoole_timer_del(cli->timer);
        cli->timer = nullptr;
    }
    cli->onConnect(cli);
}

void Client::init_reactor(Reactor *reactor) {
    reactor->set_handler(SW_FD_STREAM_CLIENT | SW_EVENT_READ, Client_onStreamRead);
    reactor->set_handler(SW_FD_DGRAM_CLIENT | SW_EVENT_READ, Client_onDgramRead);
    reactor->set_handler(SW_FD_STREAM_CLIENT | SW_EVENT_WRITE, Client_onWrite);
    reactor->set_handler(SW_FD_STREAM_CLIENT | SW_EVENT_ERROR, Client_onError);
}

Client::Client(SocketType _type, bool _async) : async(_async) {
    fd_type = Socket::is_stream(_type) ? SW_FD_STREAM_CLIENT : SW_FD_DGRAM_CLIENT;
    socket = swoole::make_socket(_type, fd_type, (async ? SW_SOCK_NONBLOCK : 0) | SW_SOCK_CLOEXEC);
    if (socket == nullptr) {
        swoole_sys_warning("socket() failed");
        return;
    }

    socket->object = this;
    input_buffer_size = SW_CLIENT_BUFFER_SIZE;
    socket->chunk_size = SW_SEND_BUFFER_SIZE;
    socket->dont_restart = 1;

    if (socket->is_stream()) {
        recv_ = Client_tcp_recv_sync;
        if (async) {
            connect_ = Client_tcp_connect_async;
            send_ = Client_tcp_send_async;
            sendfile_ = Client_tcp_sendfile_async;
        } else {
            connect_ = Client_tcp_connect_sync;
            send_ = Client_tcp_send_sync;
            sendfile_ = Client_tcp_sendfile_sync;
        }
    } else {
        connect_ = Client_udp_connect;
        recv_ = Client_udp_recv;
        send_ = Client_udp_send;
    }

    Socket::get_domain_and_type(_type, &sock_domain_, &sock_type_);
    remote_addr.type = _type;

    protocol.package_length_type = 'N';
    protocol.package_length_size = 4;
    protocol.package_body_offset = 0;
    protocol.package_max_length = SW_INPUT_BUFFER_SIZE;
    protocol.onPackage = Client_onPackage;
}

int Client::bind(const std::string &addr, int port) {
    if (socket->set_reuse_addr() < 0) {
        swoole_sys_warning("setsockopt(%d, SO_REUSEADDR) failed", socket->get_fd());
    }
    if (socket->bind(addr, port) < 0) {
        swoole_set_last_error(errno);
        return SW_ERR;
    }
    return SW_OK;
}

void Client::set_socks5_proxy(const std::string &host, int port, const std::string &user, const std::string &pwd) {
    socks5_proxy.reset(Socks5Proxy::create(host, port, user, pwd));
}

void Client::set_http_proxy(const std::string &host, int port, const std::string &user, const std::string &pwd) {
    http_proxy.reset(HttpProxy::create(host, port, user, pwd));
}

int Client::sleep() {
    int ret;
    if (socket->events & SW_EVENT_WRITE) {
        ret = swoole_event_set(socket, SW_EVENT_WRITE);
    } else {
        ret = swoole_event_del(socket);
    }
    if (ret == SW_OK) {
        sleep_ = true;
    }
    return ret;
}

int Client::wakeup() {
    int ret;
    if (socket->events & SW_EVENT_WRITE) {
        ret = swoole_event_set(socket, SW_EVENT_READ | SW_EVENT_WRITE);
    } else {
        ret = swoole_event_add(socket, SW_EVENT_READ);
    }
    if (ret == SW_OK) {
        sleep_ = false;
    }
    return ret;
}

int Client::sendto(const std::string &host, int port, const char *data, size_t len) {
    if (!socket->is_dgram()) {
        swoole_set_last_error(SW_ERROR_OPERATION_NOT_SUPPORT);
        swoole_warning("only supports SWOOLE_SOCK_(UDP/UDP6/UNIX_DGRAM)");
        return SW_ERR;
    }

    Address remote_addr;
    if (!remote_addr.assign(socket->socket_type, host, port, true)) {
        return SW_ERR;
    }

    double ori_timeout = Socket::default_write_timeout;
    Socket::default_write_timeout = timeout;

    if (socket->sendto(remote_addr, data, len, 0) < 0) {
        swoole_set_last_error(errno);
        return SW_ERR;
    }

    Socket::default_write_timeout = ori_timeout;
    return SW_OK;
}

int Client::get_peer_name(Address *addr) {
    if (socket->is_dgram()) {
        *addr = remote_addr;
        return SW_OK;
    } else {
        return socket->get_peer_name(addr);
    }
}

int Client::shutdown(int _how) {
    if (!socket || closed) {
        return SW_ERR;
    }
    swoole_trace_log(SW_TRACE_CLIENT, "how=%d, fd=%d", _how, socket->fd);
    if (_how == SHUT_RD) {
        if (shutdown_read || shutdow_rw || ::shutdown(socket->fd, SHUT_RD)) {
            return SW_ERR;
        } else {
            shutdown_read = true;
            return SW_OK;
        }
    } else if (_how == SHUT_WR) {
        if (shutdown_write || shutdow_rw || ::shutdown(socket->fd, SHUT_WR) < 0) {
            return SW_ERR;
        } else {
            shutdown_write = true;
            return SW_OK;
        }
    } else if (_how == SHUT_RDWR) {
        if (shutdow_rw || ::shutdown(socket->fd, SHUT_RDWR) < 0) {
            return SW_ERR;
        } else {
            shutdown_read = true;
            return SW_OK;
        }
    } else {
        return SW_ERR;
    }
}

int Client::socks5_handshake(const char *recv_data, size_t length) {
    Socks5Proxy *ctx = socks5_proxy.get();
    char *buf = ctx->buf;
    uchar version, status, result, method;

    if (ctx->state == SW_SOCKS5_STATE_HANDSHAKE) {
        version = recv_data[0];
        method = recv_data[1];
        if (version != SW_SOCKS5_VERSION_CODE) {
            swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SOCKS5_UNSUPPORT_VERSION, "SOCKS version is not supported");
            return SW_ERR;
        }
        if (method != ctx->method) {
            swoole_error_log(
                SW_LOG_NOTICE, SW_ERROR_SOCKS5_UNSUPPORT_METHOD, "SOCKS authentication method is not supported");
            return SW_ERR;
        }
        // authenticate request
        if (method == SW_SOCKS5_METHOD_AUTH) {
            buf[0] = 0x01;
            buf[1] = ctx->username.length();

            buf += 2;
            memcpy(buf, ctx->username.c_str(), ctx->username.length());
            buf += ctx->username.length();
            buf[0] = ctx->password.length();
            memcpy(buf + 1, ctx->password.c_str(), ctx->password.length());

            ctx->state = SW_SOCKS5_STATE_AUTH;

            return send(ctx->buf, ctx->username.length() + ctx->password.length() + 3, 0) > 0 ? SW_OK : SW_ERR;
        }
        // send connect request
        else {
        _send_connect_request:
            buf[0] = SW_SOCKS5_VERSION_CODE;
            buf[1] = 0x01;
            buf[2] = 0x00;

            ctx->state = SW_SOCKS5_STATE_CONNECT;

            if (ctx->dns_tunnel) {
                buf[3] = 0x03;
                buf[4] = ctx->target_host.length();
                buf += 5;
                memcpy(buf, ctx->target_host.c_str(), ctx->target_host.length());
                buf += ctx->target_host.length();
                *(uint16_t *) buf = htons(ctx->target_port);
                return send(ctx->buf, ctx->target_host.length() + 7, 0) > 0 ? SW_OK : SW_ERR;
            } else {
                buf[3] = 0x01;
                buf += 4;
                *(uint32_t *) buf = htons(ctx->target_host.length());
                buf += 4;
                *(uint16_t *) buf = htons(ctx->target_port);
                return send(ctx->buf, ctx->target_host.length() + 7, 0) > 0 ? SW_OK : SW_ERR;
            }
        }
    } else if (ctx->state == SW_SOCKS5_STATE_AUTH) {
        version = recv_data[0];
        status = recv_data[1];
        if (version != 0x01) {
            swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SOCKS5_UNSUPPORT_VERSION, "SOCKS version is not supported");
            return SW_ERR;
        }
        if (status != 0) {
            swoole_error_log(
                SW_LOG_NOTICE, SW_ERROR_SOCKS5_AUTH_FAILED, "SOCKS username/password authentication failed");
            return SW_ERR;
        }
        goto _send_connect_request;
    } else if (ctx->state == SW_SOCKS5_STATE_CONNECT) {
        version = recv_data[0];
        if (version != SW_SOCKS5_VERSION_CODE) {
            swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SOCKS5_UNSUPPORT_VERSION, "SOCKS version is not supported");
            return SW_ERR;
        }
        result = recv_data[1];
#if 0
        uchar reg = recv_data[2];
        uchar type = recv_data[3];
        uint32_t ip = *(uint32_t *) (recv_data + 4);
        uint16_t port = *(uint16_t *) (recv_data + 8);
#endif
        if (result == 0) {
            ctx->state = SW_SOCKS5_STATE_READY;
            return SW_OK;
        } else {
            swoole_error_log(SW_LOG_NOTICE,
                             SW_ERROR_SOCKS5_SERVER_ERROR,
                             "Socks5 server error, reason :%s",
                             Socks5Proxy::strerror(result));
            return SW_ERR;
        }
    }
    return SW_OK;
}

#ifdef SW_USE_OPENSSL
#ifdef SW_SUPPORT_DTLS
void Client::enable_dtls() {
    ssl_context->protocols = SW_SSL_DTLS;
    socket->dtls = 1;
    socket->chunk_size = SW_SSL_BUFFER_SIZE;
    send_ = Client_tcp_send_sync;
    recv_ = Client_tcp_recv_sync;
}
#endif

int Client::enable_ssl_encrypt() {
    if (ssl_context) {
        return SW_ERR;
    }
    ssl_context = std::make_shared<SSLContext>();
    open_ssl = true;
#ifdef SW_SUPPORT_DTLS
    if (socket->is_dgram()) {
        enable_dtls();
    }
#else
    {
        swoole_warning("DTLS support require openssl-1.1 or later");
        return SW_ERR;
    }
#endif
    return SW_OK;
}

int Client::ssl_handshake() {
    if (socket->ssl_state == SW_SSL_STATE_READY) {
        return SW_ERR;
    }
    if (!ssl_context->ready()) {
        ssl_context->http_v2 = http2;
        if (!ssl_context->create()) {
            return SW_ERR;
        }
    }
    if (!socket->ssl) {
        socket->ssl_send_ = 1;
        if (socket->ssl_create(ssl_context.get(), SW_SSL_CLIENT) < 0) {
            return SW_ERR;
        }
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
        if (!ssl_context->tls_host_name.empty()) {
            SSL_set_tlsext_host_name(socket->ssl, ssl_context->tls_host_name.c_str());
        }
#endif
    }
    if (socket->ssl_connect() < 0) {
        return SW_ERR;
    }
    if (socket->ssl_state == SW_SSL_STATE_READY && ssl_context->verify_peer) {
        if (ssl_verify(ssl_context->allow_self_signed) < 0) {
            return SW_ERR;
        }
    }
    return SW_OK;
}

int Client::ssl_verify(int allow_self_signed) {
    if (!socket->ssl_verify(allow_self_signed)) {
        return SW_ERR;
    }
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
    if (!ssl_context->tls_host_name.empty() && !socket->ssl_check_host(ssl_context->tls_host_name.c_str())) {
        return SW_ERR;
    }
#endif
    return SW_OK;
}

#endif

static int Client_inet_addr(Client *cli, const char *host, int port) {
    if (!cli->host_preseted) {
        // enable socks5 proxy
        if (cli->socks5_proxy) {
            cli->socks5_proxy->target_host = host;
            cli->socks5_proxy->target_port = port;

            host = cli->socks5_proxy->host.c_str();
            port = cli->socks5_proxy->port;
        }

        // enable http proxy
        if (cli->http_proxy) {
            cli->http_proxy->target_host = host;
            cli->http_proxy->target_port = port;

            host = cli->http_proxy->host.c_str();
            port = cli->http_proxy->port;
        }

        cli->server_host = host;
        cli->server_port = port;

        cli->host_preseted = true;
    }

    if (!cli->server_addr.assign(cli->socket->socket_type, host, port, !cli->async)) {
        if (!cli->dns_completed && swoole_get_last_error() == SW_ERROR_BAD_HOST_ADDR) {
            cli->wait_dns = true;
        } else {
            return SW_ERR;
        }
    }

    return SW_OK;
}

Client::~Client() {
    if (!socket) {
        return;
    }
    assert(socket->fd != 0);
    // remove from reactor
    if (!closed) {
        close();
    }
    // clear buffer
    if (buffer) {
        delete buffer;
        buffer = nullptr;
    }
    if (async) {
        socket->free();
    } else {
        delete socket;
    }
}

int Client::close() {
    if (socket == nullptr || closed) {
        return SW_ERR;
    }
    closed = true;

#ifdef SW_USE_OPENSSL
    if (open_ssl && ssl_context) {
        if (socket->ssl) {
            socket->ssl_close();
        }
    }
#endif

    if (socket->socket_type == SW_SOCK_UNIX_DGRAM) {
        unlink(socket->info.addr.un.sun_path);
    }
    if (async) {
        // remove from reactor
        if (!socket->removed) {
            swoole_event_del(socket);
        }
        if (timer) {
            swoole_timer_del(timer);
            timer = nullptr;
        }
        // onClose callback
        if (active) {
            active = false;
            onClose(this);
        }
    } else {
        active = false;
    }

    if (socket->fd == -1) {
        return SW_OK;
    }

    /**
     * fd marked -1, prevent double close
     */
    const int fd = socket->fd;
    socket->fd = -1;
    swoole_trace_log(SW_TRACE_CLIENT, "fd=%d", fd);

    return ::close(fd);
}

static int Client_tcp_connect_sync(Client *cli, const char *host, int port, double timeout, int nonblock) {
    int ret;

    cli->timeout = timeout;

    if (Client_inet_addr(cli, host, port) < 0) {
        return SW_ERR;
    }

    if (nonblock) {
        cli->socket->set_nonblock();
    } else {
        if (cli->timeout > 0) {
            cli->socket->set_timeout(timeout);
        }
#ifndef HAVE_KQUEUE
        cli->socket->set_block();
#endif
    }
    while (true) {
#ifdef HAVE_KQUEUE
        if (nonblock == 2) {
            // special case on macOS
            ret = cli->socket->connect(cli->server_addr);
        } else {
            ret = cli->socket->connect_sync(cli->server_addr, cli->timeout);
        }
#else
        ret = cli->socket->connect(cli->server_addr);
#endif
        if (ret < 0) {
            if (errno == EINTR) {
                continue;
            } else if (errno == EINPROGRESS) {
                if (nonblock) {
                    cli->async_connect = true;
                } else {
                    errno = ETIMEDOUT;
                }
            }
            swoole_set_last_error(errno);
        }
        break;
    }

    if (ret >= 0) {
        cli->active = true;

        if (cli->socks5_proxy) {
            char buf[1024];
            Socks5Proxy::pack(buf, cli->socks5_proxy->username.empty() ? 0x00 : 0x02);
            if (cli->send(buf, 3, 0) < 0) {
                return SW_ERR;
            }
            cli->socks5_proxy->state = SW_SOCKS5_STATE_HANDSHAKE;
            while (true) {
                ssize_t n = cli->recv(buf, sizeof(buf), 0);
                if (n > 0) {
                    if (cli->socks5_handshake(buf, n) < 0) {
                        return SW_ERR;
                    }
                    if (cli->socks5_proxy->state == SW_SOCKS5_STATE_READY) {
                        break;
                    } else {
                        continue;
                    }
                }
                return SW_ERR;
            }
        } else if (cli->http_proxy) {
            auto proxy_buf = sw_tg_buffer();
            const std::string *host_name = cli->get_http_proxy_host_name();
            size_t n_write = cli->http_proxy->pack(proxy_buf, host_name);
            if (cli->send(proxy_buf->str, n_write, 0) < 0) {
                return SW_ERR;
            }
            ssize_t n_read = cli->recv(proxy_buf->str, proxy_buf->size, 0);
            if (n_read <= 0) {
                return SW_ERR;
            }
            proxy_buf->length = n_read;
            if (!cli->http_proxy->handshake(proxy_buf)) {
                return SW_ERR;
            }
        }

#ifdef SW_USE_OPENSSL
        if (cli->open_ssl && cli->ssl_handshake() < 0) {
            return SW_ERR;
        }
#endif
    }

    return ret;
}

static int Client_dns_lookup(Client *cli) {
    AsyncEvent ev{};
    auto req = new GethostbynameRequest(cli->server_host, cli->sock_domain_);
    ev.data = std::shared_ptr<AsyncRequest>(req);
    ev.object = cli;
    ev.handler = async::handler_gethostbyname;
    ev.callback = Client_onResolveCompleted;

    if (async::dispatch(&ev) == nullptr) {
        return SW_ERR;
    } else {
        return SW_OK;
    }
}

static int Client_tcp_connect_async(Client *cli, const char *host, int port, double timeout, int nonblock) {
    int ret;

    cli->timeout = timeout;

    if (!cli->buffer) {
        cli->buffer = new String(cli->input_buffer_size);
    }

    if (!(cli->onConnect && cli->onError && cli->onClose && cli->onReceive)) {
        swoole_warning("onConnect/onError/onReceive/onClose callback have not set");
        return SW_ERR;
    }

    if (cli->onBufferFull && cli->buffer_high_watermark == 0) {
        cli->buffer_high_watermark = cli->socket->buffer_size * 0.8;
    }

    if (Client_inet_addr(cli, host, port) < 0) {
        return SW_ERR;
    }

    if (cli->wait_dns) {
        return Client_dns_lookup(cli);
    }

    do {
        ret = cli->socket->connect(cli->server_addr);
        if (ret < 0 && errno == EINTR) {
            continue;
        }
        if ((ret < 0 && errno == EINPROGRESS) || ret == 0) {
            /**
             * A return value of 0 indicates that the connection has been successfully established,
             * and there is no need to add a timer to check for connection timeouts.
             */
            if (ret < 0 && timeout > 0) {
                cli->timer = swoole_timer_add(timeout, false, Client_onTimeout, cli);
                if (!cli->timer) {
                    return SW_ERR;
                }
            }
            /**
             * Regardless of whether the connection has been successfully established or is still in progress,
             *  listen for writable events to handle the proxy and SSL handshake within those events.
             */
            return swoole_event_add(cli->socket, SW_EVENT_WRITE);
        }
        cli->active = false;
        cli->socket->removed = 1;
        cli->close();
        if (cli->onError) {
            cli->onerror_called = true;
            cli->onError(cli);
        }
        break;
    } while (true);

    return ret;
}

static ssize_t Client_tcp_send_async(Client *cli, const char *data, size_t length, int flags) {
    ssize_t n = length;
    if (swoole_event_write(cli->socket, data, length) < 0) {
        if (swoole_get_last_error() == SW_ERROR_OUTPUT_BUFFER_OVERFLOW) {
            n = -1;
            cli->high_watermark = true;
        } else {
            return SW_ERR;
        }
    }
    if (cli->onBufferFull && cli->high_watermark == 0 &&
        cli->socket->get_out_buffer_length() >= cli->buffer_high_watermark) {
        cli->high_watermark = true;
        cli->onBufferFull(cli);
    }
    return n;
}

static ssize_t Client_tcp_send_sync(Client *cli, const char *data, size_t length, int flags) {
    return cli->socket->send_sync(data, length, flags);
}

static int Client_tcp_sendfile_sync(Client *cli, const char *filename, off_t offset, size_t length) {
    if (cli->socket->sendfile_sync(filename, offset, length, cli->timeout) < 0) {
        swoole_set_last_error(errno);
        return SW_ERR;
    }
    return SW_OK;
}

static int Client_tcp_sendfile_async(Client *cli, const char *filename, off_t offset, size_t length) {
    if (cli->socket->sendfile_async(filename, offset, length) < 0) {
        swoole_set_last_error(errno);
        return SW_ERR;
    }
    if (swoole_event_add_or_update(cli->socket, SW_EVENT_WRITE) == SW_ERR) {
        return SW_ERR;
    }
    return SW_OK;
}

static ssize_t Client_tcp_recv_sync(Client *cli, char *data, size_t len, int flags) {
    auto rv = cli->socket->recv_sync(data, len, flags);
    /**
     * To maintain forward compatibility, the recv system call returns EAGAIN after a timeout,
     * while the poll() function returns 0 on timeout without setting errno,
     * which should be set to either EAGAIN or ETIMEDOUT.
     */
    if (rv == -1 && swoole_get_last_error() == SW_ERROR_SOCKET_POLL_TIMEOUT) {
        errno = EAGAIN;
    }
    return rv;
}

static int Client_udp_connect(Client *cli, const char *host, int port, double timeout, int udp_connect) {
    cli->timeout = timeout;
    cli->sock_flags_ = udp_connect;

    if (Client_inet_addr(cli, host, port) < 0) {
        return SW_ERR;
    }

    if (cli->async && !cli->onReceive) {
        swoole_warning("onReceive callback have not set");
        return SW_ERR;
    }

    if (cli->wait_dns) {
        return Client_dns_lookup(cli);
    }

    cli->active = true;
    int bufsize = Socket::default_buffer_size;

    if (timeout > 0) {
        cli->socket->set_timeout(timeout);
    }

    if (cli->socket->socket_type == SW_SOCK_UNIX_DGRAM) {
        struct sockaddr_un *client_addr = &cli->socket->info.addr.un;
        sprintf(client_addr->sun_path, "/tmp/swoole-client.%d.%d.sock", getpid(), cli->socket->fd);
        client_addr->sun_family = AF_UNIX;
        unlink(client_addr->sun_path);

        if (bind(cli->socket->fd, (struct sockaddr *) client_addr, sizeof(cli->socket->info.addr.un)) < 0) {
            swoole_sys_warning("bind(%s) failed", client_addr->sun_path);
            return SW_ERR;
        }
    }

#ifdef SW_USE_OPENSSL
    if (cli->open_ssl)
#ifdef SW_SUPPORT_DTLS
    {
        udp_connect = 1;
        cli->enable_dtls();
    }
#else
    {
        swoole_warning("DTLS support require openssl-1.1 or later");
        return SW_ERR;
    }
#endif
#endif

    if (udp_connect != 1) {
        goto _connect_ok;
    }

    if (cli->socket->connect(cli->server_addr) == 0) {
        cli->socket->clean();
    _connect_ok:

        cli->socket->set_option(SOL_SOCKET, SO_SNDBUF, bufsize);
        cli->socket->set_option(SOL_SOCKET, SO_RCVBUF, bufsize);

        if (cli->async && cli->onConnect) {
            if (swoole_event_add(cli->socket, SW_EVENT_READ) < 0) {
                return SW_ERR;
            }
            execute_onConnect(cli);
        }
#ifdef SW_USE_OPENSSL
        if (cli->open_ssl && cli->ssl_handshake() < 0) {
            return SW_ERR;
        }
#endif
        return SW_OK;
    } else {
        cli->active = false;
        cli->socket->removed = 1;
        cli->close();
        if (cli->async && cli->onError) {
            cli->onerror_called = true;
            cli->onError(cli);
        }
        return SW_ERR;
    }
}

static ssize_t Client_udp_send(Client *cli, const char *data, size_t len, int flags) {
    ssize_t n = cli->socket->sendto(cli->server_addr, data, len, 0);
    if (n < 0 || n < (ssize_t) len) {
        return SW_ERR;
    } else {
        return n;
    }
}

static ssize_t Client_udp_recv(Client *cli, char *data, size_t length, int flags) {
    if (cli->async) {
        return cli->socket->recvfrom_sync(data, length, flags, &cli->remote_addr);
    } else {
        return cli->socket->recvfrom(data, length, flags, &cli->remote_addr);
    }
}

static int Client_onPackage(const Protocol *proto, Socket *conn, const RecvData *rdata) {
    auto *cli = (Client *) conn->object;
    cli->onReceive(cli, rdata->data, rdata->info.len);
    return conn->close_wait ? SW_ERR : SW_OK;
}

static int Client_onStreamRead(Reactor *reactor, Event *event) {
    ssize_t n = -1;
    auto *cli = (Client *) event->socket->object;
    char *buf = cli->buffer->str + cli->buffer->length;
    ssize_t buf_size = cli->buffer->size - cli->buffer->length;
#ifdef SW_USE_OPENSSL
    bool do_ssl_handshake = cli->open_ssl;
#else
    bool do_ssl_handshake = false;
#endif

    if (cli->http_proxy && cli->http_proxy->state != SW_HTTP_PROXY_STATE_READY) {
        n = event->socket->recv(buf, buf_size, 0);
        if (n <= 0) {
            swoole_set_last_error(SW_ERROR_HTTP_PROXY_HANDSHAKE_ERROR);
        _connect_fail:
            cli->active = false;
            cli->close();
            if (cli->onError) {
                cli->onError(cli);
            }
            return SW_OK;
        }
        cli->buffer->length += n;
        if (!cli->http_proxy->handshake(cli->buffer)) {
            swoole_set_last_error(SW_ERROR_HTTP_PROXY_HANDSHAKE_ERROR);
            goto _connect_fail;
        }
        cli->http_proxy->state = SW_HTTP_PROXY_STATE_READY;
        cli->buffer->clear();
        if (!do_ssl_handshake) {
            execute_onConnect(cli);
            return SW_OK;
        }
    }

    if (cli->socks5_proxy && cli->socks5_proxy->state != SW_SOCKS5_STATE_READY) {
        n = event->socket->recv(buf, buf_size, 0);
        if (n <= 0) {
            swoole_set_last_error(SW_ERROR_SOCKS5_HANDSHAKE_FAILED);
            goto _connect_fail;
        }
        cli->buffer->length += n;
        if (cli->socks5_handshake(buf, buf_size) < 0) {
            swoole_set_last_error(SW_ERROR_SOCKS5_HANDSHAKE_FAILED);
            goto _connect_fail;
        }
        if (cli->socks5_proxy->state != SW_SOCKS5_STATE_READY) {
            return SW_OK;
        }
        cli->buffer->clear();
        if (!do_ssl_handshake) {
            execute_onConnect(cli);
            return SW_OK;
        }
    }

#ifdef SW_USE_OPENSSL
    if (cli->open_ssl && cli->socket->ssl_state != SW_SSL_STATE_READY) {
        if (cli->ssl_handshake() < 0) {
            swoole_set_last_error(SW_ERROR_SSL_HANDSHAKE_FAILED);
            goto _connect_fail;
        }
        if (cli->socket->ssl_state != SW_SSL_STATE_READY) {
            return SW_OK;
        } else {
            execute_onConnect(cli);
            return SW_OK;
        }
    }
#endif

    if (cli->open_eof_check || cli->open_length_check) {
        Socket *conn = cli->socket;
        Protocol *protocol = &cli->protocol;

        if (cli->open_eof_check) {
            n = protocol->recv_with_eof_protocol(conn, cli->buffer);
        } else {
            n = protocol->recv_with_length_protocol(conn, cli->buffer);
        }

        if (n < 0) {
            if (!cli->closed) {
                cli->close();
            }
            return SW_OK;
        } else {
            if (conn->removed == 0 && cli->remove_delay) {
                cli->sleep();
                cli->remove_delay = false;
            }
            return SW_OK;
        }
    }

    n = event->socket->recv(buf, buf_size, 0);
    if (n < 0) {
        switch (event->socket->catch_read_error(errno)) {
        case SW_ERROR:
            swoole_sys_warning("Read from socket[%d] failed", event->fd);
            return SW_OK;
        case SW_CLOSE:
            goto __close;
        case SW_WAIT:
            return SW_OK;
        default:
            return SW_OK;
        }
    } else if (n == 0) {
    __close:
        return cli->close();
    } else {
        cli->onReceive(cli, buf, n);
        return SW_OK;
    }
    return SW_OK;
}

static int Client_onDgramRead(Reactor *reactor, Event *event) {
    auto *cli = (Client *) event->socket->object;
    char buffer[SW_BUFFER_SIZE_UDP];

    int n = Client_udp_recv(cli, buffer, sizeof(buffer), 0);
    if (n < 0) {
        return SW_ERR;
    } else {
        cli->onReceive(cli, buffer, n);
    }
    return SW_OK;
}

static int Client_onError(Reactor *reactor, Event *event) {
    auto *cli = (Client *) event->socket->object;
    if (cli->active) {
        return cli->close();
    } else {
        Client_onWrite(reactor, event);
    }
    return SW_OK;
}

static void Client_onTimeout(Timer *timer, TimerNode *tnode) {
    auto *cli = (Client *) tnode->data;
    swoole_set_last_error(ETIMEDOUT);

#ifdef SW_USE_OPENSSL
    if (cli->open_ssl && cli->socket->ssl_state != SW_SSL_STATE_READY) {
        cli->active = false;
    }
#endif
    if (cli->socks5_proxy && cli->socks5_proxy->state != SW_SOCKS5_STATE_READY) {
        cli->active = false;
    } else if (cli->http_proxy && cli->http_proxy->state != SW_HTTP_PROXY_STATE_READY) {
        cli->active = false;
    }

    cli->close();
    if (cli->onError) {
        cli->onError(cli);
    }
}

static void Client_onResolveCompleted(AsyncEvent *event) {
    auto *req = dynamic_cast<GethostbynameRequest *>(event->data.get());

    auto *cli = (Client *) event->object;
    cli->wait_dns = false;
    cli->dns_completed = true;

    if (event->error == 0) {
        /**
         * In the callback function, the application layer cannot obtain the return value of the connect function,
         *  so it must call `onError` to notify the caller.
         */
        if (cli->connect(req->addr.get(), cli->server_port, cli->timeout, cli->sock_flags_) == SW_ERR &&
            !cli->onerror_called) {
            goto _error;
        }
    } else {
        swoole_set_last_error(SW_ERROR_DNSLOOKUP_RESOLVE_FAILED);
    _error:
        cli->socket->removed = 1;
        cli->close();
        if (cli->onError) {
            cli->onerror_called = true;
            cli->onError(cli);
        }
    }
}

static int Client_onWrite(Reactor *reactor, Event *event) {
    auto *cli = (Client *) event->socket->object;
    Socket *_socket = cli->socket;
    int ret;
    int err;

    if (cli->active) {
#ifdef SW_USE_OPENSSL
        if (cli->open_ssl && _socket->ssl_state == SW_SSL_STATE_WAIT_STREAM) {
            if (cli->ssl_handshake() < 0) {
                swoole_set_last_error(SW_ERROR_SSL_HANDSHAKE_FAILED);
                goto _connect_fail;
            } else if (_socket->ssl_state == SW_SSL_STATE_READY) {
                goto _connect_success;
            } else {
                if (_socket->ssl_want_read) {
                    swoole_event_set(event->socket, SW_EVENT_READ);
                }
                return SW_OK;
            }
        }
#endif
        if (Reactor::_writable_callback(reactor, event) < 0) {
            return SW_ERR;
        }
        if (cli->onBufferEmpty && cli->high_watermark &&
            _socket->get_out_buffer_length() <= cli->buffer_low_watermark) {
            cli->high_watermark = false;
            cli->onBufferEmpty(cli);
        }
        return SW_OK;
    }

    ret = _socket->get_option(SOL_SOCKET, SO_ERROR, &err);
    swoole_set_last_error(err);
    if (ret < 0) {
        swoole_sys_warning("getsockopt(%d) failed", event->fd);
        return SW_ERR;
    }

    // success
    if (swoole_get_last_error() == 0) {
        // listen read event
        swoole_event_set(event->socket, SW_EVENT_READ);
        // connected
        cli->active = true;
        // socks5 proxy
        if (cli->socks5_proxy && cli->socks5_proxy->state == SW_SOCKS5_STATE_WAIT) {
            char buf[3];
            Socks5Proxy::pack(buf, cli->socks5_proxy->username.empty() ? 0 : SW_SOCKS5_METHOD_AUTH);
            cli->socks5_proxy->state = SW_SOCKS5_STATE_HANDSHAKE;
            return cli->send(buf, sizeof(buf), 0);
        }
        // http proxy
        if (cli->http_proxy && cli->http_proxy->state == SW_HTTP_PROXY_STATE_WAIT) {
            auto proxy_buf = sw_tg_buffer();
            const std::string *host_name = cli->get_http_proxy_host_name();
            size_t n = cli->http_proxy->pack(proxy_buf, host_name);
            swoole_trace_log(SW_TRACE_HTTP_CLIENT, "proxy request: <<EOF\n%.*sEOF", (int) n, proxy_buf->str);
            return cli->send(proxy_buf->str, n, 0);
        }
#ifdef SW_USE_OPENSSL
        if (cli->open_ssl) {
            if (cli->ssl_handshake() < 0) {
                swoole_set_last_error(SW_ERROR_SSL_HANDSHAKE_FAILED);
                goto _connect_fail;
            } else {
                _socket->ssl_state = SW_SSL_STATE_WAIT_STREAM;
            }
            return SW_OK;
        }
    _connect_success:
#endif
        execute_onConnect(cli);
    } else {
#ifdef SW_USE_OPENSSL
    _connect_fail:
#endif
        cli->active = false;
        cli->close();
        cli->onError(cli);
    }

    return SW_OK;
}

}  // namespace network
}  // namespace swoole
