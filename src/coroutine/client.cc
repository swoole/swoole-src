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
 | Author: shiguangqi  <shiguangqi2008@gmail.com>                       |
 +----------------------------------------------------------------------+
 */

#include "swoole.h"
#include "Socket.h"
#include "CoroClient.h"
#include "Server.h"
#include "socks5.h"
#include "async.h"

using namespace swoole;

Client::Client(enum swSocket_type _type) :
        Socket(_type)
{
    int _domain;
    type = _type;
    _protocol = 0;
    reactor_fdtype = swSocket_is_stream(type) ? SW_FD_STREAM_CLIENT : SW_FD_DGRAM_CLIENT;
    _redirect_to_file = 0;
    _redirect_to_socket = 0;
    _redirect_to_session = 0;

    destroyed = 0;
    redirect = 0;
    _sleep = 0;
    shutdow_rw = 0;
    shutdown_read = 0;
    shutdown_write = 0;
    remove_delay = 0;

    open_length_check = 0;
    open_eof_check = 0;

    socks5_proxy = NULL;
    http_proxy = NULL;

    ptr = NULL;
    params = NULL;

    server_strlen = 0;

    interrupt_time = 0;

    buffer_input_size = SW_CLIENT_BUFFER_SIZE;
    buffer = NULL;
}

Client::~Client()
{
    //client close
    if (!socket->closed)
    {
        close();
    }
}

int Client::pipe(int write_fd, int flags)
{
    if (_sock_type != SOCK_STREAM)
    {
        swWarn("only tcp-client can use pipe method.");
        return SW_ERR;
    }

    int socktype;
    socklen_t length = sizeof(socktype);

    if (flags & SW_CLIENT_PIPE_TCP_SESSION)
    {
        _redirect_to_session = write_fd;
    }
    else if (getsockopt(write_fd, SOL_SOCKET, SO_TYPE, &socktype, &length) < 0)
    {
        if (errno != ENOTSOCK)
        {
            return SW_ERR;
        }
        _redirect_to_file = write_fd;
    }
    else if (fcntl(write_fd, F_GETFD) != -1 || errno != EBADF)
    {
        _redirect_to_socket = write_fd;
    }
    else
    {
        return SW_ERR;
    }
    redirect = 1;
    return SW_OK;
}

int Client::sleep()
{
    int ret;
    if (socket->events & SW_EVENT_WRITE)
    {
        ret = reactor->set(reactor, socket->fd, socket->fdtype | SW_EVENT_WRITE);
    }
    else
    {
        ret = reactor->del(reactor, socket->fd);
    }
    if (ret == SW_OK)
    {
        _sleep = 1;
    }
    return ret;
}

int Client::wakeup()
{
    int ret;
    if (socket->events & SW_EVENT_WRITE)
    {
        ret = reactor->set(reactor, socket->fd, socket->fdtype | SW_EVENT_READ | SW_EVENT_WRITE);
    }
    else
    {
        ret = reactor->add(reactor, socket->fd, socket->fdtype | SW_EVENT_READ);
    }
    if (ret == SW_OK)
    {
        _sleep = 0;
    }
    return ret;
}

int Client::shutdown(int __how)
{
    if (!socket || socket->closed)
    {
        return SW_ERR;
    }
    if (__how == SHUT_RD)
    {
        if (shutdown_read || shutdow_rw || ::shutdown(socket->fd, SHUT_RD))
        {
            return SW_ERR;
        }
        else
        {
            shutdown_read = 1;
            return SW_OK;
        }
    }
    else if (__how == SHUT_WR)
    {
        if (shutdown_write || shutdow_rw || ::shutdown(socket->fd, SHUT_RD) < 0)
        {
            return SW_ERR;
        }
        else
        {
            shutdown_write = 1;
            return SW_OK;
        }
    }
    else if (__how == SHUT_RDWR)
    {
        if (shutdow_rw || ::shutdown(socket->fd, SHUT_RDWR) < 0)
        {
            return SW_ERR;
        }
        else
        {
            shutdown_read = 1;
            return SW_OK;
        }
    }
    else
    {
        return SW_ERR;
    }
}

void Client::proxy_check(char *host, int port)
{
    //enable socks5 proxy
    if (socks5_proxy)
    {
        socks5_proxy->target_host = host;
        socks5_proxy->l_target_host = strlen(host);
        socks5_proxy->target_port = port;

        host = socks5_proxy->host;
        port = socks5_proxy->port;
    }

    //enable http proxy
    if (http_proxy)
    {
        http_proxy->target_host = host;
        http_proxy->target_port = port;

        host = http_proxy->proxy_host;
        port = http_proxy->proxy_port;
    }
}

int Client::close()
{
    if (socket == NULL || socket->closed)
    {
        return SW_ERR;
    }
    socket->closed = 1;

    int fd = socket->fd;
    assert(fd != 0);

#ifdef SW_USE_OPENSSL
    if (open_ssl && ssl_context)
    {
        if (socket->ssl)
        {
            swSSL_close(socket);
        }
        swSSL_free_context(ssl_context);
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
    }
#endif
    //clear buffer
    if (buffer)
    {
        swString_free(buffer);
        buffer = NULL;
    }
    if (type == SW_SOCK_UNIX_DGRAM)
    {
        unlink(socket->info.addr.un.sun_path);
    }
    //remove from reactor
    if (!socket->removed && reactor)
    {
        reactor->del(reactor, fd);
    }
    if (timer)
    {
        swTimer_del(&SwooleG.timer, timer);
        timer = NULL;
    }
    socket->active = 0;
    return ::close(fd);
}

bool Client::tcp_connect(char *host, int port, int flags)
{
    bool ret;
    int n;
    char buf[1024];

    proxy_check(host, port);

    ret = connect(host, port, flags);

    if (ret)
    {
        socket->active = 1;
        //socks5 proxy
        if (socks5_proxy)
        {
            swSocks5_pack(buf, socks5_proxy->username == NULL ? 0x00 : 0x02);
            if (send(buf, 3, 0) < 0)
            {
                return SW_ERR;
            }
            socks5_proxy->state = SW_SOCKS5_STATE_HANDSHAKE;
            while (1)
            {
                n = recv(buf, sizeof(buf), 0);
                if (n > 0)
                {
                    if (socks5_connect(buf, n) < 0)
                    {
                        return SW_ERR;
                    }
                    else
                    {
                        if (socks5_proxy->state == SW_SOCKS5_STATE_READY)
                        {
                            break;
                        }
                        else
                        {
                            continue;
                        }
                    }
                }
                return SW_ERR;
            }
        }

#ifdef SW_USE_OPENSSL
        if (open_ssl && ssl_handshake() < 0)
        {
            return SW_ERR;
        }
#endif
    }

    return ret;
}

int Client::socks5_connect(char *recv_data, int length)
{
    swSocks5 *ctx = socks5_proxy;
    char *buf = ctx->buf;
    uchar version, status, result, method;

    if (ctx->state == SW_SOCKS5_STATE_HANDSHAKE)
    {
        version = recv_data[0];
        method = recv_data[1];
        if (version != SW_SOCKS5_VERSION_CODE)
        {
            swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SOCKS5_UNSUPPORT_VERSION, "SOCKS version is not supported.");
            return SW_ERR;
        }
        if (method != ctx->method)
        {
            swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SOCKS5_UNSUPPORT_METHOD,
                    "SOCKS authentication method not supported.");
            return SW_ERR;
        }
        //authenticate request
        if (method == SW_SOCKS5_METHOD_AUTH)
        {
            buf[0] = 0x01;
            buf[1] = ctx->l_username;

            buf += 2;
            memcpy(buf, ctx->username, ctx->l_username);
            buf += ctx->l_username;
            buf[0] = ctx->l_password;
            memcpy(buf + 1, ctx->password, ctx->l_password);

            ctx->state = SW_SOCKS5_STATE_AUTH;

            return send(ctx->buf, ctx->l_username + ctx->l_password + 3, 0);
        }
        //send connect request
        else
        {
            send_connect_request: buf[0] = SW_SOCKS5_VERSION_CODE;
            buf[1] = 0x01;
            buf[2] = 0x00;

            ctx->state = SW_SOCKS5_STATE_CONNECT;

            if (ctx->dns_tunnel)
            {
                buf[3] = 0x03;
                buf[4] = ctx->l_target_host;
                buf += 5;
                memcpy(buf, ctx->target_host, ctx->l_target_host);
                buf += ctx->l_target_host;
                *(uint16_t *) buf = htons(ctx->target_port);
                return send(ctx->buf, ctx->l_target_host + 7, 0);
            }
            else
            {
                buf[3] = 0x01;
                buf += 4;
                *(uint32_t *) buf = htons(ctx->l_target_host);
                buf += 4;
                *(uint16_t *) buf = htons(ctx->target_port);
                return send(ctx->buf, ctx->l_target_host + 7, 0);
            }
        }
    }
    else if (ctx->state == SW_SOCKS5_STATE_AUTH)
    {
        version = recv_data[0];
        status = recv_data[1];
        if (version != 0x01)
        {
            swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SOCKS5_UNSUPPORT_VERSION, "SOCKS version is not supported.");
            return SW_ERR;
        }
        if (status != 0)
        {
            swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SOCKS5_AUTH_FAILED,
                    "SOCKS username/password authentication failed.");
            return SW_ERR;
        }
        goto send_connect_request;
    }
    else if (ctx->state == SW_SOCKS5_STATE_CONNECT)
    {
        version = recv_data[0];
        if (version != SW_SOCKS5_VERSION_CODE)
        {
            swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SOCKS5_UNSUPPORT_VERSION, "SOCKS version is not supported.");
            return SW_ERR;
        }
        result = recv_data[1];
//        uchar reg = recv_data[2];
//        uchar type = recv_data[3];
//        uint32_t ip = *(uint32_t *) (recv_data + 4);
//        uint16_t port = *(uint16_t *) (recv_data + 8);
        if (result == 0)
        {
            ctx->state = SW_SOCKS5_STATE_READY;
        }
        else
        {
            swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SOCKS5_SERVER_ERROR, "Socks5 server error, reason :%s.",
                    swSocks5_strerror(result));
        }
        return result;
    }
    return SW_OK;
}

bool Client::udp_connect(char *host, int port, int flags)
{
    proxy_check(host, port);

    socket->active = 1;

    int bufsize = SwooleG.socket_buffer_size;

    if (_timeout > 0)
    {
        swSocket_set_timeout(socket->fd, _timeout);
    }

    if (type == SW_SOCK_UNIX_DGRAM)
    {
        struct sockaddr_un* client_addr = &socket->info.addr.un;
        sprintf(client_addr->sun_path, "/tmp/swoole-client.%d.%d.sock", getpid(), socket->fd);
        client_addr->sun_family = AF_UNIX;
        unlink(client_addr->sun_path);

        if (!bind(host, port))
        {
            return SW_ERR;
        }
    }

    if (connect(host, port, flags))
    {
        swSocket_clean(socket->fd);
        connect_ok:

        setsockopt(socket->fd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
        setsockopt(socket->fd, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
        return SW_OK;
    }
    else
    {
        swSysError("connect() failed.");
        socket->active = 0;
        socket->removed = 1;
        return SW_ERR;
    }
}

int Client::tcp_send(char *data, int length, int flags)
{
    int written = 0;
    int n;

    assert(length > 0);
    assert(data != NULL);

    while (written < length)
    {
        n = swConnection_send(socket, data, length - written, flags);
        if (n < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            else if (errno == EAGAIN)
            {
                swSocket_wait(socket->fd, 1000, SW_EVENT_WRITE);
                continue;
            }
            else
            {
                SwooleG.error = errno;
                return SW_ERR;
            }
        }
        written += n;
        data += n;
    }
    return written;
}

/**
 * Only for synchronous client
 */
int Client::tcp_recv(char *data, int len, int flag)
{
    int ret;

    while (1)
    {
        ret = swConnection_recv(socket, data, len, flag);
        if (ret >= 0)
        {
            break;
        }
        if (errno == EINTR)
        {
            if (interrupt_time <= 0)
            {
                interrupt_time = swoole_microtime();
            }
            else if (swoole_microtime() > interrupt_time + _timeout)
            {
                break;
            }
            else
            {
                continue;
            }
        }
#ifdef SW_USE_OPENSSL
        if (errno == EAGAIN && socket->ssl)
        {
            int timeout_ms = (int) (_timeout * 1000);
            if (socket->ssl_want_read && swSocket_wait(socket->fd, timeout_ms, SW_EVENT_READ) == SW_OK)
            {
                continue;
            }
            else if (socket->ssl_want_write && swSocket_wait(socket->fd, timeout_ms, SW_EVENT_WRITE) == SW_OK)
            {
                continue;
            }
        }
#endif
        break;
    }

    return ret;
}

int Client::udp_send(char *data, int len, int flags)
{
    int n;
    n = sendto(socket->fd, data, len, 0, (struct sockaddr *) &server_addr.addr, server_addr.len);
    if (n < 0 || n < len)
    {
        return SW_ERR;
    }
    else
    {
        return n;
    }
}

int Client::udp_recv(char *data, int length, int flags)
{
    remote_addr.len = sizeof(remote_addr.addr);
    int ret = recvfrom(socket->fd, data, length, flags, (struct sockaddr *) &remote_addr.addr, &remote_addr.len);
    if (ret < 0)
    {
        if (errno == EINTR)
        {
            ret = recvfrom(socket->fd, data, length, flags, (struct sockaddr *) &remote_addr, &remote_addr.len);
        }
        else
        {
            return SW_ERR;
        }
    }
    return ret;
}

#ifdef SW_USE_OPENSSL
static int Client_https_proxy_handshake(Client *cli)
{
    char *buf = cli->buffer->str;
    size_t len = cli->buffer->length;
    int state = 0;
    char *p = buf;
    for (p = buf; p < buf + len; p++)
    {
        if (state == 0)
        {
            if (strncasecmp(p, "HTTP/1.1", 8) == 0 || strncasecmp(p, "HTTP/1.0", 8) == 0)
            {
                state = 1;
                p += 8;
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
                if (strncasecmp(p, "200", 3) == 0)
                {
                    state = 2;
                    p += 3;
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
                if (strncasecmp(p, "Connection established", sizeof("Connection established") - 1) == 0)
                {
                    return SW_OK;
                }
                else
                {
                    break;
                }
            }
        }
    }
    return SW_ERR;
}
#endif

