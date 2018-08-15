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
    //clear buffer
    if (buffer)
    {
        swString_free(buffer);
        buffer = NULL;
    }
    return Socket::close();
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
            if (send(buf, 3) < 0)
            {
                return SW_ERR;
            }
            socks5_proxy->state = SW_SOCKS5_STATE_HANDSHAKE;
            while (1)
            {
                n = recv(buf, sizeof(buf));
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

            return send(ctx->buf, ctx->l_username + ctx->l_password + 3);
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
                return send(ctx->buf, ctx->l_target_host + 7);
            }
            else
            {
                buf[3] = 0x01;
                buf += 4;
                *(uint32_t *) buf = htons(ctx->l_target_host);
                buf += 4;
                *(uint16_t *) buf = htons(ctx->target_port);
                return send(ctx->buf, ctx->l_target_host + 7);
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

