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
 | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
 +----------------------------------------------------------------------+
 */

#include "swoole.h"
#include "Server.h"
#include "Client.h"
#include "socks5.h"
#include "async.h"

static int swClient_inet_addr(swClient *cli, char *host, int port);
static int swClient_tcp_connect_sync(swClient *cli, char *host, int port, double _timeout, int udp_connect);
static int swClient_tcp_connect_async(swClient *cli, char *host, int port, double timeout, int nonblock);

static int swClient_tcp_send_sync(swClient *cli, char *data, int length, int flags);
static int swClient_tcp_send_async(swClient *cli, char *data, int length, int flags);
static int swClient_tcp_pipe(swClient *cli, int write_fd, int flags);
static int swClient_udp_send(swClient *cli, char *data, int length, int flags);

static int swClient_tcp_sendfile_sync(swClient *cli, char *filename, off_t offset, size_t length);
static int swClient_tcp_sendfile_async(swClient *cli, char *filename, off_t offset, size_t length);
static int swClient_tcp_recv_no_buffer(swClient *cli, char *data, int len, int flags);
static int swClient_udp_connect(swClient *cli, char *host, int port, double _timeout, int udp_connect);
static int swClient_udp_recv(swClient *cli, char *data, int len, int waitall);
static int swClient_close(swClient *cli);

static int swClient_onDgramRead(swReactor *reactor, swEvent *event);
static int swClient_onStreamRead(swReactor *reactor, swEvent *event);
static int swClient_onWrite(swReactor *reactor, swEvent *event);
static int swClient_onError(swReactor *reactor, swEvent *event);
static void swClient_onTimeout(swTimer *timer, swTimer_node *tnode);
static void swClient_onResolveCompleted(swAio_event *event);
static int swClient_onPackage(swConnection *conn, char *data, uint32_t length);

static sw_inline void execute_onConnect(swClient *cli)
{
    if (cli->timer)
    {
        swTimer_del(&SwooleG.timer, cli->timer);
        cli->timer = NULL;
    }
    cli->onConnect(cli);
}

int swClient_create(swClient *cli, int type, int async)
{
    int _domain;
    int _type;

    bzero(cli, sizeof(swClient));
    switch (type)
    {
    case SW_SOCK_TCP:
        _domain = AF_INET;
        _type = SOCK_STREAM;
        break;
    case SW_SOCK_TCP6:
        _domain = AF_INET6;
        _type = SOCK_STREAM;
        break;
    case SW_SOCK_UNIX_STREAM:
        _domain = AF_UNIX;
        _type = SOCK_STREAM;
        break;
    case SW_SOCK_UDP:
        _domain = AF_INET;
        _type = SOCK_DGRAM;
        break;
    case SW_SOCK_UDP6:
        _domain = AF_INET6;
        _type = SOCK_DGRAM;
        break;
    case SW_SOCK_UNIX_DGRAM:
        _domain = AF_UNIX;
        _type = SOCK_DGRAM;
        break;
    default:
        return SW_ERR;
    }

#ifdef SOCK_CLOEXEC
    int sockfd = socket(_domain, _type | SOCK_CLOEXEC, 0);
#else
    int sockfd = socket(_domain, _type, 0);
#endif
    if (sockfd < 0)
    {
        swWarn("socket() failed. Error: %s[%d]", strerror(errno), errno);
        return SW_ERR;
    }

    if (async)
    {
        if (swIsMaster() && SwooleTG.type == SW_THREAD_REACTOR)
        {
            cli->reactor = SwooleTG.reactor;
        }
        else
        {
            cli->reactor = SwooleG.main_reactor;
        }
        cli->socket = swReactor_get(cli->reactor, sockfd);
    }
    else
    {
        cli->socket = sw_malloc(sizeof(swConnection));
    }

    cli->buffer_input_size = SW_CLIENT_BUFFER_SIZE;

    if (!cli->socket)
    {
        swWarn("malloc(%d) failed.", (int ) sizeof(swConnection));
        close(sockfd);
        return SW_ERR;
    }

    bzero(cli->socket, sizeof(swConnection));
    cli->socket->fd = sockfd;
    cli->socket->object = cli;

    if (async)
    {
        swSetNonBlock(cli->socket->fd);
        if (!swReactor_handle_isset(cli->reactor, SW_FD_STREAM_CLIENT))
        {
            cli->reactor->setHandle(cli->reactor, SW_FD_STREAM_CLIENT | SW_EVENT_READ, swClient_onStreamRead);
            cli->reactor->setHandle(cli->reactor, SW_FD_DGRAM_CLIENT | SW_EVENT_READ, swClient_onDgramRead);
            cli->reactor->setHandle(cli->reactor, SW_FD_STREAM_CLIENT | SW_EVENT_WRITE, swClient_onWrite);
            cli->reactor->setHandle(cli->reactor, SW_FD_STREAM_CLIENT | SW_EVENT_ERROR, swClient_onError);
        }
    }

    if (swSocket_is_stream(type))
    {
        cli->recv = swClient_tcp_recv_no_buffer;
        if (async)
        {
            cli->connect = swClient_tcp_connect_async;
            cli->send = swClient_tcp_send_async;
            cli->sendfile = swClient_tcp_sendfile_async;
            cli->pipe = swClient_tcp_pipe;
            cli->socket->dontwait = 1;
        }
        else
        {
            cli->connect = swClient_tcp_connect_sync;
            cli->send = swClient_tcp_send_sync;
            cli->sendfile = swClient_tcp_sendfile_sync;
        }
        cli->reactor_fdtype = SW_FD_STREAM_CLIENT;
    }
    else
    {
        cli->connect = swClient_udp_connect;
        cli->recv = swClient_udp_recv;
        cli->send = swClient_udp_send;
        cli->reactor_fdtype = SW_FD_DGRAM_CLIENT;
    }

    cli->_sock_domain = _domain;
    cli->_sock_type = _type;

    cli->close = swClient_close;
    cli->type = type;
    cli->async = async;

    cli->protocol.package_length_type = 'N';
    cli->protocol.package_length_size = 4;
    cli->protocol.package_body_offset = 0;
    cli->protocol.package_max_length = SW_BUFFER_INPUT_SIZE;
    cli->protocol.onPackage = swClient_onPackage;

    return SW_OK;
}

int swClient_sleep(swClient *cli)
{
    int ret;
    if (cli->socket->events & SW_EVENT_WRITE)
    {
        ret = cli->reactor->set(cli->reactor, cli->socket->fd, cli->socket->fdtype | SW_EVENT_WRITE);
    }
    else
    {
        ret = cli->reactor->del(cli->reactor, cli->socket->fd);
    }
    if (ret)
    {
        cli->sleep = 1;
    }
    return ret;
}

int swClient_wakeup(swClient *cli)
{
    int ret;
    if (cli->socket->events & SW_EVENT_WRITE)
    {
        ret = cli->reactor->set(cli->reactor, cli->socket->fd, cli->socket->fdtype | SW_EVENT_READ | SW_EVENT_WRITE);
    }
    else
    {
        ret = cli->reactor->add(cli->reactor, cli->socket->fd, cli->socket->fdtype | SW_EVENT_READ);
    }
    if (ret)
    {
        cli->sleep = 0;
    }
    return ret;
}

int swClient_shutdown(swClient *cli, int __how)
{
    if (!cli->socket || cli->socket->closed)
    {
        return SW_ERR;
    }
    if (__how == SHUT_RD)
    {
        if (cli->shutdown_read || cli->shutdow_rw || shutdown(cli->socket->fd, SHUT_RD))
        {
            return SW_ERR;
        }
        else
        {
            cli->shutdown_read = 1;
            return SW_OK;
        }
    }
    else if (__how == SHUT_WR)
    {
        if (cli->shutdown_write || cli->shutdow_rw || shutdown(cli->socket->fd, SHUT_RD) < 0)
        {
            return SW_ERR;
        }
        else
        {
            cli->shutdown_write = 1;
            return SW_OK;
        }
    }
    else if (__how == SHUT_RDWR)
    {
        if (cli->shutdow_rw || shutdown(cli->socket->fd, SHUT_RDWR) < 0)
        {
            return SW_ERR;
        }
        else
        {
            cli->shutdown_read = 1;
            return SW_OK;
        }
    }
    else
    {
        return SW_ERR;
    }
}

#ifdef SW_USE_OPENSSL
int swClient_enable_ssl_encrypt(swClient *cli)
{
    cli->ssl_context = swSSL_get_context(&cli->ssl_option);
    if (cli->ssl_context == NULL)
    {
        return SW_ERR;
    }

    if (cli->ssl_option.verify_peer)
    {
        if (swSSL_set_capath(&cli->ssl_option, cli->ssl_context) < 0)
        {
            return SW_ERR;
        }
    }

    cli->socket->ssl_send = 1;
#if defined(SW_USE_HTTP2) && defined(SW_USE_OPENSSL) && OPENSSL_VERSION_NUMBER >= 0x10002000L
    if (cli->http2)
    {
        if (SSL_CTX_set_alpn_protos(cli->ssl_context, (const unsigned char *) "\x02h2", 3) < 0)
        {
            return SW_ERR;
        }
    }
#endif
    return SW_OK;
}

int swClient_ssl_handshake(swClient *cli)
{
    if (!cli->socket->ssl)
    {
        if (swSSL_create(cli->socket, cli->ssl_context, SW_SSL_CLIENT) < 0)
        {
            return SW_ERR;
        }
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
        if (cli->ssl_option.tls_host_name)
        {
            SSL_set_tlsext_host_name(cli->socket->ssl, cli->ssl_option.tls_host_name);
        }
#endif
    }
    if (swSSL_connect(cli->socket) < 0)
    {
        return SW_ERR;
    }
    if (cli->socket->ssl_state == SW_SSL_STATE_READY && cli->ssl_option.verify_peer)
    {
        if (swClient_ssl_verify(cli, cli->ssl_option.allow_self_signed) < 0)
        {
            return SW_ERR;
        }
    }
    return SW_OK;
}

int swClient_ssl_verify(swClient *cli, int allow_self_signed)
{
    if (swSSL_verify(cli->socket, allow_self_signed) < 0)
    {
        return SW_ERR;
    }
    if (cli->ssl_option.tls_host_name && swSSL_check_host(cli->socket, cli->ssl_option.tls_host_name) < 0)
    {
        return SW_ERR;
    }
    return SW_OK;
}

#endif

static int swClient_inet_addr(swClient *cli, char *host, int port)
{
    //enable socks5 proxy
    if (cli->socks5_proxy)
    {
        cli->socks5_proxy->target_host = host;
        cli->socks5_proxy->l_target_host = strlen(host);
        cli->socks5_proxy->target_port = port;

        host = cli->socks5_proxy->host;
        port = cli->socks5_proxy->port;
    }
    
    //enable http proxy
    if (cli->http_proxy)
    {
        cli->http_proxy->target_host = host;
        cli->http_proxy->target_port = port;

        host = cli->http_proxy->proxy_host;
        port = cli->http_proxy->proxy_port;
    }

    cli->server_host = host;
    cli->server_port = port;

    void *s_addr = NULL;
    if (cli->type == SW_SOCK_TCP || cli->type == SW_SOCK_UDP)
    {
        cli->server_addr.addr.inet_v4.sin_family = AF_INET;
        cli->server_addr.addr.inet_v4.sin_port = htons(port);
        cli->server_addr.len = sizeof(cli->server_addr.addr.inet_v4);
        s_addr = &cli->server_addr.addr.inet_v4.sin_addr.s_addr;

        if (inet_pton(AF_INET, host, s_addr))
        {
            return SW_OK;
        }
    }
    else if (cli->type == SW_SOCK_TCP6 || cli->type == SW_SOCK_UDP6)
    {
        cli->server_addr.addr.inet_v6.sin6_family = AF_INET6;
        cli->server_addr.addr.inet_v6.sin6_port = htons(port);
        cli->server_addr.len = sizeof(cli->server_addr.addr.inet_v6);
        s_addr = cli->server_addr.addr.inet_v6.sin6_addr.s6_addr;

        if (inet_pton(AF_INET6, host, s_addr))
        {
            return SW_OK;
        }
    }
    else if (cli->type == SW_SOCK_UNIX_STREAM || cli->type == SW_SOCK_UNIX_DGRAM)
    {
        cli->server_addr.addr.un.sun_family = AF_UNIX;
        strncpy(cli->server_addr.addr.un.sun_path, host, sizeof(cli->server_addr.addr.un.sun_path) - 1);
        cli->server_addr.addr.un.sun_path[sizeof(cli->server_addr.addr.un.sun_path) - 1] = 0;
        cli->server_addr.len = sizeof(cli->server_addr.addr.un.sun_path);
        return SW_OK;
    }
    else
    {
        return SW_ERR;
    }
    if (!cli->async)
    {
        if (swoole_gethostbyname(cli->_sock_domain, host, s_addr) < 0)
        {
            SwooleG.error = SW_ERROR_DNSLOOKUP_RESOLVE_FAILED;
            return SW_ERR;
        }
    }
    else
    {
        cli->wait_dns = 1;
    }
    return SW_OK;
}

void swClient_free(swClient *cli)
{
    assert(cli->socket->fd != 0);
    //remove from reactor
    if (!cli->socket->closed)
    {
        cli->close(cli);
    }
    if (cli->socket->out_buffer)
    {
        swBuffer_free(cli->socket->out_buffer);
        cli->socket->out_buffer = NULL;
    }
    if (cli->socket->in_buffer)
    {
        swBuffer_free(cli->socket->in_buffer);
        cli->socket->in_buffer = NULL;
    }
    bzero(cli->socket, sizeof(swConnection));
    if (cli->async)
    {
        cli->socket->removed = 1;
    }
    else
    {
        sw_free(cli->socket);
    }
}

static int swClient_close(swClient *cli)
{
    int fd = cli->socket->fd;
    assert(fd != 0);

#ifdef SW_USE_OPENSSL
    if (cli->open_ssl && cli->ssl_context)
    {
        if (cli->socket->ssl)
        {
            swSSL_close(cli->socket);
        }
        swSSL_free_context(cli->ssl_context);
        if (cli->ssl_option.cert_file)
        {
            sw_free(cli->ssl_option.cert_file);
        }
        if (cli->ssl_option.key_file)
        {
            sw_free(cli->ssl_option.key_file);
        }
        if (cli->ssl_option.passphrase)
        {
            sw_free(cli->ssl_option.passphrase);
        }
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
        if (cli->ssl_option.tls_host_name)
        {
            sw_free(cli->ssl_option.tls_host_name);
        }
#endif
        if (cli->ssl_option.cafile)
        {
            sw_free(cli->ssl_option.cafile);
        }
        if (cli->ssl_option.capath)
        {
            sw_free(cli->ssl_option.capath);
        }
    }
#endif
    //clear buffer
    if (cli->buffer)
    {
        swString_free(cli->buffer);
        cli->buffer = NULL;
    }
    if (cli->type == SW_SOCK_UNIX_DGRAM)
    {
        unlink(cli->socket->info.addr.un.sun_path);
    }
    if (cli->socket->closed)
    {
        return SW_OK;
    }
    cli->socket->closed = 1;
    if (cli->async)
    {
        //remove from reactor
        if (!cli->socket->removed && cli->reactor)
        {
            cli->reactor->del(cli->reactor, fd);
        }
        if (cli->timer)
        {
            swTimer_del(&SwooleG.timer, cli->timer);
            cli->timer = NULL;
        }
        //onClose callback
        if (cli->socket->active && cli->onClose)
        {
            cli->socket->active = 0;
            cli->onClose(cli);
        }
    }
    else
    {
        cli->socket->active = 0;
    }
    return close(fd);
}

static int swClient_tcp_connect_sync(swClient *cli, char *host, int port, double timeout, int nonblock)
{
    int ret, n;
    char buf[1024];

    cli->timeout = timeout;

    if (swClient_inet_addr(cli, host, port) < 0)
    {
        return SW_ERR;
    }

    if (nonblock == 1)
    {
        swSetNonBlock(cli->socket->fd);
    }
    else
    {
        if (cli->timeout > 0)
        {
            swSocket_set_timeout(cli->socket->fd, timeout);
        }
        swSetBlock(cli->socket->fd);
    }
    while (1)
    {
        ret = connect(cli->socket->fd, (struct sockaddr *) &cli->server_addr.addr, cli->server_addr.len);
        if (ret < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
        }
        break;
    }

    if (ret >= 0)
    {
        cli->socket->active = 1;

        //socks5 proxy
        if (cli->socks5_proxy)
        {
            swSocks5_pack(buf, cli->socks5_proxy->username == NULL ? 0x00 : 0x02);
            if (cli->send(cli, buf, 3, 0) < 0)
            {
                return SW_ERR;
            }
            cli->socks5_proxy->state = SW_SOCKS5_STATE_HANDSHAKE;
            while (1)
            {
                n = cli->recv(cli, buf, sizeof(buf), 0);
                if (n > 0)
                {
                    if (swSocks5_connect(cli, buf, n) < 0)
                    {
                        return SW_ERR;
                    }
                    else
                    {
                        if (cli->socks5_proxy->state == SW_SOCKS5_STATE_READY)
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
        if (cli->open_ssl)
        {
            if (swClient_enable_ssl_encrypt(cli) < 0)
            {
                return SW_ERR;
            }
            if (swClient_ssl_handshake(cli) < 0)
            {
                return SW_ERR;
            }
        }
#endif
    }

    return ret;
}

static int swClient_tcp_connect_async(swClient *cli, char *host, int port, double timeout, int nonblock)
{
    int ret;

    cli->timeout = timeout;

    if (!cli->buffer)
    {
        //alloc input memory buffer
        cli->buffer = swString_new(cli->buffer_input_size);
        if (!cli->buffer)
        {
            return SW_ERR;
        }
    }

    if (!(cli->onConnect && cli->onError && cli->onClose))
    {
        swWarn("onConnect/onError/onClose callback have not set.");
        return SW_ERR;
    }

    if (cli->onBufferFull && cli->buffer_high_watermark == 0)
    {
        cli->buffer_high_watermark = cli->socket->buffer_size * 0.8;
    }

    if (swClient_inet_addr(cli, host, port) < 0)
    {
        return SW_ERR;
    }

    if (cli->wait_dns)
    {
        if (SwooleAIO.mode == SW_AIO_LINUX)
        {
            SwooleAIO.mode = SW_AIO_BASE;
            SwooleAIO.init = 0;
        }
        if (SwooleAIO.init == 0)
        {
            swAio_init();
        }

        swAio_event ev;
        bzero(&ev, sizeof(swAio_event));

        int len = strlen(cli->server_host);
        if (strlen(cli->server_host) < SW_IP_MAX_LENGTH)
        {
            ev.nbytes = SW_IP_MAX_LENGTH;
        }
        else
        {
            ev.nbytes = len + 1;
        }

        ev.buf = sw_malloc(ev.nbytes);
        if (!ev.buf)
        {
            swWarn("malloc failed.");
            return SW_ERR;
        }

        memcpy(ev.buf, cli->server_host, len);
        ((char *) ev.buf)[len] = 0;
        ev.flags = cli->_sock_domain;
        ev.type = SW_AIO_GETHOSTBYNAME;
        ev.object = cli;
        ev.callback = swClient_onResolveCompleted;

        if (swAio_dispatch(&ev) < 0)
        {
            sw_free(ev.buf);
            return SW_ERR;
        }
        else
        {
            return SW_OK;
        }
    }

    while (1)
    {
        ret = connect(cli->socket->fd, (struct sockaddr *) &cli->server_addr.addr, cli->server_addr.len);
        if (ret < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            SwooleG.error = errno;
        }
        break;
    }

    if ((ret < 0 && errno == EINPROGRESS) || ret == 0)
    {
        if (cli->reactor->add(cli->reactor, cli->socket->fd, cli->reactor_fdtype | SW_EVENT_WRITE) < 0)
        {
            return SW_ERR;
        }
        if (timeout > 0)
        {
            if (SwooleG.timer.fd == 0)
            {
                swTimer_init((int) (timeout * 1000));
            }
            cli->timer = SwooleG.timer.add(&SwooleG.timer, (int) (timeout * 1000), 0, cli, swClient_onTimeout);
        }
        return SW_OK;
    }

    return ret;
}

static int swClient_tcp_pipe(swClient *cli, int write_fd, int flags)
{
    if (!cli->async || cli->_sock_type != SOCK_STREAM)
    {
        swWarn("only async tcp-client can use pipe method.");
        return SW_ERR;
    }

    int socktype;
    socklen_t length = sizeof(socktype);

    if (flags & SW_CLIENT_PIPE_TCP_SESSION)
    {
        cli->_redirect_to_session = write_fd;
    }
    else if (getsockopt(write_fd, SOL_SOCKET, SO_TYPE, &socktype, &length) < 0)
    {
        if (errno != ENOTSOCK)
        {
            return SW_ERR;
        }
        cli->_redirect_to_file = write_fd;
    }
    else if (fcntl(write_fd, F_GETFD) != -1 || errno != EBADF)
    {
        cli->_redirect_to_socket = write_fd;
    }
    else
    {
        return SW_ERR;
    }
    cli->redirect = 1;
    return SW_OK;
}

static int swClient_tcp_send_async(swClient *cli, char *data, int length, int flags)
{
    int n = length;
    if (cli->reactor->write(cli->reactor, cli->socket->fd, data, length) < 0)
    {
        if (SwooleG.error == SW_ERROR_OUTPUT_BUFFER_OVERFLOW)
        {
            n = -1;
            cli->socket->high_watermark = 1;
        }
        else
        {
            return SW_ERR;
        }
    }
    if (cli->onBufferFull && cli->socket->out_buffer && cli->socket->high_watermark == 0
            && cli->socket->out_buffer->length >= cli->buffer_high_watermark)
    {
        cli->socket->high_watermark = 1;
        cli->onBufferFull(cli);
    }
    return n;
}

static int swClient_tcp_send_sync(swClient *cli, char *data, int length, int flags)
{
    int written = 0;
    int n;

    assert(length > 0);
    assert(data != NULL);

    while (written < length)
    {
        n = swConnection_send(cli->socket, data, length - written, flags);
        if (n < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            else if (errno == EAGAIN)
            {
                swSocket_wait(cli->socket->fd, 1000, SW_EVENT_WRITE);
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

static int swClient_tcp_sendfile_sync(swClient *cli, char *filename, off_t offset, size_t length)
{
    if (swSocket_sendfile_sync(cli->socket->fd, filename, offset, length, cli->timeout) < 0)
    {
        SwooleG.error = errno;
        return SW_ERR;
    }
    return SW_OK;
}

static int swClient_tcp_sendfile_async(swClient *cli, char *filename, off_t offset, size_t length)
{
    if (swConnection_sendfile(cli->socket, filename, offset, length) < 0)
    {
        SwooleG.error = errno;
        return SW_ERR;
    }
    if (!(cli->socket->events & SW_EVENT_WRITE))
    {
        if (cli->socket->events & SW_EVENT_READ)
        {
            return cli->reactor->set(cli->reactor, cli->socket->fd,
                    cli->socket->fdtype | SW_EVENT_READ | SW_EVENT_WRITE);
        }
        else
        {
            return cli->reactor->add(cli->reactor, cli->socket->fd,
                    cli->socket->fdtype | SW_EVENT_WRITE);
        }
    }
    return SW_OK;
}

/**
 * Only for synchronous client
 */
static int swClient_tcp_recv_no_buffer(swClient *cli, char *data, int len, int flag)
{
    int ret;

    while (1)
    {
        ret = swConnection_recv(cli->socket, data, len, flag);
        if (ret >= 0)
        {
            break;
        }
        if (errno == EINTR)
        {
            if (cli->interrupt_time <= 0)
            {
                cli->interrupt_time = swoole_microtime();
            }
            else if (swoole_microtime() > cli->interrupt_time + cli->timeout)
            {
                break;
            }
            else
            {
                continue;
            }
        }
#ifdef SW_USE_OPENSSL
        if (errno == EAGAIN && cli->socket->ssl)
        {
            int timeout_ms = (int) (cli->timeout * 1000);
            if (cli->socket->ssl_want_read && swSocket_wait(cli->socket->fd, timeout_ms, SW_EVENT_READ) == SW_OK)
            {
                continue;
            }
            else if (cli->socket->ssl_want_write && swSocket_wait(cli->socket->fd, timeout_ms, SW_EVENT_WRITE) == SW_OK)
            {
                continue;
            }
        }
#endif
        break;
    }

    return ret;
}

static int swClient_udp_connect(swClient *cli, char *host, int port, double timeout, int udp_connect)
{
    if (swClient_inet_addr(cli, host, port) < 0)
    {
        return SW_ERR;
    }

    cli->socket->active = 1;
    cli->timeout = timeout;
    int bufsize = SwooleG.socket_buffer_size;

    if (timeout > 0)
    {
        swSocket_set_timeout(cli->socket->fd, timeout);
    }

    if (cli->type == SW_SOCK_UNIX_DGRAM)
    {
        struct sockaddr_un* client_addr = &cli->socket->info.addr.un;
        sprintf(client_addr->sun_path, "/tmp/swoole-client.%d.%d.sock", getpid(), cli->socket->fd);
        client_addr->sun_family = AF_UNIX;
        unlink(client_addr->sun_path);

        if (bind(cli->socket->fd, (struct sockaddr *) client_addr, sizeof(cli->socket->info.addr.un)) < 0)
        {
            swSysError("bind(%s) failed.", client_addr->sun_path);
            return SW_ERR;
        }
    }
    else if (udp_connect != 1)
    {
        goto connect_ok;
    }

    if (connect(cli->socket->fd, (struct sockaddr *) (&cli->server_addr), cli->server_addr.len) == 0)
    {
        swSocket_clean(cli->socket->fd);
        connect_ok:

        setsockopt(cli->socket->fd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
        setsockopt(cli->socket->fd, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));

        if (cli->async && cli->onConnect)
        {
            if (cli->reactor->add(cli->reactor, cli->socket->fd, cli->reactor_fdtype | SW_EVENT_READ) < 0)
            {
                return SW_ERR;
            }
            execute_onConnect(cli);
        }
        return SW_OK;
    }
    else
    {
        swSysError("connect() failed.");
        cli->socket->active = 0;
        return SW_ERR;
    }
}

static int swClient_udp_send(swClient *cli, char *data, int len, int flags)
{
    int n;
    n = sendto(cli->socket->fd, data, len, 0, (struct sockaddr *) &cli->server_addr.addr, cli->server_addr.len);
    if (n < 0 || n < len)
    {
        return SW_ERR;
    }
    else
    {
        return n;
    }
}

static int swClient_udp_recv(swClient *cli, char *data, int length, int flags)
{
    cli->remote_addr.len = sizeof(cli->remote_addr.addr);
    int ret = recvfrom(cli->socket->fd, data, length, flags, (struct sockaddr *) &cli->remote_addr.addr, &cli->remote_addr.len);
    if (ret < 0)
    {
        if (errno == EINTR)
        {
            ret = recvfrom(cli->socket->fd, data, length, flags, (struct sockaddr *) &cli->remote_addr, &cli->remote_addr.len);
        }
        else
        {
            return SW_ERR;
        }
    }
    return ret;
}

#ifdef SW_USE_OPENSSL
static int swClient_https_proxy_handshake(swClient *cli)
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

static int swClient_onPackage(swConnection *conn, char *data, uint32_t length)
{
    swClient *cli = (swClient *) conn->object;
    cli->onReceive(conn->object, data, length);
    return conn->close_wait ? SW_ERR : SW_OK;
}

static int swClient_onStreamRead(swReactor *reactor, swEvent *event)
{
    int n;
    swClient *cli = event->socket->object;
    char *buf = cli->buffer->str + cli->buffer->length;
    long buf_size = cli->buffer->size - cli->buffer->length;

    if (cli->http_proxy && cli->http_proxy->state != SW_HTTP_PROXY_STATE_READY)
    {
#ifdef SW_USE_OPENSSL
        if (cli->open_ssl)
        {
            int n = swConnection_recv(event->socket, buf, buf_size, 0);
            if (n <= 0)
            {
                goto __close;
            }
            cli->buffer->length += n;
            if (cli->buffer->length < sizeof(SW_HTTPS_PROXY_HANDSHAKE_RESPONSE) - 1)
            {
                return SW_OK;
            }
            if (swClient_https_proxy_handshake(cli) < 0)
            {
                swoole_error_log(SW_LOG_NOTICE, SW_ERROR_HTTP_PROXY_HANDSHAKE_ERROR, "failed to handshake with http proxy.");
                goto connect_fail;
            }
            else
            {
                cli->http_proxy->state = SW_HTTP_PROXY_STATE_READY;
                swString_clear(cli->buffer);
            }
            if (swClient_enable_ssl_encrypt(cli) < 0)
            {
                goto connect_fail;
            }
            else
            {
                if (swClient_ssl_handshake(cli) < 0)
                {
                    goto connect_fail;
                }
                else
                {
                    cli->socket->ssl_state = SW_SSL_STATE_WAIT_STREAM;
                }
                return cli->reactor->set(cli->reactor, event->fd, SW_FD_STREAM_CLIENT | SW_EVENT_WRITE);
            }
            if (cli->onConnect)
            {
                execute_onConnect(cli);
            }
            return SW_OK;
        }
#endif
    }
    if (cli->socks5_proxy && cli->socks5_proxy->state != SW_SOCKS5_STATE_READY)
    {
        int n = swConnection_recv(event->socket, buf, buf_size, 0);
        if (n <= 0)
        {
            goto __close;
        }
        if (swSocks5_connect(cli, buf, buf_size) < 0)
        {
            goto __close;
        }
        if (cli->socks5_proxy->state != SW_SOCKS5_STATE_READY)
        {
            return SW_OK;
        }
#ifdef SW_USE_OPENSSL
        if (cli->open_ssl)
        {
            if (swClient_enable_ssl_encrypt(cli) < 0)
            {
                connect_fail:
                cli->socket->active = 0;
                cli->close(cli);
                if (cli->onError)
                {
                    cli->onError(cli);
                }
            }
            else
            {
                if (swClient_ssl_handshake(cli) < 0)
                {
                    goto connect_fail;
                }
                else
                {
                    cli->socket->ssl_state = SW_SSL_STATE_WAIT_STREAM;
                }
                return cli->reactor->set(cli->reactor, event->fd, SW_FD_STREAM_CLIENT | SW_EVENT_WRITE);
            }
        }
        else
#endif
        {
            if (cli->onConnect)
            {
                execute_onConnect(cli);
            }
        }
        return SW_OK;
    }

#ifdef SW_USE_OPENSSL
    if (cli->open_ssl && cli->socket->ssl_state == SW_SSL_STATE_WAIT_STREAM)
    {
        if (swClient_ssl_handshake(cli) < 0)
        {
            goto connect_fail;
        }
        if (cli->socket->ssl_state != SW_SSL_STATE_READY)
        {
            return SW_OK;
        }
        //ssl handshake sucess
        else if (cli->onConnect)
        {
            execute_onConnect(cli);
        }
    }
#endif

    /**
     * redirect stream data to other socket
     */
    if (cli->redirect)
    {
        int ret = 0;
        n = swConnection_recv(event->socket, buf, buf_size, 0);
        if (n < 0)
        {
            goto __error;
        }
        else if (n == 0)
        {
            goto __close;
        }
        if (cli->_redirect_to_socket)
        {
            ret = cli->reactor->write(cli->reactor, cli->_redirect_to_socket, buf, n);
        }
        else if (cli->_redirect_to_session)
        {
            if (SwooleG.serv->send(SwooleG.serv, cli->_redirect_to_session, buf, n) < 0)
            {
                if (SwooleG.error >= SW_ERROR_SESSION_CLOSED_BY_SERVER || SwooleG.error >= SW_ERROR_SESSION_INVALID_ID)
                {
                    goto __close;
                }
            }
            else
            {
                return SW_OK;
            }
        }
        else
        {
            ret = swSocket_write_blocking(cli->_redirect_to_file, buf, n);
        }
        if (ret < 0)
        {
            goto __error;
        }
        return SW_OK;
    }

    if (cli->open_eof_check || cli->open_length_check)
    {
        swConnection *conn = cli->socket;
        swProtocol *protocol = &cli->protocol;

        if (cli->open_eof_check)
        {
            n = swProtocol_recv_check_eof(protocol, conn, cli->buffer);
        }
        else
        {
            n = swProtocol_recv_check_length(protocol, conn, cli->buffer);
        }

        if (n < 0)
        {
            return  cli->close(cli);
        }
        else
        {
            return SW_OK;
        }
    }

#ifdef SW_CLIENT_RECV_AGAIN
    recv_again:
#endif
    n = swConnection_recv(event->socket, buf, buf_size, 0);
    if (n < 0)
    {
        __error:
        switch (swConnection_error(errno))
        {
        case SW_ERROR:
            swSysError("Read from socket[%d] failed.", event->fd);
            return SW_OK;
        case SW_CLOSE:
            goto __close;
        case SW_WAIT:
            return SW_OK;
        default:
            return SW_OK;
        }
    }
    else if (n == 0)
    {
        __close:
        return  cli->close(cli);
    }
    else
    {
        cli->onReceive(cli, buf, n);
#ifdef SW_CLIENT_RECV_AGAIN
        if (n == buf_size)
        {
            goto recv_again;
        }
#endif
        return SW_OK;
    }
    return SW_OK;
}

static int swClient_onDgramRead(swReactor *reactor, swEvent *event)
{
    swClient *cli = event->socket->object;
    char buffer[SW_BUFFER_SIZE_UDP];

    int n = swClient_udp_recv(cli, buffer, sizeof(buffer), 0);
    if (n < 0)
    {
        return SW_ERR;
    }
    else
    {
        cli->onReceive(cli, buffer, n);
    }
    return SW_OK;
}

static int swClient_onError(swReactor *reactor, swEvent *event)
{
    swClient *cli = event->socket->object;
    if (cli->socket->active)
    {
        return cli->close(cli);
    }
    else
    {
        swClient_onWrite(reactor, event);
    }
    return SW_OK;
}

static void swClient_onTimeout(swTimer *timer, swTimer_node *tnode)
{
    swClient *cli = (swClient *) tnode->data;
    SwooleG.error = ETIMEDOUT;

#ifdef SW_USE_OPENSSL
    if (cli->open_ssl && cli->socket->ssl_state != SW_SSL_STATE_READY)
    {
        cli->socket->active = 0;
    }
#endif
    if (cli->socks5_proxy && cli->socks5_proxy->state != SW_SOCKS5_STATE_READY)
    {
        cli->socket->active = 0;
    }
    else if (cli->http_proxy && cli->http_proxy->state != SW_HTTP_PROXY_STATE_READY)
    {
        cli->socket->active = 0;
    }

    cli->close(cli);
    if (cli->onError)
    {
        cli->onError(cli);
    }
}

static void swClient_onResolveCompleted(swAio_event *event)
{
    swClient *cli = event->object;
    cli->wait_dns = 0;

    if (event->error == 0)
    {
        swClient_tcp_connect_async(cli, event->buf, cli->server_port, cli->timeout, 1);
    }
    else
    {
        SwooleG.error = SW_ERROR_DNSLOOKUP_RESOLVE_FAILED;
        cli->socket->removed = 1;
        cli->close(cli);
        if (cli->onError)
        {
            cli->onError(cli);
        }
    }
    sw_free(event->buf);
}

static int swClient_onWrite(swReactor *reactor, swEvent *event)
{
    swClient *cli = event->socket->object;
    swConnection *_socket = cli->socket;

    if (cli->socket->active)
    {
#ifdef SW_USE_OPENSSL
        if (cli->open_ssl && _socket->ssl_state == SW_SSL_STATE_WAIT_STREAM)
        {
            if (swClient_ssl_handshake(cli) < 0)
            {
                goto connect_fail;
            }
            else if (_socket->ssl_state == SW_SSL_STATE_READY)
            {
                goto connect_success;
            }
            else
            {
                if (_socket->ssl_want_read)
                {
                    cli->reactor->set(cli->reactor, event->fd, SW_FD_STREAM_CLIENT | SW_EVENT_READ);
                }
                return SW_OK;
            }
        }
#endif
        if (swReactor_onWrite(cli->reactor, event) < 0)
        {
            return SW_ERR;
        }
        if (cli->onBufferEmpty && _socket->high_watermark && _socket->out_buffer->length <= cli->buffer_low_watermark)
        {
            _socket->high_watermark = 0;
            cli->onBufferEmpty(cli);
        }
        return SW_OK;
    }

    socklen_t len = sizeof(SwooleG.error);
    if (getsockopt(event->fd, SOL_SOCKET, SO_ERROR, &SwooleG.error, &len) < 0)
    {
        swWarn("getsockopt(%d) failed. Error: %s[%d]", event->fd, strerror(errno), errno);
        return SW_ERR;
    }

    //success
    if (SwooleG.error == 0)
    {
        //listen read event
        cli->reactor->set(cli->reactor, event->fd, SW_FD_STREAM_CLIENT | SW_EVENT_READ);
        //connected
        _socket->active = 1;
        //socks5 proxy
        if (cli->socks5_proxy && cli->socks5_proxy->state == SW_SOCKS5_STATE_WAIT)
        {
            char buf[3];
            swSocks5_pack(buf, cli->socks5_proxy->username == NULL ? 0x00 : 0x02);
            cli->socks5_proxy->state = SW_SOCKS5_STATE_HANDSHAKE;
            return cli->send(cli, buf, sizeof(buf), 0);
        }
        //http proxy
        if (cli->http_proxy && cli->http_proxy->state == SW_HTTP_PROXY_STATE_WAIT)
        {
#ifdef SW_USE_OPENSSL
            if (cli->open_ssl)
            {
                cli->http_proxy->state = SW_HTTP_PROXY_STATE_HANDSHAKE;
                int n = snprintf(cli->http_proxy->buf, sizeof (cli->http_proxy->buf), "CONNECT %s:%d HTTP/1.1\r\n\r\n", cli->http_proxy->target_host, cli->http_proxy->target_port);
                return cli->send(cli, cli->http_proxy->buf, n, 0);
            }
#endif
        }
#ifdef SW_USE_OPENSSL
        if (cli->open_ssl)
        {
            if (swClient_enable_ssl_encrypt(cli) < 0)
            {
                goto connect_fail;
            }
            if (swClient_ssl_handshake(cli) < 0)
            {
                goto connect_fail;
            }
            else
            {
                _socket->ssl_state = SW_SSL_STATE_WAIT_STREAM;
            }
            return SW_OK;
        }
        connect_success:
#endif
        if (cli->onConnect)
        {
            execute_onConnect(cli);
        }
    }
    else
    {
#ifdef SW_USE_OPENSSL
        connect_fail:
#endif
        _socket->active = 0;
        cli->close(cli);
        if (cli->onError)
        {
            cli->onError(cli);
        }
    }

    return SW_OK;
}

void swoole_open_remote_debug(void)
{
    swClient debug_client;
    swClient_create(&debug_client, SW_SOCK_UDP, 0);

    if (debug_client.connect(&debug_client, SW_DEBUG_SERVER_HOST, SW_DEBUG_SERVER_PORT, -1, 1) < 0)
    {
        swWarn("connect to remote_debug_server[%s:%d] failed.", SW_DEBUG_SERVER_HOST, SW_DEBUG_SERVER_PORT);
        SwooleG.debug_fd = 1;
    }
    else
    {
        SwooleG.debug_fd = debug_client.socket->fd;
    }
}
