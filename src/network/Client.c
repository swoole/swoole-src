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
#include "Client.h"

static int swClient_inet_addr(swClient *cli, char *host, int port);
static int swClient_tcp_connect_sync(swClient *cli, char *host, int port, double _timeout, int udp_connect);
static int swClient_tcp_connect_async(swClient *cli, char *host, int port, double timeout, int nonblock);

static int swClient_tcp_send_sync(swClient *cli, char *data, int length, int flags);
static int swClient_tcp_send_async(swClient *cli, char *data, int length, int flags);
static int swClient_udp_send(swClient *cli, char *data, int length, int flags);

static int swClient_tcp_sendfile_sync(swClient *cli, char *filename);
static int swClient_tcp_sendfile_async(swClient *cli, char *filename);
static int swClient_tcp_recv_no_buffer(swClient *cli, char *data, int len, int flags);
static int swClient_udp_connect(swClient *cli, char *host, int port, double _timeout, int udp_connect);
static int swClient_udp_recv(swClient *cli, char *data, int len, int waitall);
static int swClient_close(swClient *cli);

static int swClient_onDgramRead(swReactor *reactor, swEvent *event);
static int swClient_onStreamRead(swReactor *reactor, swEvent *event);
static int swClient_onWrite(swReactor *reactor, swEvent *event);
static int swClient_onError(swReactor *reactor, swEvent *event);

#ifdef SW_USE_OPENSSL
static int swClient_enable_ssl_encrypt(swClient *cli);
static int swClient_ssl_handshake(swClient *cli);
#endif

static swHashMap *swoole_dns_cache = NULL;
static int isset_event_handle = 0;

typedef struct
{
    int length;
    char addr[0];

} swDNS_cache;

int swClient_create(swClient *cli, int type, int async)
{
    int _domain;
    int _type;

    bzero(cli, sizeof(*cli));
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

    int sockfd = socket(_domain, _type, 0);
    if (sockfd < 0)
    {
        swWarn("socket() failed. Error: %s[%d]", strerror(errno), errno);
        return SW_ERR;
    }

    if (async)
    {
        cli->socket = swReactor_get(SwooleG.main_reactor, sockfd);
    }
    else
    {
        cli->socket = sw_malloc(sizeof(swConnection));
    }

    cli->buffer_input_size = SW_CLIENT_BUFFER_SIZE;

    if (!cli->socket)
    {
        swWarn("malloc(%d) failed.", (int ) sizeof(swConnection));
        return SW_ERR;
    }

    bzero(cli->socket, sizeof(swConnection));
    cli->socket->fd = sockfd;
    cli->socket->object = cli;

    if (async)
    {
        swSetNonBlock(cli->socket->fd);
        if (isset_event_handle == 0)
        {
            SwooleG.main_reactor->setHandle(SwooleG.main_reactor, SW_FD_STREAM_CLIENT | SW_EVENT_READ, swClient_onStreamRead);
            SwooleG.main_reactor->setHandle(SwooleG.main_reactor, SW_FD_DGRAM_CLIENT | SW_EVENT_READ, swClient_onDgramRead);
            SwooleG.main_reactor->setHandle(SwooleG.main_reactor, SW_FD_STREAM_CLIENT | SW_EVENT_WRITE, swClient_onWrite);
            SwooleG.main_reactor->setHandle(SwooleG.main_reactor, SW_FD_STREAM_CLIENT | SW_EVENT_ERROR, swClient_onError);
            isset_event_handle = 1;
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
        }
        else
        {
            cli->connect = swClient_tcp_connect_sync;
            cli->send = swClient_tcp_send_sync;
            cli->sendfile = swClient_tcp_sendfile_sync;
        }
    }
    else
    {
        cli->connect = swClient_udp_connect;
        cli->recv = swClient_udp_recv;
        cli->send = swClient_udp_send;
    }

    cli->_sock_domain = _domain;
    cli->_sock_type = _type;

    cli->close = swClient_close;
    cli->type = type;
    cli->async = async;

    return SW_OK;
}

#ifdef SW_USE_OPENSSL
int swClient_enable_ssl_encrypt(swClient *cli)
{
    cli->ssl_context = swSSL_get_context(cli->ssl_method, cli->ssl_cert_file, cli->ssl_key_file);
    if (cli->ssl_context == NULL)
    {
        return SW_ERR;
    }
    cli->socket->ssl_send = 1;
    return SW_OK;
}

static int swClient_ssl_handshake(swClient *cli)
{
    if (!cli->socket->ssl)
    {
        if (swSSL_create(cli->socket, cli->ssl_context, SW_SSL_CLIENT) < 0)
        {
            return SW_ERR;
        }
    }
    if (swSSL_connect(cli->socket) < 0)
    {
        return SW_ERR;
    }
    return SW_OK;
}
#endif

static int swClient_inet_addr(swClient *cli, char *host, int port)
{
    struct hostent *host_entry;
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
        strncpy(cli->server_addr.addr.un.sun_path, host, sizeof(cli->server_addr.addr.un.sun_path));
        cli->server_addr.len = sizeof(cli->server_addr.addr.un);
        return SW_OK;
    }

    if (!swoole_dns_cache)
    {
        swoole_dns_cache = swHashMap_new(SW_HASHMAP_INIT_BUCKET_N, free);
    }

    swDNS_cache *cache = swHashMap_find(swoole_dns_cache, host, strlen(host));
    if (cache == NULL)
    {
        if (cli->async)
        {
            swWarn("DNS lookup will block the process. Please use swoole_async_dns_lookup.");
        }
        if (!(host_entry = gethostbyname(host)))
        {
            swWarn("gethostbyname('%s') failed.", host);
            return SW_ERR;
        }
        if (host_entry->h_addrtype != AF_INET)
        {
            swWarn("Host lookup failed: Non AF_INET domain returned on AF_INET socket.");
            return 0;
        }
        cache = sw_malloc(sizeof(int) + host_entry->h_length);
        if (cache == NULL)
        {
            swWarn("malloc() failed.");
            memcpy(s_addr, host_entry->h_addr_list[0], host_entry->h_length);
            return SW_OK;
        }
        else
        {
            memcpy(cache->addr, host_entry->h_addr_list[0], host_entry->h_length);
            cache->length = host_entry->h_length;
        }
        swHashMap_add(swoole_dns_cache, host, strlen(host), cache);
    }
    memcpy(s_addr, cache->addr, cache->length);
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
        if (cli->ssl_cert_file)
        {
            free(cli->ssl_cert_file);
        }
        if (cli->ssl_key_file)
        {
            free(cli->ssl_key_file);
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
        if (!cli->socket->removed && SwooleG.main_reactor)
        {
            SwooleG.main_reactor->del(SwooleG.main_reactor, fd);
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
    int ret;
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

    //alloc input memory buffer
    cli->buffer = swString_new(cli->buffer_input_size);
    if (!cli->buffer)
    {
        return SW_ERR;
    }

    if (!(cli->onConnect && cli->onError && cli->onClose))
    {
        swWarn("onConnect/onError/onClose callback have not set.");
        return SW_ERR;
    }

    if (swClient_inet_addr(cli, host, port) < 0)
    {
        return SW_ERR;
    }

    if (cli->type == SW_SOCK_UNIX_STREAM)
    {
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
        if (ret == 0)
        {
            SwooleG.main_reactor->add(SwooleG.main_reactor, cli->socket->fd, SW_FD_STREAM_CLIENT | SW_EVENT_WRITE);
        }
        else
        {
            SwooleG.error = errno;
        }
        return ret;
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

    if (ret < 0 &&  errno == EINPROGRESS)
    {
        if (SwooleG.main_reactor->add(SwooleG.main_reactor, cli->socket->fd, cli->reactor_fdtype | SW_EVENT_WRITE) < 0)
        {
            return SW_ERR;
        }
        return SW_OK;
    }

    return ret;
}

static int swClient_tcp_send_async(swClient *cli, char *data, int length, int flags)
{
    if (SwooleG.main_reactor->write(SwooleG.main_reactor, cli->socket->fd, data, length) < 0)
    {
        return SW_ERR;
    }
    else
    {
        return length;
    }
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
                return SW_ERR;
            }
        }
        written += n;
        data += n;
    }
    return written;
}

static int swClient_tcp_sendfile_sync(swClient *cli, char *filename)
{
    if (swSocket_sendfile_sync(cli->socket->fd, filename, cli->timeout) < 0)
    {
        SwooleG.error = errno;
        return SW_ERR;
    }
    return SW_OK;
}

static int swClient_tcp_sendfile_async(swClient *cli, char *filename)
{
    if (swConnection_sendfile(cli->socket, filename) < 0)
    {
        SwooleG.error = errno;
        return SW_ERR;
    }
    return SW_OK;
}

static int swClient_tcp_recv_no_buffer(swClient *cli, char *data, int len, int flag)
{
#ifdef SW_CLIENT_SOCKET_WAIT
    if (cli->socket->socket_wait)
    {
        swSocket_wait(cli->socket->fd, cli->timeout_ms, SW_EVENT_READ);
    }
#endif
    int ret = swConnection_recv(cli->socket, data, len, flag);
    if (ret < 0)
    {
        if (errno == EINTR)
        {
            ret = swConnection_recv(cli->socket, data, len, flag);
        }
        else
        {
            return SW_ERR;
        }
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
            if (SwooleG.main_reactor->add(SwooleG.main_reactor, cli->socket->fd, cli->reactor_fdtype | SW_EVENT_READ) < 0)
            {
                return SW_ERR;
            }
            cli->onConnect(cli);
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

static int swClient_onStreamRead(swReactor *reactor, swEvent *event)
{
    int n;
    swClient *cli = event->socket->object;
    char *buf = cli->buffer->str;
    long buf_size = cli->buffer->size;

#ifdef SW_USE_OPENSSL
    if (cli->open_ssl && cli->socket->ssl_state == SW_SSL_STATE_WAIT_STREAM)
    {
        if (swClient_ssl_handshake(cli) < 0)
        {
            return cli->close(cli);
        }
        if (cli->socket->ssl_state != SW_SSL_STATE_READY)
        {
            return SW_OK;
        }
        //ssl handshake sucess
        else if (cli->onConnect)
        {
            cli->onConnect(cli);
        }
    }
#endif

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
    //packet mode
    else if (cli->packet_mode == 1)
    {
        uint32_t len_tmp = 0;
        n = swConnection_recv(event->socket, &len_tmp, 4, 0);
        if (n <= 0)
        {
            return cli->close(cli);
        }
        else
        {
            buf_size = ntohl(len_tmp);
            if (buf_size > cli->buffer->size)
            {
                swString_extend(cli->buffer, buf_size);
            }
        }
    }

#ifdef SW_CLIENT_RECV_AGAIN
    recv_again:
#endif
    n = swConnection_recv(event->socket, buf, buf_size, 0);
    if (n < 0)
    {
        switch (swConnection_error(errno))
        {
        case SW_ERROR:
            swSysError("Read from socket[%d] failed.", event->fd);
            return SW_OK;
        case SW_CLOSE:
            goto close_fd;
        case SW_WAIT:
            return SW_OK;
        default:
            return SW_OK;
        }
    }
    else if (n == 0)
    {
        close_fd:
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
    int ret = cli->close(cli);
    if (!cli->socket->active && cli->onError)
    {
        cli->onError(cli);
    }
    return ret;
}

static int swClient_onWrite(swReactor *reactor, swEvent *event)
{
    swClient *cli = event->socket->object;

    if (cli->socket->active)
    {
#ifdef SW_USE_OPENSSL
        if (cli->open_ssl && cli->socket->ssl_state == SW_SSL_STATE_WAIT_STREAM)
        {
            if (swClient_ssl_handshake(cli) < 0)
            {
                goto connect_fail;
            }
            else if (cli->socket->ssl_state == SW_SSL_STATE_READY)
            {
                goto connect_success;
            }
            else
            {
                return SW_OK;
            }
        }
#endif
        return swReactor_onWrite(SwooleG.main_reactor, event);
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
        SwooleG.main_reactor->set(SwooleG.main_reactor, event->fd, SW_FD_STREAM_CLIENT | SW_EVENT_READ);
        //connected
        cli->socket->active = 1;

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
                cli->socket->ssl_state = SW_SSL_STATE_WAIT_STREAM;
            }
            return SW_OK;
        }
        connect_success:
#endif
        if (cli->onConnect)
        {
            cli->onConnect(cli);
        }
    }
    else
    {
#ifdef SW_USE_OPENSSL
        connect_fail:
#endif
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
