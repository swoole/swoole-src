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
static int swClient_tcp_connect(swClient *cli, char *host, int port, double _timeout, int udp_connect);
static int swClient_tcp_send_sync(swClient *cli, char *data, int length);
static int swClient_tcp_send_async(swClient *cli, char *data, int length);
static int swClient_tcp_sendfile_sync(swClient *cli, char *filename);
static int swClient_tcp_sendfile_async(swClient *cli, char *filename);
static int swClient_tcp_recv_no_buffer(swClient *cli, char *data, int len, int waitall);
//static int swClient_tcp_recv_eof_check(swClient *cli, char *data, int len, int waitall);
//static int swClient_tcp_recv_length_check(swClient *cli, char *data, int len, int waitall);
static int swClient_udp_connect(swClient *cli, char *host, int port, double _timeout, int udp_connect);
static int swClient_udp_send(swClient *cli, char *data, int length);
static int swClient_udp_recv(swClient *cli, char *data, int len, int waitall);
static int swClient_close(swClient *cli);
static swHashMap *swoole_dns_cache = NULL;

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

    if (!cli->socket)
    {
        swWarn("malloc(%d) failed.", (int ) sizeof(swConnection));
        return SW_ERR;
    }

    bzero(cli->socket, sizeof(swConnection));
    cli->socket->fd = sockfd;

    if (type == SW_SOCK_TCP || type == SW_SOCK_TCP6 || type == SW_SOCK_UNIX_STREAM)
    {
        cli->connect = swClient_tcp_connect;
        cli->recv = swClient_tcp_recv_no_buffer;

        if (async)
        {
            cli->send = swClient_tcp_send_async;
            cli->sendfile = swClient_tcp_sendfile_async;
        }
        else
        {
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
        swHashMap_add(swoole_dns_cache, host, strlen(host), cache, NULL);
    }
    memcpy(s_addr, cache->addr, cache->length);
    return SW_OK;
}

static int swClient_close(swClient *cli)
{
    int fd = cli->socket->fd;
    int ret;

    if (cli->async)
    {
        ret = swReactor_close(SwooleG.main_reactor, fd);
    }
    else
    {
        bzero(cli->socket, sizeof(swConnection));
        ret = close(fd);
    }

    if (cli->type == SW_SOCK_UNIX_DGRAM)
    {
        unlink(cli->socket->info.addr.un.sun_path);
    }

    return ret;
}

static int swClient_tcp_connect(swClient *cli, char *host, int port, double timeout, int nonblock)
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
    }
    return ret;
}

static int swClient_tcp_send_async(swClient *cli, char *data, int length)
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

static int swClient_tcp_send_sync(swClient *cli, char *data, int length)
{
    int written = 0;
    int n;

    assert(length > 0);
    assert(data != NULL);

    while (written < length)
    {
        n = send(cli->socket->fd, data, length - written, 0);
        if (n < 0)
        {
            //中断
            if (errno == EINTR)
            {
                continue;
            }
            //让出
            else if (errno == EAGAIN)
            {
                swYield();
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

static int swClient_tcp_recv_no_buffer(swClient *cli, char *data, int len, int waitall)
{
    int flag = 0, ret;
    if (waitall == 1)
    {
        flag = MSG_WAITALL;
    }

#ifdef SW_CLIENT_SOCKET_WAIT
    if (cli->socket->socket_wait)
    {
        swSocket_wait(cli->socket->fd, cli->timeout_ms, SW_EVENT_READ);
    }
#endif

    ret = recv(cli->socket->fd, data, len, flag);
    if (ret < 0)
    {
        if (errno == EINTR)
        {
            ret = recv(cli->socket->fd, data, len, flag);
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
    char buf[1024];

    if (swClient_inet_addr(cli, host, port) < 0)
    {
        return SW_ERR;
    }

    cli->timeout = timeout;
    if (timeout > 0)
    {
        swSocket_set_timeout(cli->socket->fd, timeout);
    }

    cli->socket->active = 1;

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
        return SW_OK;
    }

    int bufsize = SwooleG.socket_buffer_size;
    setsockopt(cli->socket->fd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
    setsockopt(cli->socket->fd, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));

    if (connect(cli->socket->fd, (struct sockaddr *) (&cli->server_addr), cli->server_addr.len) == 0)
    {
        //清理connect前的buffer数据遗留
        while (recv(cli->socket->fd, buf, 1024, MSG_DONTWAIT) > 0);
        return SW_OK;
    }
    else
    {
        swSysError("connect() failed.");
        cli->socket->active = 0;
        return SW_ERR;
    }
}

static int swClient_udp_send(swClient *cli, char *data, int len)
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

static int swClient_udp_recv(swClient *cli, char *data, int length, int waitall)
{
    int flag = 0, ret;

    if (waitall == 1)
    {
        flag = MSG_WAITALL;
    }
    cli->remote_addr.len = sizeof(cli->remote_addr.addr);
    ret = recvfrom(cli->socket->fd, data, length, flag, (struct sockaddr *) &cli->remote_addr.addr, &cli->remote_addr.len);
    if (ret < 0)
    {
        if (errno == EINTR)
        {
            ret = recvfrom(cli->socket->fd, data, length, flag, (struct sockaddr *) &cli->remote_addr, &cli->remote_addr.len);
        }
        else
        {
            return SW_ERR;
        }
    }
    return ret;
}

void swoole_open_remote_debug(void)
{
    swClient debug_client;
    swClient_create(&debug_client, SW_SOCK_UDP, 0);

    if (debug_client.connect(&debug_client, SW_DEBUG_SERVER_HOST, SW_DEBUG_SERVER_PORT, -1, 1) < 0)
    {
        swWarn("connect to remove_debug_server[%s:%d] failed.", SW_DEBUG_SERVER_HOST, SW_DEBUG_SERVER_PORT);
        SwooleG.debug_fd = 1;
    }
    else
    {
        SwooleG.debug_fd = debug_client.socket->fd;
    }
}
