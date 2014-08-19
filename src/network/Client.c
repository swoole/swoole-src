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
 | license@php.net so we can mail you a copy immediately.               |
 +----------------------------------------------------------------------+
 | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
 +----------------------------------------------------------------------+
 */

#include "swoole.h"
#include "Client.h"

static int swClient_inet_addr(swClient *cli, char *string);
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
    case SW_SOCK_UDP:
        _domain = AF_INET;
        _type = SOCK_DGRAM;
        break;
    case SW_SOCK_UDP6:
        _domain = AF_INET6;
        _type = SOCK_DGRAM;
        break;
    default:
        return SW_ERR;
    }
    cli->connection.fd = socket(_domain, _type, 0);
    if (cli->connection.fd < 0)
    {
        swWarn("socket() failed. Error: %s[%d]", strerror(errno), errno);
        return SW_ERR;
    }
    if (type < SW_SOCK_UDP)
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

        cli->udp_sock_buffer_size = SW_UNSOCK_BUFSIZE;
    }
    else
    {
        cli->connect = swClient_udp_connect;
        cli->recv = swClient_udp_recv;
        cli->send = swClient_udp_send;
    }

    cli->close = swClient_close;
    cli->sock_domain = _domain;
    cli->sock_type = SOCK_DGRAM;
    cli->type = type;
    cli->async = async;
    return SW_OK;
}

static int swClient_inet_addr(swClient *cli, char *string)
{
    struct in_addr tmp;
    struct hostent *host_entry;
    struct sockaddr_in *sin = &cli->server_addr;

    if (inet_aton(string, &tmp))
    {
        sin->sin_addr.s_addr = tmp.s_addr;
    }
    else
    {
        if (!swoole_dns_cache)
        {
            swoole_dns_cache = swHashMap_new(SW_HASHMAP_INIT_BUCKET_N, free);
        }

        swDNS_cache *cache = swHashMap_find(swoole_dns_cache, string, strlen(string));
        if (cache == NULL)
        {
            if (cli->async)
            {
                swWarn("DNS lookup will block the process. Please use swoole_async_dns_lookup.");
            }
            if (!(host_entry = gethostbyname(string)))
            {
                swWarn("SwooleClient: Host lookup failed. Error: %s[%d] ", strerror(errno), errno);
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
                memcpy(&(sin->sin_addr.s_addr), host_entry->h_addr_list[0], host_entry->h_length);
                return SW_OK;
            }
            else
            {
                memcpy(cache->addr, host_entry->h_addr_list[0], host_entry->h_length);
                cache->length = host_entry->h_length;
            }
            swHashMap_add(swoole_dns_cache, string, strlen(string), cache);
        }
        memcpy(&(sin->sin_addr.s_addr), cache->addr, cache->length);
    }
    return SW_OK;
}

static int swClient_close(swClient *cli)
{
    int fd = cli->connection.fd;
    cli->connection.fd = 0;
    cli->connection.active = 0;
    return close(fd);
}

static int swClient_tcp_connect(swClient *cli, char *host, int port, double timeout, int nonblock)
{
    int ret;
    cli->server_addr.sin_family = cli->sock_domain;
    cli->server_addr.sin_port = htons(port);

    if (swClient_inet_addr(cli, host) < 0)
    {
        return SW_ERR;
    }

    cli->timeout = timeout;

    if (nonblock == 1)
    {
        swSetNonBlock(cli->connection.fd);
    }
    else
    {
        if (cli->timeout > 0)
        {
            swSetTimeout(cli->connection.fd, timeout);
        }
        swSetBlock(cli->connection.fd);
    }

    while (1)
    {
        ret = connect(cli->connection.fd, (struct sockaddr *) (&cli->server_addr), sizeof(cli->server_addr));
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
        cli->connection.active = 1;
    }
    return ret;
}

static int swClient_tcp_send_async(swClient *cli, char *data, int length)
{
    if (cli->connection.out_buffer == NULL)
    {
        cli->connection.out_buffer = swBuffer_new(SW_BUFFER_SIZE);
        if (cli->connection.out_buffer == NULL)
        {
            return SW_ERR;
        }
    }

    if (swBuffer_empty(cli->connection.out_buffer))
    {
        SwooleG.main_reactor->set(SwooleG.main_reactor, cli->connection.fd, cli->reactor_fdtype | SW_EVENT_READ | SW_EVENT_WRITE);
    }

    /**
     * append data to buffer
     */
    if (swBuffer_append(cli->connection.out_buffer, data, length) < 0)
    {
        return SW_ERR;
    }

    return SW_OK;
}

static int swClient_tcp_send_sync(swClient *cli, char *data, int length)
{
    int written = 0;
    int n;

    assert(length > 0);
    assert(data != NULL);

    while (written < length)
    {
        n = send(cli->connection.fd, data, length - written, 0);
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
    if (swSocket_sendfile_sync(cli->connection.fd, filename, cli->timeout) < 0)
    {
        SwooleG.error = errno;
        return SW_ERR;
    }
    return SW_OK;
}

static int swClient_tcp_sendfile_async(swClient *cli, char *filename)
{
    if (swBuffer_empty(cli->connection.out_buffer))
    {
        SwooleG.main_reactor->set(SwooleG.main_reactor, cli->connection.fd, cli->reactor_fdtype | SW_EVENT_READ | SW_EVENT_WRITE);
    }
    if (swConnection_sendfile(&cli->connection, filename) < 0)
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

    ret = recv(cli->connection.fd, data, len, flag);

    if (ret < 0)
    {
        if (errno == EINTR)
        {
            ret = recv(cli->connection.fd, data, len, flag);
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

    cli->timeout = timeout;
    if (timeout > 0)
    {
        swSetTimeout(cli->connection.fd, timeout);
    }

    cli->server_addr.sin_family = cli->sock_domain;
    cli->server_addr.sin_port = htons(port);
    cli->connection.active = 1;

    if (swClient_inet_addr(cli, host) < 0)
    {
        return SW_ERR;
    }

    if (udp_connect != 1)
    {
        return SW_OK;
    }

    int bufsize = cli->udp_sock_buffer_size;
    setsockopt(cli->connection.fd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
    setsockopt(cli->connection.fd, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));

    if (connect(cli->connection.fd, (struct sockaddr *) (&cli->server_addr), sizeof(cli->server_addr)) == 0)
    {
        //清理connect前的buffer数据遗留
        while (recv(cli->connection.fd, buf, 1024, MSG_DONTWAIT) > 0);
        return SW_OK;
    }
    else
    {
        return SW_ERR;
    }
}

static int swClient_udp_send(swClient *cli, char *data, int len)
{
    int n;
    n = sendto(cli->connection.fd, data, len, 0, (struct sockaddr *) (&cli->server_addr), sizeof(struct sockaddr));
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
    socklen_t len;

    if (waitall == 1)
    {
        flag = MSG_WAITALL;

    }
    len = sizeof(struct sockaddr);
    ret = recvfrom(cli->connection.fd, data, length, flag, (struct sockaddr *) (&cli->remote_addr), &len);
    if (ret < 0)
    {
        if (errno == EINTR)
        {
            ret = recvfrom(cli->connection.fd, data, length, flag, (struct sockaddr *) (&cli->remote_addr), &len);
        }
        else
        {
            return SW_ERR;
        }
    }
    return ret;
}
