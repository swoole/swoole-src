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

static void swStream_free(swStream *stream);

static void swStream_onConnect(swClient *cli)
{
    swStream *stream = (swStream*) cli->object;
    if (stream->cancel)
    {
        cli->close(cli);
    }
    *((uint32_t *) stream->buffer->str) = ntohl(stream->buffer->length - 4);
    if (cli->send(cli, stream->buffer->str, stream->buffer->length, 0) < 0)
    {
        cli->close(cli);
    }
    else
    {
        swString_free(stream->buffer);
        stream->buffer = NULL;
    }
}

static void swStream_onError(swClient *cli)
{
    swStream_free(cli->object);
}

static void swStream_onReceive(swClient *cli, char *data, uint32_t length)
{
    swStream *stream = (swStream*) cli->object;
    if (length == 4)
    {
        cli->socket->close_wait = 1;
    }
    else
    {
        stream->response(stream, data + 4, length - 4);
    }
}

static void swStream_onClose(swClient *cli)
{
    swStream_free(cli->object);
}

static void swStream_free(swStream *stream)
{
    if (stream->buffer)
    {
        swString_free(stream->buffer);
    }
    sw_free(stream);
}

swStream* swStream_new(char *dst_host, int dst_port, int type)
{
    swStream *stream = (swStream*) sw_malloc(sizeof(swStream));
    bzero(stream, sizeof(swStream));

    swClient *cli = &stream->client;
    if (swClient_create(cli, type, 1) < 0)
    {
        swStream_free(stream);
        return NULL;
    }

    cli->onConnect = swStream_onConnect;
    cli->onReceive = swStream_onReceive;
    cli->onError = swStream_onError;
    cli->onClose = swStream_onClose;
    cli->object = stream;

    cli->open_length_check = 1;
    swStream_set_protocol(&cli->protocol);

    if (cli->connect(cli, dst_host, dst_port, -1, 0) < 0)
    {
        swSysError("failed to connect to [%s:%d].", dst_host, dst_port);
        swStream_free(stream);
        return NULL;
    }
    else
    {
        return stream;
    }
}

/**
 * Stream Protocol: Length(32bit/Network Byte Order) + Body
 */
void swStream_set_protocol(swProtocol *protocol)
{
    protocol->get_package_length = swProtocol_get_package_length;
    protocol->package_length_size = 4;
    protocol->package_length_type = 'N';
    protocol->package_body_offset = 4;
    protocol->package_length_offset = 0;
}

void swStream_set_max_length(swStream *stream, uint32_t max_length)
{
    stream->client.protocol.package_max_length = max_length;
}

int swStream_send(swStream *stream, char *data, size_t length)
{
    if (stream->buffer == NULL)
    {
        stream->buffer = swString_new(swoole_size_align(length + 4, SwooleG.pagesize));
        if (stream->buffer == NULL)
        {
            return SW_ERR;
        }
        stream->buffer->length = 4;
    }
    if (swString_append_ptr(stream->buffer, data, length) < 0)
    {
        return SW_ERR;
    }
    return SW_OK;
}

int swStream_recv_blocking(int fd, void *__buf, size_t __len)
{
    int tmp = 0;
    int ret = swSocket_recv_blocking(fd, &tmp, sizeof(tmp), MSG_WAITALL);

    if (ret <= 0)
    {
        return SW_CLOSE;
    }
    int length = ntohl(tmp);
    if (length <= 0)
    {
        return SW_CLOSE;
    }
    else if (length > __len)
    {
        return SW_CLOSE;
    }

    ret = swSocket_recv_blocking(fd, __buf, length, MSG_WAITALL);
    if (ret <= 0)
    {
        return SW_CLOSE;
    }
    else
    {
        return SW_READY;
    }
}
