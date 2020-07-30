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
#include "swoole_api.h"
#include "swoole_string.h"
#include "swoole_socket.h"
#include "swoole_reactor.h"
#include "swoole_log.h"
#include "swoole_protocol.h"
#include "client.h"

namespace swoole { namespace network {

static void Stream_free(Stream *stream);

static void Stream_onConnect(Client *cli) {
    Stream *stream = (Stream *) cli->object;
    if (stream->cancel) {
        cli->close();
    }
    *((uint32_t *) stream->buffer->str) = ntohl(stream->buffer->length - 4);
    if (cli->send(cli, stream->buffer->str, stream->buffer->length, 0) < 0) {
        cli->close();
    } else {
        swString_free(stream->buffer);
        stream->buffer = nullptr;
    }
}

static void Stream_onError(Client *cli) {
    Stream *stream = (Stream *) cli->object;
    stream->errCode = swoole_get_last_error();

    swoole_error_log(SW_LOG_WARNING,
                     SW_ERROR_SERVER_CONNECT_FAIL,
                     " connect() failed (%d: %s) while connecting to worker process",
                     stream->errCode,
                     swoole_strerror(stream->errCode));

    stream->response(stream, nullptr, 0);
    delete cli;
    Stream_free(stream);
}

static void Stream_onReceive(Client *cli, const char *data, uint32_t length) {
    Stream *stream = (Stream *) cli->object;
    if (length == 4) {
        cli->socket->close_wait = 1;
    } else {
        stream->response(stream, data + 4, length - 4);
    }
}

static void Stream_onClose(Client *cli) {
    swoole_event_defer(
        [](void *data) {
            Client *cli = (Client *) data;
            Stream_free((Stream *) cli->object);
            delete cli;
        },
        cli);
}

static void Stream_free(Stream *stream) {
    delete stream;
}

Stream::Stream(const char *dst_host, int dst_port, enum swSocket_type type)
        : client(SW_SOCK_TCP, true)

{
    if (client.socket == nullptr) {
        return;
    }

    client.onConnect = Stream_onConnect;
    client.onReceive = Stream_onReceive;
    client.onError = Stream_onError;
    client.onClose = Stream_onClose;
    client.object = this;

    client.open_length_check = 1;
    set_protocol(&client.protocol);

    if (client.connect(&client, dst_host, dst_port, -1, 0) < 0) {
        swSysWarn("failed to connect to [%s:%d]", dst_host, dst_port);
        return;
    }
    connected = true;
}

Stream::~Stream() {
    if (buffer) {
        swString_free(buffer);
    }
}

/**
 * Stream Protocol: Length(32bit/Network Byte Order) + Body
 */
void Stream::set_protocol(swProtocol *protocol) {
    protocol->get_package_length = swProtocol_get_package_length;
    protocol->package_length_size = 4;
    protocol->package_length_type = 'N';
    protocol->package_body_offset = 4;
    protocol->package_length_offset = 0;
}

void Stream::set_max_length(uint32_t max_length) {
    client.protocol.package_max_length = max_length;
}

int Stream::send(const char *data, size_t length) {
    if (buffer == nullptr) {
        buffer = swString_new(swoole_size_align(length + 4, SwooleG.pagesize));
        if (buffer == nullptr) {
            return SW_ERR;
        }
        buffer->length = 4;
    }
    if (swString_append_ptr(buffer, data, length) < 0) {
        return SW_ERR;
    }
    return SW_OK;
}

int Stream::recv_blocking(swSocket *sock, void *__buf, size_t __len) {
    int tmp = 0;
    ssize_t ret = sock->recv_blocking(&tmp, sizeof(tmp), MSG_WAITALL);

    if (ret <= 0) {
        return SW_CLOSE;
    }
    int length = (int) ntohl(tmp);
    if (length <= 0) {
        return SW_CLOSE;
    } else if (length > (int) __len) {
        return SW_CLOSE;
    }

    ret = sock->recv_blocking(__buf, length, MSG_WAITALL);
    if (ret <= 0) {
        return SW_CLOSE;
    } else {
        return SW_READY;
    }
}

}}
