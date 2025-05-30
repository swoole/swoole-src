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
#include "swoole_protocol.h"
#include "swoole_client.h"

namespace swoole {
namespace network {

static void Stream_onConnect(Client *cli) {
    auto *stream = static_cast<Stream *>(cli->object);
    if (stream->cancel) {
        cli->close();
    }
    *reinterpret_cast<uint32_t *>(stream->buffer->str) = ntohl(stream->buffer->length - 4);
    if (cli->send(stream->buffer->str, stream->buffer->length, 0) < 0) {
        cli->close();
    } else {
        delete stream->buffer;
        stream->buffer = nullptr;
    }
}

static void Stream_onError(const Client *cli) {
    auto *stream = static_cast<Stream *>(cli->object);
    stream->errCode = swoole_get_last_error();

    swoole_error_log(SW_LOG_WARNING,
                     SW_ERROR_SERVER_CONNECT_FAIL,
                     " connect() failed (%d: %s) while connecting to worker process",
                     stream->errCode,
                     swoole_strerror(stream->errCode));

    if (!stream->response) {
        return;
    }

    stream->response(stream, nullptr, 0);
    delete stream;
}

static void Stream_onReceive(const Client *cli, const char *data, uint32_t length) {
    auto *stream = static_cast<Stream *>(cli->object);
    if (length == 4) {
        cli->socket->close_wait = 1;
    } else {
        stream->response(stream, data + 4, length - 4);
    }
}

static void Stream_onClose(Client *cli) {
    swoole_event_defer(
        [](void *data) {
            const auto *cli = static_cast<Client *>(data);
            delete static_cast<Stream *>(cli->object);
        },
        cli);
}

Stream::Stream(const char *dst_host, int dst_port, SocketType type) : client(type, true) {
    if (client.socket == nullptr) {
        return;
    }

    client.onConnect = Stream_onConnect;
    client.onReceive = Stream_onReceive;
    client.onError = Stream_onError;
    client.onClose = Stream_onClose;
    client.object = this;

    client.open_length_check = true;
    set_protocol(&client.protocol);

    if (client.connect(dst_host, dst_port, -1, 0) < 0) {
        swoole_sys_warning("failed to connect to [%s:%d]", dst_host, dst_port);
        return;
    }
    connected = true;
}

Stream *Stream::create(const char *dst_host, int dst_port, SocketType type) {
    auto *stream = new Stream(dst_host, dst_port, type);
    if (!stream->connected) {
        delete stream;
        return nullptr;
    } else {
        return stream;
    }
}

Stream::~Stream() {
    delete buffer;
}

/**
 * Stream Protocol: Length(32bit/Network Byte Order) + Body
 */
void Stream::set_protocol(Protocol *protocol) {
    protocol->get_package_length = Protocol::default_length_func;
    protocol->package_length_type = 'N';
    protocol->package_length_size = swoole_type_size(protocol->package_length_type);
    protocol->package_body_offset = 4;
    protocol->package_length_offset = 0;
}

void Stream::set_max_length(uint32_t max_length) {
    client.protocol.package_max_length = max_length;
}

int Stream::send(const char *data, size_t length) {
    assert(data != nullptr);
    assert(length > 0);
    if (buffer == nullptr) {
        buffer = new String(swoole_size_align(length + 4, swoole_pagesize()));
        buffer->length = 4;
    }
    if (buffer->append(data, length) < 0) {
        return SW_ERR;
    }
    return SW_OK;
}

ssize_t Stream::recv_sync(Socket *sock, void *_buf, size_t _len) {
    int tmp = 0;
    ssize_t ret = sock->recv_sync(&tmp, sizeof(tmp), MSG_WAITALL);
    if (ret <= 0) {
        return SW_ERR;
    }
    const int length = static_cast<int>(ntohl(tmp));
    if (length <= 0 || length > static_cast<int>(_len)) {
        return SW_ERR;
    }
    return sock->recv_sync(_buf, length, MSG_WAITALL);
}

}  // namespace network
}  // namespace swoole
