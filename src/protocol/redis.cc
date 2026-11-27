/*
 +----------------------------------------------------------------------+
 | Swoole                                                               |
 +----------------------------------------------------------------------+
 | Copyright (c) 2012-2015 The Swoole Group                             |
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

#include "swoole_string.h"
#include "swoole_socket.h"
#include "swoole_protocol.h"
#include "swoole_server.h"
#include "swoole_redis.h"

namespace swoole {
namespace redis {

const char *get_number(const char *p, const char *pe, int *_ret) {
    // p points at the type byte ('*', '$' or ':'); the number must be followed by CRLF inside [p, pe).
    const char *q = p + 1;
    bool negative = false;
    if (q < pe && *q == '-') {
        negative = true;
        q++;
    }
    if (q >= pe || *q < '0' || *q > '9') {
        return nullptr;
    }
    int64_t value = 0;
    while (q < pe && *q >= '0' && *q <= '9') {
        value = value * 10 + (*q - '0');
        if (value > INT32_MAX) {
            return nullptr;
        }
        q++;
    }
    if (pe - q < SW_CRLF_LEN || memcmp(q, SW_CRLF, SW_CRLF_LEN) != 0) {
        return nullptr;
    }
    *_ret = static_cast<int>(negative ? -value : value);
    return q + SW_CRLF_LEN;
}

#ifndef _WIN32
// Returns one request's length, zero for an incomplete request, or SW_ERR for malformed/oversized input.
static ssize_t get_request_length(const char *data, size_t length, size_t limit) {
    const char *p = data;
    const char *end = data + length;
    int arguments = -1;
    int received = 0;
    while (p < end) {
        // A numeric line may be split at any byte, independently of later commands in the buffer.
        const char *newline = static_cast<const char *>(memchr(p, '\n', end - p));
        if (!newline) {
            return length >= limit ? SW_ERR : 0;
        }
        const char type = *p;
        int value;
        const char *next = get_number(p, newline + 1, &value);
        if (!next) {
            return SW_ERR;
        }
        p = next;
        if (static_cast<size_t>(p - data) > limit) {
            return SW_ERR;
        }
        if (arguments < 0) {
            if (type != '*' || value < 0) {
                return SW_ERR;
            }
            arguments = value;
            if (arguments == 0) {
                return p - data;
            }
            continue;
        }

        if (type == '$') {
            if (value < -1) {
                return SW_ERR;
            }
            if (value >= 0) {
                const size_t body_length = static_cast<size_t>(value) + SW_CRLF_LEN;
                const size_t packet_length = (p - data) + body_length;
                if (packet_length > limit) {
                    return SW_ERR;
                }
                if (static_cast<size_t>(end - p) < body_length) {
                    return 0;
                }
                if (memcmp(p + value, SW_CRLF, SW_CRLF_LEN) != 0) {
                    return SW_ERR;
                }
                p += body_length;
            }
        } else if (type != ':') {
            return SW_ERR;
        }
        if (++received == arguments) {
            return p - data;
        }
    }
    return length >= limit ? SW_ERR : 0;
}

int recv_packet(Protocol *protocol, Connection *conn, String *buffer) {
    auto *socket = conn->socket;
    bool parse_buffer = socket->skip_recv;
    socket->skip_recv = 0;

    while (true) {
        if (!parse_buffer) {
            if (buffer->length == buffer->size) {
                if (buffer->size >= protocol->package_max_length) {
                    swoole_warning("Package is too big. package_length=%zu", buffer->length);
                    return SW_ERR;
                }
                const size_t size = buffer->size >= protocol->package_max_length / 2
                                        ? protocol->package_max_length
                                        : std::min(swoole_size_align(buffer->size * 2, swoole_pagesize()),
                                                   static_cast<size_t>(protocol->package_max_length));
                buffer->extend(size);
            }

            ssize_t n = socket->recv(buffer->str + buffer->length, buffer->size - buffer->length, 0);
            if (n < 0) {
                switch (socket->catch_read_error(errno)) {
                case SW_ERROR:
                    swoole_sys_warning("recv from socket#%d failed", conn->fd);
                    return SW_OK;
                case SW_CLOSE:
                    return SW_ERR;
                default:
                    return SW_OK;
                }
            }
            if (n == 0) {
                return SW_ERR;
            }
            buffer->length += n;
        }
        parse_buffer = false;

        size_t consumed = 0;
        while (consumed < buffer->length) {
            const auto length =
                get_request_length(buffer->str + consumed, buffer->length - consumed, protocol->package_max_length);
            if (length < 0) {
                swoole_warning("redis protocol error or package too big");
                return SW_ERR;
            }
            if (length == 0) {
                break;
            }
            RecvData data{};
            data.data = buffer->str + consumed;
            data.info.len = length;
            consumed += length;
            if (protocol->onPackage(protocol, socket, &data) < 0) {
                return SW_ERR;
            }
            if (socket->removed || !conn->can_receive()) {
                // The callback may close the connection synchronously and release its receive buffer.
                if (socket->recv_buffer == buffer) {
                    buffer->reduce(consumed);
                    socket->skip_recv = buffer->length > 0;
                }
                return SW_OK;
            }
        }
        // Compact only once per receive, retaining the incomplete tail for the next read.
        buffer->reduce(consumed);
        if (buffer->length == 0) {
            return SW_OK;
        }
    }
}
#endif  // _WIN32

void format_nil(String *buf) {
    buf->append(SW_STRL(SW_REDIS_RETURN_NIL));
}

void format(String *buf, ReplyType type, const std::string &value) {
    if (type == REPLY_STATUS) {
        if (value.empty()) {
            buf->append(SW_STRL("+OK\r\n"));
        } else {
            buf->format("+%.*s\r\n", value.length(), value.c_str());
        }
    } else if (type == REPLY_ERROR) {
        if (value.empty()) {
            buf->append(SW_STRL("-ERR\r\n"));
        } else {
            buf->format("-%.*s\r\n", value.length(), value.c_str());
        }
    } else if (type == REPLY_STRING) {
        // Empty bulk strings are valid RESP values and still require their length and CRLF.
        buf->format("$%zu\r\n", value.length());
        buf->append(value);
        buf->append(SW_CRLF, SW_CRLF_LEN);
    }
}

void format(String *buf, ReplyType type, long value) {
    buf->format(":%" PRId64 "\r\n", value);
}

std::vector<std::string> parse(const char *data, size_t len) {
    int state = STATE_RECEIVE_TOTAL_LINE;

    const char *p = data;
    const char *pe = p + len;
    const char *q;
    int ret;
    int length = 0;

    std::vector<std::string> result;
    if (len == 0) {
        return result;
    }
    do {
        switch (state) {
        case STATE_RECEIVE_TOTAL_LINE:
            if (*p == '*' && ((q = get_number(p, pe, &ret)))) {
                p = q;
                state = STATE_RECEIVE_LENGTH;
                break;
            }
            /* no break */

        case STATE_RECEIVE_LENGTH:
            if (*p == '$' && ((q = get_number(p, pe, &ret)))) {
                p = q;
                if (ret < 0) {
                    break;
                }
                length = ret;
                state = STATE_RECEIVE_STRING;
                break;
            }
            // integer
            else if (*p == ':' && ((q = get_number(p, pe, &ret)))) {
                p = q;
                result.push_back(std::to_string(ret));
                break;
            }
            /* no break */

        case STATE_RECEIVE_STRING:
            if (pe - p < static_cast<ptrdiff_t>(length) + SW_CRLF_LEN) {
                return result;
            }
            result.emplace_back(p, length);
            p += length + SW_CRLF_LEN;
            state = STATE_RECEIVE_LENGTH;
            break;

        default:
            break;
        }
    } while (p < pe);

    return result;
}
}  // namespace redis
}  // namespace swoole
