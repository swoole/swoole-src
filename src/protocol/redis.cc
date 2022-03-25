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

#include "swoole.h"
#include "swoole_string.h"
#include "swoole_socket.h"
#include "swoole_protocol.h"
#include "swoole_server.h"
#include "swoole_redis.h"

namespace swoole {
namespace redis {

struct Request {
    uint8_t state;

    int n_lines_total;
    int n_lines_received;

    int n_bytes_total;
    int n_bytes_received;

    int offset;
};

int recv_packet(Protocol *protocol, Connection *conn, String *buffer) {
    const char *p, *pe;
    int ret;
    char *buf_ptr;
    size_t buf_size;
    RecvData rdata{};
    Request *request;
    network::Socket *socket = conn->socket;

    if (conn->object == nullptr) {
        request = (Request *) sw_malloc(sizeof(Request));
        if (!request) {
            swoole_warning("malloc(%ld) failed", sizeof(Request));
            return SW_ERR;
        }
        sw_memset_zero(request, sizeof(Request));
        conn->object = request;
    } else {
        request = (Request *) conn->object;
    }

_recv_data:
    buf_ptr = buffer->str + buffer->length;
    buf_size = buffer->size - buffer->length;

    int n = socket->recv(buf_ptr, buf_size, 0);
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
    } else if (n == 0) {
        return SW_ERR;
    } else {
        buffer->length += n;

        if (strncmp(buffer->str + buffer->length - SW_CRLF_LEN, SW_CRLF, SW_CRLF_LEN) != 0) {
            if (buffer->size < protocol->package_max_length) {
                uint32_t extend_size = swoole_size_align(buffer->size * 2, SwooleG.pagesize);
                if (extend_size > protocol->package_max_length) {
                    extend_size = protocol->package_max_length;
                }
                if (!buffer->extend(extend_size)) {
                    return SW_ERR;
                }
            } else if (buffer->length == buffer->size) {
            _package_too_big:
                swoole_warning("Package is too big. package_length=%ld", buffer->length);
                return SW_ERR;
            }
            goto _recv_data;
        }

        p = buffer->str;
        pe = p + buffer->length;

        do {
            switch (request->state) {
            case STATE_RECEIVE_TOTAL_LINE:
                if (*p == '*') {
                    if ((p = get_number(p, &ret)) == nullptr) {
                        goto _failed;
                    }
                    request->n_lines_total = ret;
                    request->state = STATE_RECEIVE_LENGTH;
                    break;
                }
                /* no break */

            case STATE_RECEIVE_LENGTH:
                if (*p == '$') {
                    if ((p = get_number(p, &ret)) == nullptr) {
                        goto _failed;
                    }
                    if (ret < 0) {
                        break;
                    }
                    if (ret + (p - buffer->str) > protocol->package_max_length) {
                        goto _package_too_big;
                    }
                    request->n_bytes_total = ret;
                    request->state = STATE_RECEIVE_STRING;
                    break;
                }
                // integer
                else if (*p == ':') {
                    if ((p = get_number(p, &ret)) == nullptr) {
                        goto _failed;
                    }
                    break;
                }
                /* no break */

            case STATE_RECEIVE_STRING:
                if (pe - p < request->n_bytes_total - request->n_bytes_received) {
                    request->n_bytes_received += pe - p;
                    return SW_OK;
                } else {
                    p += request->n_bytes_total + SW_CRLF_LEN;
                    request->n_bytes_total = 0;
                    request->n_lines_received++;
                    request->state = STATE_RECEIVE_LENGTH;
                    buffer->offset = buffer->length;

                    if (request->n_lines_received == request->n_lines_total) {
                        rdata.info.len = buffer->length;
                        rdata.data = buffer->str;
                        if (protocol->onPackage(protocol, socket, &rdata) < 0) {
                            return SW_ERR;
                        }
                        if (socket->removed) {
                            return SW_OK;
                        }
                        buffer->clear();
                        sw_memset_zero(request, sizeof(Request));
                        return SW_OK;
                    }
                }
                break;

            default:
                goto _failed;
            }
        } while (p < pe);
    }
_failed:
    swoole_warning("redis protocol error");
    return SW_ERR;
}

bool format(String *buf) {
    return buf->append(SW_STRL(SW_REDIS_RETURN_NIL)) == SW_OK;
}

bool format(String *buf, enum ReplyType type, const std::string &value) {
    if (type == REPLY_STATUS) {
        if (value.empty()) {
            return buf->append(SW_STRL("+OK\r\n")) == SW_OK;
        } else {
            return buf->format("+%.*s\r\n", value.length(), value.c_str()) > 0;
        }
    } else if (type == REPLY_ERROR) {
        if (value.empty()) {
            return buf->append(SW_STRL("-ERR\r\n")) == SW_OK;
        } else {
            return buf->format("-%.*s\r\n", value.length(), value.c_str()) > 0;
        }
    } else if (type == REPLY_STRING) {
        if (value.empty() or value.length() > SW_REDIS_MAX_STRING_SIZE) {
            return false;
        } else {
            if (buf->format("$%zu\r\n", value.length()) == 0) {
                return false;
            }
            buf->append(value);
            buf->append(SW_CRLF, SW_CRLF_LEN);
            return true;
        }
    }
    return false;
}

bool format(String *buf, enum ReplyType type, long value) {
    return buf->format(":%" PRId64 "\r\n", value) > 0;
}

std::vector<std::string> parse(const char *data, size_t len) {
    int state = STATE_RECEIVE_TOTAL_LINE;

    const char *p = data;
    const char *pe = p + len;
    int ret;
    int length = 0;

    std::vector<std::string> result;
    do {
        switch (state) {
        case STATE_RECEIVE_TOTAL_LINE:
            if (*p == '*' && (p = get_number(p, &ret))) {
                state = STATE_RECEIVE_LENGTH;
                break;
            }
            /* no break */

        case STATE_RECEIVE_LENGTH:
            if (*p == '$' && (p = get_number(p, &ret))) {
                if (ret == -1) {
                    break;
                }
                length = ret;
                state = STATE_RECEIVE_STRING;
                break;
            }
            // integer
            else if (*p == ':' && (p = get_number(p, &ret))) {
                result.push_back(std::to_string(ret));
                break;
            }
            /* no break */

        case STATE_RECEIVE_STRING:
            result.push_back(std::string(p, length));
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
