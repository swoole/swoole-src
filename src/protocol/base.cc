/*
 +----------------------------------------------------------------------+
 | Swoole                                                               |
 +----------------------------------------------------------------------+
 | Copyright (c) 2012-2017 The Swoole Group                             |
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

namespace swoole {
#define proto_error(_sock, _error, _fmt, ...)                                                                          \
    network::Address _remote_addr;                                                                                     \
    if (_sock->get_peer_name(&_remote_addr) < 0) {                                                                     \
        _remote_addr = _sock->info;                                                                                    \
    }                                                                                                                  \
    swoole_error_log(                                                                                                  \
        SW_LOG_WARNING, _error, _fmt "<%s:%d>", ##__VA_ARGS__, _remote_addr.get_addr(), _remote_addr.get_port())

/**
 * return the package total length
 */
ssize_t Protocol::default_length_func(const Protocol *protocol, network::Socket *socket, PacketLength *pl) {
    uint16_t length_offset = protocol->package_length_offset;
    uint8_t package_length_size =
        protocol->get_package_length_size ? protocol->get_package_length_size(socket) : protocol->package_length_size;
    int64_t body_length;

    if (package_length_size == 0) {
        // protocol error
        return SW_ERR;
    }
    /**
     * no have length field, wait more data
     */
    if (pl->buf_size < length_offset + package_length_size) {
        pl->header_len = length_offset + package_length_size;
        return 0;
    }
    body_length = swoole_unpack(protocol->package_length_type, pl->buf + length_offset);
    // Length error
    // Protocol length is not legitimate, out of bounds or exceed the allocated length
    if (body_length < 0) {
        return SW_ERR;
    }
    swoole_debug("length=%d", protocol->package_body_offset + body_length);
    pl->header_len = protocol->package_length_size;

    // total package length
    return protocol->package_body_offset + body_length;
}

int Protocol::recv_split_by_eof(network::Socket *socket, String *buffer) {
    RecvData rdata{};

    if (buffer->length < package_eof_len) {
        return SW_CONTINUE;
    }

    ssize_t n = buffer->split(package_eof, package_eof_len, [&](const char *data, size_t length) -> int {
        rdata.info.len = length;
        rdata.data = data;
        if (onPackage(this, socket, &rdata) < 0) {
            return false;
        }
        if (socket->removed) {
            return false;
        }
        return true;
    });

    if (socket->removed || n < 0) {
        return SW_CLOSE;
    } else if (n == 0) {
        return SW_CONTINUE;
    } else if (n < (ssize_t) buffer->length) {
        off_t offset;
        buffer->reduce(n);
        offset = buffer->length - package_eof_len;
        buffer->offset = offset > 0 ? offset : 0;
    } else {
        buffer->clear();
    }

#ifdef SW_USE_OPENSSL
    if (socket->ssl) {
        return SW_CONTINUE;
    }
#endif

    return SW_OK;
}

/**
 * @return SW_ERR: close the connection
 * @return SW_OK: continue
 */
int Protocol::recv_with_length_protocol(network::Socket *socket, String *buffer) {
    RecvData rdata{};
    PacketLength pl{};
    ssize_t package_length;
    uint8_t _package_length_size = get_package_length_size ? get_package_length_size(socket) : package_length_size;
    uint32_t recv_size = 0;
    ssize_t recv_n = 0;

    // protocol error
    if (get_package_length_size && _package_length_size == 0) {
        return SW_ERR;
    }

    if (socket->skip_recv) {
        socket->skip_recv = 0;
        goto _do_get_length;
    }

_do_recv:
    if (socket->removed) {
        return SW_OK;
    }
    if (buffer->offset > 0) {
        recv_size = buffer->offset - buffer->length;
    } else {
        recv_size = package_length_offset + _package_length_size;
    }

    recv_n = socket->recv(buffer->str + buffer->length, recv_size, 0);
    if (recv_n < 0) {
        switch (socket->catch_read_error(errno)) {
        case SW_ERROR:
            swoole_sys_warning("recv(%d, %d) failed", socket->fd, recv_size);
            return SW_OK;
        case SW_CLOSE:
            return SW_ERR;
        default:
            return SW_OK;
        }
    } else if (recv_n == 0) {
        return SW_ERR;
    } else {
        buffer->length += recv_n;

        if (socket->recv_wait) {
            if (buffer->length >= (size_t) buffer->offset) {
            _do_dispatch:
                rdata.info.len = buffer->offset;
                rdata.data = buffer->str;
                if (onPackage(this, socket, &rdata) < 0) {
                    return SW_ERR;
                }
                if (socket->removed) {
                    return SW_OK;
                }
                socket->recv_wait = 0;

                if (buffer->length > (size_t) buffer->offset) {
                    buffer->reduce(buffer->offset);
                    goto _do_get_length;
                } else {
                    buffer->clear();
                }
            }
#ifdef SW_USE_OPENSSL
            if (socket->ssl) {
                goto _do_recv;
            }
#endif
            return SW_OK;
        } else {
        _do_get_length:
            pl.buf = buffer->str;
            pl.buf_size = buffer->length;
            // TODO: support dynamic calculation of header buffer length (recv_size)
            pl.header_len = 0;
            package_length = get_package_length(this, socket, &pl);
            // invalid package, close connection.
            if (package_length < 0) {
                proto_error(socket,
                            SW_ERROR_PACKAGE_MALFORMED_DATA,
                            "received %zu bytes of malformed data, remote_addr=",
                            buffer->length);
                return SW_ERR;
            }
            // no length
            else if (package_length == 0) {
                if (buffer->length == recv_size) {
                    swoole_error_log(SW_LOG_WARNING,
                                     SW_ERROR_PACKAGE_LENGTH_NOT_FOUND,
                                     "bad request, no length found in %zu bytes, remote_addr=",
                                     buffer->length);
                    return SW_ERR;
                } else {
                    return SW_OK;
                }
            } else if (package_length > package_max_length) {
                proto_error(socket,
                            SW_ERROR_PACKAGE_LENGTH_TOO_LARGE,
                            "the received packet length %ld is too large, remote_addr=",
                            package_length);
                return SW_ERR;
            }
            // get length success
            else {
                if (buffer->size < (size_t) package_length) {
                    if (!buffer->extend(package_length)) {
                        return SW_ERR;
                    }
                }
                socket->recv_wait = 1;
                buffer->offset = package_length;

                if (buffer->length >= (size_t) package_length) {
                    goto _do_dispatch;
                } else {
                    goto _do_recv;
                }
            }
        }
    }
    return SW_OK;
}

/**
 * @return SW_ERR: close the connection
 * @return SW_OK: continue
 */
int Protocol::recv_with_eof_protocol(network::Socket *socket, String *buffer) {
    bool recv_again = false;
    size_t buf_size;
    RecvData rdata{};

_recv_data:
    buf_size = buffer->size - buffer->length;
    char *buf_ptr = buffer->str + buffer->length;

    if (buf_size > SW_BUFFER_SIZE_STD) {
        buf_size = SW_BUFFER_SIZE_STD;
    }

    ssize_t n = socket->recv(buf_ptr, buf_size, 0);
    if (n < 0) {
        switch (socket->catch_read_error(errno)) {
        case SW_ERROR:
            swoole_sys_warning("recv from socket#%d failed", socket->fd);
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

        if (buffer->length < package_eof_len) {
            return SW_OK;
        }

        if (split_by_eof) {
            int retval = recv_split_by_eof(socket, buffer);
            if (retval == SW_CONTINUE) {
                recv_again = true;
            } else if (retval == SW_CLOSE) {
                return SW_ERR;
            } else {
                return SW_OK;
            }
        } else if (memcmp(buffer->str + buffer->length - package_eof_len, package_eof, package_eof_len) == 0) {
            buffer->offset = buffer->length;
            rdata.info.len = buffer->length;
            rdata.data = buffer->str;
            if (onPackage(this, socket, &rdata) < 0) {
                return SW_ERR;
            }
            if (socket->removed) {
                return SW_OK;
            }
            buffer->clear();
#ifdef SW_USE_OPENSSL
            if (socket->ssl && SSL_pending(socket->ssl) > 0) {
                goto _recv_data;
            }
#endif
            return SW_OK;
        }

        // over max length, will discard
        if (buffer->length == package_max_length) {
            proto_error(socket,
                        SW_ERROR_PACKAGE_LENGTH_TOO_LARGE,
                        "The received data packet is too large, length=%lu",
                        (ulong_t) buffer->length);
            return SW_ERR;
        }

        // buffer is full, may have not read data
        if (buffer->length == buffer->size) {
            recv_again = true;
            if (buffer->size < package_max_length) {
                uint32_t extend_size = swoole_size_align(buffer->size * 2, swoole_pagesize());
                if (extend_size > package_max_length) {
                    extend_size = package_max_length;
                }
                if (!buffer->extend(extend_size)) {
                    return SW_ERR;
                }
            }
        }
        // no eof
        if (recv_again) {
            goto _recv_data;
        }
    }
    return SW_OK;
}

}  // namespace swoole

int64_t swoole_unpack(char type, const void *data) {
    switch (type) {
    /*-------------------------8bit-----------------------------*/
    case 'c':  // signed char
        return *(const int8_t *) data;
    case 'C':  // unsigned char
        return *(const uint8_t *) data;

    /*-------------------------16bit-----------------------------*/
    case 's': {  // signed short (16 bit, host byte order)
        int16_t val;
        memcpy(&val, data, sizeof(val));
        return val;
    }
    case 'S': {  // unsigned short (16 bit, host byte order)
        uint16_t val;
        memcpy(&val, data, sizeof(val));
        return val;
    }
    case 'n': {  // unsigned short (16 bit, big endian byte order)
        uint16_t val;
        memcpy(&val, data, sizeof(val));
        return ntohs(val);
    }
    case 'v': {  // unsigned short (16 bit, little endian byte order)
        uint16_t val;
        memcpy(&val, data, sizeof(val));
#if SW_BYTE_ORDER == SW_LITTLE_ENDIAN
        return val;
#else
        return swoole_swap_endian16(val);
#endif
    }

    /*-------------------------Machine dependent size-----------------------------*/
    case 'i': {  // signed integer (machine dependent size and byte order)
        int val;
        memcpy(&val, data, sizeof(val));
        return val;
    }
    case 'I': {  // unsigned integer (machine dependent size and byte order)
        unsigned int val;
        memcpy(&val, data, sizeof(val));
        return val;
    }

    /*-------------------------32bit-----------------------------*/
    case 'l': {  // signed long (32 bit, host byte order)
        int32_t val;
        memcpy(&val, data, sizeof(val));
        return val;
    }
    case 'L': {  // unsigned long (32 bit, host byte order)
        uint32_t val;
        memcpy(&val, data, sizeof(val));
        return val;
    }
    case 'N': {  // unsigned long (32 bit, big endian byte order)
        uint32_t val;
        memcpy(&val, data, sizeof(val));
        return ntohl(val);
    }
    case 'V': {  // unsigned long (32 bit, little endian byte order)
        uint32_t val;
        memcpy(&val, data, sizeof(val));
#if SW_BYTE_ORDER == SW_LITTLE_ENDIAN
        return val;
#else
        return swoole_swap_endian32(val);
#endif
    }

    /*-------------------------64bit-----------------------------*/
    case 'q': {  // signed long long (64 bit, host byte order)
        int64_t val;
        memcpy(&val, data, sizeof(val));
        return val;
    }
    case 'Q': {  // unsigned long long (64 bit, host byte order)
        uint64_t val;
        memcpy(&val, data, sizeof(val));
        return val;
    }
    case 'J': {  // unsigned long long (64 bit, big endian byte order)
        uint64_t val;
        memcpy(&val, data, sizeof(val));
        return swoole_ntoh64(val);  // Network byte order (big endian) to host byte order
    }
    case 'P': {  // unsigned long long (64 bit, little endian byte order)
        uint64_t val;
        memcpy(&val, data, sizeof(val));
#if SW_BYTE_ORDER == SW_LITTLE_ENDIAN
        return val;
#else
        return swoole_swap_endian64(val);
#endif
    }
    default: {
        swoole_error_log(SW_LOG_ERROR, SW_ERROR_INVALID_PARAMS, "Invalid format specifier '%c'", type);
        return -1;
    }
    }
}

uint64_t swoole_hton64(uint64_t value) {
#if SW_BYTE_ORDER == SW_LITTLE_ENDIAN
    return swoole_swap_endian64(value);
#else
    return value;
#endif
}

uint64_t swoole_ntoh64(uint64_t value) {
#if SW_BYTE_ORDER == SW_LITTLE_ENDIAN
    return swoole_swap_endian64(value);
#else
    return value;
#endif
}
