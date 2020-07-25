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
 | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
 +----------------------------------------------------------------------+
 */

#include "swoole.h"
#include "swoole_string.h"
#include "swoole_socket.h"
#include "swoole_protocol.h"
#include "swoole_log.h"

using namespace swoole;

/**
 * return the package total length
 */
ssize_t swProtocol_get_package_length(swProtocol *protocol, swSocket *socket, const char *data, uint32_t size) {
    uint16_t length_offset = protocol->package_length_offset;
    uint8_t package_length_size =
        protocol->get_package_length_size ? protocol->get_package_length_size(socket) : protocol->package_length_size;
    int32_t body_length;

    if (package_length_size == 0) {
        // protocol error
        return SW_ERR;
    }
    /**
     * no have length field, wait more data
     */
    if (size < length_offset + package_length_size) {
        protocol->real_header_length = length_offset + package_length_size;
        return 0;
    }
    body_length = swoole_unpack(protocol->package_length_type, data + length_offset);
    // Length error
    // Protocol length is not legitimate, out of bounds or exceed the allocated length
    if (body_length < 0) {
        swWarn("invalid package (size=%d) from socket#%u<%s:%d>",
               size,
               socket->fd,
               swSocket_get_ip(socket->socket_type, &socket->info),
               swSocket_get_port(socket->socket_type, &socket->info));
        return SW_ERR;
    }
    swDebug("length=%d", protocol->package_body_offset + body_length);

    // total package length
    return protocol->package_body_offset + body_length;
}

static sw_inline int swProtocol_split_package_by_eof(swProtocol *protocol, swSocket *socket, swString *buffer) {
    if (buffer->length < protocol->package_eof_len) {
        return SW_CONTINUE;
    }

    int retval;

    size_t n = buffer->split(protocol->package_eof, protocol->package_eof_len, [&](const char *data, size_t length) -> int {
        if (protocol->onPackage(protocol, socket, data, length) < 0) {
            retval = SW_CLOSE;
            return false;
        }
        if (socket->removed) {
            return false;
        }
        return true;
    });

    if (socket->removed) {
        return SW_CLOSE;
    }

    if (n < 0) {
        return retval;
    } else if (n == 0) {
        return SW_CONTINUE;
    } else if (n < buffer->length) {
        off_t offset;
        buffer->reduce(n);
        offset = buffer->length - protocol->package_eof_len;
        buffer->offset = offset > 0 ? offset : 0;
    } else {
        swString_clear(buffer);
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
int swProtocol_recv_check_length(swProtocol *protocol, swSocket *socket, swString *buffer) {
    ssize_t package_length;
    uint8_t package_length_size =
        protocol->get_package_length_size ? protocol->get_package_length_size(socket) : protocol->package_length_size;
    uint32_t recv_size;
    ssize_t recv_n = 0;

    if (package_length_size == 0) {
        // protocol error
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
        recv_size = protocol->package_length_offset + package_length_size;
    }

    recv_n = socket->recv(buffer->str + buffer->length, recv_size, 0);
    if (recv_n < 0) {
        switch (swSocket_error(errno)) {
        case SW_ERROR:
            swSysWarn("recv(%d, %d) failed", socket->fd, recv_size);
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
                if (protocol->onPackage(protocol, socket, buffer->str, buffer->offset) < 0) {
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
                    swString_clear(buffer);
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
            package_length = protocol->get_package_length(protocol, socket, buffer->str, buffer->length);
            // invalid package, close connection.
            if (package_length < 0) {
                return SW_ERR;
            }
            // no length
            else if (package_length == 0) {
                if (buffer->length == protocol->package_length_offset + package_length_size) {
                    swoole_error_log(SW_LOG_WARNING,
                                     SW_ERROR_PACKAGE_LENGTH_NOT_FOUND,
                                     "bad request, No length found in %ld bytes",
                                     buffer->length);
                    return SW_ERR;
                } else {
                    return SW_OK;
                }
            } else if (package_length > protocol->package_max_length) {
                swoole_error_log(SW_LOG_WARNING,
                                 SW_ERROR_PACKAGE_LENGTH_TOO_LARGE,
                                 "package is too big, remote_addr=%s:%d, length=%zu",
                                 swSocket_get_ip(socket->socket_type, &socket->info),
                                 swSocket_get_port(socket->socket_type, &socket->info),
                                 package_length);
                return SW_ERR;
            }
            // get length success
            else {
                if (buffer->size < (size_t) package_length) {
                    if (swString_extend(buffer, package_length) < 0) {
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
int swProtocol_recv_check_eof(swProtocol *protocol, swSocket *socket, swString *buffer) {
    int recv_again = SW_FALSE;
    int buf_size;

_recv_data:
    buf_size = buffer->size - buffer->length;
    char *buf_ptr = buffer->str + buffer->length;

    if (buf_size > SW_BUFFER_SIZE_STD) {
        buf_size = SW_BUFFER_SIZE_STD;
    }

    int n = socket->recv(buf_ptr, buf_size, 0);
    if (n < 0) {
        switch (swSocket_error(errno)) {
        case SW_ERROR:
            swSysWarn("recv from socket#%d failed", socket->fd);
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

        if (buffer->length < protocol->package_eof_len) {
            return SW_OK;
        }

        if (protocol->split_by_eof) {
            int retval = swProtocol_split_package_by_eof(protocol, socket, buffer);
            if (retval == SW_CONTINUE) {
                recv_again = SW_TRUE;
            } else if (retval == SW_CLOSE) {
                return SW_ERR;
            } else {
                return SW_OK;
            }
        } else if (memcmp(buffer->str + buffer->length - protocol->package_eof_len,
                          protocol->package_eof,
                          protocol->package_eof_len) == 0) {
            buffer->offset = buffer->length;
            if (protocol->onPackage(protocol, socket, buffer->str, buffer->length) < 0) {
                return SW_ERR;
            }
            if (socket->removed) {
                return SW_OK;
            }
            swString_clear(buffer);
#ifdef SW_USE_OPENSSL
            if (socket->ssl && SSL_pending(socket->ssl) > 0) {
                goto _recv_data;
            }
#endif
            return SW_OK;
        }

        // over max length, will discard
        if (buffer->length == protocol->package_max_length) {
            swWarn("Package is too big. package_length=%d", (int) buffer->length);
            return SW_ERR;
        }

        // buffer is full, may have not read data
        if (buffer->length == buffer->size) {
            recv_again = SW_TRUE;
            if (buffer->size < protocol->package_max_length) {
                uint32_t extend_size = swoole_size_align(buffer->size * 2, SwooleG.pagesize);
                if (extend_size > protocol->package_max_length) {
                    extend_size = protocol->package_max_length;
                }
                if (swString_extend(buffer, extend_size) < 0) {
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
