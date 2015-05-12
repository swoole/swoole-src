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
 | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
 +----------------------------------------------------------------------+
 */

#include "swoole.h"
#include "Connection.h"

/**
 * return the package total length
 */
int swProtocol_get_package_length(swProtocol *protocol, swConnection *conn, char *data, uint32_t size)
{
    uint16_t length_offset = protocol->package_length_offset;
    uint32_t body_length;
    /**
     * no have length field, wait more data
     */
    if (size < length_offset + protocol->package_length_size)
    {
        return 0;
    }
    body_length = swoole_unpack(protocol->package_length_type, data + length_offset);
    //Length error
    //Protocol length is not legitimate, out of bounds or exceed the allocated length
    if (body_length < 1 || body_length > protocol->package_max_length)
    {
        swWarn("invalid package, remote_addr=%s:%d, length=%d, size=%d.", swConnection_get_ip(conn), swConnection_get_port(conn), body_length, size);
        return SW_ERR;
    }
    //total package length
    return protocol->package_body_offset + body_length;
}
