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
    int32_t body_length;
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
    if (body_length < 0)
    {
        swWarn("invalid package, remote_addr=%s:%d, length=%d, size=%d.", swConnection_get_ip(conn), swConnection_get_port(conn), body_length, size);
        return SW_ERR;
    }
    //total package length
    return protocol->package_body_offset + body_length;
}

static sw_inline int swProtocol_split_package_by_eof(swProtocol *protocol, void *object, swString *buffer)
{
#if 0
    static count;
    count ++;
#endif

    char stack_buf[SW_BUFFER_SIZE_BIG];
    int eof_pos;
    if (buffer->length - buffer->offset < protocol->package_eof_len)
    {
        eof_pos = -1;
    }
    else
    {
        eof_pos = swoole_strnpos(buffer->str + buffer->offset, buffer->length - buffer->offset, protocol->package_eof, protocol->package_eof_len);
    }

    //swNotice("#[0] count=%d, length=%ld, size=%ld, offset=%ld", count, buffer->length, buffer->size, buffer->offset);

    //waiting for more data
    if (eof_pos < 0)
    {
        buffer->offset = buffer->length - protocol->package_eof_len;
        return buffer->length;
    }

    uint32_t length = buffer->offset + eof_pos + protocol->package_eof_len;
    //swNotice("#[4] count=%d, length=%d", count, length);
    protocol->onPackage(object, buffer->str, length);

    //there are remaining data
    if (length < buffer->length)
    {
        uint32_t remaining_length = buffer->length - length;
        char *remaining_data = buffer->str + length;
        //swNotice("#[5] count=%d, remaining_length=%d", count, remaining_length);

        while (1)
        {
            if (remaining_length < protocol->package_eof_len)
            {
                goto wait_more_data;
            }
            eof_pos = swoole_strnpos(remaining_data, remaining_length, protocol->package_eof, protocol->package_eof_len);
            if (eof_pos < 0)
            {
                wait_more_data:
                //swNotice("#[1] count=%d, remaining_length=%d, length=%d", count, remaining_length, length);
                memcpy(stack_buf, remaining_data, remaining_length);
                memcpy(buffer->str, stack_buf, remaining_length);
                buffer->length = remaining_length;
                buffer->offset = 0;
                return remaining_length;
            }
            else
            {
                length = eof_pos + protocol->package_eof_len;
                protocol->onPackage(object, remaining_data, length);
                //swNotice("#[2] count=%d, remaining_length=%d, length=%d", count, remaining_length, length);
                remaining_data += length;
                remaining_length -= length;
            }
        }
    }
    //swNotice("#[3] length=%ld, size=%ld, offset=%ld", buffer->length, buffer->size, buffer->offset);
    swString_clear(buffer);
    return 0;
}

/**
 * @return SW_ERR: close the connection
 * @return SW_OK: continue
 */
int swProtocol_recv_check_length(swProtocol *protocol, swConnection *conn, swString *buffer)
{
    int package_length;
    uint32_t recv_size;
    char swap[SW_BUFFER_SIZE_STD];

    do_recv:
    if (buffer->offset > 0)
    {
        recv_size = buffer->offset - buffer->length;
    }
    else
    {
        recv_size = protocol->package_length_offset + protocol->package_length_size;
    }

    int n = swConnection_recv(conn, buffer->str + buffer->length, recv_size, 0);
    if (n < 0)
    {
        switch (swConnection_error(errno))
        {
        case SW_ERROR:
            swSysError("recv(%d, %d) failed.", conn->fd, recv_size);
            return SW_OK;
        case SW_CLOSE:
            conn->close_errno = errno;
            return SW_ERR;
        default:
            return SW_OK;
        }
    }
    else if (n == 0)
    {
        return SW_ERR;
    }
    else
    {
        buffer->length += n;

        if (conn->recv_wait)
        {
            if (buffer->length >= buffer->offset)
            {
                do_dispatch:
                if (protocol->onPackage(conn, buffer->str, buffer->offset) < 0)
                {
                    return SW_ERR;
                }
                if (conn->removed)
                {
                    return SW_OK;
                }
                conn->recv_wait = 0;

                int remaining_length = buffer->length - buffer->offset;
                if (remaining_length > 0)
                {
                    assert(remaining_length < sizeof(swap));
                    memcpy(swap, buffer->str + buffer->offset, remaining_length);
                    memcpy(buffer->str, swap, remaining_length);
                    buffer->offset = 0;
                    buffer->length = remaining_length;
                    goto do_get_length;
                }
                else
                {
                    swString_clear(buffer);
                    goto do_recv;
                }
            }
            else
            {
                return SW_OK;
            }
        }
        else
        {
            do_get_length: package_length = protocol->get_package_length(protocol, conn, buffer->str, buffer->length);
            //invalid package, close connection.
            if (package_length < 0)
            {
                return SW_ERR;
            }
            //no length
            else if (package_length == 0)
            {
                return SW_OK;
            }
            else if (package_length > protocol->package_max_length)
            {
                swWarn("package is too big, remote_addr=%s:%d, length=%d.", swConnection_get_ip(conn), swConnection_get_port(conn), package_length);
                return SW_ERR;
            }
            //get length success
            else
            {
                if (buffer->size < package_length)
                {
                    if (swString_extend(buffer, package_length) < 0)
                    {
                        return SW_ERR;
                    }
                }
                conn->recv_wait = 1;
                buffer->offset = package_length;

                if (buffer->length >= package_length)
                {
                    goto do_dispatch;
                }
                else
                {
                    goto do_recv;
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
int swProtocol_recv_check_eof(swProtocol *protocol, swConnection *conn, swString *buffer)
{
    int recv_again = SW_FALSE;
    int buf_size;

    recv_data: buf_size = buffer->size - buffer->length;
    char *buf_ptr = buffer->str + buffer->length;

    if (buf_size > SW_BUFFER_SIZE_STD)
    {
        buf_size = SW_BUFFER_SIZE_STD;
    }

    int n = swConnection_recv(conn, buf_ptr, buf_size, 0);
    //swNotice("ReactorThread: recv[len=%d]", n);
    if (n < 0)
    {
        switch (swConnection_error(errno))
        {
        case SW_ERROR:
            swSysError("recv from socket#%d failed.", conn->fd);
            return SW_OK;
        case SW_CLOSE:
            conn->close_errno = errno;
            return SW_ERR;
        default:
            return SW_OK;
        }
    }
    else if (n == 0)
    {
        return SW_ERR;
    }
    else
    {
        buffer->length += n;

        if (buffer->length < protocol->package_eof_len)
        {
            return SW_OK;
        }

        if (protocol->split_by_eof)
        {
            if (swProtocol_split_package_by_eof(protocol, conn, buffer) == 0)
            {
                return SW_OK;
            }
            else
            {
                recv_again = SW_TRUE;
            }
        }
        else if (memcmp(buffer->str + buffer->length - protocol->package_eof_len, protocol->package_eof, protocol->package_eof_len) == 0)
        {
            if (protocol->onPackage(conn, buffer->str, buffer->length) < 0)
            {
                return SW_ERR;
            }
            if (conn->removed)
            {
                return SW_OK;
            }
            swString_clear(buffer);
            return SW_OK;
        }

        //over max length, will discard
        if (buffer->length == protocol->package_max_length)
        {
            swWarn("Package is too big. package_length=%d", (int )buffer->length);
            return SW_ERR;
        }

        //buffer is full, may have not read data
        if (buffer->length == buffer->size)
        {
            recv_again = SW_TRUE;
            if (buffer->size < protocol->package_max_length)
            {
                uint32_t extend_size = swoole_size_align(buffer->size * 2, SwooleG.pagesize);
                if (extend_size > protocol->package_max_length)
                {
                    extend_size = protocol->package_max_length;
                }
                if (swString_extend(buffer, extend_size) < 0)
                {
                    return SW_ERR;
                }
            }
        }
        //no eof
        if (recv_again)
        {
            goto recv_data;
        }
    }
    return SW_OK;
}
