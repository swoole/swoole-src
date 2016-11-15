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
#include "redis.h"
#include "Connection.h"

typedef struct
{
    uint8_t state;

    int n_lines_total;
    int n_lines_received;

    int n_bytes_total;
    int n_bytes_received;

    int offset;

} swRedis_request;

int swRedis_recv(swProtocol *protocol, swConnection *conn, swString *buffer)
{
    char *p, *pe;
    int ret;
    char *buf_ptr;

    swRedis_request *request;

    if (conn->object == NULL)
    {
        request = sw_malloc(sizeof(swRedis_request));
        bzero(request, sizeof(swRedis_request));
        conn->object = request;
    }
    else
    {
        request = (swRedis_request *) conn->object;
    }

    recv_data: buf_ptr = buffer->str + buffer->length;

    int n = swConnection_recv(conn, buf_ptr, SW_BUFFER_SIZE_STD, 0);
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
        p = buffer->str + buffer->length;
        pe = p + n;
        buffer->length += n;

        if (strncmp(buffer->str + buffer->length - SW_CRLF_LEN, SW_CRLF, SW_CRLF_LEN) != 0)
        {
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
            else if (buffer->length == buffer->size)
            {
                package_too_big:
                swWarn("Package is too big. package_length=%d", (int )buffer->length);
                return SW_ERR;
            }
            goto recv_data;
        }

        do
        {
            switch(request->state)
            {
            case SW_REDIS_RECEIVE_TOTAL_LINE:
                if (*p == '*' && (p = swRedis_get_number(p, &ret)))
                {
                    request->n_lines_total = ret;
                    request->state = SW_REDIS_RECEIVE_LENGTH;
                    break;
                }
                /* no break */

            case SW_REDIS_RECEIVE_LENGTH:
                if (*p == '$' && (p = swRedis_get_number(p, &ret)))
                {
                    if (ret < 0)
                    {
                        break;
                    }
                    if (ret + buffer->length > protocol->package_max_length)
                    {
                        goto package_too_big;
                    }
                    request->n_bytes_total = ret;
                    request->state = SW_REDIS_RECEIVE_STRING;
                    break;
                }
                //integer
                else if (*p == ':' && (p = swRedis_get_number(p, &ret)))
                {
                    break;
                }
                /* no break */

            case SW_REDIS_RECEIVE_STRING:
                if (pe - p < request->n_bytes_total - request->n_bytes_received)
                {
                    request->n_bytes_received += pe - p;
                    return SW_OK;
                }
                else
                {
                    p += request->n_bytes_total + SW_CRLF_LEN;
                    request->n_bytes_total = 0;
                    request->n_lines_received++;

                    if (request->n_lines_received == request->n_lines_total)
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
                        bzero(request, sizeof(swRedis_request));
                        return SW_OK;
                    }
                }
                break;

            default:
                goto failed;
            }
        } while(p < pe);
    }
    failed:
    swWarn("redis protocol error.");
    return SW_ERR;
}
