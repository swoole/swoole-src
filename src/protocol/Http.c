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
 | license@php.net so we can mail you a copy immediately.               |
 +----------------------------------------------------------------------+
 | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
 +----------------------------------------------------------------------+
 */
#include "swoole.h"
#include "Http.h"

#include <assert.h>
#include <stddef.h>

/**
 * only GET/POST
 */
int swHttpRequest_get_protocol(swHttpRequest *request)
{
    char *buf = request->buffer->str;
    char *pe = buf + request->buffer->length;

    //http method
    if (memcmp(buf, "GET", 3) == 0)
    {
        request->method = HTTP_GET;
        buf += 4;
    }
    else if (memcmp(buf, "POST", 4) == 0)
    {
        request->method = HTTP_POST;
        buf += 5;
    }
    else
    {
        return SW_ERR;
    }

    //http version
    char *p;
    char cmp = 0;
    for (p = buf; p < pe; p++)
    {
        if (cmp == 0 && *p == SW_SPACE)
        {
            cmp = 1;
        }
        else if (cmp == 1)
        {
            if (p + 8 > pe)
            {
                return SW_ERR;
            }
            if (memcmp(p, "HTTP/1.1", 8) == 0)
            {
                request->version = HTTP_VERSION_11;
                break;
            }
            else if (memcmp(p, "HTTP/1.0", 8) == 0)
            {
                request->version = HTTP_VERSION_10;
                break;
            }
            else
            {
                return SW_ERR;
            }
        }
    }
    p += 8;
    request->buffer->offset = p - request->buffer->str;
    return SW_OK;
}

void swHttpRequest_free(swHttpRequest *request)
{
    if (request->state > 0 && request->buffer)
    {
        swTrace("RequestShutdown. free buffer=%p, request=%p\n", request->buffer, request);
        swString_free(request->buffer);
    }
    request->content_length = 0;
    request->header_length = 0;
    request->state = 0;
    request->method = 0;
    request->version = 0;
    request->buffer = NULL;
}

/**
 * POST content-length
 */
int swHttpRequest_get_content_length(swHttpRequest *request)
{
    swString *buffer = request->buffer;
    char *buf = buffer->str + buffer->offset;
    int len = buffer->length - buffer->offset;

    char *pe = buf + len;
    char *p;
    char state = 0;

    for (p = buf; p < pe; p++)
    {
        if (*p == '\r' && *(p + 1) == '\n')
        {
            if (state == 0)
            {
                if (memcmp(p + 2, SW_STRL("Content-Length") - 1) == 0)
                {
                    p += sizeof("Content-Length: ");
                    request->content_length = atoi(p);
                    state = 1;
                }
                else
                {
                    p++;
                }
            }
            else
            {
                if (memcmp(p + 2, SW_STRL("\r\n") - 1) == 0)
                {
                    request->header_length = p - buffer->str + 4;
                    buffer->offset = request->header_length;
                    return SW_OK;
                }
            }
        }
    }
    buffer->offset = p - buffer->str;
    return SW_ERR;
}

