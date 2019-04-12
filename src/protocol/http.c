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
#include "server.h"
#include "http.h"
#include "http2.h"
#include "websocket.h"

#include <assert.h>
#include <stddef.h>

static const char *method_strings[] =
{
    "DELETE", "GET", "HEAD", "POST", "PUT", "PATCH", "CONNECT", "OPTIONS", "TRACE", "COPY", "LOCK", "MKCOL", "MOVE",
    "PROPFIND", "PROPPATCH", "UNLOCK", "REPORT", "MKACTIVITY", "CHECKOUT", "MERGE", "M-SEARCH", "NOTIFY",
    "SUBSCRIBE", "UNSUBSCRIBE", "PRI",
};

int swHttp_get_method(const char *method_str, int method_len)
{
    int i;
    for (i = 0; i < SW_HTTP_PRI; i++)
    {
        if (strncasecmp(method_strings[i], method_str, method_len) == 0)
        {
            return i + 1;
        }
    }
    return -1;
}

const char* swHttp_get_method_string(int method)
{
    if (method < 0 || method > SW_HTTP_PRI)
    {
        return NULL;
    }
    return method_strings[method - 1];
}

/**
 * only GET/POST
 */
int swHttpRequest_get_protocol(swHttpRequest *request)
{
    char *buf = request->buffer->str;
    char *pe = buf + request->buffer->length;

    if (request->buffer->length < 16)
    {
        return SW_ERR;
    }

    //http method
    if (memcmp(buf, "GET", 3) == 0)
    {
        request->method = SW_HTTP_GET;
        request->offset = 4;
        buf += 4;
    }
    else if (memcmp(buf, "POST", 4) == 0)
    {
        request->method = SW_HTTP_POST;
        request->offset = 5;
        buf += 5;
    }
    else if (memcmp(buf, "PUT", 3) == 0)
    {
        request->method = SW_HTTP_PUT;
        request->offset = 4;
        buf += 4;
    }
    else if (memcmp(buf, "PATCH", 5) == 0)
    {
        request->method = SW_HTTP_PATCH;
        request->offset = 6;
        buf += 6;
    }
    else if (memcmp(buf, "DELETE", 6) == 0)
    {
        request->method = SW_HTTP_DELETE;
        request->offset = 7;
        buf += 7;
    }
    else if (memcmp(buf, "HEAD", 4) == 0)
    {
        request->method = SW_HTTP_HEAD;
        request->offset = 5;
        buf += 5;
    }
    else if (memcmp(buf, "OPTIONS", 7) == 0)
    {
        request->method = SW_HTTP_OPTIONS;
        request->offset = 8;
        buf += 8;
    }
    else if (memcmp(buf, "COPY", 4) == 0)
    {
        request->method = SW_HTTP_COPY;
        request->offset = 5;
        buf += 5;
    }
    else if (memcmp(buf, "LOCK", 4) == 0)
    {
        request->method = SW_HTTP_LOCK;
        request->offset = 5;
        buf += 5;
    }
    else if (memcmp(buf, "MKCOL", 5) == 0)
    {
        request->method = SW_HTTP_MKCOL;
        request->offset = 4;
        buf += 4;
    }
    else if (memcmp(buf, "MOVE", 4) == 0)
    {
        request->method = SW_HTTP_MOVE;
        request->offset = 5;
        buf += 5;
    }
    else if (memcmp(buf, "PROPFIND", 8) == 0)
    {
        request->method = SW_HTTP_PROPFIND;
        request->offset = 9;
        buf += 9;
    }
    else if (memcmp(buf, "PROPPATCH", 9) == 0)
    {
        request->method = SW_HTTP_PROPPATCH;
        request->offset = 10;
        buf += 10;
    }
    else if (memcmp(buf, "UNLOCK", 6) == 0)
    {
        request->method = SW_HTTP_UNLOCK;
        request->offset = 7;
        buf += 7;
    }
    else if (memcmp(buf, "REPORT", 6) == 0)
    {
        request->method = SW_HTTP_REPORT;
        request->offset = 7;
        buf += 7;
    }
#ifdef SW_USE_HTTP2
    //HTTP2 Connection Preface
    else if (memcmp(buf, "PRI", 3) == 0)
    {
        request->method = SW_HTTP_PRI;
        if (memcmp(buf, SW_HTTP2_PRI_STRING, sizeof(SW_HTTP2_PRI_STRING) - 1) == 0)
        {
            request->buffer->offset = sizeof(SW_HTTP2_PRI_STRING) - 1;
            return SW_OK;
        }
        else
        {
            goto _excepted;
        }
    }
#endif
    else
    {
        _excepted: request->excepted = 1;
        return SW_ERR;
    }

    //http version
    char *p;
    char state = 0;
    for (p = buf; p < pe; p++)
    {
        switch(state)
        {
        case 0:
            if (isspace(*p))
            {
                continue;
            }
            state = 1;
            request->url_offset = p - request->buffer->str;
            break;
        case 1:
            if (isspace(*p))
            {
                state = 2;
                request->url_length = p - request->buffer->str - request->url_offset;
                continue;
            }
            break;
        case 2:
            if (isspace(*p))
            {
                continue;
            }
            if (pe - p < 8)
            {
                return SW_ERR;
            }
            if (memcmp(p, "HTTP/1.1", 8) == 0)
            {
                request->version = SW_HTTP_VERSION_11;
                goto end;
            }
            else if (memcmp(p, "HTTP/1.0", 8) == 0)
            {
                request->version = SW_HTTP_VERSION_10;
                goto end;
            }
            else
            {
                goto _excepted;
            }
        default:
            break;
        }
    }
    end: p += 8;
    request->buffer->offset = p - request->buffer->str;
    return SW_OK;
}

void swHttpRequest_free(swConnection *conn)
{
    swHttpRequest *request = conn->object;
    if (!request)
    {
        return;
    }
    if (request->buffer)
    {
        swString_free(request->buffer);
    }
    bzero(request, sizeof(swHttpRequest));
    sw_free(request);
    conn->object = NULL;
}

/**
 * simple get headers info
 * @return content-length exist
 */
int swHttpRequest_get_header_info(swHttpRequest *request)
{
    swString *buffer = request->buffer;
    // header field start
    char *buf = buffer->str + buffer->offset;

    //point-end: start + strlen(all-header) without strlen("\r\n\r\n")
    char *pe = buffer->str + request->header_length - 4;
    char *p;
    uint8_t got_len = 0;

    *(pe) = '\0';
    for (p = buf + 1; p < pe; p++)
    {
        if (*p == '\n' && *(p-1) == '\r')
        {
            p++;
            if (strncasecmp(p, SW_STRL("Content-Length:")) == 0)
            {
                // strlen("Content-Length:")
                p += (sizeof("Content-Length:") - 1);
                // skip one space
                if (*p == ' ')
                {
                    p++;
                }
                request->content_length = atoi(p);
                got_len = 1;
            }
            else if (strncasecmp(p, SW_STRL("Connection:")) == 0)
            {
                // strlen("Connection:")
                p += (sizeof("Connection:") - 1);
                //skip space
                if (*p == ' ')
                {
                    p++;
                }
                if (strncasecmp(p, SW_STRL("keep-alive")) == 0)
                {
                    request->keep_alive = 1;
                }
            }
        }
    }
    *(pe) = '\r';

    return got_len ? SW_OK: SW_ERR;
}

#ifdef SW_HTTP_100_CONTINUE
int swHttpRequest_has_expect_header(swHttpRequest *request)
{
    swString *buffer = request->buffer;
    //char *buf = buffer->str + buffer->offset;
    char *buf = buffer->str;
    //int len = buffer->length - buffer->offset;
    int len = buffer->length;

    char *pe = buf + len;
    char *p;

    for (p = buf; p < pe; p++)
    {
        if (*p == '\r' && pe - p > sizeof("\r\nExpect"))
        {
            p += 2;
            if (strncasecmp(p, SW_STRL("Expect")) == 0)
            {
                p += sizeof("Expect: ") - 1;
                if (strncasecmp(p, SW_STRL("100-continue")) == 0)
                {
                    return 1;
                }
                else
                {
                    return 0;
                }
            }
            else
            {
                p++;
            }
        }
    }
    return 0;
}
#endif

/**
 * header-length
 */
int swHttpRequest_get_header_length(swHttpRequest *request)
{
    swString *buffer = request->buffer;
    char *buf = buffer->str + buffer->offset;
    int len = buffer->length - buffer->offset;

    char *pe = buf + len;
    char *p;

    for (p = buf; p < pe; p++)
    {
        if (*p == '\r' && p + 4 <= pe && memcmp(p, "\r\n\r\n", 4) == 0)
        {
            //strlen(header) + strlen("\r\n\r\n")
            request->header_length = p - buffer->str + 4;
            return SW_OK;
        }
    }
    return SW_ERR;
}

#ifdef SW_USE_HTTP2
ssize_t swHttpMix_get_package_length(struct _swProtocol *protocol, swConnection *conn, char *data, uint32_t length)
{
    if (conn->websocket_status == WEBSOCKET_STATUS_ACTIVE)
    {
        return swWebSocket_get_package_length(protocol, conn, data, length);
    }
    else if (conn->http2_stream)
    {
        return swHttp2_get_frame_length(protocol, conn, data, length);
    }
    else
    {
        assert(0);
        return SW_ERR;
    }
}

uint8_t swHttpMix_get_package_length_size(swConnection *conn)
{
    if (conn->websocket_status == WEBSOCKET_STATUS_ACTIVE)
    {
        return SW_WEBSOCKET_HEADER_LEN + SW_WEBSOCKET_MASK_LEN + sizeof(uint64_t);
    }
    else if (conn->http2_stream)
    {
        return SW_HTTP2_FRAME_HEADER_SIZE;
    }
    else
    {
        assert(0);
        return 0;
    }
}

int swHttpMix_dispatch_frame(swConnection *conn, char *data, uint32_t length)
{
    if (conn->websocket_status == WEBSOCKET_STATUS_ACTIVE)
    {
        return swWebSocket_dispatch_frame(conn, data, length);
    }
    else if (conn->http2_stream)
    {
        return swReactorThread_dispatch(conn, data, length);
    }
    else
    {
        assert(0);
        return SW_ERR;
    }
}
#endif
