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
#include "http.h"
#include "http2.h"

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
    for (i = 0; i < HTTP_PRI; i++)
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
    if (method < 0 || method > HTTP_PRI)
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

    //http method
    if (memcmp(buf, "GET", 3) == 0)
    {
        request->method = HTTP_GET;
        request->offset = 4;
        buf += 4;
    }
    else if (memcmp(buf, "POST", 4) == 0)
    {
        request->method = HTTP_POST;
        request->offset = 5;
        buf += 5;
    }
    else if (memcmp(buf, "PUT", 3) == 0)
    {
        request->method = HTTP_PUT;
        request->offset = 4;
        buf += 4;
    }
    else if (memcmp(buf, "PATCH", 5) == 0)
    {
        request->method = HTTP_PATCH;
        request->offset = 6;
        buf += 6;
    }
    else if (memcmp(buf, "DELETE", 6) == 0)
    {
        request->method = HTTP_DELETE;
        request->offset = 7;
        buf += 7;
    }
    else if (memcmp(buf, "HEAD", 4) == 0)
    {
        request->method = HTTP_HEAD;
        request->offset = 5;
        buf += 5;
    }
    else if (memcmp(buf, "OPTIONS", 7) == 0)
    {
        request->method = HTTP_OPTIONS;
        request->offset = 8;
        buf += 8;
    }
#ifdef SW_USE_HTTP2
    //HTTP2 Connection Preface
    else if (memcmp(buf, "PRI", 3) == 0)
    {
        request->method = HTTP_PRI;
        if (memcmp(buf, SW_HTTP2_PRI_STRING, sizeof(SW_HTTP2_PRI_STRING) - 1) == 0)
        {
            request->buffer->offset = sizeof(SW_HTTP2_PRI_STRING) - 1;
            return SW_OK;
        }
        else
        {
            return SW_ERR;
        }
    }
#endif
    else
    {
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
            if (memcmp(p, "HTTP/1.1", 8) == 0)
            {
                request->version = HTTP_VERSION_11;
                goto end;
            }
            else if (memcmp(p, "HTTP/1.0", 8) == 0)
            {
                request->version = HTTP_VERSION_10;
                goto end;
            }
            else
            {
                request->excepted = 1;
                return SW_ERR;
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
 * POST content-length
 */
int swHttpRequest_get_content_length(swHttpRequest *request)
{
    swString *buffer = request->buffer;
    char *buf = buffer->str + buffer->offset;
    int len = buffer->length - buffer->offset;

    char *pe = buf + len;
    char *p;
    char *eol;

    for (p = buf; p < pe; p++)
    {
        if (*p == '\r' && pe - p > sizeof("Content-Length"))
        {
            if (strncasecmp(p, SW_STRL("\r\nContent-Length") - 1) == 0)
            {
                //strlen("\r\n") + strlen("Content-Length")
                p += (2 + (sizeof("Content-Length:") - 1));
                //skip space
                if (*p == ' ')
                {
                    p++;
                }
                eol = strstr(p, "\r\n");
                if (eol == NULL)
                {
                    return SW_ERR;
                }
                request->content_length = atoi(p);
                return SW_OK;
            }
        }
    }

    return SW_ERR;
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
            if (strncasecmp(p + 2, SW_STRL("\r\nExpect") - 1) == 0)
            {
                p += sizeof("Expect: ") + 1;
                if (strncasecmp(p, SW_STRL("100-continue") - 1) == 0)
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
