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
    "SUBSCRIBE", "UNSUBSCRIBE", "PURGE", "PRI",
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


const char *swHttp_get_status_message(int code)
{
    switch (code)
    {
    case 100:
        return "100 Continue";
    case 101:
        return "101 Switching Protocols";
    case 201:
        return "201 Created";
    case 202:
        return "202 Accepted";
    case 203:
        return "203 Non-Authoritative Information";
    case 204:
        return "204 No Content";
    case 205:
        return "205 Reset Content";
    case 206:
        return "206 Partial Content";
    case 207:
        return "207 Multi-Status";
    case 208:
        return "208 Already Reported";
    case 226:
        return "226 IM Used";
    case 300:
        return "300 Multiple Choices";
    case 301:
        return "301 Moved Permanently";
    case 302:
        return "302 Found";
    case 303:
        return "303 See Other";
    case 304:
        return "304 Not Modified";
    case 305:
        return "305 Use Proxy";
    case 307:
        return "307 Temporary Redirect";
    case 400:
        return "400 Bad Request";
    case 401:
        return "401 Unauthorized";
    case 402:
        return "402 Payment Required";
    case 403:
        return "403 Forbidden";
    case 404:
        return "404 Not Found";
    case 405:
        return "405 Method Not Allowed";
    case 406:
        return "406 Not Acceptable";
    case 407:
        return "407 Proxy Authentication Required";
    case 408:
        return "408 Request Timeout";
    case 409:
        return "409 Conflict";
    case 410:
        return "410 Gone";
    case 411:
        return "411 Length Required";
    case 412:
        return "412 Precondition Failed";
    case 413:
        return "413 Request Entity Too Large";
    case 414:
        return "414 Request URI Too Long";
    case 415:
        return "415 Unsupported Media Type";
    case 416:
        return "416 Requested Range Not Satisfiable";
    case 417:
        return "417 Expectation Failed";
    case 418:
        return "418 I'm a teapot";
    case 421:
        return "421 Misdirected Request";
    case 422:
        return "422 Unprocessable Entity";
    case 423:
        return "423 Locked";
    case 424:
        return "424 Failed Dependency";
    case 426:
        return "426 Upgrade Required";
    case 428:
        return "428 Precondition Required";
    case 429:
        return "429 Too Many Requests";
    case 431:
        return "431 Request Header Fields Too Large";
    case 500:
        return "500 Internal Server Error";
    case 501:
        return "501 Method Not Implemented";
    case 502:
        return "502 Bad Gateway";
    case 503:
        return "503 Service Unavailable";
    case 504:
        return "504 Gateway Timeout";
    case 505:
        return "505 HTTP Version Not Supported";
    case 506:
        return "506 Variant Also Negotiates";
    case 507:
        return "507 Insufficient Storage";
    case 508:
        return "508 Loop Detected";
    case 510:
        return "510 Not Extended";
    case 511:
        return "511 Network Authentication Required";
    case 200:
    default:
        return "200 OK";
    }
}

static int sw_htoi(char *s)
{
    int value;
    int c;

    c = ((unsigned char *)s)[0];
    if (isupper(c))
    {
        c = tolower(c);
    }
    value = (c >= '0' && c <= '9' ? c - '0' : c - 'a' + 10) * 16;

    c = ((unsigned char *)s)[1];
    if (isupper(c))
    {
        c = tolower(c);
    }
    value += c >= '0' && c <= '9' ? c - '0' : c - 'a' + 10;

    return (value);
}

/* return value: length of decoded string */
size_t swHttp_url_decode(char *str, size_t len)
{
    char *dest = str;
    char *data = str;

    while (len--) {
        if (*data == '+') {
            *dest = ' ';
        }
        else if (*data == '%' && len >= 2 && isxdigit((int) *(data + 1)) && isxdigit((int) *(data + 2))) {
            *dest = (char) sw_htoi(data + 1);
            data += 2;
            len -= 2;
        } else {
            *dest = *data;
        }
        data++;
        dest++;
    }
    *dest = '\0';

    return dest - str;
}

char* swHttp_url_encode(char const *str, size_t len)
{
    static unsigned char hexchars[] = "0123456789ABCDEF";

    register size_t x, y;
    char *ret = sw_malloc(len * 3);

    for (x = 0, y = 0; len--; x++, y++) {
        char c = str[x];

        ret[y] = c;
        if ((c < '0' && c != '-' &&  c != '.') ||
            (c < 'A' && c > '9') ||
            (c > 'Z' && c < 'a' && c != '_') ||
            (c > 'z' && c != '~')) {
            ret[y++] = '%';
            ret[y++] = hexchars[(unsigned char) c >> 4];
            ret[y] = hexchars[(unsigned char) c & 15];
        }
    }
    ret[y] = '\0';

    do {
        size_t size = y + 1;
        char *tmp = sw_malloc(size);
        memcpy(tmp, ret, size);
        sw_free(ret);
        ret = tmp;
    } while (0);

    return ret;
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
    else if (memcmp(buf, "PURGE", 5) == 0)
    {
        request->method = SW_HTTP_PURGE;
        request->offset = 6;
        buf += 6;
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
        _excepted:
        request->excepted = 1;
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
                goto _end;
            }
            else if (memcmp(p, "HTTP/1.0", 8) == 0)
            {
                request->version = SW_HTTP_VERSION_10;
                goto _end;
            }
            else
            {
                goto _excepted;
            }
        default:
            break;
        }
    }
    _end:
    p += 8;
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
ssize_t swHttpMix_get_package_length(swProtocol *protocol, swConnection *conn, char *data, uint32_t length)
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
        abort();
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
        abort();
        return 0;
    }
}

int swHttpMix_dispatch_frame(swProtocol *proto, swConnection *conn, char *data, uint32_t length)
{
    if (conn->websocket_status == WEBSOCKET_STATUS_ACTIVE)
    {
        return swWebSocket_dispatch_frame(proto, conn, data, length);
    }
    else if (conn->http2_stream)
    {
        return swReactorThread_dispatch(proto, conn, data, length);
    }
    else
    {
        abort();
        return SW_ERR;
    }
}
#endif
