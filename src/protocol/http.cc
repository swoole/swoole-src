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
#include "server.h"
#include "http.h"
#include "http2.h"
#include "websocket.h"
#include "static_handler.h"

#include <assert.h>
#include <stddef.h>

#include <string>
#include <algorithm>

using std::string;
using swoole::http::StaticHandler;

static const char *method_strings[] =
{
    "DELETE", "GET", "HEAD", "POST", "PUT", "PATCH", "CONNECT", "OPTIONS", "TRACE", "COPY", "LOCK", "MKCOL", "MOVE",
    "PROPFIND", "PROPPATCH", "UNLOCK", "REPORT", "MKACTIVITY", "CHECKOUT", "MERGE", "M-SEARCH", "NOTIFY",
    "SUBSCRIBE", "UNSUBSCRIBE", "PURGE", "PRI",
};

string swHttpRequest_get_date_if_modified_since(swHttpRequest *request);

int swHttp_get_method(const char *method_str, size_t method_len)
{
    int i = 0;
    for (; i < SW_HTTP_PRI; i++)
    {
        if (swoole_strcaseeq(method_strings[i], strlen(method_strings[i]), method_str, method_len))
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
 * TODO: need to modify, maybe should return v3 in order of v1
 */
std::vector<std::string> intersection(std::vector<std::string> &v1,
                                      std::vector<std::string> &v2)
{
    /**
     * do not define it as std::vector<std::string> v3(n), otherwise there may be empty strings in v3
     */
    std::vector<std::string> v3;

    std::sort(v1.begin(), v1.end());
    std::sort(v2.begin(), v2.end());

    std::set_intersection(v1.begin(),v1.end(),
                          v2.begin(),v2.end(),
                          back_inserter(v3));
    return v3;
}

int swServer_http_static_handler_hit(swServer *serv, swHttpRequest *request, swConnection *conn)
{
    char *url = request->buffer->str + request->url_offset;
    size_t url_length = request->url_length;

    StaticHandler handler(serv, url, url_length);
    if (!handler.hit())
    {
        return false;
    }

    char header_buffer[1024];
    swSendData response;
    response.info.fd = conn->session_id;
    response.info.type = SW_SERVER_EVENT_SEND_DATA;

    if (handler.status_code == SW_HTTP_NOT_FOUND)
    {
        response.info.len = sw_snprintf(
            header_buffer, sizeof(header_buffer),
            "HTTP/1.1 %s\r\n"
            "Server: " SW_HTTP_SERVER_SOFTWARE "\r\n"
            "Content-Length: %zu\r\n"
            "\r\n%s",
            swHttp_get_status_message(SW_HTTP_NOT_FOUND),
            sizeof(SW_HTTP_PAGE_404) - 1, SW_HTTP_PAGE_404
        );
        response.data = header_buffer;
        swServer_master_send(serv, &response);

        return true;
    }

    auto date_str = handler.get_date();
    auto date_str_last_modified = handler.get_date_last_modified();

    string date_if_modified_since = swHttpRequest_get_date_if_modified_since(request);
    if (!date_if_modified_since.empty() && handler.is_modified(date_if_modified_since))
    {
        response.info.len = sw_snprintf(header_buffer, sizeof(header_buffer),
            "HTTP/1.1 304 Not Modified\r\n"
            "%s"
            "Date: %s\r\n"
            "Last-Modified: %s\r\n"
            "Server: %s\r\n\r\n",
            request->keep_alive ? "Connection: keep-alive\r\n" : "",
            date_str.c_str(),
            date_str_last_modified.c_str(),
            SW_HTTP_SERVER_SOFTWARE
        );
        response.data = header_buffer;
        swServer_master_send(serv, &response);

        return true;
    }

    const swSendFile_request *task = handler.get_task();

    if (serv->http_autoindex && handler.is_dir())
    {
        std::vector<std::string> dir_files;
        std::vector<std::string> intersection_files;

        handler.get_dir_files(dir_files);
        intersection_files = intersection(*serv->http_index_files, dir_files);

        /**
         * the index file was not found in the current directory
         */
        if (intersection_files.empty())
        {
            size_t body_length = handler.get_index_page(dir_files, SwooleTG.buffer_stack->str, SwooleTG.buffer_stack->size);

            response.info.len = sw_snprintf(header_buffer, sizeof(header_buffer),
                "HTTP/1.1 200 OK\r\n"
                "%s"
                "Content-Length: %ld\r\n"
                "Content-Type: text/html\r\n"
                "Date: %s\r\n"
                "Last-Modified: %s\r\n"
                "Server: %s\r\n\r\n",
                request->keep_alive ?"Connection: keep-alive\r\n" : "",
                (long) body_length,
                date_str.c_str(),
                date_str_last_modified.c_str(),
                SW_HTTP_SERVER_SOFTWARE
            );
            response.data = header_buffer;
            swServer_master_send(serv, &response);

            response.info.len = body_length;
            response.data = SwooleTG.buffer_stack->str;
            swServer_master_send(serv, &response);
            return true;
        }
        else
        {
            if (!handler.set_filename(intersection_files[0]))
            {
                return false;
            }
        }
    }

    response.info.len = sw_snprintf(header_buffer, sizeof(header_buffer),
        "HTTP/1.1 200 OK\r\n"
        "%s"
        "Content-Length: %ld\r\n"
        "Content-Type: %s\r\n"
        "Date: %s\r\n"
        "Last-Modified: %s\r\n"
        "Server: %s\r\n\r\n",
        request->keep_alive ?"Connection: keep-alive\r\n" : "",
        (long) task->length,
        handler.get_mimetype(),
        date_str.c_str(),
        date_str_last_modified.c_str(),
        SW_HTTP_SERVER_SOFTWARE
    );

    response.data = header_buffer;

#ifdef HAVE_TCP_NOPUSH
    if (conn->socket->tcp_nopush == 0)
    {
        if (swSocket_tcp_nopush(conn->fd, 1) == -1)
        {
            swSysWarn("swSocket_tcp_nopush() failed");
        }
        conn->socket->tcp_nopush = 1;
    }
#endif
    swServer_master_send(serv, &response);

    response.info.type = SW_SERVER_EVENT_SEND_FILE;
    response.info.len = sizeof(swSendFile_request) + task->length + 1;
    response.data = (char *) task;

    swServer_master_send(serv, &response);

    if (!request->keep_alive)
    {
        response.info.type = SW_SERVER_EVENT_CLOSE;
        response.info.len = 0;
        response.data = NULL;
        swServer_master_send(serv, &response);
    }

    return true;
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
    char *ret = (char*) sw_malloc(len * 3);

    for (x = 0, y = 0; len--; x++, y++)
    {
        char c = str[x];

        ret[y] = c;
        if ((c < '0' && c != '-' && c != '.') || (c < 'A' && c > '9') || (c > 'Z' && c < 'a' && c != '_')
                || (c > 'z' && c != '~'))
        {
            ret[y++] = '%';
            ret[y++] = hexchars[(unsigned char) c >> 4];
            ret[y] = hexchars[(unsigned char) c & 15];
        }
    }
    ret[y] = '\0';

    do
    {
        size_t size = y + 1;
        char *tmp = (char*) sw_malloc(size);
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
    char *p = request->buffer->str;
    char *pe = p + request->buffer->length;

    if (request->buffer->length < (sizeof("GET / HTTP/1.x\r\n") - 1))
    {
        return SW_ERR;
    }

    //http method
    if (memcmp(p, SW_STRL("GET")) == 0)
    {
        request->method = SW_HTTP_GET;
        p += 3;
    }
    else if (memcmp(p, SW_STRL("POST")) == 0)
    {
        request->method = SW_HTTP_POST;
        p += 4;
    }
    else if (memcmp(p, SW_STRL("PUT")) == 0)
    {
        request->method = SW_HTTP_PUT;
        p += 3;
    }
    else if (memcmp(p, SW_STRL("PATCH")) == 0)
    {
        request->method = SW_HTTP_PATCH;
        p += 5;
    }
    else if (memcmp(p, SW_STRL("DELETE")) == 0)
    {
        request->method = SW_HTTP_DELETE;
        p += 6;
    }
    else if (memcmp(p, SW_STRL("HEAD")) == 0)
    {
        request->method = SW_HTTP_HEAD;
        p += 4;
    }
    else if (memcmp(p, SW_STRL("OPTIONS")) == 0)
    {
        request->method = SW_HTTP_OPTIONS;
        p += 7;
    }
    else if (memcmp(p, SW_STRL("COPY")) == 0)
    {
        request->method = SW_HTTP_COPY;
        p += 4;
    }
    else if (memcmp(p, SW_STRL("LOCK")) == 0)
    {
        request->method = SW_HTTP_LOCK;
        p += 4;
    }
    else if (memcmp(p, SW_STRL("MKCOL")) == 0)
    {
        request->method = SW_HTTP_MKCOL;
        p += 5;
    }
    else if (memcmp(p, SW_STRL("MOVE")) == 0)
    {
        request->method = SW_HTTP_MOVE;
        p += 4;
    }
    else if (memcmp(p, SW_STRL("PROPFIND")) == 0)
    {
        request->method = SW_HTTP_PROPFIND;
        p += 8;
    }
    else if (memcmp(p, SW_STRL("PROPPATCH")) == 0)
    {
        request->method = SW_HTTP_PROPPATCH;
        p += 9;
    }
    else if (memcmp(p, SW_STRL("UNLOCK")) == 0)
    {
        request->method = SW_HTTP_UNLOCK;
        p += 6;
    }
    else if (memcmp(p, SW_STRL("REPORT")) == 0)
    {
        request->method = SW_HTTP_REPORT;
        p += 6;
    }
    else if (memcmp(p, SW_STRL("PURGE")) == 0)
    {
        request->method = SW_HTTP_PURGE;
        p += 5;
    }
#ifdef SW_USE_HTTP2
    // HTTP2 Connection Preface
    else if (memcmp(p, SW_STRL("PRI")) == 0)
    {
        request->method = SW_HTTP_PRI;
        if (memcmp(p, SW_STRL(SW_HTTP2_PRI_STRING)) == 0)
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
    char state = 0;
    for (; p < pe; p++)
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
            if ((size_t) (pe - p) < (sizeof("HTTP/1.x") - 1))
            {
                return SW_ERR;
            }
            if (memcmp(p, SW_STRL("HTTP/1.1")) == 0)
            {
                request->version = SW_HTTP_VERSION_11;
                goto _end;
            }
            else if (memcmp(p, SW_STRL("HTTP/1.0")) == 0)
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
    p += sizeof("HTTP/1.x") - 1;
    request->request_line_length = request->buffer->offset = p - request->buffer->str;
    return SW_OK;
}

void swHttpRequest_free(swConnection *conn)
{
    swHttpRequest *request = (swHttpRequest *) conn->object;
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
    conn->object = nullptr;
}

/**
 * simple get headers info
 */
void swHttpRequest_parse_header_info(swHttpRequest *request)
{
    swString *buffer = request->buffer;
    // header field start
    char *p = buffer->str + request->request_line_length + (sizeof("\r\n") - 1);
    // point-end: start + strlen(all-header) without strlen("\r\n\r\n")
    char *pe = buffer->str + request->header_length - (sizeof("\r\n\r\n") - 1);

    for (; p < pe; p++)
    {
        if (*(p - 1) == '\n' && *(p - 2) == '\r')
        {
            if (SW_STRCASECT(p, pe - p, "Content-Length:"))
            {
                unsigned long long content_length;
                // strlen("Content-Length:")
                p += (sizeof("Content-Length:") - 1);
                // skip spaces
                while (*p == ' ')
                {
                    p++;
                }
                content_length = strtoull(p, NULL, 10);
                request->content_length = SW_MIN(content_length, UINT32_MAX);
                request->known_length = 1;
            }
            else if (SW_STRCASECT(p, pe - p, "Connection:"))
            {
                // strlen("Connection:")
                p += (sizeof("Connection:") - 1);
                // skip spaces
                while (*p == ' ')
                {
                    p++;
                }
                if (SW_STRCASECT(p, pe - p, "keep-alive"))
                {
                    request->keep_alive = 1;
                }
            }
            else if (SW_STRCASECT(p, pe - p, "Transfer-Encoding:"))
            {
                // strlen("Transfer-Encoding:")
                p += (sizeof("Transfer-Encoding:") - 1);
                // skip spaces
                while (*p == ' ')
                {
                    p++;
                }
                if (SW_STRCASECT(p, pe - p, "chunked"))
                {
                    request->chunked = 1;
                }
            }
        }
    }

    request->header_parsed = 1;
    if (request->chunked && request->known_length && request->content_length == 0)
    {
        request->nobody_chunked = 1;
    }
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
            if (SW_STRCASECT(p, pe - p, "Expect: "))
            {
                p += sizeof("Expect: ") - 1;
                if (SW_STRCASECT(p, pe - p, "100-continue"))
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

int swHttpRequest_get_header_length(swHttpRequest *request)
{
    swString *buffer = request->buffer;
    char *p = buffer->str + buffer->offset;
    char *pe = buffer->str + buffer->length;

    for (; p <= pe - (sizeof("\r\n\r\n") - 1); p++)
    {
        if (memcmp(p, SW_STRL("\r\n\r\n")) == 0)
        {
            // strlen(header) + strlen("\r\n\r\n")
            request->header_length = buffer->offset = p - buffer->str + (sizeof("\r\n\r\n") - 1);
            return SW_OK;
        }
    }

    buffer->offset = p - buffer->str;
    return SW_ERR;
}

int swHttpRequest_get_chunked_body_length(swHttpRequest *request)
{
    swString *buffer = request->buffer;
    char *p = buffer->str + buffer->offset;
    char *pe = buffer->str + buffer->length;

    while (1)
    {
        char *end = p;
        size_t chunk_length = swoole_hex2dec(&end);
        if (*end != '\r')
        {
            request->excepted = 1;
            return SW_ERR;
        }
        p = end + (sizeof("\r\n") - 1) + chunk_length + (sizeof("\r\n") - 1);
        /* used to check package_max_length */
        request->content_length = p - (buffer->str  + request->header_length);
        if (p > pe)
        {
            /* need recv again */
            return SW_ERR;
        }
        buffer->offset = p - buffer->str;
        if (chunk_length == 0)
        {
            break;
        }
    }
    request->known_length = 1;

    return SW_OK;
}

string swHttpRequest_get_date_if_modified_since(swHttpRequest *request)
{
    char *p = request->buffer->str + request->url_offset + request->url_length + 10;
    char *pe = request->buffer->str + request->header_length;

    string result;

    char *date_if_modified_since = NULL;
    size_t length_if_modified_since = 0;

    int state = 0;
    for (; p < pe; p++)
    {
        switch (state)
        {
        case 0:
            if (SW_STRCASECT(p, pe - p, "If-Modified-Since"))
            {
                p += sizeof("If-Modified-Since");
                state = 1;
            }
            break;
        case 1:
            if (!isspace(*p))
            {
                date_if_modified_since = p;
                state = 2;
            }
            break;
        case 2:
            if (SW_STRCASECT(p, pe - p, "\r\n"))
            {
                length_if_modified_since = p - date_if_modified_since;
                return string(date_if_modified_since, length_if_modified_since);
            }
            break;
        default:
            break;
        }
    }

    return string("");
}


#ifdef SW_USE_HTTP2
ssize_t swHttpMix_get_package_length(swProtocol *protocol, swSocket *socket, char *data, uint32_t length)
{
    swConnection *conn = (swConnection *) socket->object;
    if (conn->websocket_status == WEBSOCKET_STATUS_ACTIVE)
    {
        return swWebSocket_get_package_length(protocol, socket, data, length);
    }
    else if (conn->http2_stream)
    {
        return swHttp2_get_frame_length(protocol, socket, data, length);
    }
    else
    {
        abort();
        return SW_ERR;
    }
}

uint8_t swHttpMix_get_package_length_size(swSocket *socket)
{
    swConnection *conn = (swConnection *) socket->object;
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

int swHttpMix_dispatch_frame(swProtocol *proto, swSocket *socket, char *data, uint32_t length)
{
    swConnection *conn = (swConnection *) socket->object;
    if (conn->websocket_status == WEBSOCKET_STATUS_ACTIVE)
    {
        return swWebSocket_dispatch_frame(proto, socket, data, length);
    }
    else if (conn->http2_stream)
    {
        return swReactorThread_dispatch(proto, socket, data, length);
    }
    else
    {
        abort();
        return SW_ERR;
    }
}
#endif
