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
 | Author: Tianfeng Han  <rango@swoole.com>                             |
 +----------------------------------------------------------------------+
 */

#include "swoole_http.h"
#include "swoole_server.h"

#include <string>

#include "swoole_util.h"
#include "swoole_http2.h"
#include "swoole_websocket.h"
#include "swoole_static_handler.h"

#include "thirdparty/multipart_parser.h"

using std::string;
using swoole::http_server::Request;
using swoole::http_server::StaticHandler;
using swoole::network::SendfileTask;
using swoole::network::Socket;

// clang-format off
static const char *method_strings[] = {
    "DELETE", "GET", "HEAD", "POST", "PUT", "PATCH", "CONNECT", "OPTIONS", "TRACE", "COPY", "LOCK", "MKCOL", "MOVE",
    "PROPFIND", "PROPPATCH", "UNLOCK", "REPORT", "MKACTIVITY", "CHECKOUT", "MERGE", "M-SEARCH", "NOTIFY",
    "SUBSCRIBE", "UNSUBSCRIBE", "PURGE", "PRI",
};
// clang-format on

namespace swoole {

bool Server::select_static_handler(http_server::Request *request, Connection *conn) {
    const char *url = request->buffer_->str + request->url_offset_;
    size_t url_length = request->url_length_;

    StaticHandler handler(this, url, url_length);
    if (!handler.hit()) {
        return false;
    }

    char header_buffer[1024];
    SendData response;
    response.info.fd = conn->session_id;
    response.info.type = SW_SERVER_EVENT_SEND_DATA;

    if (handler.status_code == SW_HTTP_NOT_FOUND) {
        response.info.len = sw_snprintf(header_buffer,
                                        sizeof(header_buffer),
                                        "HTTP/1.1 %s\r\n"
                                        "Server: " SW_HTTP_SERVER_SOFTWARE "\r\n"
                                        "Content-Length: %zu\r\n"
                                        "\r\n%s",
                                        http_server::get_status_message(SW_HTTP_NOT_FOUND),
                                        sizeof(SW_HTTP_PAGE_404) - 1,
                                        SW_HTTP_PAGE_404);
        response.data = header_buffer;
        send_to_connection(&response);

        return true;
    }

    auto date_str = handler.get_date();
    auto date_str_last_modified = handler.get_date_last_modified();

    string date_if_modified_since = request->get_date_if_modified_since();
    if (!date_if_modified_since.empty() && handler.is_modified(date_if_modified_since)) {
        response.info.len = sw_snprintf(header_buffer,
                                        sizeof(header_buffer),
                                        "HTTP/1.1 304 Not Modified\r\n"
                                        "Connection: %s\r\n"
                                        "Date: %s\r\n"
                                        "Last-Modified: %s\r\n"
                                        "Server: %s\r\n\r\n",
                                        request->keep_alive ? "keep-alive" : "close",
                                        date_str.c_str(),
                                        date_str_last_modified.c_str(),
                                        SW_HTTP_SERVER_SOFTWARE);
        response.data = header_buffer;
        send_to_connection(&response);

        return true;
    }

    /**
     * if http_index_files is enabled, need to search the index file first.
     * if the index file is found, set filename to index filename.
     */
    if (!handler.hit_index_file()) {
        return false;
    }

    /**
     * the index file was not found in the current directory,
     * if http_autoindex is enabled, should show the list of files in the current directory.
     */
    if (!handler.has_index_file() && handler.is_enabled_auto_index() && handler.is_dir()) {
        sw_tg_buffer()->clear();
        size_t body_length = handler.make_index_page(sw_tg_buffer());

        response.info.len = sw_snprintf(header_buffer,
                                        sizeof(header_buffer),
                                        "HTTP/1.1 200 OK\r\n"
                                        "Connection: %s\r\n"
                                        "Content-Length: %ld\r\n"
                                        "Content-Type: text/html\r\n"
                                        "Date: %s\r\n"
                                        "Last-Modified: %s\r\n"
                                        "Server: %s\r\n\r\n",
                                        request->keep_alive ? "keep-alive" : "close",
                                        (long) body_length,
                                        date_str.c_str(),
                                        date_str_last_modified.c_str(),
                                        SW_HTTP_SERVER_SOFTWARE);
        response.data = header_buffer;
        send_to_connection(&response);

        response.info.len = body_length;
        response.data = sw_tg_buffer()->str;
        send_to_connection(&response);
        return true;
    }

    auto task = handler.get_task();
    response.info.len = sw_snprintf(header_buffer,
                                    sizeof(header_buffer),
                                    "HTTP/1.1 200 OK\r\n"
                                    "Connection: %s\r\n"
                                    "Content-Length: %ld\r\n"
                                    "Content-Type: %s\r\n"
                                    "Date: %s\r\n"
                                    "Last-Modified: %s\r\n"
                                    "Server: %s\r\n\r\n",
                                    request->keep_alive ? "keep-alive" : "close",
                                    (long) task->length,
                                    handler.get_mimetype(),
                                    date_str.c_str(),
                                    date_str_last_modified.c_str(),
                                    SW_HTTP_SERVER_SOFTWARE);

    response.data = header_buffer;

    // Use tcp_nopush to improve sending efficiency
    conn->socket->cork();

    // Send HTTP header
    send_to_connection(&response);

    // Send HTTP body
    if (task->length != 0) {
        response.info.type = SW_SERVER_EVENT_SEND_FILE;
        response.info.len = sizeof(*task) + task->length + 1;
        response.data = (char *) task;
        send_to_connection(&response);
    }

    // Close the connection if keepalive is not used
    if (!request->keep_alive) {
        response.info.type = SW_SERVER_EVENT_CLOSE;
        response.info.len = 0;
        response.data = nullptr;
        send_to_connection(&response);
    }

    return true;
}

void Server::destroy_http_request(Connection *conn) {
    auto request = reinterpret_cast<swoole::http_server::Request *>(conn->object);
    if (!request) {
        return;
    }
    delete request;
    conn->object = nullptr;
}

void Server::add_http_compression_type(const std::string &type) {
    if (http_compression_types == nullptr) {
        http_compression_types = std::make_shared<std::unordered_set<std::string>>();
    }
    http_compression_types->emplace(type);
}

namespace http_server {
//-----------------------------------------------------------------

static int multipart_on_header_field(multipart_parser *p, const char *at, size_t length) {
    Request *request = (Request *) p->data;
    request->form_data_->current_header_name = at;
    request->form_data_->current_header_name_len = length;

    swoole_trace("header_field: at=%.*s, length=%lu", (int) length, at, length);
    return 0;
}

static int multipart_on_header_value(multipart_parser *p, const char *at, size_t length) {
    swoole_trace("header_value: at=%.*s, length=%lu", (int) length, at, length);

    Request *request = (Request *) p->data;
    FormData *form_data = request->form_data_;

    form_data->multipart_buffer_->append(form_data->current_header_name, form_data->current_header_name_len);
    form_data->multipart_buffer_->append(SW_STRL(": "));
    form_data->multipart_buffer_->append(at, length);
    form_data->multipart_buffer_->append(SW_STRL("\r\n"));

    if (SW_STRCASEEQ(form_data->current_header_name, form_data->current_header_name_len, "content-disposition")) {
        ParseCookieCallback cb = [request, form_data, p](char *key, size_t key_len, char *value, size_t value_len) {
            if (SW_STRCASEEQ(key, key_len, "filename")) {
                memcpy(form_data->upload_tmpfile->str,
                       form_data->upload_tmpfile_fmt_.c_str(),
                       form_data->upload_tmpfile_fmt_.length());
                form_data->upload_tmpfile->str[form_data->upload_tmpfile_fmt_.length()] = 0;
                form_data->upload_filesize = 0;
                int tmpfile = swoole_tmpfile(form_data->upload_tmpfile->str);
                if (tmpfile < 0) {
                    request->excepted = true;
                    return false;
                }

                FILE *fp = fdopen(tmpfile, "wb+");
                if (fp == nullptr) {
                    swoole_sys_warning("fopen(%s) failed", form_data->upload_tmpfile->str);
                    return false;
                }
                p->fp = fp;

                return false;
            }
            return true;
        };
        parse_cookie(at, length, cb);
    }

    return 0;
}

static int multipart_on_data(multipart_parser *p, const char *at, size_t length) {
    Request *request = (Request *) p->data;
    swoole_trace("on_data: length=%lu", length);

    if (!p->fp) {
        request->form_data_->multipart_buffer_->append(at, length);
        return 0;
    }

    request->form_data_->upload_filesize += length;
    if (request->form_data_->upload_filesize > request->form_data_->upload_max_filesize) {
        request->too_large = 1;
        return 1;
    }
    ssize_t n = fwrite(at, sizeof(char), length, p->fp);
    if (n != (off_t) length) {
        fclose(p->fp);
        p->fp = nullptr;
        request->excepted = 1;
        swoole_sys_warning("write upload file failed");
        return 1;
    }

    return 0;
}

static int multipart_on_header_complete(multipart_parser *p) {
    swoole_trace("on_header_complete");
    Request *request = (Request *) p->data;
    FormData *form_data = request->form_data_;
    if (p->fp) {
        form_data->multipart_buffer_->append(SW_STRL(SW_HTTP_UPLOAD_FILE ": "));
        form_data->multipart_buffer_->append(form_data->upload_tmpfile->str, strlen(form_data->upload_tmpfile->str));
    }
    request->multipart_header_parsed = 1;
    form_data->multipart_buffer_->append(SW_STRL("\r\n"));
    return 0;
}

static int multipart_on_data_end(multipart_parser *p) {
    swoole_trace("on_data_end\n");
    Request *request = (Request *) p->data;
    FormData *form_data = request->form_data_;
    request->multipart_header_parsed = 0;
    if (p->fp) {
        form_data->multipart_buffer_->append(SW_STRL("\r\n" SW_HTTP_UPLOAD_FILE));
        fflush(p->fp);
        fclose(p->fp);
        p->fp = nullptr;
    }
    form_data->multipart_buffer_->append(SW_STRL("\r\n"));
    return 0;
}

static int multipart_on_part_begin(multipart_parser *p) {
    swoole_trace("on_part_begi\n");
    Request *request = (Request *) p->data;
    FormData *form_data = request->form_data_;
    form_data->multipart_buffer_->append(p->multipart_boundary, p->boundary_length);
    form_data->multipart_buffer_->append(SW_STRL("\r\n"));
    return 0;
}

static int multipart_on_body_end(multipart_parser *p) {
    Request *request = (Request *) p->data;
    FormData *form_data = request->form_data_;
    form_data->multipart_buffer_->append(p->multipart_boundary, p->boundary_length);
    form_data->multipart_buffer_->append(SW_STRL("--"));

    request->content_length_ = form_data->multipart_buffer_->length - request->header_length_;
    request->tried_to_dispatch = 1;

#if 0
    /**
     * Replace content-length with the actual value
     */
    char *ptr = request->multipart_buffer_->str - (sizeof("\r\n\r\n") - 1);
    char *ptr_end = request->multipart_buffer_->str + (request->multipart_buffer_->length - (sizeof("\r\n\r\n") - 1));

    for (; ptr < ptr_end; ptr++) {
        if (SW_STRCASECT(ptr, ptr_end - ptr, "Content-Length:")) {
            ptr += (sizeof("Content-Length:") - 1);
            // skip spaces
            while (*ptr == ' ') {
                ptr++;
            }
            break;
        }
    }

    std::string actual_content_length = std::to_string(request->content_length_);
    memcpy(ptr, actual_content_length.c_str(), actual_content_length.length());

    ptr += actual_content_length.length();
    SW_LOOP {
        if (*ptr == '\r') {
            break;
        } else {
            *ptr = ' ';
            ptr++;
        }
    }
#endif

    swoole_trace("end, buffer=%.*s", (int) form_data->multipart_buffer_->length, form_data->multipart_buffer_->str);

    return 0;
}

static const multipart_parser_settings mt_parser_settings = {
    multipart_on_header_field,
    multipart_on_header_value,
    multipart_on_data,
    multipart_on_part_begin,
    multipart_on_header_complete,
    multipart_on_data_end,
    multipart_on_body_end,
};

const char *get_status_message(int code) {
    switch (code) {
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

void parse_cookie(const char *at, size_t length, const ParseCookieCallback &cb) {
    char *key, *value;
    const char *separator = ";\0";
    size_t key_len = 0;
    char *strtok_buf = nullptr;

    char *_c = sw_tg_buffer()->str;
    memcpy(_c, at, length);
    _c[length] = '\0';

    key = strtok_r(_c, separator, &strtok_buf);
    while (key) {
        size_t value_len;
        value = strchr(key, '=');

        while (isspace(*key)) {
            key++;
        }

        if (key == value || *key == '\0') {
            goto next_cookie;
        }

        if (value) {
            *value++ = '\0';
            value_len = strlen(value);
        } else {
            value = (char *) "";
            value_len = 0;
        }

        key_len = strlen(key);
        if (!cb(key, key_len, value, value_len)) {
            break;
        }
    next_cookie:
        key = strtok_r(NULL, separator, &strtok_buf);
    }
}

bool parse_multipart_boundary(
    const char *at, size_t length, size_t offset, char **out_boundary_str, int *out_boundary_len) {
    while (offset < length) {
        if (at[offset] == ' ' || at[offset] == ';') {
            offset++;
            continue;
        }
        if (SW_STRCASECT(at + offset, length - offset, "boundary=")) {
            offset += sizeof("boundary=") - 1;
            break;
        }
        void *delimiter = memchr((void *) (at + offset), ';', length - offset);
        if (delimiter == nullptr) {
            return false;
        } else {
            offset += (const char *) delimiter - (at + offset);
        }
    }

    int boundary_len = length - offset;
    char *boundary_str = (char *) at + offset;
    // find eof of boundary
    if (boundary_len > 0) {
        // find ';'
        char *tmp = (char *) memchr(boundary_str, ';', boundary_len);
        if (tmp) {
            boundary_len = tmp - boundary_str;
        }
    }
    if (boundary_len <= 0) {
        return false;
    }
    // trim '"'
    if (boundary_len >= 2 && boundary_str[0] == '"' && *(boundary_str + boundary_len - 1) == '"') {
        boundary_str++;
        boundary_len -= 2;
    }
    *out_boundary_str = boundary_str;
    *out_boundary_len = boundary_len;

    return true;
}

static int url_htoi(char *s) {
    int value;
    int c;

    c = ((unsigned char *) s)[0];
    if (isupper(c)) {
        c = tolower(c);
    }
    value = (c >= '0' && c <= '9' ? c - '0' : c - 'a' + 10) * 16;

    c = ((unsigned char *) s)[1];
    if (isupper(c)) {
        c = tolower(c);
    }
    value += c >= '0' && c <= '9' ? c - '0' : c - 'a' + 10;

    return (value);
}

/* return value: length of decoded string */
size_t url_decode(char *str, size_t len) {
    char *dest = str;
    char *data = str;

    while (len--) {
        if (*data == '+') {
            *dest = ' ';
        } else if (*data == '%' && len >= 2 && isxdigit((int) *(data + 1)) && isxdigit((int) *(data + 2))) {
            *dest = (char) url_htoi(data + 1);
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

char *url_encode(char const *str, size_t len) {
    static uchar hexchars[] = "0123456789ABCDEF";

    size_t x, y;
    char *ret = (char *) sw_malloc(len * 3);

    for (x = 0, y = 0; len--; x++, y++) {
        char c = str[x];

        ret[y] = c;
        if ((c < '0' && c != '-' && c != '.') || (c < 'A' && c > '9') || (c > 'Z' && c < 'a' && c != '_') ||
            (c > 'z' && c != '~')) {
            ret[y++] = '%';
            ret[y++] = hexchars[(unsigned char) c >> 4];
            ret[y] = hexchars[(unsigned char) c & 15];
        }
    }
    ret[y] = '\0';

    do {
        size_t size = y + 1;
        char *tmp = (char *) sw_malloc(size);
        memcpy(tmp, ret, size);
        sw_free(ret);
        ret = tmp;
    } while (0);

    return ret;
}

/**
 * only GET/POST
 */
int Request::get_protocol() {
    char *p = buffer_->str;
    char *pe = p + buffer_->length;

    if (buffer_->length < (sizeof("GET / HTTP/1.x\r\n") - 1)) {
        return SW_ERR;
    }

    // http method
    if (memcmp(p, SW_STRL("GET")) == 0) {
        method = SW_HTTP_GET;
        p += 3;
    } else if (memcmp(p, SW_STRL("POST")) == 0) {
        method = SW_HTTP_POST;
        p += 4;
    } else if (memcmp(p, SW_STRL("PUT")) == 0) {
        method = SW_HTTP_PUT;
        p += 3;
    } else if (memcmp(p, SW_STRL("PATCH")) == 0) {
        method = SW_HTTP_PATCH;
        p += 5;
    } else if (memcmp(p, SW_STRL("DELETE")) == 0) {
        method = SW_HTTP_DELETE;
        p += 6;
    } else if (memcmp(p, SW_STRL("HEAD")) == 0) {
        method = SW_HTTP_HEAD;
        p += 4;
    } else if (memcmp(p, SW_STRL("OPTIONS")) == 0) {
        method = SW_HTTP_OPTIONS;
        p += 7;
    } else if (memcmp(p, SW_STRL("COPY")) == 0) {
        method = SW_HTTP_COPY;
        p += 4;
    } else if (memcmp(p, SW_STRL("LOCK")) == 0) {
        method = SW_HTTP_LOCK;
        p += 4;
    } else if (memcmp(p, SW_STRL("MKCOL")) == 0) {
        method = SW_HTTP_MKCOL;
        p += 5;
    } else if (memcmp(p, SW_STRL("MOVE")) == 0) {
        method = SW_HTTP_MOVE;
        p += 4;
    } else if (memcmp(p, SW_STRL("PROPFIND")) == 0) {
        method = SW_HTTP_PROPFIND;
        p += 8;
    } else if (memcmp(p, SW_STRL("PROPPATCH")) == 0) {
        method = SW_HTTP_PROPPATCH;
        p += 9;
    } else if (memcmp(p, SW_STRL("UNLOCK")) == 0) {
        method = SW_HTTP_UNLOCK;
        p += 6;
    } else if (memcmp(p, SW_STRL("REPORT")) == 0) {
        method = SW_HTTP_REPORT;
        p += 6;
    } else if (memcmp(p, SW_STRL("PURGE")) == 0) {
        method = SW_HTTP_PURGE;
        p += 5;
    }
#ifdef SW_USE_HTTP2
    // HTTP2 Connection Preface
    else if (memcmp(p, SW_STRL("PRI")) == 0) {
        method = SW_HTTP_PRI;
        if (buffer_->length >= (sizeof(SW_HTTP2_PRI_STRING) - 1) && memcmp(p, SW_STRL(SW_HTTP2_PRI_STRING)) == 0) {
            buffer_->offset = sizeof(SW_HTTP2_PRI_STRING) - 1;
            return SW_OK;
        } else {
            goto _excepted;
        }
    }
#endif
    else {
    _excepted:
        excepted = 1;
        return SW_ERR;
    }

    // http version
    char state = 0;
    for (; p < pe; p++) {
        switch (state) {
        case 0:
            if (isspace(*p)) {
                continue;
            }
            state = 1;
            url_offset_ = p - buffer_->str;
            break;
        case 1:
            if (isspace(*p)) {
                state = 2;
                url_length_ = p - buffer_->str - url_offset_;
                continue;
            }
            break;
        case 2:
            if (isspace(*p)) {
                continue;
            }
            if ((size_t)(pe - p) < (sizeof("HTTP/1.x") - 1)) {
                return SW_ERR;
            }
            if (memcmp(p, SW_STRL("HTTP/1.1")) == 0) {
                version = SW_HTTP_VERSION_11;
                goto _end;
            } else if (memcmp(p, SW_STRL("HTTP/1.0")) == 0) {
                version = SW_HTTP_VERSION_10;
                goto _end;
            } else {
                goto _excepted;
            }
        default:
            break;
        }
    }
_end:
    p += sizeof("HTTP/1.x") - 1;
    request_line_length_ = buffer_->offset = p - buffer_->str;
    return SW_OK;
}

/**
 * simple get headers info
 */
void Request::parse_header_info() {
    // header field start
    char *p = buffer_->str + request_line_length_ + (sizeof("\r\n") - 1);
    // point-end: start + strlen(all-header) without strlen("\r\n\r\n")
    char *pe = buffer_->str + header_length_ - (sizeof("\r\n\r\n") - 1);

    for (; p < pe; p++) {
        if (*(p - 1) == '\n' && *(p - 2) == '\r') {
            if (SW_STRCASECT(p, pe - p, "Content-Length:")) {
                // strlen("Content-Length:")
                p += (sizeof("Content-Length:") - 1);
                // skip spaces
                while (*p == ' ') {
                    p++;
                }
                content_length_ = strtoull(p, nullptr, 10);
                known_length = 1;
            } else if (SW_STRCASECT(p, pe - p, "Connection:")) {
                // strlen("Connection:")
                p += (sizeof("Connection:") - 1);
                // skip spaces
                while (*p == ' ') {
                    p++;
                }
                if (SW_STRCASECT(p, pe - p, "keep-alive")) {
                    keep_alive = 1;
                }
            } else if (SW_STRCASECT(p, pe - p, "Transfer-Encoding:")) {
                // strlen("Transfer-Encoding:")
                p += (sizeof("Transfer-Encoding:") - 1);
                // skip spaces
                while (*p == ' ') {
                    p++;
                }
                if (SW_STRCASECT(p, pe - p, "chunked")) {
                    chunked = 1;
                }
            } else if (SW_STRCASECT(p, pe - p, "Content-Type:")) {
                p += (sizeof("Content-Type:") - 1);
                while (*p == ' ') {
                    p++;
                }
                if (SW_STRCASECT(p, pe - p, "multipart/form-data")) {
                    form_data_ = new FormData();
                    form_data_->multipart_boundary_buf = p + (sizeof("multipart/form-data") - 1);
                    form_data_->multipart_boundary_len = strchr(p, '\r') - form_data_->multipart_boundary_buf;
                }
            }
        }
    }

    header_parsed = 1;
    if (chunked && known_length && content_length_ == 0) {
        nobody_chunked = 1;
    }
}

bool Request::init_multipart_parser(Server *server) {
    char *boundary_str;
    int boundary_len;
    if (!parse_multipart_boundary(
            form_data_->multipart_boundary_buf, form_data_->multipart_boundary_len, 0, &boundary_str, &boundary_len)) {
        return false;
    }

    form_data_->multipart_parser_ = multipart_parser_init(boundary_str, boundary_len, &mt_parser_settings);
    if (!form_data_->multipart_parser_) {
        swoole_warning("multipart_parser_init() failed");
        return false;
    }
    form_data_->multipart_parser_->data = this;

    auto tmp_buffer = new String(SW_BUFFER_SIZE_BIG);
    tmp_buffer->append(buffer_->str + header_length_, buffer_->length - header_length_);
    form_data_->multipart_buffer_ = buffer_;
    form_data_->multipart_buffer_->length = header_length_;
    buffer_ = tmp_buffer;
    form_data_->upload_tmpfile_fmt_ = server->upload_tmp_dir + "/swoole.upfile.XXXXXX";
    form_data_->upload_tmpfile = new String(form_data_->upload_tmpfile_fmt_);
    form_data_->upload_max_filesize = server->upload_max_filesize;

    return true;
}

void Request::destroy_multipart_parser() {
    auto tmp_buffer = buffer_;
    delete tmp_buffer;
    buffer_ = form_data_->multipart_buffer_;
    form_data_->multipart_buffer_ = nullptr;
    if (form_data_->multipart_parser_->fp) {
        fclose(form_data_->multipart_parser_->fp);
        unlink(form_data_->upload_tmpfile->str);
    }
    multipart_parser_free(form_data_->multipart_parser_);
    form_data_->multipart_parser_ = nullptr;
    delete form_data_->upload_tmpfile;
    form_data_->upload_tmpfile = nullptr;
    delete form_data_;
    form_data_ = nullptr;
}

bool Request::parse_multipart_data(String *buffer) {
    size_t n = multipart_parser_execute(form_data_->multipart_parser_, buffer->str, buffer->length);
    swoole_trace("multipart_parser_execute: buffer->length=%lu, n=%lu\n", buffer->length, n);
    if (n != buffer->length) {
        swoole_error_log(SW_LOG_WARNING,
                         SW_ERROR_SERVER_INVALID_REQUEST,
                         "parse multipart body failed, %zu/%zu bytes processed",
                         n,
                         buffer->length);
        return false;
    }
    buffer->clear();
    return true;
}

Request::~Request() {
    if (form_data_) {
        destroy_multipart_parser();
    }
}

bool Request::has_expect_header() {
    // char *buf = buffer->str + buffer->offset;
    char *buf = buffer_->str;
    // int len = buffer->length - buffer->offset;
    size_t len = buffer_->length;

    char *pe = buf + len;
    char *p;

    for (p = buf; p < pe; p++) {
        if (*p == '\r' && (size_t)(pe - p) > sizeof("\r\nExpect")) {
            p += 2;
            if (SW_STRCASECT(p, pe - p, "Expect: ")) {
                p += sizeof("Expect: ") - 1;
                if (SW_STRCASECT(p, pe - p, "100-continue")) {
                    return true;
                } else {
                    return false;
                }
            } else {
                p++;
            }
        }
    }
    return false;
}

int Request::get_header_length() {
    char *p = buffer_->str + buffer_->offset;
    char *pe = buffer_->str + buffer_->length;

    for (; p <= pe - (sizeof("\r\n\r\n") - 1); p++) {
        if (memcmp(p, SW_STRL("\r\n\r\n")) == 0) {
            // strlen(header) + strlen("\r\n\r\n")
            header_length_ = buffer_->offset = p - buffer_->str + (sizeof("\r\n\r\n") - 1);
            return SW_OK;
        }
    }

    buffer_->offset = p - buffer_->str;
    return SW_ERR;
}

int Request::get_chunked_body_length() {
    char *p = buffer_->str + buffer_->offset;
    char *pe = buffer_->str + buffer_->length;

    while (1) {
        if ((size_t)(pe - p) < (1 + (sizeof("\r\n") - 1))) {
            /* need the next chunk */
            return SW_ERR;
        }
        char *head = p;
        size_t n_parsed;
        size_t chunk_length = swoole_hex2dec(head, &n_parsed);
        head += n_parsed;
        if (*head != '\r') {
            excepted = 1;
            return SW_ERR;
        }
        p = head + (sizeof("\r\n") - 1) + chunk_length + (sizeof("\r\n") - 1);
        /* used to check package_max_length */
        content_length_ = p - (buffer_->str + header_length_);
        if (p > pe) {
            /* need recv chunk body again */
            return SW_ERR;
        }
        buffer_->offset = p - buffer_->str;
        if (chunk_length == 0) {
            break;
        }
    }
    known_length = 1;

    return SW_OK;
}

string Request::get_date_if_modified_since() {
    char *p = buffer_->str + url_offset_ + url_length_ + 10;
    char *pe = buffer_->str + header_length_;

    string result;

    char *date_if_modified_since = nullptr;
    size_t length_if_modified_since = 0;

    int state = 0;
    for (; p < pe; p++) {
        switch (state) {
        case 0:
            if (SW_STRCASECT(p, pe - p, "If-Modified-Since")) {
                p += sizeof("If-Modified-Since");
                state = 1;
            }
            break;
        case 1:
            if (!isspace(*p)) {
                date_if_modified_since = p;
                state = 2;
            }
            break;
        case 2:
            if (SW_STRCASECT(p, pe - p, "\r\n")) {
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

int get_method(const char *method_str, size_t method_len) {
    int i = 0;
    for (; i < SW_HTTP_PRI; i++) {
        if (swoole_strcaseeq(method_strings[i], strlen(method_strings[i]), method_str, method_len)) {
            return i + 1;
        }
    }
    return -1;
}

const char *get_method_string(int method) {
    if (method < 0 || method > SW_HTTP_PRI) {
        return nullptr;
    }
    return method_strings[method - 1];
}

int dispatch_request(Server *serv, const Protocol *proto, Socket *_socket, const RecvData *rdata) {
    if (serv->is_unavailable()) {
        _socket->send(SW_STRL(SW_HTTP_SERVICE_UNAVAILABLE_PACKET), 0);
        return SW_ERR;
    }
    return Server::dispatch_task(proto, _socket, rdata);
}

//-----------------------------------------------------------------

#ifdef SW_USE_HTTP2

static void protocol_status_error(Socket *socket, Connection *conn) {
    swoole_error_log(SW_LOG_WARNING,
                     SW_ERROR_PROTOCOL_ERROR,
                     "unexpected protocol status of session#%ld<%s:%d>",
                     conn->session_id,
                     conn->info.get_ip(),
                     conn->info.get_port());
}

ssize_t get_package_length(const Protocol *protocol, Socket *socket, PacketLength *pl) {
    Connection *conn = (Connection *) socket->object;
    if (conn->websocket_status >= websocket::STATUS_HANDSHAKE) {
        return websocket::get_package_length(protocol, socket, pl);
    } else if (conn->http2_stream) {
        return http2::get_frame_length(protocol, socket, pl);
    } else {
        protocol_status_error(socket, conn);
        return SW_ERR;
    }
}

uint8_t get_package_length_size(Socket *socket) {
    Connection *conn = (Connection *) socket->object;
    if (conn->websocket_status >= websocket::STATUS_HANDSHAKE) {
        return SW_WEBSOCKET_HEADER_LEN + SW_WEBSOCKET_MASK_LEN + sizeof(uint64_t);
    } else if (conn->http2_stream) {
        return SW_HTTP2_FRAME_HEADER_SIZE;
    } else {
        protocol_status_error(socket, conn);
        return 0;
    }
}

int dispatch_frame(const Protocol *proto, Socket *socket, const RecvData *rdata) {
    Connection *conn = (Connection *) socket->object;
    if (conn->websocket_status >= websocket::STATUS_HANDSHAKE) {
        return websocket::dispatch_frame(proto, socket, rdata);
    } else if (conn->http2_stream) {
        return Server::dispatch_task(proto, socket, rdata);
    } else {
        protocol_status_error(socket, conn);
        return SW_ERR;
    }
}
#endif
}  // namespace http_server
}  // namespace swoole
