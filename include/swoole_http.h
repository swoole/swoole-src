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
 | Author: Tianfeng Han  <rango@swoole.com>                             |
 +----------------------------------------------------------------------+
 */
#pragma once

#include "swoole.h"
#include "swoole_protocol.h"

enum swHttpVersion {
    SW_HTTP_VERSION_10 = 1,
    SW_HTTP_VERSION_11,
    SW_HTTP_VERSION_2,
    SW_HTTP_VERSION_3,
};

enum swHttpMethod {
    SW_HTTP_DELETE = 1,
    SW_HTTP_GET,
    SW_HTTP_HEAD,
    SW_HTTP_POST,
    SW_HTTP_PUT,
    SW_HTTP_PATCH,
    /* pathological */
    SW_HTTP_CONNECT,
    SW_HTTP_OPTIONS,
    SW_HTTP_TRACE,
    /* webdav */
    SW_HTTP_COPY,
    SW_HTTP_LOCK,
    SW_HTTP_MKCOL,
    SW_HTTP_MOVE,
    SW_HTTP_PROPFIND,
    SW_HTTP_PROPPATCH,
    SW_HTTP_UNLOCK,
    /* subversion */
    SW_HTTP_REPORT,
    SW_HTTP_MKACTIVITY,
    SW_HTTP_CHECKOUT,
    SW_HTTP_MERGE,
    /* upnp */
    SW_HTTP_MSEARCH,
    SW_HTTP_NOTIFY,
    SW_HTTP_SUBSCRIBE,
    SW_HTTP_UNSUBSCRIBE,
    /* proxy */
    SW_HTTP_PURGE,
    /* Http2 */
    SW_HTTP_PRI,
};

enum swHttpStatusCode {
    SW_HTTP_CONTINUE = 100,
    SW_HTTP_SWITCHING_PROTOCOLS = 101,
    SW_HTTP_PROCESSING = 102,

    SW_HTTP_OK = 200,
    SW_HTTP_CREATED = 201,
    SW_HTTP_ACCEPTED = 202,
    SW_HTTP_NO_CONTENT = 204,
    SW_HTTP_PARTIAL_CONTENT = 206,

    SW_HTTP_SPECIAL_RESPONSE = 300,
    SW_HTTP_MOVED_PERMANENTLY = 301,
    SW_HTTP_MOVED_TEMPORARILY = 302,
    SW_HTTP_SEE_OTHER = 303,
    SW_HTTP_NOT_MODIFIED = 304,
    SW_HTTP_TEMPORARY_REDIRECT = 307,
    SW_HTTP_PERMANENT_REDIRECT = 308,

    SW_HTTP_BAD_REQUEST = 400,
    SW_HTTP_UNAUTHORIZED = 401,
    SW_HTTP_FORBIDDEN = 403,
    SW_HTTP_NOT_FOUND = 404,
    SW_HTTP_NOT_ALLOWED = 405,
    SW_HTTP_REQUEST_TIME_OUT = 408,
    SW_HTTP_CONFLICT = 409,
    SW_HTTP_LENGTH_REQUIRED = 411,
    SW_HTTP_PRECONDITION_FAILED = 412,
    SW_HTTP_REQUEST_ENTITY_TOO_LARGE = 413,
    SW_HTTP_REQUEST_URI_TOO_LARGE = 414,
    SW_HTTP_UNSUPPORTED_MEDIA_TYPE = 415,
    SW_HTTP_RANGE_NOT_SATISFIABLE = 416,
    SW_HTTP_MISDIRECTED_REQUEST = 421,
    SW_HTTP_TOO_MANY_REQUESTS = 429,

    SW_HTTP_INTERNAL_SERVER_ERROR = 500,
    SW_HTTP_NOT_IMPLEMENTED = 501,
    SW_HTTP_BAD_GATEWAY = 502,
    SW_HTTP_SERVICE_UNAVAILABLE = 503,
    SW_HTTP_GATEWAY_TIME_OUT = 504,
    SW_HTTP_VERSION_NOT_SUPPORTED = 505,
    SW_HTTP_INSUFFICIENT_STORAGE = 507
};

namespace swoole {
namespace http_server {
//-----------------------------------------------------------------
struct Request {
  public:
    uint8_t method;
    uint8_t version;
    uchar excepted : 1;

    uchar header_parsed : 1;
    uchar tried_to_dispatch : 1;

    uchar known_length : 1;
    uchar keep_alive : 1;
    uchar chunked : 1;
    uchar nobody_chunked : 1;

    uint32_t url_offset_;
    uint32_t url_length_;

    uint32_t request_line_length_; /* without \r\n  */
    uint32_t header_length_;       /* include request_line_length + \r\n */
    uint64_t content_length_;

    String *buffer_;

  public:
    Request() {
        clean();
        buffer_ = nullptr;
    }
    inline void clean() {
        memset(this, 0, offsetof(Request, buffer_));
    }
    int get_protocol();
    int get_header_length();
    int get_chunked_body_length();
    void parse_header_info();
    std::string get_header(const char *name);
#ifdef SW_HTTP_100_CONTINUE
    bool has_expect_header();
#endif
};

int get_method(const char *method_str, size_t method_len);
const char *get_method_string(int method);
const char *get_status_message(int code);
size_t url_decode(char *str, size_t len);
char *url_encode(char const *str, size_t len);

#ifdef SW_USE_HTTP2
ssize_t get_package_length(const Protocol *protocol, network::Socket *conn, PacketLength *pl);
uint8_t get_package_length_size(network::Socket *conn);
int dispatch_frame(const Protocol *protocol, network::Socket *conn, const RecvData *rdata);
#endif

//-----------------------------------------------------------------
}  // namespace http_server
}  // namespace swoole
