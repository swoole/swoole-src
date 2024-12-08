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
  | @link     https://www.swoole.com/                                    |
  | @contact  team@swoole.com                                            |
  | @license  https://github.com/swoole/swoole-src/blob/master/LICENSE   |
  | Author    NathanFreeman  <mariasocute@163.com>                         |
  +----------------------------------------------------------------------+
 */
#include "test_core.h"
#include "llhttp.h"

using namespace std;

static int http_request_on_query_string(llhttp_t *parser, const char *at, size_t length);
static int http_request_on_body(llhttp_t *parser, const char *at, size_t length);
static int http_request_on_header_field(llhttp_t *parser, const char *at, size_t length);
static int http_request_on_header_value(llhttp_t *parser, const char *at, size_t length);
static int http_request_on_headers_complete(llhttp_t *parser);
static int http_request_message_complete(llhttp_t *parser);
static int http_request_llhttp_data_cb(llhttp_t *parser, const char *at, size_t length);
static int http_request_llhttp_cb(llhttp_t *parser);

// clang-format off
static const llhttp_settings_t http_parser_settings =
{
    http_request_llhttp_cb, // on_message_begin
    http_request_on_query_string, // on_url
    http_request_llhttp_data_cb, // on_status
    http_request_llhttp_data_cb, // on_method
    http_request_llhttp_data_cb, // on_version
    http_request_on_header_field, // on_header_field
    http_request_on_header_value, // on_header_value
    http_request_llhttp_data_cb, // on_chunk_extension_name
    http_request_llhttp_data_cb, // on_chunk_extension_value
    http_request_on_headers_complete, // on_headers_complete
    http_request_on_body, // on_body
    http_request_message_complete, // on_message_complete
    http_request_llhttp_cb,  // on_url_complete
    http_request_llhttp_cb, // on_status_complete
    http_request_llhttp_cb, // on_method_complete
    http_request_llhttp_cb, // on_version_complete
    http_request_llhttp_cb, // on_header_field_complete
    http_request_llhttp_cb, // on_header_value_complete
    http_request_llhttp_cb, // on_chunk_extension_name_complete
    http_request_llhttp_cb, // on_chunk_extension_value_complete
    http_request_llhttp_cb, // on_chunk_header
    http_request_llhttp_cb, // on_chunk_complete
    http_request_llhttp_cb, // on_reset
};
// clang-format on

typedef struct {
    long fd;
    uchar completed : 1;
    uchar end_ : 1;
    uchar send_header_ : 1;

    uchar send_chunked : 1;
    uchar recv_chunked : 1;
    uchar send_trailer_ : 1;
    uchar keepalive : 1;
    uchar websocket : 1;

    uchar upgrade : 1;
    uchar detached : 1;
    uchar parse_cookie : 1;
    uchar parse_body : 1;
    uchar parse_files : 1;
    uchar co_socket : 1;
    uchar http2 : 1;

    llhttp_t parser;

    uint16_t input_var_num;
    char *current_header_name;
    size_t current_header_name_len;
    char *current_input_name;
    size_t current_input_name_len;
    char *current_form_data_name;
    size_t current_form_data_name_len;

    vector<string> header_fields;
    vector<string> header_values;
    string query_string;
} HttpContext;

static llhttp_t *swoole_http_parser_create(swoole_http_parser_t type = PHP_HTTP_REQUEST) {
    HttpContext *ctx = new HttpContext();
    llhttp_t *parser = &ctx->parser;
    swoole_http_parser_init(parser, type);
    parser->data = ctx;
    return parser;
}

static void swoole_http_destroy_context(llhttp_t *parser) {
    delete (HttpContext *) parser->data;
    return;
}

static int swoole_http_parser_method(string protocol) {
    llhttp_t *parser = swoole_http_parser_create();
    swoole_http_parser_execute(parser, &http_parser_settings, protocol.c_str(), protocol.length());

    int ret = parser->method;
    swoole_http_destroy_context(parser);
    return ret;
}

static const char *swoole_get_method_name(swoole_http_method_t method) {
    return llhttp_method_name((llhttp_method_t) method);
}

static int http_request_on_query_string(llhttp_t *parser, const char *at, size_t length) {
    HttpContext *ctx = (HttpContext *) parser->data;
    uint32_t q = length;
    for (size_t i = 0; i < length; i++) {
        if (at[i] == '?') {
            q = i;
            break;
        }
    }

    if (length - q > 1) {
        ctx->query_string = std::string(at + q + 1, length - q - 1);
    }

    return 0;
}

static int http_request_on_header_field(llhttp_t *parser, const char *at, size_t length) {
    HttpContext *ctx = (HttpContext *) parser->data;
    ctx->header_fields.push_back(string(at, length));
    return 0;
}

static int http_request_on_header_value(llhttp_t *parser, const char *at, size_t length) {
    HttpContext *ctx = (HttpContext *) parser->data;
    ctx->header_values.push_back(string(at, length));
    return 0;
}

static int http_request_on_headers_complete(llhttp_t *parser) {
    return 0;
}

static int http_request_on_body(llhttp_t *parser, const char *at, size_t length) {
    return 0;
}

static int http_request_message_complete(llhttp_t *parser) {
    return 0;
}

static int http_request_llhttp_data_cb(llhttp_t *parser, const char *at, size_t length) {
    return 0;
}

static int http_request_llhttp_cb(llhttp_t *parser) {
    return 0;
}

static const string request_get = "GET /get HTTP/1.1\r\n"
                                  "Host: www.maria.com\r\n"
                                  "User-Agent: curl/7.64.1\r\n"
                                  "Accept: */*\r\n"
                                  "Connection: keep-alive\r\n"
                                  "\r\n";

static const string request_get_http2 = "GET /get HTTP/2\r\n"
                                        "Host: www.maria.com\r\n"
                                        "User-Agent: curl/7.64.1\r\n"
                                        "Accept: */*\r\n"
                                        "Connection: keep-alive\r\n"
                                        "\r\n";

static const string request_get_http09 = "GET /index.html\r\n\r\n";

static const string request_head = "HEAD /get HTTP/1.1\r\n"
                                   "Host: www.maria.com\r\n"
                                   "User-Agent: curl/7.64.1\r\n"
                                   "Accept: */*\r\n"
                                   "Connection: keep-alive\r\n"
                                   "\r\n";

static const string request_get_with_query_string = "GET /get?a=foo&b=bar&c=456%26789#frag=123 HTTP/1.1\r\n"
                                                    "Host: www.maria.com\r\n"
                                                    "User-Agent: curl/7.64.1\r\n"
                                                    "Accept: */*\r\n"
                                                    "Connection: keep-alive\r\n"
                                                    "\r\n";

static const string request_get_with_query_string2 = "GET /get? HTTP/1.1\r\n"
                                                     "Host: www.maria.com\r\n"
                                                     "User-Agent: curl/7.64.1\r\n"
                                                     "Accept: */*\r\n"
                                                     "Connection: keep-alive\r\n"
                                                     "\r\n";

static const string request_get_with_query_string3 = "GET /index.html?a=123\r\n\r\n\r\n";

static const string request_get_with_query_string4 = "GET /index.html?a=123\r\n\r\n\r\n";

static const string request_get_with_query_string5 = "GET /get#frag=123 HTTP/1.1\r\n"
                                                     "Host: www.maria.com\r\n"
                                                     "User-Agent: curl/7.64.1\r\n"
                                                     "Accept: */*\r\n"
                                                     "Connection: keep-alive\r\n"
                                                     "\r\n";

static const string request_get_with_schema = "GET http://127.0.0.1:8081/get HTTP/1.1\r\n"
                                              "Host: www.maria.com\r\n"
                                              "User-Agent: curl/7.64.1\r\n"
                                              "Accept: */*\r\n"
                                              "Connection: keep-alive\r\n"
                                              "\r\n";

static const string request_get_with_proxy_connection = "GET /get HTTP/1.1\r\n"
                                                        "Host: www.maria.com\r\n"
                                                        "User-Agent: curl/7.64.1\r\n"
                                                        "Accept: */*\r\n"
                                                        "Connection: keep-alive\r\n"
                                                        "Proxy-Connection: keep-alive\r\n"
                                                        "\r\n";

static const string request_get_with_connection_close = "GET /get HTTP/1.1\r\n"
                                                        "Host: www.maria.com\r\n"
                                                        "User-Agent: curl/7.64.1\r\n"
                                                        "Accept: */*\r\n"
                                                        "Connection: close\r\n"
                                                        "\r\n";

static const string request_get_http10 = "GET /get HTTP/1.0\r\n"
                                         "Host: www.maria.com\r\n"
                                         "User-Agent: curl/7.64.1\r\n"
                                         "Accept: */*\r\n"
                                         "\r\n";

static const string request_get_http10_with_keep_alive = "GET /get HTTP/1.1\r\n"
                                                         "Host: www.maria.com\r\n"
                                                         "User-Agent: curl/7.64.1\r\n"
                                                         "Accept: */*\r\n"
                                                         "Connection: keep-alive\r\n"
                                                         "\r\n"
                                                         "foo=bar\r\n\r\n";

static const string request_post = "POST /api/build/v1/foo HTTP/1.1\r\n"
                                   "Host: www.maria.com\r\n"
                                   "User-Agent: curl/7.64.1\r\n"
                                   "Accept: */*\r\n"
                                   "Content-Length: 7\r\n"
                                   "Content-Type: application/x-www-form-urlencoded\r\n"
                                   "\r\n"
                                   "foo=bar";

static const string request_upgrade = "GET /get HTTP/1.1\r\n"
                                      "Host: www.maria.com\r\n"
                                      "upgrade: websocket\r\n"
                                      "User-Agent: curl/7.64.1\r\n"
                                      "Connection: Upgrade\r\n"
                                      "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                                      "Sec-WebSocket-Version: 13\r\n"
                                      "\r\n";

static const string request_dead = "POST /dead HTTP/1.1\r\n"
                                   "Host: www.maria.com\r\n"
                                   "User-Agent: curl/7.64.1\r\n"
                                   "Accept: */*\r\n"
                                   "Content-Length: abcd\r\n"
                                   "Content-Type: application/x-www-form-urlencoded\r\n"
                                   "\r\n"
                                   "foo=bar";

static const string response_200 = "HTTP/1.1 200 OK\r\n"
                                   "server: CLOUD ELB 1.0.0\r\n"
                                   "date: Sat, 04 Feb 2023 08:47:14 GMT\r\n"
                                   "content-type: application/json\r\n"
                                   "content-length: 19\r\n"
                                   "Connection: close\r\n"
                                   "\r\n"
                                   "{\"name\" : \"guoji\"}";

static const string response_200_without_ok = "HTTP/1.1 200\r\n"
                                              "server: CLOUD ELB 1.0.0\r\n"
                                              "date: Sat, 04 Feb 2023 08:47:14 GMT\r\n"
                                              "content-type: application/json\r\n"
                                              "content-length: 19\r\n"
                                              "Connection: close\r\n"
                                              "\r\n"
                                              "{\"name\" : \"guoji\"}";

static const string response_chunk = "HTTP/1.1 200 OK\r\n"
                                     "server: CLOUD ELB 1.0.0\r\n"
                                     "date: Sat, 04 Feb 2023 08:47:14 GMT\r\n"
                                     "content-type: application/json\r\n"
                                     "Transfer-Encoding: chunked\r\n"
                                     "Connection: close\r\n"
                                     "\r\n"
                                     "19\r\n"
                                     "{\"name\" : \"guoji\"}\r\n"
                                     "19\r\n"
                                     "{\"name\" : \"guoji\"}\r\n"
                                     "19\r\n"
                                     "{\"name\" : \"guoji\"}\r\n"
                                     "19\r\n"
                                     "{\"name\" : \"guoji\"}\r\n"
                                     "0\r\n"
                                     "\r\n";

TEST(http_parser, method_name) {
    ASSERT_STREQ(swoole_get_method_name(PHP_HTTP_DELETE), "DELETE");
    ASSERT_STREQ(swoole_get_method_name(PHP_HTTP_GET), "GET");
    ASSERT_STREQ(swoole_get_method_name(PHP_HTTP_HEAD), "HEAD");
    ASSERT_STREQ(swoole_get_method_name(PHP_HTTP_POST), "POST");
    ASSERT_STREQ(swoole_get_method_name(PHP_HTTP_PUT), "PUT");
    ASSERT_STREQ(swoole_get_method_name(PHP_HTTP_PATCH), "PATCH");
    ASSERT_STREQ(swoole_get_method_name(PHP_HTTP_CONNECT), "CONNECT");
    ASSERT_STREQ(swoole_get_method_name(PHP_HTTP_OPTIONS), "OPTIONS");
    ASSERT_STREQ(swoole_get_method_name(PHP_HTTP_TRACE), "TRACE");
    ASSERT_STREQ(swoole_get_method_name(PHP_HTTP_COPY), "COPY");
    ASSERT_STREQ(swoole_get_method_name(PHP_HTTP_LOCK), "LOCK");
    ASSERT_STREQ(swoole_get_method_name(PHP_HTTP_MKCOL), "MKCOL");
    ASSERT_STREQ(swoole_get_method_name(PHP_HTTP_MOVE), "MOVE");
    ASSERT_STREQ(swoole_get_method_name(PHP_HTTP_MKCALENDAR), "MKCALENDAR");
    ASSERT_STREQ(swoole_get_method_name(PHP_HTTP_PROPFIND), "PROPFIND");
    ASSERT_STREQ(swoole_get_method_name(PHP_HTTP_PROPPATCH), "PROPPATCH");
    ASSERT_STREQ(swoole_get_method_name(PHP_HTTP_SEARCH), "SEARCH");
    ASSERT_STREQ(swoole_get_method_name(PHP_HTTP_UNLOCK), "UNLOCK");
    ASSERT_STREQ(swoole_get_method_name(PHP_HTTP_REPORT), "REPORT");
    ASSERT_STREQ(swoole_get_method_name(PHP_HTTP_MKACTIVITY), "MKACTIVITY");
    ASSERT_STREQ(swoole_get_method_name(PHP_HTTP_CHECKOUT), "CHECKOUT");
    ASSERT_STREQ(swoole_get_method_name(PHP_HTTP_MERGE), "MERGE");
    ASSERT_STREQ(swoole_get_method_name(PHP_HTTP_MSEARCH), "M - SEARCH");
    ASSERT_STREQ(swoole_get_method_name(PHP_HTTP_NOTIFY), "NOTIFY");
    ASSERT_STREQ(swoole_get_method_name(PHP_HTTP_SUBSCRIBE), "SUBSCRIBE");
    ASSERT_STREQ(swoole_get_method_name(PHP_HTTP_UNSUBSCRIBE), "UNSUBSCRIBE");
    ASSERT_STREQ(swoole_get_method_name(PHP_HTTP_PURGE), "PURGE");
    ASSERT_STREQ(swoole_get_method_name(PHP_HTTP_PRI), "PRI");
    ASSERT_STREQ(swoole_get_method_name(PHP_HTTP_GET_PARAMETER), "GET_PARAMETER");
    ASSERT_STREQ(swoole_get_method_name(PHP_HTTP_SET_PARAMETER), "SET_PARAMETER");
}

TEST(http_parser, http_version) {
    llhttp_t *parser = swoole_http_parser_create();
    swoole_http_parser_execute(parser, &http_parser_settings, request_get.c_str(), request_get.length());
    ASSERT_TRUE(llhttp_get_http_major(parser) == 1);
    ASSERT_TRUE(llhttp_get_http_minor(parser) == 1);
    swoole_http_destroy_context(parser);

    parser = swoole_http_parser_create();
    swoole_http_parser_execute(parser, &http_parser_settings, request_get_http2.c_str(), request_get_http2.length());
    ASSERT_TRUE(parser->http_major == 2);
    ASSERT_TRUE(parser->http_minor == 0);
    swoole_http_destroy_context(parser);

    parser = swoole_http_parser_create();
    swoole_http_parser_execute(parser, &http_parser_settings, request_get_http09.c_str(), request_get_http09.length());
    ASSERT_TRUE(parser->http_major == 0);
    ASSERT_TRUE(parser->http_minor == 9);
    swoole_http_destroy_context(parser);

    parser = swoole_http_parser_create();
    swoole_http_parser_execute(parser, &http_parser_settings, request_get_http10.c_str(), request_get_http10.length());
    ASSERT_TRUE(parser->http_major == 1);
    ASSERT_TRUE(parser->http_minor == 0);
    swoole_http_destroy_context(parser);

    parser = swoole_http_parser_create();
    parser->type = PHP_HTTP_BOTH;
    swoole_http_parser_execute(parser, &http_parser_settings, request_get.c_str(), request_get.length());
    ASSERT_TRUE(parser->http_major == 1);
    ASSERT_TRUE(parser->http_minor == 1);
    swoole_http_destroy_context(parser);
}

TEST(http_parser, should_keep_alive) {
    llhttp_t *parser = swoole_http_parser_create();
    swoole_http_parser_execute(parser, &http_parser_settings, request_get.c_str(), request_get.length());
    ASSERT_TRUE(!!llhttp_should_keep_alive(parser));
    swoole_http_destroy_context(parser);

    parser = swoole_http_parser_create();
    swoole_http_parser_execute(parser,
                               &http_parser_settings,
                               request_get_with_connection_close.c_str(),
                               request_get_with_connection_close.length());
    ASSERT_FALSE(llhttp_should_keep_alive(parser) == 0);
    swoole_http_destroy_context(parser);

    parser = swoole_http_parser_create();
    swoole_http_parser_execute(parser, &http_parser_settings, request_get_http10.c_str(), request_get_http10.length());
    ASSERT_FALSE(!!llhttp_should_keep_alive(parser));
    swoole_http_destroy_context(parser);

    parser = swoole_http_parser_create();
    swoole_http_parser_execute(parser,
                               &http_parser_settings,
                               request_get_http10_with_keep_alive.c_str(),
                               request_get_http10_with_keep_alive.length());
    ASSERT_TRUE(llhttp_should_keep_alive(parser) == 1);
    swoole_http_destroy_context(parser);

    parser = swoole_http_parser_create();
    swoole_http_parser_execute(parser, &http_parser_settings, request_get_http10.c_str(), request_get_http10.length());
    ASSERT_FALSE(!!llhttp_should_keep_alive(parser));
    swoole_http_destroy_context(parser);

    parser = swoole_http_parser_create();
    swoole_http_parser_execute(
        parser, &http_parser_settings, request_get_with_schema.c_str(), request_get_with_schema.length());
    ASSERT_TRUE(!!llhttp_should_keep_alive(parser));
    swoole_http_destroy_context(parser);

    parser = swoole_http_parser_create();
    parser->type = PHP_HTTP_BOTH;
    swoole_http_parser_execute(parser, &http_parser_settings, request_head.c_str(), request_head.length());
    ASSERT_TRUE(!!llhttp_should_keep_alive(parser));
    swoole_http_destroy_context(parser);
}

TEST(http_parser, upgrade) {
    llhttp_t *parser = swoole_http_parser_create();
    swoole_http_parser_execute(parser, &http_parser_settings, request_upgrade.c_str(), request_upgrade.length());
    ASSERT_TRUE(llhttp_get_upgrade(parser) == 1);
    swoole_http_destroy_context(parser);
}

TEST(http_parser, dead) {
    llhttp_t *parser = swoole_http_parser_create();
    swoole_http_parser_execute(parser, &http_parser_settings, request_dead.c_str(), request_dead.length());
    ASSERT_TRUE(parser->error != PHP_HTTP_OK);
    swoole_http_destroy_context(parser);
}

TEST(http_parser, zero) {
    llhttp_t *parser = swoole_http_parser_create();
    int ret = swoole_http_parser_execute(parser, &http_parser_settings, "", 0);
    ASSERT_TRUE(ret == 0);
    swoole_http_destroy_context(parser);
}

TEST(http_parser, methods) {
    ASSERT_EQ(swoole_http_parser_method("DELETE /get HTTP/1.1\r\n\r\n"), PHP_HTTP_DELETE);
    ASSERT_EQ(swoole_http_parser_method("GET /get HTTP/1.1\r\n\r\n"), PHP_HTTP_GET);
    ASSERT_EQ(swoole_http_parser_method("HEAD /get HTTP/1.1\r\n\r\n"), PHP_HTTP_HEAD);
    ASSERT_EQ(swoole_http_parser_method("POST /get HTTP/1.1\r\n\r\n"), PHP_HTTP_POST);
    ASSERT_EQ(swoole_http_parser_method("PUT /get HTTP/1.1\r\n\r\n"), PHP_HTTP_PUT);
    ASSERT_EQ(swoole_http_parser_method("CONNECT /get HTTP/1.1\r\n\r\n"), PHP_HTTP_CONNECT);
    ASSERT_EQ(swoole_http_parser_method("OPTIONS /get HTTP/1.1\r\n\r\n"), PHP_HTTP_OPTIONS);
    ASSERT_EQ(swoole_http_parser_method("TRACE /get HTTP/1.1\r\n\r\n"), PHP_HTTP_TRACE);
    ASSERT_EQ(swoole_http_parser_method("COPY /get HTTP/1.1\r\n\r\n"), PHP_HTTP_COPY);
    ASSERT_EQ(swoole_http_parser_method("LOCK /get HTTP/1.1\r\n\r\n"), PHP_HTTP_LOCK);
    ASSERT_EQ(swoole_http_parser_method("MKCOL /get HTTP/1.1\r\n\r\n"), PHP_HTTP_MKCOL);
    ASSERT_EQ(swoole_http_parser_method("MOVE /get HTTP/1.1\r\n\r\n"), PHP_HTTP_MOVE);
    ASSERT_EQ(swoole_http_parser_method("PROPFIND /get HTTP/1.1\r\n\r\n"), PHP_HTTP_PROPFIND);
    ASSERT_EQ(swoole_http_parser_method("PROPPATCH /get HTTP/1.1\r\n\r\n"), PHP_HTTP_PROPPATCH);
    ASSERT_EQ(swoole_http_parser_method("SEARCH /get HTTP/1.1\r\n\r\n"), PHP_HTTP_SEARCH);
    ASSERT_EQ(swoole_http_parser_method("UNLOCK /get HTTP/1.1\r\n\r\n"), PHP_HTTP_UNLOCK);
    ASSERT_EQ(swoole_http_parser_method("BIND /get HTTP/1.1\r\n\r\n"), PHP_HTTP_BIND);
    ASSERT_EQ(swoole_http_parser_method("REBIND /get HTTP/1.1\r\n\r\n"), PHP_HTTP_REBIND);
    ASSERT_EQ(swoole_http_parser_method("UNBIND /get HTTP/1.1\r\n\r\n"), PHP_HTTP_UNBIND);
    ASSERT_EQ(swoole_http_parser_method("ACL /get HTTP/1.1\r\n\r\n"), PHP_HTTP_ACL);
    ASSERT_EQ(swoole_http_parser_method("REPORT /get HTTP/1.1\r\n\r\n"), PHP_HTTP_REPORT);
    ASSERT_EQ(swoole_http_parser_method("MKACTIVITY /get HTTP/1.1\r\n\r\n"), PHP_HTTP_MKACTIVITY);
    ASSERT_EQ(swoole_http_parser_method("CHECKOUT /get HTTP/1.1\r\n\r\n"), PHP_HTTP_CHECKOUT);
    ASSERT_EQ(swoole_http_parser_method("M-SEARCH /get HTTP/1.1\r\n\r\n"), PHP_HTTP_MSEARCH);
    ASSERT_EQ(swoole_http_parser_method("NOTIFY /get HTTP/1.1\r\n\r\n"), PHP_HTTP_NOTIFY);
    ASSERT_EQ(swoole_http_parser_method("SUBSCRIBE /get HTTP/1.1\r\n\r\n"), PHP_HTTP_SUBSCRIBE);
    ASSERT_EQ(swoole_http_parser_method("UNSUBSCRIBE /get HTTP/1.1\r\n\r\n"), PHP_HTTP_UNSUBSCRIBE);
    ASSERT_EQ(swoole_http_parser_method("PATCH /get HTTP/1.1\r\n\r\n"), PHP_HTTP_PATCH);
    ASSERT_EQ(swoole_http_parser_method("PURGE /get HTTP/1.1\r\n\r\n"), PHP_HTTP_PURGE);
    ASSERT_EQ(swoole_http_parser_method("MKCALENDAR /get HTTP/1.1\r\n\r\n"), PHP_HTTP_MKCALENDAR);
    ASSERT_EQ(swoole_http_parser_method("LINK /get HTTP/1.1\r\n\r\n"), PHP_HTTP_LINK);
    ASSERT_EQ(swoole_http_parser_method("UNLINK /get HTTP/1.1\r\n\r\n"), PHP_HTTP_UNLINK);
    ASSERT_EQ(swoole_http_parser_method("SOURCE /get HTTP/1.1\r\n\r\n"), PHP_HTTP_SOURCE);
    ASSERT_EQ(swoole_http_parser_method("PRI /get HTTP/1.1\r\n\r\n"), PHP_HTTP_PRI);
    ASSERT_EQ(swoole_http_parser_method("DESCRIBE /get HTTP/1.1\r\n\r\n"), PHP_HTTP_DESCRIBE);
    ASSERT_EQ(swoole_http_parser_method("ANNOUNCE /get HTTP/1.1\r\n\r\n"), PHP_HTTP_ANNOUNCE);
    ASSERT_EQ(swoole_http_parser_method("SETUP /get HTTP/1.1\r\n\r\n"), PHP_HTTP_SETUP);
    ASSERT_EQ(swoole_http_parser_method("PLAY /get HTTP/1.1\r\n\r\n"), PHP_HTTP_PLAY);
    ASSERT_EQ(swoole_http_parser_method("PAUSE /get HTTP/1.1\r\n\r\n"), PHP_HTTP_PAUSE);
    ASSERT_EQ(swoole_http_parser_method("TEARDOWN /get HTTP/1.1\r\n\r\n"), PHP_HTTP_TEARDOWN);
    ASSERT_EQ(swoole_http_parser_method("GET_PARAMETER /get HTTP/1.1\r\n\r\n"), PHP_HTTP_GET_PARAMETER);
    ASSERT_EQ(swoole_http_parser_method("SET_PARAMETER /get HTTP/1.1\r\n\r\n"), PHP_HTTP_SET_PARAMETER);
    ASSERT_EQ(swoole_http_parser_method("REDIRECT /get HTTP/1.1\r\n\r\n"), PHP_HTTP_REDIRECT);
    ASSERT_EQ(swoole_http_parser_method("RECORD /get HTTP/1.1\r\n\r\n"), PHP_HTTP_RECORD);
    ASSERT_EQ(swoole_http_parser_method("FLUSH /get HTTP/1.1\r\n\r\n"), PHP_HTTP_FLUSH);
    ASSERT_EQ(swoole_http_parser_method("QUERY /get HTTP/1.1\r\n\r\n"), PHP_HTTP_QUERY);
}

TEST(http_parser, proxy_connection) {
    llhttp_t *parser = swoole_http_parser_create();
    swoole_http_parser_execute(parser,
                               &http_parser_settings,
                               request_get_with_proxy_connection.c_str(),
                               request_get_with_proxy_connection.length());

    HttpContext *ctx = (HttpContext *) parser->data;
    ASSERT_STREQ(ctx->header_fields[4].c_str(), "Proxy-Connection");
    swoole_http_destroy_context(parser);
}

TEST(http_parser, header_field_and_value) {
    string header = "GET /get HTTP/1.1\r\n"
                    "Host: www.maria.com\r\n"
                    "User-Agent: curl/7.64.1\r\n"
                    "Accept: */*\r\n"
                    "Connection: keep-alive\r\n"
                    "\r\n"
                    "\r\n\r\n";

    llhttp_t *parser = swoole_http_parser_create();
    swoole_http_parser_execute(parser, &http_parser_settings, header.c_str(), header.length());

    HttpContext *ctx = (HttpContext *) parser->data;
    ASSERT_STREQ(ctx->header_fields[1].c_str(), "User-Agent");
    ASSERT_STREQ(ctx->header_values[1].c_str(), "curl/7.64.1");
    swoole_http_destroy_context(parser);
}

TEST(http_parser, invalid_token) {
    string header = "GET /get HTTP/1.1\r\n"
                    "Host: www.maria.com\r\n"
                    "curl/7.64.1\r\n"
                    "Accept: */*\r\n"
                    "Connection: keep-alive\r\n"
                    "\r\n"
                    "\r\n\r\n";
    llhttp_t *parser = swoole_http_parser_create();
    swoole_http_parser_execute(parser, &http_parser_settings, header.c_str(), header.length());
    ASSERT_TRUE(parser->error != PHP_HTTP_OK);
    ASSERT_STREQ(llhttp_get_error_reason(parser), "Invalid header token");
    swoole_http_destroy_context(parser);
}

TEST(http_parser, response) {
    llhttp_t *parser = swoole_http_parser_create(PHP_HTTP_RESPONSE);
    swoole_http_parser_execute(parser, &http_parser_settings, response_200.c_str(), response_200.length());

    ASSERT_EQ(llhttp_get_status_code(parser), 200);
    ASSERT_TRUE(parser->http_major == 1);
    ASSERT_TRUE(parser->http_minor == 1);
    swoole_http_destroy_context(parser);

    parser = swoole_http_parser_create(PHP_HTTP_RESPONSE);
    parser->type = PHP_HTTP_BOTH;
    swoole_http_parser_execute(parser, &http_parser_settings, response_200.c_str(), response_200.length());

    ASSERT_EQ(parser->status_code, 200);
    ASSERT_TRUE(parser->http_major == 1);
    ASSERT_TRUE(parser->http_minor == 1);
    swoole_http_destroy_context(parser);

    parser = swoole_http_parser_create(PHP_HTTP_RESPONSE);
    parser->type = PHP_HTTP_BOTH;
    swoole_http_parser_execute(
        parser, &http_parser_settings, response_200_without_ok.c_str(), response_200_without_ok.length());

    ASSERT_EQ(parser->status_code, 200);
    swoole_http_destroy_context(parser);

    parser = swoole_http_parser_create(PHP_HTTP_RESPONSE);
    parser->type = PHP_HTTP_BOTH;
    swoole_http_parser_execute(parser, &http_parser_settings, response_chunk.c_str(), response_chunk.length());

    ASSERT_EQ(parser->status_code, 200);
    swoole_http_destroy_context(parser);
}

TEST(http_parser, query_string) {
    llhttp_t *parser = swoole_http_parser_create();
    swoole_http_parser_execute(
        parser, &http_parser_settings, request_get_with_query_string.c_str(), request_get_with_query_string.length());

    HttpContext *ctx = (HttpContext *) parser->data;
    ASSERT_STREQ(ctx->query_string.c_str(), "a=foo&b=bar&c=456%26789#frag=123");
    swoole_http_destroy_context(parser);

    parser = swoole_http_parser_create();
    swoole_http_parser_execute(
        parser, &http_parser_settings, request_get_with_query_string2.c_str(), request_get_with_query_string2.length());

    ASSERT_TRUE(!!llhttp_should_keep_alive(parser));
    swoole_http_destroy_context(parser);

    parser = swoole_http_parser_create();
    swoole_http_parser_execute(
        parser, &http_parser_settings, request_get_with_query_string3.c_str(), request_get_with_query_string3.length());

    ASSERT_TRUE(parser->http_major == 0);
    ASSERT_TRUE(parser->http_minor == 9);
    ctx = (HttpContext *) parser->data;
    ASSERT_STREQ(ctx->query_string.c_str(), "a=123");
    swoole_http_destroy_context(parser);

    parser = swoole_http_parser_create();
    swoole_http_parser_execute(
        parser, &http_parser_settings, request_get_with_query_string4.c_str(), request_get_with_query_string4.length());

    ASSERT_TRUE(parser->http_major == 0);
    ASSERT_TRUE(parser->http_minor == 9);
    ctx = (HttpContext *) parser->data;
    ASSERT_STREQ(ctx->query_string.c_str(), "a=123");
    swoole_http_destroy_context(parser);

    parser = swoole_http_parser_create();
    swoole_http_parser_execute(
        parser, &http_parser_settings, request_get_with_query_string5.c_str(), request_get_with_query_string5.length());

    ASSERT_TRUE(!!llhttp_should_keep_alive(parser));
    swoole_http_destroy_context(parser);
}

TEST(http_parser, http09) {
    string request_get_with_query_string_http09 = "GET /index.html\r\n\r\n\r\n";
    llhttp_t *parser = swoole_http_parser_create();
    swoole_http_parser_execute(parser,
                               &http_parser_settings,
                               request_get_with_query_string_http09.c_str(),
                               request_get_with_query_string_http09.length());

    ASSERT_TRUE(parser->http_major == 0);
    ASSERT_TRUE(parser->http_minor == 9);
    swoole_http_destroy_context(parser);

    request_get_with_query_string_http09 = "GET /index.html\r\n\r\n\r\n";
    parser = swoole_http_parser_create();
    swoole_http_parser_execute(parser,
                               &http_parser_settings,
                               request_get_with_query_string_http09.c_str(),
                               request_get_with_query_string_http09.length());

    ASSERT_TRUE(parser->http_major == 0);
    ASSERT_TRUE(parser->http_minor == 9);
    swoole_http_destroy_context(parser);
}

/**
 * Just for coverage purposes, in practice, we do not allow these lenient settings for parsing HTTP
 */
TEST(http_parser, lenient) {
    llhttp_t parser = {};
    llhttp_t *_parser = &parser;

    uint16_t lenient_flags = _parser->lenient_flags;
    llhttp_set_lenient_headers(_parser, true);
    llhttp_set_lenient_headers(_parser, false);

    llhttp_set_lenient_chunked_length(_parser, true);
    llhttp_set_lenient_chunked_length(_parser, false);

    llhttp_set_lenient_keep_alive(_parser, true);
    llhttp_set_lenient_keep_alive(_parser, false);

    llhttp_set_lenient_data_after_close(_parser, true);
    llhttp_set_lenient_data_after_close(_parser, false);

    llhttp_set_lenient_optional_lf_after_cr(_parser, true);
    llhttp_set_lenient_optional_lf_after_cr(_parser, false);

    llhttp_set_lenient_optional_crlf_after_chunk(_parser, true);
    llhttp_set_lenient_optional_crlf_after_chunk(_parser, false);

    llhttp_set_lenient_optional_cr_before_lf(_parser, true);
    llhttp_set_lenient_optional_cr_before_lf(_parser, false);

    llhttp_set_lenient_spaces_after_chunk_size(_parser, true);
    llhttp_set_lenient_spaces_after_chunk_size(_parser, false);

    ASSERT_TRUE(_parser->lenient_flags == lenient_flags);
}

TEST(http_parser, reset) {
    string error_protocol = "ET / HTTP/1.1\r\n\r\n\r\n";

    llhttp_t *parser = swoole_http_parser_create();
    parser->error = 0;
    parser->reason = nullptr;
    parser->error_pos = 0;

    swoole_http_parser_execute(parser, &http_parser_settings, error_protocol.c_str(), error_protocol.length());
    llhttp_errno_t error = llhttp_get_errno(parser);
    ASSERT_TRUE(error != 0);
    ASSERT_TRUE(llhttp_get_error_reason(parser) != nullptr);
    ASSERT_TRUE(llhttp_get_error_pos(parser) != 0);
    ASSERT_STREQ(llhttp_errno_name(error), "HPE_INVALID_METHOD");

    llhttp_reset(parser);
    parser->type = PHP_HTTP_RESPONSE;
    swoole_http_parser_execute(parser, &http_parser_settings, response_200.c_str(), response_200.length());
    ASSERT_EQ(llhttp_get_status_code(parser), 200);
    swoole_http_destroy_context(parser);
}

TEST(http_parser, type) {
    llhttp_t *parser = swoole_http_parser_create();
    uint8_t type = llhttp_get_type(parser);
    ASSERT_TRUE(type == PHP_HTTP_REQUEST);

    parser = swoole_http_parser_create(PHP_HTTP_RESPONSE);
    type = llhttp_get_type(parser);
    ASSERT_TRUE(type == PHP_HTTP_RESPONSE);
    swoole_http_destroy_context(parser);
}

TEST(http_parser, status_name) {
    ASSERT_STREQ(llhttp_status_name(HTTP_STATUS_OK), "OK");
}
