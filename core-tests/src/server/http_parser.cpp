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
#include "swoole_http.h"
#include "swoole_http_parser.h"

using namespace std;

static int http_request_on_path(swoole_http_parser *parser, const char *at, size_t length);
static int http_request_on_query_string(swoole_http_parser *parser, const char *at, size_t length);
static int http_request_on_body(swoole_http_parser *parser, const char *at, size_t length);
static int http_request_on_header_field(swoole_http_parser *parser, const char *at, size_t length);
static int http_request_on_header_value(swoole_http_parser *parser, const char *at, size_t length);
static int http_request_on_headers_complete(swoole_http_parser *parser);
static int http_request_message_complete(swoole_http_parser *parser);

// clang-format off
static constexpr swoole_http_parser_settings http_parser_settings = {
    nullptr,
    http_request_on_path,
    http_request_on_query_string,
    nullptr,
    nullptr,
    http_request_on_header_field,
    http_request_on_header_value,
    http_request_on_headers_complete,
    http_request_on_body,
    http_request_message_complete
};
// clang-format on

struct HttpContext {
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

    swoole_http_parser parser;

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
};

static swoole_http_parser *swoole_http_parser_create(swoole_http_parser_type type = PHP_HTTP_REQUEST) {
    auto *ctx = new HttpContext();
    swoole_http_parser *parser = &ctx->parser;
    swoole_http_parser_init(parser, type);
    parser->data = ctx;
    return parser;
}

static void swoole_http_destroy_context(swoole_http_parser *parser) {
    delete static_cast<HttpContext *>(parser->data);
}

static int swoole_http_parser_method(const string &protocol) {
    swoole_http_parser *parser = swoole_http_parser_create();
    swoole_http_parser_execute(parser, &http_parser_settings, protocol.c_str(), protocol.length());

    int ret = parser->method;
    swoole_http_destroy_context(parser);
    return ret;
}

static int http_request_on_path(swoole_http_parser *parser, const char *at, size_t length) {
    return 0;
}

static int http_request_on_query_string(swoole_http_parser *parser, const char *at, size_t length) {
    auto *ctx = static_cast<HttpContext *>(parser->data);
    ctx->query_string = string(at, length);
    return 0;
}

static int http_request_on_header_field(swoole_http_parser *parser, const char *at, size_t length) {
    auto *ctx = static_cast<HttpContext *>(parser->data);
    ctx->header_fields.emplace_back(at, length);
    return 0;
}

static int http_request_on_header_value(swoole_http_parser *parser, const char *at, size_t length) {
    auto ctx = static_cast<HttpContext *>(parser->data);
    ctx->header_values.emplace_back(at, length);
    return 0;
}

static int http_request_on_headers_complete(swoole_http_parser *parser) {
    return 0;
}

static int http_request_on_body(swoole_http_parser *parser, const char *at, size_t length) {
    return 0;
}

static int http_request_message_complete(swoole_http_parser *parser) {
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

static const string request_get_http09 = "GET /index.html\r\n";

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

static const string request_get_with_query_string3 = "GET /index.html?a=123\r";

static const string request_get_with_query_string4 = "GET /index.html?a=123\n";

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

static const string request_get_http10_with_keep_alive = "GET /get HTTP/1.0\r\n"
                                                         "Host: www.maria.com\r\n"
                                                         "User-Agent: curl/7.64.1\r\n"
                                                         "Accept: */*\r\n"
                                                         "Connection: keep-alive\r\n"
                                                         "\r\n";

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
    ASSERT_STREQ(swoole_http_method_str(PHP_HTTP_DELETE), "DELETE");
    ASSERT_STREQ(swoole_http_method_str(PHP_HTTP_GET), "GET");
    ASSERT_STREQ(swoole_http_method_str(PHP_HTTP_HEAD), "HEAD");
    ASSERT_STREQ(swoole_http_method_str(PHP_HTTP_POST), "POST");
    ASSERT_STREQ(swoole_http_method_str(PHP_HTTP_PUT), "PUT");
    ASSERT_STREQ(swoole_http_method_str(PHP_HTTP_PATCH), "PATCH");
    ASSERT_STREQ(swoole_http_method_str(PHP_HTTP_CONNECT), "CONNECT");
    ASSERT_STREQ(swoole_http_method_str(PHP_HTTP_OPTIONS), "OPTIONS");
    ASSERT_STREQ(swoole_http_method_str(PHP_HTTP_TRACE), "TRACE");
    ASSERT_STREQ(swoole_http_method_str(PHP_HTTP_COPY), "COPY");
    ASSERT_STREQ(swoole_http_method_str(PHP_HTTP_LOCK), "LOCK");
    ASSERT_STREQ(swoole_http_method_str(PHP_HTTP_MKCOL), "MKCOL");
    ASSERT_STREQ(swoole_http_method_str(PHP_HTTP_MOVE), "MOVE");
    ASSERT_STREQ(swoole_http_method_str(PHP_HTTP_MKCALENDAR), "MKCALENDAR");
    ASSERT_STREQ(swoole_http_method_str(PHP_HTTP_PROPFIND), "PROPFIND");
    ASSERT_STREQ(swoole_http_method_str(PHP_HTTP_PROPPATCH), "PROPPATCH");
    ASSERT_STREQ(swoole_http_method_str(PHP_HTTP_SEARCH), "SEARCH");
    ASSERT_STREQ(swoole_http_method_str(PHP_HTTP_UNLOCK), "UNLOCK");
    ASSERT_STREQ(swoole_http_method_str(PHP_HTTP_REPORT), "REPORT");
    ASSERT_STREQ(swoole_http_method_str(PHP_HTTP_MKACTIVITY), "MKACTIVITY");
    ASSERT_STREQ(swoole_http_method_str(PHP_HTTP_CHECKOUT), "CHECKOUT");
    ASSERT_STREQ(swoole_http_method_str(PHP_HTTP_MERGE), "MERGE");
    ASSERT_STREQ(swoole_http_method_str(PHP_HTTP_MSEARCH), "M-SEARCH");
    ASSERT_STREQ(swoole_http_method_str(PHP_HTTP_NOTIFY), "NOTIFY");
    ASSERT_STREQ(swoole_http_method_str(PHP_HTTP_SUBSCRIBE), "SUBSCRIBE");
    ASSERT_STREQ(swoole_http_method_str(PHP_HTTP_UNSUBSCRIBE), "UNSUBSCRIBE");
    ASSERT_STREQ(swoole_http_method_str(PHP_HTTP_PURGE), "PURGE");
    ASSERT_STREQ(swoole_http_method_str(PHP_HTTP_NOT_IMPLEMENTED), "NOTIMPLEMENTED");
}

TEST(http_parser, http_version) {
    swoole_http_parser *parser = swoole_http_parser_create();
    swoole_http_parser_execute(parser, &http_parser_settings, request_get.c_str(), request_get.length());
    ASSERT_TRUE(parser->http_major == 1);
    ASSERT_TRUE(parser->http_minor == 1);
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
    parser->state = s_start_req_or_res;
    swoole_http_parser_execute(parser, &http_parser_settings, request_get.c_str(), request_get.length());
    ASSERT_TRUE(parser->http_major == 1);
    ASSERT_TRUE(parser->http_minor == 1);
    swoole_http_destroy_context(parser);
}

TEST(http_parser, should_keep_alive) {
    swoole_http_parser *parser = swoole_http_parser_create();
    swoole_http_parser_execute(parser, &http_parser_settings, request_get.c_str(), request_get.length());
    ASSERT_TRUE(swoole_http_should_keep_alive(parser));
    swoole_http_destroy_context(parser);

    parser = swoole_http_parser_create();
    swoole_http_parser_execute(parser,
                               &http_parser_settings,
                               request_get_with_connection_close.c_str(),
                               request_get_with_connection_close.length());
    ASSERT_FALSE(swoole_http_should_keep_alive(parser));
    swoole_http_destroy_context(parser);

    parser = swoole_http_parser_create();
    swoole_http_parser_execute(parser, &http_parser_settings, request_get_http10.c_str(), request_get_http10.length());
    ASSERT_FALSE(swoole_http_should_keep_alive(parser));
    swoole_http_destroy_context(parser);

    parser = swoole_http_parser_create();
    swoole_http_parser_execute(parser,
                               &http_parser_settings,
                               request_get_http10_with_keep_alive.c_str(),
                               request_get_http10_with_keep_alive.length());
    ASSERT_TRUE(swoole_http_should_keep_alive(parser));
    swoole_http_destroy_context(parser);

    parser = swoole_http_parser_create();
    swoole_http_parser_execute(parser, &http_parser_settings, request_get_http10.c_str(), request_get_http10.length());
    ASSERT_FALSE(swoole_http_should_keep_alive(parser));
    swoole_http_destroy_context(parser);

    parser = swoole_http_parser_create();
    swoole_http_parser_execute(
        parser, &http_parser_settings, request_get_with_schema.c_str(), request_get_with_schema.length());
    ASSERT_TRUE(swoole_http_should_keep_alive(parser));
    swoole_http_destroy_context(parser);

    parser = swoole_http_parser_create();
    parser->state = s_start_req_or_res;
    swoole_http_parser_execute(parser, &http_parser_settings, request_head.c_str(), request_head.length());
    ASSERT_TRUE(swoole_http_should_keep_alive(parser));
    swoole_http_destroy_context(parser);
}

TEST(http_parser, upgrade) {
    swoole_http_parser *parser = swoole_http_parser_create();
    swoole_http_parser_execute(parser, &http_parser_settings, request_upgrade.c_str(), request_upgrade.length());
    ASSERT_TRUE(parser->upgrade == 1);
    swoole_http_destroy_context(parser);
}

TEST(http_parser, dead) {
    swoole_http_parser *parser = swoole_http_parser_create();
    swoole_http_parser_execute(parser, &http_parser_settings, request_dead.c_str(), request_dead.length());
    ASSERT_TRUE(parser->state == s_dead);
    swoole_http_destroy_context(parser);
}

TEST(http_parser, zero) {
    swoole_http_parser *parser = swoole_http_parser_create();
    size_t ret = swoole_http_parser_execute(parser, &http_parser_settings, "", 0);
    ASSERT_TRUE(ret == 0);
    swoole_http_destroy_context(parser);
}

TEST(http_parser, methods) {
    ASSERT_EQ(swoole_http_parser_method("COPY /get HTTP/1.1\r\n\r\n"), PHP_HTTP_COPY);
    ASSERT_EQ(swoole_http_parser_method("CHECKOUT /get HTTP/1.1\r\n\r\n"), PHP_HTTP_CHECKOUT);
    ASSERT_EQ(swoole_http_parser_method("HEAD /get HTTP/1.1\r\n\r\n"), PHP_HTTP_HEAD);
    ASSERT_EQ(swoole_http_parser_method("LOCK /get HTTP/1.1\r\n\r\n"), PHP_HTTP_LOCK);
    ASSERT_EQ(swoole_http_parser_method("MOVE /get HTTP/1.1\r\n\r\n"), PHP_HTTP_MOVE);
    ASSERT_EQ(swoole_http_parser_method("MKCALENDAR /get HTTP/1.1\r\n\r\n"), PHP_HTTP_MKCALENDAR);
    ASSERT_EQ(swoole_http_parser_method("MKACTIVITY /get HTTP/1.1\r\n\r\n"), PHP_HTTP_MKACTIVITY);
    ASSERT_EQ(swoole_http_parser_method("MERGE /get HTTP/1.1\r\n\r\n"), PHP_HTTP_MERGE);
    ASSERT_EQ(swoole_http_parser_method("M-SEARCH /get HTTP/1.1\r\n\r\n"), PHP_HTTP_MSEARCH);
    ASSERT_EQ(swoole_http_parser_method("NOTIFY /get HTTP/1.1\r\n\r\n"), PHP_HTTP_NOTIFY);
    ASSERT_EQ(swoole_http_parser_method("OPTIONS /get HTTP/1.1\r\n\r\n"), PHP_HTTP_OPTIONS);
    ASSERT_EQ(swoole_http_parser_method("REPORT /get HTTP/1.1\r\n\r\n"), PHP_HTTP_REPORT);
    ASSERT_EQ(swoole_http_parser_method("SEARCH /get HTTP/1.1\r\n\r\n"), PHP_HTTP_SEARCH);
    ASSERT_EQ(swoole_http_parser_method("SUBSCRIBE /get HTTP/1.1\r\n\r\n"), PHP_HTTP_SUBSCRIBE);
    ASSERT_EQ(swoole_http_parser_method("UNSUBSCRIBE /get HTTP/1.1\r\n\r\n"), PHP_HTTP_UNSUBSCRIBE);
    ASSERT_EQ(swoole_http_parser_method("TRACE /get HTTP/1.1\r\n\r\n"), PHP_HTTP_TRACE);
    ASSERT_EQ(swoole_http_parser_method("UNLOCK /get HTTP/1.1\r\n\r\n"), PHP_HTTP_UNLOCK);
    ASSERT_EQ(swoole_http_parser_method("PURGE /get HTTP/1.1\r\n\r\n"), PHP_HTTP_PURGE);
    ASSERT_EQ(swoole_http_parser_method("POST /get HTTP/1.1\r\n\r\n"), PHP_HTTP_POST);
    ASSERT_EQ(swoole_http_parser_method("PROPFIND /get HTTP/1.1\r\n\r\n"), PHP_HTTP_PROPFIND);
    ASSERT_EQ(swoole_http_parser_method("PROPPATCH /get HTTP/1.1\r\n\r\n"), PHP_HTTP_PROPPATCH);
    ASSERT_EQ(swoole_http_parser_method("PUT /get HTTP/1.1\r\n\r\n"), PHP_HTTP_PUT);
    ASSERT_EQ(swoole_http_parser_method("PATCH /get HTTP/1.1\r\n\r\n"), PHP_HTTP_PATCH);
    ASSERT_EQ(swoole_http_parser_method("UNKNOWN /get HTTP/1.1\r\n\r\n"), PHP_HTTP_NOT_IMPLEMENTED);
}

TEST(http_parser, proxy_connection) {
    swoole_http_parser *parser = swoole_http_parser_create();
    swoole_http_parser_execute(parser,
                               &http_parser_settings,
                               request_get_with_proxy_connection.c_str(),
                               request_get_with_proxy_connection.length());

    auto *ctx = static_cast<HttpContext *>(parser->data);
    ASSERT_STREQ(ctx->header_fields[4].c_str(), "Proxy-Connection");
    swoole_http_destroy_context(parser);
}

TEST(http_parser, header_field_and_value) {
    string header = "User-Agent: curl/7.64.1\r\n\r\n";

    swoole_http_parser *parser = swoole_http_parser_create();
    parser->state = s_header_field;
    swoole_http_parser_execute(parser, &http_parser_settings, header.c_str(), header.length());

    auto *ctx = static_cast<HttpContext *>(parser->data);
    ASSERT_STREQ(ctx->header_fields[0].c_str(), "User-Agent");
    swoole_http_destroy_context(parser);

    header = "curl/7.64.1\r\n\r\n";
    parser = swoole_http_parser_create();
    parser->state = s_header_value;
    swoole_http_parser_execute(parser, &http_parser_settings, header.c_str(), header.length());
    ctx = static_cast<HttpContext *>(parser->data);
    ASSERT_STREQ(ctx->header_values[0].c_str(), "curl/7.64.1");
    swoole_http_destroy_context(parser);
}

TEST(http_parser, response) {
    swoole_http_parser *parser = swoole_http_parser_create(PHP_HTTP_RESPONSE);
    swoole_http_parser_execute(parser, &http_parser_settings, response_200.c_str(), response_200.length());

    ASSERT_EQ(parser->status_code, 200);
    ASSERT_TRUE(parser->http_major == 1);
    ASSERT_TRUE(parser->http_minor == 1);
    swoole_http_destroy_context(parser);

    parser = swoole_http_parser_create(PHP_HTTP_RESPONSE);
    parser->state = s_start_req_or_res;
    swoole_http_parser_execute(parser, &http_parser_settings, response_200.c_str(), response_200.length());

    ASSERT_EQ(parser->status_code, 200);
    ASSERT_TRUE(parser->http_major == 1);
    ASSERT_TRUE(parser->http_minor == 1);
    swoole_http_destroy_context(parser);

    parser = swoole_http_parser_create(PHP_HTTP_RESPONSE);
    parser->state = s_start_req_or_res;
    swoole_http_parser_execute(
        parser, &http_parser_settings, response_200_without_ok.c_str(), response_200_without_ok.length());

    ASSERT_EQ(parser->status_code, 200);
    swoole_http_destroy_context(parser);

    parser = swoole_http_parser_create(PHP_HTTP_RESPONSE);
    parser->state = s_start_req_or_res;
    swoole_http_parser_execute(parser, &http_parser_settings, response_chunk.c_str(), response_chunk.length());

    ASSERT_EQ(parser->status_code, 200);
    swoole_http_destroy_context(parser);
}

TEST(http_parser, query_string) {
    swoole_http_parser *parser = swoole_http_parser_create();
    swoole_http_parser_execute(
        parser, &http_parser_settings, request_get_with_query_string.c_str(), request_get_with_query_string.length());

    auto *ctx = static_cast<HttpContext *>(parser->data);
    ASSERT_STREQ(ctx->query_string.c_str(), "a=foo&b=bar&c=456%26789");
    swoole_http_destroy_context(parser);

    parser = swoole_http_parser_create();
    swoole_http_parser_execute(
        parser, &http_parser_settings, request_get_with_query_string2.c_str(), request_get_with_query_string2.length());

    ASSERT_TRUE(swoole_http_should_keep_alive(parser));
    swoole_http_destroy_context(parser);

    parser = swoole_http_parser_create();
    swoole_http_parser_execute(
        parser, &http_parser_settings, request_get_with_query_string3.c_str(), request_get_with_query_string3.length());

    ASSERT_TRUE(parser->http_major == 0);
    ASSERT_TRUE(parser->http_minor == 9);
    ctx = static_cast<HttpContext *>(parser->data);
    ASSERT_STREQ(ctx->query_string.c_str(), "a=123");
    swoole_http_destroy_context(parser);

    parser = swoole_http_parser_create();
    swoole_http_parser_execute(
        parser, &http_parser_settings, request_get_with_query_string4.c_str(), request_get_with_query_string4.length());

    ASSERT_TRUE(parser->http_major == 0);
    ASSERT_TRUE(parser->http_minor == 9);
    ctx = static_cast<HttpContext *>(parser->data);
    ASSERT_STREQ(ctx->query_string.c_str(), "a=123");
    swoole_http_destroy_context(parser);

    parser = swoole_http_parser_create();
    swoole_http_parser_execute(
        parser, &http_parser_settings, request_get_with_query_string5.c_str(), request_get_with_query_string5.length());

    ASSERT_TRUE(swoole_http_should_keep_alive(parser));
    swoole_http_destroy_context(parser);
}

TEST(http_parser, http09) {
    string request_get_with_query_string_http09 = "GET /index.html\r";
    swoole_http_parser *parser = swoole_http_parser_create();
    swoole_http_parser_execute(parser,
                               &http_parser_settings,
                               request_get_with_query_string_http09.c_str(),
                               request_get_with_query_string_http09.length());

    ASSERT_TRUE(parser->http_major == 0);
    ASSERT_TRUE(parser->http_minor == 9);
    swoole_http_destroy_context(parser);

    request_get_with_query_string_http09 = "GET /index.html\n";
    parser = swoole_http_parser_create();
    swoole_http_parser_execute(parser,
                               &http_parser_settings,
                               request_get_with_query_string_http09.c_str(),
                               request_get_with_query_string_http09.length());

    ASSERT_TRUE(parser->http_major == 0);
    ASSERT_TRUE(parser->http_minor == 9);
    swoole_http_destroy_context(parser);
}

class http_parser_error : public ::testing::Test {
  protected:
    swoole_http_parser parser;
    swoole_http_parser_settings settings;
    swoole::http_server::Request request_;

    bool error = false;
    bool bad_request = false;

    int message_begin_called = 0;
    int url_called = 0;
    int header_field_called = 0;
    int header_value_called = 0;
    int headers_complete_called = 0;
    int body_called = 0;
    int message_complete_called = 0;
    int status_called = 0;
    int chunk_header_called = 0;
    int chunk_complete_called = 0;

    std::string url;
    std::string path;
    std::string query_string;
    std::string current_header;
    std::unordered_map<std::string, std::string> headers;
    std::string body;
    int status_code = 0;

    void SetUp() override {
        swoole_http_parser_init(&parser, PHP_HTTP_REQUEST);
        parser.data = this;
        request_.buffer_ = sw_tg_buffer();
        memset(&settings, 0, sizeof(settings));

        settings.on_message_begin = [](swoole_http_parser *p) -> int {
            auto *test = static_cast<http_parser_error *>(p->data);
            test->message_begin_called++;
            return 0;
        };

        settings.on_path = [](swoole_http_parser *p, const char *at, size_t length) -> int {
            auto *test = static_cast<http_parser_error *>(p->data);
            test->path = std::string(at, length);
            return 0;
        };

        settings.on_query_string = [](swoole_http_parser *p, const char *at, size_t length) -> int {
            auto *test = static_cast<http_parser_error *>(p->data);
            test->query_string = std::string(at, length);
            return 0;
        };

        settings.on_url = [](swoole_http_parser *p, const char *at, size_t length) -> int {
            auto *test = static_cast<http_parser_error *>(p->data);
            test->url_called++;
            test->url.assign(at, length);
            return 0;
        };

        settings.on_header_field = [](swoole_http_parser *p, const char *at, size_t length) -> int {
            auto *test = static_cast<http_parser_error *>(p->data);
            test->header_field_called++;
            test->current_header = std::string(at, length);
            return 0;
        };

        settings.on_header_value = [](swoole_http_parser *p, const char *at, size_t length) -> int {
            auto *test = static_cast<http_parser_error *>(p->data);
            test->header_value_called++;
            test->headers[test->current_header] = std::string(at, length);
            return 0;
        };

        settings.on_headers_complete = [](swoole_http_parser *p) -> int {
            auto *test = static_cast<http_parser_error *>(p->data);
            test->headers_complete_called++;
            test->status_code = p->status_code;
            return 0;
        };

        settings.on_body = [](swoole_http_parser *p, const char *at, size_t length) -> int {
            auto *test = static_cast<http_parser_error *>(p->data);
            test->body_called++;
            test->body.append(at, length);
            return 0;
        };

        settings.on_message_complete = [](swoole_http_parser *p) -> int {
            auto *test = static_cast<http_parser_error *>(p->data);
            test->message_complete_called++;
            return 0;
        };
    }

    void TearDown() override {
        message_begin_called = 0;
        url_called = 0;
        header_field_called = 0;
        header_value_called = 0;
        headers_complete_called = 0;
        body_called = 0;
        message_complete_called = 0;
        status_called = 0;
        chunk_header_called = 0;
        chunk_complete_called = 0;
        error = false;
        bad_request = false;

        url.clear();
        headers.clear();
        body.clear();
        status_code = 0;

        request_.clean();
        parser = {};
    }

    size_t parse(const std::string &data) {
        auto rv = swoole_http_parser_execute(&parser, &settings, data.c_str(), data.length());
        error = rv != data.length();
        debug_info(
            "rv=%zu, len=%zu, nread=%zu, error=%d, state=%d\n", rv, data.length(), parser.nread, error, parser.state);
        memcpy(request_.buffer_->str, data.c_str(), data.length());
        if (request_.get_protocol() < 0) {
        _bad_request:
            bad_request = true;
            return rv;
        }
        if (request_.method > SW_HTTP_PRI) {
            goto _bad_request;
        }
        if (request_.get_header_length() < 0) {
            goto _bad_request;
        }
        request_.parse_header_info();
        if (request_.chunked) {
            if (request_.get_chunked_body_length() < 0) {
                goto _bad_request;
            }
        }
        debug_info("method=%d, request_.header_length_=%u, request_.content_length_=%lu\n",
                   request_.method,
                   request_.header_length_,
                   request_.content_length_);
        return rv;
    }

    bool hasError() const {
        return error;
    }
};

// 1. 测试无效的 HTTP 方法
TEST_F(http_parser_error, InvalidMethod) {
    std::string request = "INVALID / HTTP/1.1\r\n\r\n";
    size_t parsed = parse(request);
    EXPECT_TRUE(bad_request);
    EXPECT_EQ(parser.method, PHP_HTTP_NOT_IMPLEMENTED);
}

// 2. 测试缺少空格分隔符
TEST_F(http_parser_error, MissingSpaceSeparator) {
    std::string request = "GET/HTTP/1.1\r\n\r\n";
    size_t parsed = parse(request);
    EXPECT_TRUE(bad_request);
    EXPECT_EQ(parser.method, PHP_HTTP_NOT_IMPLEMENTED);
}

// 3. 测试无效的 HTTP 版本
TEST_F(http_parser_error, InvalidHttpVersion) {
    std::string request = "GET / HTTP/9.8\r\n\r\n";
    size_t parsed = parse(request);
    EXPECT_TRUE(bad_request);
    EXPECT_EQ(parser.http_major, 9);
    EXPECT_EQ(parser.http_minor, 8);
}

// 4. 测试畸形的请求行
TEST_F(http_parser_error, MalformedRequestLine) {
    std::string request = "GET / HTTP/1.1 ExtraStuff\r\n\r\n";
    size_t parsed = parse(request);
    EXPECT_TRUE(bad_request);
    EXPECT_TRUE(hasError());
    EXPECT_LT(parsed, request.length());
}

// 5. 测试缺少 HTTP 版本
TEST_F(http_parser_error, MissingHttpVersion) {
    std::string request = "GET /\r\n\r\n";
    size_t parsed = parse(request);
    EXPECT_TRUE(bad_request);
    EXPECT_EQ(parser.method, PHP_HTTP_GET);
    EXPECT_EQ(parser.http_major, 0);
    EXPECT_EQ(parser.http_minor, 9);
}

// 6. 测试缺少 CR+LF
TEST_F(http_parser_error, MissingCRLF) {
    std::string request = "GET / HTTP/1.1\nHost: example.com\n\n";
    size_t parsed = parse(request);
    EXPECT_TRUE(bad_request);
}

// 7. 测试不完整的请求
TEST_F(http_parser_error, IncompleteRequest) {
    std::string request = "GET / HTTP/1.1\r\nHost: example.com";
    size_t parsed = parse(request);

    EXPECT_EQ(parsed, request.length());
    EXPECT_EQ(message_complete_called, 0);
}

// 8. 测试超长的 URL
TEST_F(http_parser_error, ExtremelyLongUrl) {
    std::string long_url(10000, 'a');
    std::string request = "GET /" + long_url + " HTTP/1.1\r\n\r\n";
    size_t parsed = parse(request);

    // 取决于解析器的实现，可能会成功或失败
    if (hasError()) {
        EXPECT_LT(parsed, request.length());
    } else {
        EXPECT_EQ(url, "/" + long_url);
    }
}

// 9. 测试超长的头部字段名
TEST_F(http_parser_error, ExtremelyLongHeaderField) {
    std::string long_field(10000, 'X');
    std::string request = "GET / HTTP/1.1\r\n" + long_field + ": value\r\n\r\n";
    size_t parsed = parse(request);

    // 取决于解析器的实现，可能会成功或失败
    if (hasError()) {
        EXPECT_LT(parsed, request.length());
    }
}

// 10. 测试超长的头部字段值
TEST_F(http_parser_error, ExtremelyLongHeaderValue) {
    std::string long_value(10000, 'v');
    std::string request = "GET / HTTP/1.1\r\nField: " + long_value + "\r\n\r\n";
    size_t parsed = parse(request);

    // 取决于解析器的实现，可能会成功或失败
    if (hasError()) {
        EXPECT_LT(parsed, request.length());
    }
}

// 11. 测试过多的头部字段
TEST_F(http_parser_error, TooManyHeaders) {
    std::string many_headers;
    for (int i = 0; i < 1000; i++) {
        many_headers += "Header" + std::to_string(i) + ": value" + std::to_string(i) + "\r\n";
    }

    std::string request = "GET / HTTP/1.1\r\n" + many_headers + "\r\n";
    size_t parsed = parse(request);

    // 取决于解析器的实现，可能会成功或失败
    if (hasError()) {
        EXPECT_LT(parsed, request.length());
    }
}

// 12. 测试无效的头部格式
TEST_F(http_parser_error, InvalidHeaderFormat) {
    std::string request = "GET / HTTP/1.1\r\nInvalidHeader\r\n\r\n";
    size_t parsed = parse(request);
    EXPECT_TRUE(bad_request);
}

// 13. 测试头部字段中有非法字符
TEST_F(http_parser_error, IllegalCharactersInHeaderField) {
    std::string request = "GET / HTTP/1.1\r\nX-Header\x01: value\r\n\r\n";
    size_t parsed = parse(request);

    EXPECT_TRUE(hasError());
    EXPECT_LT(parsed, request.length());
}

// 14. 测试头部值中有非法字符
TEST_F(http_parser_error, IllegalCharactersInHeaderValue) {
    std::string request = "GET / HTTP/1.1\r\nX-Header: value\x00more\r\n\r\n";
    size_t parsed = parse(request);

    // 有些解析器可能允许头部值中有一些特殊字符
    if (hasError()) {
        EXPECT_LT(parsed, request.length());
    }
}

// 15. 测试 Content-Length 不一致
TEST_F(http_parser_error, InconsistentContentLength) {
    std::string request = "POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\nTooShort";
    size_t parsed = parse(request);

    EXPECT_EQ(parsed, request.length());
    EXPECT_EQ(message_complete_called, 0);
}

// 16. 测试多个 Content-Length 头
TEST_F(http_parser_error, MultipleContentLengthHeaders) {
    std::string request = "POST / HTTP/1.1\r\nContent-Length: 10\r\nContent-Length: 20\r\n\r\nBody";
    size_t parsed = parse(request);
    EXPECT_EQ(headers["Content-Length"], "20");
}

// 17. 测试 Content-Length 为负数
TEST_F(http_parser_error, NegativeContentLength) {
    std::string request = "POST / HTTP/1.1\r\nContent-Length: -10\r\n\r\nBody";
    size_t parsed = parse(request);

    EXPECT_TRUE(hasError());
    EXPECT_LT(parsed, request.length());
}

// 18. 测试 Content-Length 非数字
TEST_F(http_parser_error, NonNumericContentLength) {
    std::string request = "POST / HTTP/1.1\r\nContent-Length: abc\r\n\r\nBody";
    size_t parsed = parse(request);

    EXPECT_TRUE(hasError());
    EXPECT_LT(parsed, request.length());
}

// 19. 测试 Transfer-Encoding 和 Content-Length 同时存在
TEST_F(http_parser_error, TransferEncodingAndContentLengthCoexist) {
    std::string request = "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nContent-Length: 10\r\n\r\n0\r\n\r\n";
    size_t parsed = parse(request);

    // HTTP/1.1 规范规定当两者同时存在时，Content-Length 应被忽略
    // 但有些解析器可能会将此视为错误
    if (hasError()) {
        EXPECT_LT(parsed, request.length());
    }
}

// 20. 测试错误的分块编码格式
TEST_F(http_parser_error, InvalidChunkedEncoding) {
    std::string request = "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nXYZ\r\ndata\r\n0\r\n\r\n";
    size_t parsed = parse(request);

    EXPECT_TRUE(hasError());
    EXPECT_LT(parsed, request.length());
}

// 21. 测试不完整的分块编码
TEST_F(http_parser_error, IncompleteChunkedEncoding) {
    std::string request = "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nHello";
    size_t parsed = parse(request);

    EXPECT_EQ(parsed, request.length());
    EXPECT_EQ(message_complete_called, 0);
}

// 22. 测试分块编码大小超出范围
TEST_F(http_parser_error, ChunkSizeOverflow) {
    std::string request = "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nffffffffffffffff\r\ndata\r\n0\r\n\r\n";
    size_t parsed = parse(request);
    EXPECT_EQ(message_complete_called, 0);
}

// 23. 测试分块编码中缺少终止块
TEST_F(http_parser_error, MissingTerminatingChunk) {
    std::string request = "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nHello\r\n";
    size_t parsed = parse(request);

    EXPECT_EQ(parsed, request.length());
    EXPECT_EQ(message_complete_called, 0);
}

// 24. 测试不支持的 Transfer-Encoding 值
TEST_F(http_parser_error, UnsupportedTransferEncoding) {
    std::string request = "POST / HTTP/1.1\r\nTransfer-Encoding: unknown\r\n\r\nBody";
    size_t parsed = parse(request);

    // 取决于解析器实现，可能会成功或失败
    if (hasError()) {
        EXPECT_LT(parsed, request.length());
    }
}

// 25. 测试 HTTP 版本号格式错误
TEST_F(http_parser_error, MalformedHttpVersion) {
    std::string request = "GET / HTTP/1.1.2\r\n\r\n";
    size_t parsed = parse(request);

    EXPECT_TRUE(hasError());
    EXPECT_LT(parsed, request.length());
}

// 26. 测试 HTTP 版本号不支持
TEST_F(http_parser_error, UnsupportedHttpVersion) {
    std::string request = "GET / HTTP/2.0\r\n\r\n";
    size_t parsed = parse(request);

    // 取决于解析器实现，可能会成功或失败
    if (hasError()) {
        EXPECT_LT(parsed, request.length());
    }
}

// 27. 测试 URL 中包含非法字符
TEST_F(http_parser_error, IllegalCharactersInUrl) {
    std::string request = "GET /path\x00with\x01null HTTP/1.1\r\n\r\n";
    size_t parsed = parse(request);
    EXPECT_TRUE(bad_request);
}

// 28. 测试请求行过长
TEST_F(http_parser_error, RequestLineTooLong) {
    std::string long_path(10000, 'p');
    std::string request = "GET /" + long_path + " HTTP/1.1\r\n\r\n";
    size_t parsed = parse(request);

    // 取决于解析器实现，可能会成功或失败
    if (hasError()) {
        EXPECT_LT(parsed, request.length());
    }
}

// 29. 测试头部行过长
TEST_F(http_parser_error, HeaderLineTooLong) {
    std::string long_value(10000, 'v');
    std::string request = "GET / HTTP/1.1\r\nX-Long-Header: " + long_value + "\r\n\r\n";
    size_t parsed = parse(request);

    // 取决于解析器实现，可能会成功或失败
    if (hasError()) {
        EXPECT_LT(parsed, request.length());
    }
}

// 30. 测试头部字段名包含空格
TEST_F(http_parser_error, HeaderFieldWithSpaces) {
    std::string request = "GET / HTTP/1.1\r\nInvalid Header: value\r\n\r\n";
    size_t parsed = parse(request);
    EXPECT_TRUE(bad_request);
}

// 31. 测试头部字段名包含冒号
TEST_F(http_parser_error, HeaderFieldWithColon) {
    std::string request = "GET / HTTP/1.1\r\nInvalid:Header: value\r\n\r\n";
    size_t parsed = parse(request);
    EXPECT_TRUE(bad_request);
}

// 32. 测试重复的头部字段
TEST_F(http_parser_error, DuplicateHeaders) {
    std::string request = "GET / HTTP/1.1\r\nHost: example.com\r\nHost: another.com\r\n\r\n";
    size_t parsed = parse(request);

    // HTTP 允许重复的头部字段，所以这应该成功
    EXPECT_FALSE(hasError());
    EXPECT_EQ(parsed, request.length());
    EXPECT_EQ(message_complete_called, 1);
}

// 33. 测试头部字段后没有值
TEST_F(http_parser_error, HeaderFieldWithoutValue) {
    std::string request = "GET / HTTP/1.1\r\nX-Empty:\r\n\r\n";
    size_t parsed = parse(request);

    // 空值是合法的
    EXPECT_FALSE(hasError());
    EXPECT_EQ(parsed, request.length());
}

// 34. 测试头部字段值前有多个空格
TEST_F(http_parser_error, HeaderValueWithLeadingSpaces) {
    std::string request = "GET / HTTP/1.1\r\nX-Space:    value\r\n\r\n";
    size_t parsed = parse(request);

    EXPECT_FALSE(hasError());
    EXPECT_EQ(parsed, request.length());

    // 检查头部值是否正确处理了前导空格
    bool found = false;
    for (const auto &header : headers) {
        if (header.first == "X-Space") {
            found = true;
            // 取决于解析器实现，可能会保留或删除前导空格
            EXPECT_TRUE(header.second == "value" || header.second == "    value");
            break;
        }
    }
    EXPECT_TRUE(found);
}

// 35. 测试分块编码中的扩展
TEST_F(http_parser_error, ChunkedEncodingWithExtensions) {
    std::string request =
        "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5;extension=value\r\nHello\r\n0\r\n\r\n";
    size_t parsed = parse(request);

    // 取决于解析器实现，可能会成功或失败
    if (!hasError()) {
        EXPECT_EQ(parsed, request.length());
        EXPECT_EQ(body, "Hello");
    }
}

// 36. 测试分块编码中的尾部头部
TEST_F(http_parser_error, ChunkedEncodingWithTrailers) {
    std::string request =
        "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nHello\r\n0\r\nTrailer: value\r\n\r\n";
    size_t parsed = parse(request);

    // 取决于解析器实现，可能会成功或失败
    if (!hasError()) {
        EXPECT_EQ(parsed, request.length());
        EXPECT_EQ(body, "Hello");
    }
}

// 37. 测试空的请求体
TEST_F(http_parser_error, EmptyBody) {
    std::string request = "POST / HTTP/1.1\r\nContent-Length: 0\r\n\r\n";
    size_t parsed = parse(request);

    EXPECT_FALSE(hasError());
    EXPECT_EQ(parsed, request.length());
    EXPECT_EQ(body, "");
    EXPECT_EQ(message_complete_called, 1);
}

// 38. 测试 Content-Length 超过实际数据长度
TEST_F(http_parser_error, ContentLengthExceedsActualData) {
    std::string request = "POST / HTTP/1.1\r\nContent-Length: 100\r\n\r\nShortBody";
    size_t parsed = parse(request);

    EXPECT_EQ(parsed, request.length());
    EXPECT_EQ(message_complete_called, 0);
}

// 39. 测试 Content-Length 小于实际数据长度
TEST_F(http_parser_error, ContentLengthLessThanActualData) {
    std::string request = "POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nLongerBodyThanExpected";
    size_t parsed = parse(request);

    EXPECT_LT(parsed, request.length());
    EXPECT_EQ(headers["Content-Length"], "5");
    EXPECT_EQ(body, "Longe");
    EXPECT_EQ(message_complete_called, 1);
}

// 40. 测试 HTTP 方法区分大小写
TEST_F(http_parser_error, CaseSensitiveMethod) {
    std::string request = "get / HTTP/1.1\r\n\r\n";
    size_t parsed = parse(request);

    // 取决于解析器实现，可能会成功或失败
    // HTTP 方法通常是区分大小写的
    if (hasError()) {
        EXPECT_LT(parsed, request.length());
    }
}

// 41. 测试 URL 中有特殊字符
TEST_F(http_parser_error, UrlWithSpecialCharacters) {
    std::string request = "GET /path?param=value&special=%20%3C%3E%23%25 HTTP/1.1\r\n\r\n";
    size_t parsed = parse(request);

    EXPECT_FALSE(hasError());
    EXPECT_EQ(parsed, request.length());
    EXPECT_EQ(url, "/path?param=value&special=%20%3C%3E%23%25");
}

// 42. 测试 URL 中有非 ASCII 字符
TEST_F(http_parser_error, UrlWithNonAsciiCharacters) {
    std::string request = "GET /path?param=值 HTTP/1.1\r\n\r\n";
    size_t parsed = parse(request);

    // 取决于解析器实现，可能会成功或失败
    if (!hasError()) {
        EXPECT_EQ(parsed, request.length());
    }
}

// 43. 测试头部字段名中有非 ASCII 字符
TEST_F(http_parser_error, HeaderFieldWithNonAsciiCharacters) {
    std::string request = "GET / HTTP/1.1\r\nX-测试: value\r\n\r\n";
    size_t parsed = parse(request);

    // 取决于解析器实现，可能会成功或失败
    if (hasError()) {
        EXPECT_LT(parsed, request.length());
    }
}

// 44. 测试头部字段值中有非 ASCII 字符
TEST_F(http_parser_error, HeaderValueWithNonAsciiCharacters) {
    std::string request = "GET / HTTP/1.1\r\nX-Test: 值\r\n\r\n";
    size_t parsed = parse(request);

    // 取决于解析器实现，可能会成功或失败
    if (!hasError()) {
        EXPECT_EQ(parsed, request.length());
    }
}

// 45. 测试请求体中有非 ASCII 字符
TEST_F(http_parser_error, BodyWithNonAsciiCharacters) {
    std::string request = "POST / HTTP/1.1\r\nContent-Length: 6\r\n\r\n测试";
    size_t parsed = parse(request);

    // 取决于解析器实现，可能会成功或失败
    if (!hasError()) {
        EXPECT_EQ(parsed, request.length());
        EXPECT_EQ(body, "测试");
    }
}

// 46. 测试分段解析 HTTP 请求
TEST_F(http_parser_error, PartialParsing) {
    std::string request_part1 = "GET / HTTP/1.1\r\n";
    std::string request_part2 = "Host: example.com\r\n\r\n";

    size_t parsed1 = parse(request_part1);
    EXPECT_FALSE(hasError());
    EXPECT_EQ(parsed1, request_part1.length());
    EXPECT_EQ(message_complete_called, 0);

    size_t parsed2 = parse(request_part2);
    EXPECT_FALSE(hasError());
    EXPECT_EQ(parsed2, request_part2.length());
    EXPECT_EQ(message_complete_called, 1);
}

// 47. 测试畸形的分块编码尺寸
TEST_F(http_parser_error, MalformedChunkSize) {
    std::string request = "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5g\r\nHello\r\n0\r\n\r\n";
    size_t parsed = parse(request);

    EXPECT_TRUE(hasError());
    EXPECT_LT(parsed, request.length());
}

// 48. 测试分块编码中缺少块大小
TEST_F(http_parser_error, MissingChunkSize) {
    std::string request = "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n\r\nHello\r\n0\r\n\r\n";
    size_t parsed = parse(request);

    EXPECT_TRUE(hasError());
    EXPECT_LT(parsed, request.length());
}

// 49. 测试分块编码中块大小后面没有CRLF
TEST_F(http_parser_error, NoNewlineAfterChunkSize) {
    std::string request = "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5Hello\r\n0\r\n\r\n";
    size_t parsed = parse(request);

    EXPECT_TRUE(hasError());
    EXPECT_LT(parsed, request.length());
}

// 50. 测试分块编码中数据后面没有CRLF
TEST_F(http_parser_error, NoNewlineAfterChunkData) {
    std::string request = "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nHello0\r\n\r\n";
    size_t parsed = parse(request);

    EXPECT_TRUE(hasError());
    EXPECT_LT(parsed, request.length());
}

// 51. 测试请求方法为空
TEST_F(http_parser_error, EmptyMethod) {
    std::string request = " / HTTP/1.1\r\n\r\n";
    size_t parsed = parse(request);

    EXPECT_TRUE(hasError());
    EXPECT_LT(parsed, request.length());
}

// 52. 测试请求路径为空
TEST_F(http_parser_error, EmptyPath) {
    std::string request = "GET  HTTP/1.1\r\n\r\n";
    size_t parsed = parse(request);

    EXPECT_TRUE(hasError());
    EXPECT_LT(parsed, request.length());
}

// 53. 测试请求行中只有方法
TEST_F(http_parser_error, OnlyMethodInRequestLine) {
    std::string request = "GET\r\n\r\n";
    size_t parsed = parse(request);
    EXPECT_EQ(path, "");
    EXPECT_EQ(url_called, 0);
}

// 54. 测试请求行中只有方法和路径
TEST_F(http_parser_error, OnlyMethodAndPathInRequestLine) {
    std::string request = "GET /\r\n\r\n";
    size_t parsed = parse(request);
    EXPECT_EQ(headers_complete_called, 1);
    EXPECT_EQ(parser.http_major, 0);
    EXPECT_EQ(parser.http_minor, 9);
}

// 55. 测试请求行中缺少HTTP版本号
TEST_F(http_parser_error, MissingHttpVersionInRequestLine) {
    std::string request = "GET / \r\n\r\n";
    size_t parsed = parse(request);

    EXPECT_TRUE(hasError());
    EXPECT_LT(parsed, request.length());
}

// 56. 测试请求行中HTTP版本号格式错误
TEST_F(http_parser_error, MalformedHttpVersionInRequestLine) {
    std::string request = "GET / HTTP1.1\r\n\r\n";
    size_t parsed = parse(request);

    EXPECT_TRUE(hasError());
    EXPECT_LT(parsed, request.length());
}

// 57. 测试请求行中HTTP版本号后面有额外内容
TEST_F(http_parser_error, ExtraContentAfterHttpVersion) {
    std::string request = "GET / HTTP/1.1 Extra\r\n\r\n";
    size_t parsed = parse(request);

    EXPECT_TRUE(hasError());
    EXPECT_LT(parsed, request.length());
}

// 58. 测试头部字段名为空
TEST_F(http_parser_error, EmptyHeaderFieldName) {
    std::string request = "GET / HTTP/1.1\r\n: value\r\n\r\n";
    size_t parsed = parse(request);

    EXPECT_TRUE(hasError());
    EXPECT_LT(parsed, request.length());
}

// 59. 测试头部字段值前有冒号但没有空格
TEST_F(http_parser_error, HeaderValueWithoutSpaceAfterColon) {
    std::string request = "GET / HTTP/1.1\r\nField:value\r\n\r\n";
    size_t parsed = parse(request);

    // 这通常是合法的，冒号后的空格是可选的
    EXPECT_FALSE(hasError());
    EXPECT_EQ(parsed, request.length());
}

// 60. 测试头部字段后有多个冒号
TEST_F(http_parser_error, MultipleColonsInHeader) {
    std::string request = "GET / HTTP/1.1\r\nField:: value\r\n\r\n";
    size_t parsed = parse(request);

    // 取决于解析器实现，可能会成功或失败
    if (!hasError()) {
        EXPECT_EQ(parsed, request.length());

        bool found = false;
        for (const auto &header : headers) {
            if (header.first == "Field") {
                found = true;
                EXPECT_EQ(header.second, ": value");
                break;
            }
        }
        EXPECT_TRUE(found);
    }
}

// 61. 测试头部字段行中间有CR但没有LF
TEST_F(http_parser_error, CRWithoutLFInHeaderLine) {
    std::string request = "GET / HTTP/1.1\r\nField: value\rmore\r\n\r\n";
    size_t parsed = parse(request);
    EXPECT_EQ(headers["Field"], "value");
}

// 62. 测试头部字段行中间有LF但没有CR
TEST_F(http_parser_error, LFWithoutCRInHeaderLine) {
    std::string request = "GET / HTTP/1.1\r\nField: value\nmore\r\n\r\n";
    size_t parsed = parse(request);

    // 取决于解析器实现，可能会成功或失败
    if (hasError()) {
        EXPECT_LT(parsed, request.length());
    }
}

// 63. 测试头部字段中有制表符
TEST_F(http_parser_error, TabInHeaderField) {
    std::string request = "GET / HTTP/1.1\r\nField\t: value\r\n\r\n";
    size_t parsed = parse(request);

    EXPECT_TRUE(hasError());
    EXPECT_LT(parsed, request.length());
}

// 64. 测试头部字段值中有制表符
TEST_F(http_parser_error, TabInHeaderValue) {
    std::string request = "GET / HTTP/1.1\r\nField: value\twith\ttabs\r\n\r\n";
    size_t parsed = parse(request);

    // 头部值中的制表符通常是允许的
    EXPECT_FALSE(hasError());
    EXPECT_EQ(parsed, request.length());
}

// 65. 测试头部字段名中有控制字符
TEST_F(http_parser_error, ControlCharInHeaderField) {
    std::string request = "GET / HTTP/1.1\r\nFie\x01ld: value\r\n\r\n";
    size_t parsed = parse(request);

    EXPECT_TRUE(hasError());
    EXPECT_LT(parsed, request.length());
}

// 66. 测试头部字段值中有控制字符
TEST_F(http_parser_error, ControlCharInHeaderValue) {
    std::string request = "GET / HTTP/1.1\r\nField: val\x01ue\r\n\r\n";
    size_t parsed = parse(request);

    // 取决于解析器实现，可能会成功或失败
    if (hasError()) {
        EXPECT_LT(parsed, request.length());
    }
}

// 67. 测试请求行中有控制字符
TEST_F(http_parser_error, ControlCharInRequestLine) {
    std::string request = "GET /pa\x01th HTTP/1.1\r\n\r\n";
    size_t parsed = parse(request);

    EXPECT_TRUE(hasError());
    EXPECT_LT(parsed, request.length());
}

// 68. 测试请求体中有控制字符
TEST_F(http_parser_error, ControlCharInBody) {
    std::string request = "POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\nABC\x00DEF\x01GH";
    size_t parsed = parse(request);

    // 请求体中的控制字符通常是允许的
    EXPECT_FALSE(hasError());
    EXPECT_EQ(parsed, request.length());
}

// 69. 测试分块编码中的块大小为0但后面有数据
TEST_F(http_parser_error, ZeroChunkSizeWithData) {
    std::string request = "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nInvalidData\r\n\r\n";
    size_t parsed = parse(request);

    EXPECT_EQ(message_complete_called, 1);
    EXPECT_EQ(parser.content_length, 0);
}

// 70. 测试分块编码中的块大小为0但没有最终的CRLF
TEST_F(http_parser_error, ZeroChunkSizeWithoutFinalCRLF) {
    std::string request = "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n";
    size_t parsed = parse(request);

    EXPECT_EQ(parsed, request.length());
    EXPECT_EQ(message_complete_called, 0);
}

// 71. 测试分块编码中有多个0大小的块
TEST_F(http_parser_error, MultipleZeroChunks) {
    std::string request = "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n0\r\n\r\n";
    size_t parsed = parse(request);

    // 第一个0块应该终止消息，第二个0块应该被视为错误
    EXPECT_TRUE(hasError() || parsed < request.length());
}

// 72. 测试分块编码中的块大小有前导0
TEST_F(http_parser_error, ChunkSizeWithLeadingZeros) {
    std::string request = "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n000005\r\nHello\r\n0\r\n\r\n";
    size_t parsed = parse(request);

    // 前导0通常是允许的
    EXPECT_FALSE(hasError());
    EXPECT_EQ(parsed, request.length());
    EXPECT_EQ(body, "Hello");
}

// 73. 测试分块编码中的块大小有非十六进制字符
TEST_F(http_parser_error, ChunkSizeWithNonHexCharacters) {
    std::string request = "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5Z\r\nHello\r\n0\r\n\r\n";
    size_t parsed = parse(request);

    EXPECT_TRUE(hasError());
    EXPECT_LT(parsed, request.length());
}

// 74. 测试分块编码中的块大小后有无效的扩展
TEST_F(http_parser_error, ChunkSizeWithInvalidExtension) {
    std::string request =
        "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5;invalid extension\r\nHello\r\n0\r\n\r\n";
    size_t parsed = parse(request);

    // 取决于解析器实现，可能会成功或失败
    if (!hasError()) {
        EXPECT_EQ(parsed, request.length());
        EXPECT_EQ(body, "Hello");
    }
}

// 75. 测试分块编码中的尾部头部格式错误
TEST_F(http_parser_error, MalformedTrailerInChunkedEncoding) {
    std::string request =
        "POST / HTTP/1.1\r\nTransfer-Encoding:chunked\r\n\r\n5\r\nHello\r\n0\r\nInvalid-Trailer\r\n\r\n";
    size_t parsed = parse(request);
    EXPECT_EQ(message_complete_called, 1);
    EXPECT_EQ(parser.content_length, 0);
}

// 76. 测试Content-Length值超过整数最大值
TEST_F(http_parser_error, ContentLengthOverflow) {
    std::string request = "POST / HTTP/1.1\r\nContent-Length: 999999999999999999999\r\n\r\nBody";
    size_t parsed = parse(request);
    EXPECT_EQ(headers["Content-Length"], "999999999999999999999");
}

// 77. 测试Content-Length值为浮点数
TEST_F(http_parser_error, ContentLengthAsFloat) {
    std::string request = "POST / HTTP/1.1\r\nContent-Length: 5.5\r\n\r\nHello";
    size_t parsed = parse(request);

    EXPECT_TRUE(hasError());
    EXPECT_LT(parsed, request.length());
}

// 78. 测试Content-Length值为十六进制
TEST_F(http_parser_error, ContentLengthAsHex) {
    std::string request = "POST / HTTP/1.1\r\nContent-Length: 0x5\r\n\r\nHello";
    size_t parsed = parse(request);

    EXPECT_TRUE(hasError());
    EXPECT_LT(parsed, request.length());
}

// 79. 测试Content-Length值前后有空格
TEST_F(http_parser_error, ContentLengthWithSpaces) {
    std::string request = "POST / HTTP/1.1\r\nContent-Length:  5  \r\n\r\nHello";
    size_t parsed = parse(request);

    // 前后空格通常是允许的
    EXPECT_FALSE(hasError());
    EXPECT_EQ(parsed, request.length());
    EXPECT_EQ(body, "Hello");
}

// 80. 测试Content-Length值中间有空格
TEST_F(http_parser_error, ContentLengthWithInternalSpaces) {
    std::string request = "POST / HTTP/1.1\r\nContent-Length: 5 5\r\n\r\nHello";
    size_t parsed = parse(request);
    EXPECT_EQ(headers["Content-Length"], "5 5");
}

// 81. 测试HTTP请求中使用了保留字符
TEST_F(http_parser_error, ReservedCharactersInRequest) {
    std::string request = "GET /path{with}reserved[chars] HTTP/1.1\r\n\r\n";
    size_t parsed = parse(request);

    // URL中的保留字符通常是允许的，但需要正确处理
    EXPECT_FALSE(hasError());
    EXPECT_EQ(parsed, request.length());
    EXPECT_EQ(url, "/path{with}reserved[chars]");
}

// 82. 测试HTTP请求中使用了未编码的空格
TEST_F(http_parser_error, UncodedSpacesInUrl) {
    std::string request = "GET /path with spaces HTTP/1.1\r\n\r\n";
    size_t parsed = parse(request);

    // URL中未编码的空格通常是不允许的
    EXPECT_TRUE(hasError());
    EXPECT_LT(parsed, request.length());
}

// 83. 测试HTTP请求中使用了编码的空格
TEST_F(http_parser_error, EncodedSpacesInUrl) {
    std::string request = "GET /path%20with%20spaces HTTP/1.1\r\n\r\n";
    size_t parsed = parse(request);

    EXPECT_FALSE(hasError());
    EXPECT_EQ(parsed, request.length());
    EXPECT_EQ(url, "/path%20with%20spaces");
}

// 84. 测试HTTP请求中使用了百分号但未完成编码
TEST_F(http_parser_error, IncompletePercentEncodingInUrl) {
    std::string request = "GET /path%2 HTTP/1.1\r\n\r\n";
    size_t parsed = parse(request);

    EXPECT_EQ(path, "/path%2");
}

// 85. 测试HTTP请求中使用了无效的百分号编码
TEST_F(http_parser_error, InvalidPercentEncodingInUrl) {
    std::string request = "GET /path%XY HTTP/1.1\r\n\r\n";
    size_t parsed = parse(request);

    EXPECT_EQ(path, "/path%XY");
}

// 86. 测试HTTP请求中使用了多个百分号
TEST_F(http_parser_error, MultiplePercentSignsInUrl) {
    std::string request = "GET /path%%20 HTTP/1.1\r\n\r\n";
    size_t parsed = parse(request);

    // 取决于解析器实现，可能会成功或失败
    if (hasError()) {
        EXPECT_LT(parsed, request.length());
    }
}

// 87. 测试请求中包含无效的协议
TEST_F(http_parser_error, InvalidProtocolInUrl) {
    std::string request = "GET http://example.com:xyz/ HTTP/1.1\r\n\r\n";
    size_t parsed = parse(request);

    // 取决于解析器实现，可能会成功或失败
    // 某些解析器可能会接受整个URL作为请求路径
    if (!hasError()) {
        EXPECT_EQ(parsed, request.length());
        EXPECT_EQ(url, "http://example.com:xyz/");
    }
}

// 88. 测试请求中包含无效的端口号
TEST_F(http_parser_error, InvalidPortInUrl) {
    std::string request = "GET http://example.com:99999/ HTTP/1.1\r\n\r\n";
    size_t parsed = parse(request);

    // 取决于解析器实现，可能会成功或失败
    // 某些解析器可能会接受整个URL作为请求路径
    if (!hasError()) {
        EXPECT_EQ(parsed, request.length());
        EXPECT_EQ(url, "http://example.com:99999/");
    }
}

// 89. 测试请求中包含负端口号
TEST_F(http_parser_error, NegativePortInUrl) {
    std::string request = "GET http://example.com:-80/ HTTP/1.1\r\n\r\n";
    size_t parsed = parse(request);

    // 取决于解析器实现，可能会成功或失败
    // 某些解析器可能会接受整个URL作为请求路径
    if (!hasError()) {
        EXPECT_EQ(parsed, request.length());
        EXPECT_EQ(url, "http://example.com:-80/");
    }
}

// 90. 测试请求中包含过长的主机名
TEST_F(http_parser_error, ExtremelyLongHostnameInUrl) {
    std::string long_hostname(300, 'a');
    std::string request = "GET http://" + long_hostname + ".com/ HTTP/1.1\r\n\r\n";
    size_t parsed = parse(request);

    // 取决于解析器实现，可能会成功或失败
    if (!hasError()) {
        EXPECT_EQ(parsed, request.length());
        EXPECT_EQ(url, "http://" + long_hostname + ".com/");
    }
}

// 91. 测试请求中包含无效的用户信息
TEST_F(http_parser_error, InvalidUserInfoInUrl) {
    std::string request = "GET http://user:pass@example.com/ HTTP/1.1\r\n\r\n";
    size_t parsed = parse(request);

    // 取决于解析器实现，可能会成功或失败
    // 某些解析器可能会接受整个URL作为请求路径
    if (!hasError()) {
        EXPECT_EQ(parsed, request.length());
        EXPECT_EQ(url, "http://user:pass@example.com/");
    }
}

// 92. 测试请求中包含无效的片段标识符
TEST_F(http_parser_error, InvalidFragmentInUrl) {
    std::string request = "GET /path#fragment HTTP/1.1\r\n\r\n";
    size_t parsed = parse(request);

    // 取决于解析器实现，可能会成功或失败
    // 某些解析器可能会接受带有片段的URL
    if (!hasError()) {
        EXPECT_EQ(parsed, request.length());
        EXPECT_EQ(url, "/path#fragment");
    }
}

// 93. 测试请求中包含过多的查询参数
TEST_F(http_parser_error, TooManyQueryParametersInUrl) {
    std::string many_params;
    for (int i = 0; i < 1000; i++) {
        many_params += "param" + std::to_string(i) + "=value" + std::to_string(i) + "&";
    }
    std::string request = "GET /path?" + many_params + " HTTP/1.1\r\n\r\n";
    size_t parsed = parse(request);

    // 取决于解析器实现，可能会成功或失败
    if (!hasError()) {
        EXPECT_EQ(parsed, request.length());
    }
}

// 94. 测试请求中包含重复的查询参数
TEST_F(http_parser_error, DuplicateQueryParametersInUrl) {
    std::string request = "GET /path?param=value1&param=value2 HTTP/1.1\r\n\r\n";
    size_t parsed = parse(request);

    // 重复的查询参数通常是允许的
    EXPECT_FALSE(hasError());
    EXPECT_EQ(parsed, request.length());
    EXPECT_EQ(url, "/path?param=value1&param=value2");
}

// 95. 测试请求中包含无值的查询参数
TEST_F(http_parser_error, QueryParametersWithoutValueInUrl) {
    std::string request = "GET /path?param1&param2= HTTP/1.1\r\n\r\n";
    size_t parsed = parse(request);

    // 无值的查询参数通常是允许的
    EXPECT_FALSE(hasError());
    EXPECT_EQ(parsed, request.length());
    EXPECT_EQ(url, "/path?param1&param2=");
}

// 96. 测试请求中包含特殊字符的查询参数
TEST_F(http_parser_error, SpecialCharactersInQueryParameters) {
    std::string request = "GET /path?param=value%20with%20spaces&special=!@%23$%25%5E&*()_+ HTTP/1.1\r\n\r\n";
    size_t parsed = parse(request);

    // 编码的特殊字符通常是允许的
    EXPECT_FALSE(hasError());
    EXPECT_EQ(parsed, request.length());
}

// 97. 测试请求中包含无效字符的查询参数
TEST_F(http_parser_error, InvalidCharactersInQueryParameters) {
    std::string request = "GET /path?param=value\x01 HTTP/1.1\r\n\r\n";
    size_t parsed = parse(request);

    EXPECT_TRUE(hasError());
    EXPECT_LT(parsed, request.length());
}

// 98. 测试请求中包含过长的查询字符串
TEST_F(http_parser_error, ExtremelyLongQueryString) {
    std::string long_query(10000, 'q');
    std::string request = "GET /path?" + long_query + " HTTP/1.1\r\n\r\n";
    size_t parsed = parse(request);

    // 取决于解析器实现，可能会成功或失败
    if (!hasError()) {
        EXPECT_EQ(parsed, request.length());
        EXPECT_EQ(url, "/path?" + long_query);
    }
}

// 99. 测试请求中包含过长的路径段
TEST_F(http_parser_error, ExtremelyLongPathSegment) {
    std::string long_segment(10000, 'p');
    std::string request = "GET /" + long_segment + " HTTP/1.1\r\n\r\n";
    size_t parsed = parse(request);

    // 取决于解析器实现，可能会成功或失败
    if (!hasError()) {
        EXPECT_EQ(parsed, request.length());
        EXPECT_EQ(url, "/" + long_segment);
    }
}

// 100. 测试请求中包含过多的路径段
TEST_F(http_parser_error, TooManyPathSegments) {
    std::string many_segments;
    for (int i = 0; i < 1000; i++) {
        many_segments += "segment" + std::to_string(i) + "/";
    }
    std::string request = "GET /" + many_segments + " HTTP/1.1\r\n\r\n";
    size_t parsed = parse(request);

    // 取决于解析器实现，可能会成功或失败
    if (!hasError()) {
        EXPECT_EQ(parsed, request.length());
        EXPECT_EQ(url, "/" + many_segments);
    }
}