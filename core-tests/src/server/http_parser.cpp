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
#include "swoole_util.h"
#include "swoole_llhttp.h"

using namespace std;

static int http_request_on_url(llhttp_t *parser, const char *at, size_t length);
static int http_request_on_body(llhttp_t *parser, const char *at, size_t length);
static int http_request_on_header_field(llhttp_t *parser, const char *at, size_t length);
static int http_request_on_header_value(llhttp_t *parser, const char *at, size_t length);
static int http_request_on_headers_complete(llhttp_t *parser);
static int http_request_message_complete(llhttp_t *parser);
static int http_llhttp_data_cb(llhttp_t *parser, const char *at, size_t length);
static int http_llhttp_cb(llhttp_t *parser);

// clang-format off
static const llhttp_settings_t http_parser_settings =
{
    http_llhttp_cb,                         // on_message_begin
    http_llhttp_data_cb,                    // on_protocol
    http_request_on_url,                    // on_url
    http_llhttp_data_cb,                    // on_status
    http_llhttp_data_cb,                    // on_method
    http_llhttp_data_cb,                    // on_version
    http_request_on_header_field,           // on_header_field
    http_request_on_header_value,           // on_header_value
    http_llhttp_data_cb,                    // on_chunk_extension_name
    http_llhttp_data_cb,                    // on_chunk_extension_value
    http_request_on_headers_complete,       // on_headers_complete
    http_request_on_body,                   // on_body
    http_request_message_complete,          // on_message_complete
    http_llhttp_cb,                         // on_protocol_complete
    http_llhttp_cb,                         // on_url_complete
    http_llhttp_cb,                         // on_status_complete
    http_llhttp_cb,                         // on_method_complete
    http_llhttp_cb,                         // on_version_complete
    http_llhttp_cb,                         // on_header_field_complete
    http_llhttp_cb,                         // on_header_value_complete
    http_llhttp_cb,                         // on_chunk_extension_name_complete
    http_llhttp_cb,                         // on_chunk_extension_value_complete
    http_llhttp_cb,                         // on_chunk_header
    http_llhttp_cb,                         // on_chunk_complete
    http_llhttp_cb,                         // on_reset
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
};

static llhttp_t *swoole_http_parser_create(llhttp_type type = HTTP_REQUEST) {
    auto *ctx = new HttpContext();
    llhttp_t *parser = &ctx->parser;
    swoole_llhttp_parser_init(parser, type, static_cast<void *>(ctx));
    return parser;
}

static void swoole_http_destroy_context(llhttp_t *parser) {
    delete static_cast<HttpContext *>(parser->data);
}

static int http_request_on_url(llhttp_t *parser, const char *at, size_t length) {
    auto *ctx = static_cast<HttpContext *>(parser->data);
    ctx->query_string = string(at, length);
    return 0;
}

static int http_request_on_header_field(llhttp_t *parser, const char *at, size_t length) {
    auto *ctx = static_cast<HttpContext *>(parser->data);
    ctx->header_fields.emplace_back(at, length);
    return 0;
}

static int http_request_on_header_value(llhttp_t *parser, const char *at, size_t length) {
    auto ctx = static_cast<HttpContext *>(parser->data);
    ctx->header_values.emplace_back(at, length);
    return 0;
}

static int http_request_on_headers_complete(llhttp_t *parser) {
    return 0;
}

static int http_request_on_body(llhttp_t *parser, const char *at, size_t length) {
    return 0;
}

static int http_request_message_complete(llhttp_t *parser) {
    auto ctx = static_cast<HttpContext *>(parser->data);
    ctx->completed = 1;
    return 0;
}

static int http_llhttp_data_cb(llhttp_t *parser, const char *at, size_t length) {
    return 0;
}

static int http_llhttp_cb(llhttp_t *parser) {
    return 0;
}

TEST(http_parser, get_request) {
    llhttp_t *parser = swoole_http_parser_create();
    ON_SCOPE_EXIT {
        swoole_http_destroy_context(parser);
    };

    string request = "GET /get HTTP/1.1\r\n"
                     "Host: www.maria.com\r\n"
                     "User-Agent: curl/7.64.1\r\n"
                     "Accept: */*\r\n"
                     "Connection: keep-alive\r\n"
                     "\r\n";
    size_t length = swoole_llhttp_parser_execute(parser, &http_parser_settings, request.c_str(), request.length());
    HttpContext *ctx = static_cast<HttpContext *>(parser->data);
    ASSERT_TRUE(length == request.length());
    ASSERT_TRUE(llhttp_get_errno(parser) == HPE_OK);
    ASSERT_TRUE(ctx->completed == 1);
    ASSERT_TRUE(llhttp_should_keep_alive(parser) == 1);
}

TEST(http_parser, version) {
    llhttp_t *parser = swoole_http_parser_create();
    ON_SCOPE_EXIT {
        swoole_http_destroy_context(parser);
    };

    string http11 = "GET /get HTTP/1.1\r\n\r\n";
    size_t length = swoole_llhttp_parser_execute(parser, &http_parser_settings, http11.c_str(), http11.length());
    ASSERT_TRUE(length == http11.length());

    HttpContext *ctx = static_cast<HttpContext *>(parser->data);
    ASSERT_TRUE(llhttp_get_errno(parser) == HPE_OK);
    ASSERT_TRUE(ctx->completed == 1);
    ASSERT_TRUE(llhttp_get_http_major(parser) == 1);
    ASSERT_TRUE(llhttp_get_http_minor(parser) == 1);
}

TEST(http_parser, incomplete) {
    llhttp_t *parser = swoole_http_parser_create();
    ON_SCOPE_EXIT {
        swoole_http_destroy_context(parser);
    };

    string incomplete = "GET /get HTTP/1.1\r\n";
    size_t length =
        swoole_llhttp_parser_execute(parser, &http_parser_settings, incomplete.c_str(), incomplete.length());
    ASSERT_TRUE(length == incomplete.length());
    ASSERT_TRUE(llhttp_get_errno(parser) == HPE_OK);

    HttpContext *ctx = static_cast<HttpContext *>(parser->data);
    ASSERT_TRUE(ctx->completed == 0);
}

TEST(http_parser, method) {
    llhttp_t *parser = swoole_http_parser_create();
    ON_SCOPE_EXIT {
        swoole_http_destroy_context(parser);
    };

    string incomplete = "GET /get HTTP/1.1\r\n\r\n";
    size_t length =
        swoole_llhttp_parser_execute(parser, &http_parser_settings, incomplete.c_str(), incomplete.length());
    ASSERT_TRUE(length == incomplete.length());
    ASSERT_TRUE(llhttp_get_method(parser) == HTTP_GET);
    ASSERT_STREQ(llhttp_method_name(HTTP_GET), "GET");
}

TEST(http_parser, websocket) {
    llhttp_t *parser = swoole_http_parser_create();
    ON_SCOPE_EXIT {
        swoole_http_destroy_context(parser);
    };

    string websocket = "GET /chat HTTP/1.1\r\n"
                       "Host: example.com\r\n"
                       "Upgrade: websocket\r\n"
                       "Connection: Upgrade\r\n"
                       "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                       "Sec-WebSocket-Version: 13\r\n"
                       "Origin: http://example.com\r\n\r\n";
    size_t length = swoole_llhttp_parser_execute(parser, &http_parser_settings, websocket.c_str(), websocket.length());
    ASSERT_TRUE(length == websocket.length());
    ASSERT_TRUE(llhttp_get_errno(parser) == HPE_OK);
    ASSERT_TRUE(llhttp_get_upgrade(parser) == 1);

    HttpContext *ctx = static_cast<HttpContext *>(parser->data);
    ASSERT_TRUE(ctx->completed == 1);
}

TEST(http_parser, http2) {
    llhttp_t *parser = swoole_http_parser_create();
    ON_SCOPE_EXIT {
        swoole_http_destroy_context(parser);
    };

    string http2 = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    size_t length = swoole_llhttp_parser_execute(parser, &http_parser_settings, http2.c_str(), http2.length());
    ASSERT_TRUE(length == http2.length());
    ASSERT_TRUE(llhttp_get_errno(parser) == HPE_PAUSED_H2_UPGRADE);
    ASSERT_TRUE(llhttp_get_method(parser) == HTTP_PRI);
}

TEST(http_parser, header_field_and_value) {
    string request = "GET /get HTTP/1.1\r\n"
                     "Host: www.maria.com\r\n"
                     "User-Agent: curl/7.64.1\r\n"
                     "Accept: */*\r\n"
                     "Connection: keep-alive\r\n"
                     "\r\n";

    llhttp_t *parser = swoole_http_parser_create();
    ON_SCOPE_EXIT {
        swoole_http_destroy_context(parser);
    };

    size_t length = swoole_llhttp_parser_execute(parser, &http_parser_settings, request.c_str(), request.length());
    ASSERT_TRUE(length == request.length());
    HttpContext *ctx = static_cast<HttpContext *>(parser->data);
    ASSERT_TRUE(ctx->completed == 1);

    ASSERT_STREQ(ctx->header_fields[0].c_str(), "Host");
    ASSERT_STREQ(ctx->header_fields[1].c_str(), "User-Agent");
    ASSERT_STREQ(ctx->header_fields[2].c_str(), "Accept");
    ASSERT_STREQ(ctx->header_fields[3].c_str(), "Connection");

    ASSERT_STREQ(ctx->header_values[0].c_str(), "www.maria.com");
    ASSERT_STREQ(ctx->header_values[1].c_str(), "curl/7.64.1");
    ASSERT_STREQ(ctx->header_values[2].c_str(), "*/*");
    ASSERT_STREQ(ctx->header_values[3].c_str(), "keep-alive");
}

TEST(http_parser, query_string) {
    string request = "GET /get/swoole?a=1&b=2 HTTP/1.1\r\n\r\n";
    llhttp_t *parser = swoole_http_parser_create();
    ON_SCOPE_EXIT {
        swoole_http_destroy_context(parser);
    };

    size_t length = swoole_llhttp_parser_execute(parser, &http_parser_settings, request.c_str(), request.length());
    ASSERT_TRUE(length == request.length());
    ASSERT_TRUE(llhttp_get_errno(parser) == HPE_OK);

    HttpContext *ctx = static_cast<HttpContext *>(parser->data);
    ASSERT_STREQ(ctx->query_string.c_str(), "/get/swoole?a=1&b=2");
}

TEST(http_parser, chunk) {
    string chunk = "HTTP/1.1 200 OK\r\n"
                   "Content-Type: text/plain\r\n"
                   "Transfer-Encoding: chunked\r\n\r\n"
                   "5\r\n"
                   "Hello\r\n"
                   "6\r\n"
                   " World\r\n"
                   "3\r\n"
                   "!!!\r\n"
                   "0\r\n\r\n";

    llhttp_t *parser = swoole_http_parser_create(HTTP_RESPONSE);
    ON_SCOPE_EXIT {
        swoole_http_destroy_context(parser);
    };

    size_t length = swoole_llhttp_parser_execute(parser, &http_parser_settings, chunk.c_str(), chunk.length());
    ASSERT_EQ(length, chunk.length());
    ASSERT_EQ(llhttp_get_errno(parser), HPE_OK);

    HttpContext *ctx = static_cast<HttpContext *>(parser->data);
    ASSERT_TRUE(ctx->completed == 1);
}

TEST(http_parser, response) {
    string response = "HTTP/1.1 200 OK\r\n"
                      "Server: CLOUD ELB 1.0.0\r\n"
                      "Date: Sat, 04 Feb 2023 08:47:14 GMT\r\n"
                      "Content-Type: application/json\r\n"
                      "Content-Length: 18\r\n"
                      "Connection: close\r\n"
                      "\r\n"
                      "{\"name\" : \"laala\"}";

    llhttp_t *parser = swoole_http_parser_create(HTTP_RESPONSE);
    ON_SCOPE_EXIT {
        swoole_http_destroy_context(parser);
    };

    size_t length = swoole_llhttp_parser_execute(parser, &http_parser_settings, response.c_str(), response.length());
    ASSERT_TRUE(length == response.length());
    ASSERT_TRUE(llhttp_get_errno(parser) == HPE_OK);
    ASSERT_TRUE(llhttp_get_status_code(parser) == HTTP_STATUS_OK);
    ASSERT_TRUE(llhttp_get_http_major(parser) == 1);
    ASSERT_TRUE(llhttp_get_http_minor(parser) == 1);

    HttpContext *ctx = static_cast<HttpContext *>(parser->data);
    ASSERT_TRUE(ctx->completed == 1);
    ASSERT_STREQ(ctx->header_fields[0].c_str(), "Server");
    ASSERT_STREQ(ctx->header_fields[1].c_str(), "Date");
    ASSERT_STREQ(ctx->header_fields[2].c_str(), "Content-Type");
    ASSERT_STREQ(ctx->header_fields[3].c_str(), "Content-Length");
    ASSERT_STREQ(ctx->header_fields[4].c_str(), "Connection");

    ASSERT_STREQ(ctx->header_values[0].c_str(), "CLOUD ELB 1.0.0");
    ASSERT_STREQ(ctx->header_values[1].c_str(), "Sat, 04 Feb 2023 08:47:14 GMT");
    ASSERT_STREQ(ctx->header_values[2].c_str(), "application/json");
    ASSERT_STREQ(ctx->header_values[3].c_str(), "18");
    ASSERT_STREQ(ctx->header_values[4].c_str(), "close");
}

// clang-format off
const vector<string> request_error_protocols = {
    // request/connection
    "PUT /url HTTP/1.0\r\n\r\nPUT /url HTTP/1.1\r\n\r\n",
    "POST / HTTP/1.1\r\nHost: www.example.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 4\r\nConnection: close\r\n\r\nq=42\r\n\r\nGET / HTTP/1.1\r\n",
    "PUT /url HTTP/1.1\r\nConnection : upgrade\r\nContent-Length: 4\r\nUpgrade: ws\r\n\r\nabcdefgh",

    // request/content-length
    "PUT /url HTTP/1.1\r\nContent-Length: 1000000000000000000000\r\n\r\n",
    "PUT /url HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n",
    "PUT /url HTTP/1.1\r\nContent-Length: 1\r\nTransfer-Encoding: identity\r\n\r\n",
    "PUT /url HTTP/1.1\r\nConnection: upgrade\r\nContent-Length : 4\r\nUpgrade: ws\r\n\r\nabcdefgh",
    "POST / HTTP/1.1\r\nContent-Length: 4 2\r\n\r\n",
    "POST / HTTP/1.1\r\nContent-Length: 13 37\r\n\r\n",
    "POST / HTTP/1.1\r\nContent-Length:\r\n\r\n",
    "PUT /url HTTP/1.1\r\nContent\rLength: 003\r\n\r\nabc",
    "PUT /url HTTP/1.1\r\nContent-Length: 3\r\n\rabc",

    // request/method
    "PRI * HTTP/1.1\r\n\r\nSM\r\n\r\n",

    // request/sample
    "GET / HTTP/1.1\rLine: 1\r\n\r\n",
    "GET / HTTP/1.1\r\nLine1:   abc\n\tdef\n ghi\n\t\tjkl\n  mno \n\t \tqrs\nLine2: \t line2\t\nLine3:\n line3\nLine4: \n \nConnection:\n close\n\n",

    // request/transfer-encoding
    "POST /chunked_w_unicorns_after_length HTTP/1.1\r\nHost: localhost\r\nTransfer-encoding: chunked\r\n\r\n2 erfrferferf\r\naa\r\n0 rrrr\r\n\r\n",
    "POST /chunked_w_unicorns_after_length HTTP/1.1\r\nHost: localhost\r\nTransfer-encoding: chunked\r\n\r\n2;\r\naa\r\n0\r\n\r\n",
    "POST /chunked_w_unicorns_after_length HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5;ilovew3=\"abc\";somuchlove=\"def; ghi\r\nhello\r\n6;blahblah;blah\r\n world\r\n0\r\n\r\n",
    "PUT /url HTTP/1.1\r\nTransfer-Encoding: pigeons\r\n\r\n",
    "POST /post_identity_body_world?q=search#hey HTTP/1.1\r\nAccept: */*\r\nTransfer-Encoding: identity\r\nContent-Length: 5\r\n\r\nWorld",
    "POST / HTTP/1.1\r\nHost: foo\r\nContent-Length: 10\r\nTransfer-Encoding:\r\nTransfer-Encoding:\r\nTransfer-Encoding:\r\n\r\n2\r\nAA\r\n0\r\n",
    "POST /post_identity_body_world?q=search#hey HTTP/1.1\r\nAccept: */*\r\nTransfer-Encoding: chunked, deflate\r\n\r\nWorld",
    "POST /post_identity_body_world?q=search#hey HTTP/1.1\r\nAccept: */*\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: deflate\r\n\r\nWorld",
    "POST /post_identity_body_world?q=search#hey HTTP/1.1\r\nAccept: */*\r\nTransfer-Encoding: chunkedchunked\r\n\r\n5\r\nWorld\r\n0\r\n\r\n",
    "PUT /url HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nfoo\r\n\r\n",
    "PUT /url HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3 \n  \r\n\\\r\nfoo\r\n\r\n",
    "PUT /url HTTP/1.1\r\nTransfer-Encoding: chunked  abc\r\n\r\n5\r\nWorld\r\n0\r\n\r\n",
    "GET / HTTP/1.1\r\nHost: a\r\nConnection: close \r\nTransfer-Encoding: chunked \r\n\r\n5\r\r;ABCD\r\n34\r\nE\r\n0\r\n\r\nGET / HTTP/1.1 \r\nHost: a\r\nContent-Length: 5\r\n\r\n0\r\n\r\n",
    "GET / HTTP/1.1\r\nHost: a\r\nConnection: close \r\nTransfer-Encoding: chunked \r\n\r\n5\r\nABCDE0\r\n\r\n",
    "PUT /url HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\na \r\n0123456789\r\n0\r\n\r\n",

    // request/invalid
    "GET /music/sweet/music ICE/1.0\r\nHost: example.com\r\n\r\n",
    "GET /music/sweet/music IHTTP/1.0\r\nHost: example.com\r\n\r\n",
    "PUT /music/sweet/music RTSP/1.0\r\nHost: example.com\r\n\r\n",
    "ANNOUNCE /music/sweet/music HTTP/1.0\r\nHost: example.com\r\n\r\n",
    "GET / HTTP/1.1\r\nFoo: 1\rBar: 2\r\n\r\n",
    "POST / HTTP/1.1\r\nHost: localhost:5000\r\nx:x\nTransfer-Encoding: chunked\r\n\r\n1\r\nA\r\n0\r\n\r\n",
    "GET / HTTP/1.1\r\nConnection: close\r\nHost: a\r\n\rZGET /evil: HTTP/1.1\r\nHost: a\r\n\r\n",
    "GET / HTTP/1.1\r\nConnection: close\r\nHost: a\r\n\r\nZGET /evil: HTTP/1.1\r\nHost: a\r\n\r\n",
    "POST / HTTP/1.1\r\nConnection: Close\r\nHost: localhost:5000\r\nx:\rTransfer-Encoding: chunked\r\n\r\n1\r\nA\r\n0\r\n\r\n",
    "POST / HTTP/1.1\r\nHost: localhost:5000\r\nx:\nTransfer-Encoding: chunked\r\n\r\n1\r\nA\r\n0\r\n\r\n",
    "GET / HTTP/1.1\r\nFo@: Failure\r\n\r\n",
    "GET / HTTP/1.1\r\nFoo\01\test: Bar\r\n\r\n",
    "GET / HTTP/1.1\r\n: Bar\r\n\r\n",
    "MKCOLA / HTTP/1.1\r\n\r\n",
    "GET / HTTP/1.1\r\nname\r\n : value\r\n\r\n",
    "GET / HTTP/1.1\r\nHost: www.example.com\r\nConnection\r\033\065\325eep-Alive\r\nAccept-Encoding: gzip\r\n\r\n",
    "GET / HTTP/1.1\r\nHost: www.example.com\r\nX-Some-Header\r\033\065\325eep-Alive\r\nAccept-Encoding: gzip\r\n\r\n",
    "GET / HTTP/1.1\r\nHost: localhost\r\nDummy: x\nContent-Length: 23\r\n\r\nGET / HTTP/1.1\r\nDummy: GET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n",
    "GET / HTTP/5.6",
    "GET / HTTP/1.1\r\n Host: foo\r\n",
    "POST / HTTP/1.1\nTransfer-Encoding: chunked\nTrailer: Baz\nFoo: abc\nBar: def\n\n1\nA\n1;abc\nB\n1;def=ghi\nC\n1;jkl=\"mno\"\nD\n0\n\nBaz: ghi\n\n",
    "POST /hello HTTP/1.1\r\nHost: localhost\r\nFoo: bar\r\n Content-Length: 38\r\n\r\nGET /bye HTTP/1.1\r\nHost: localhost\r\n\r\n",

    // request/uri
    "GET /δ¶/δt/pope?q=1#narf HTTP/1.1\r\nHost: github.com\r\n\r\n",
    "GET /foo bar/ HTTP/1.1\r\n\r\n",
};

const vector<string> request_error_messages = {
    // request/connection
    "Data after `Connection: close`",
    "Data after `Connection: close`",
    "Invalid header field char",

    // request/content-length
    "Content-Length overflow",
    "Duplicate Content-Length",
    "Transfer-Encoding can't be present with Content-Length",
    "Invalid header field char",
    "Invalid character in Content-Length",
    "Invalid character in Content-Length",
    "Empty Content-Length",
    "Invalid header token",
    "Expected LF after headers",

    // request/method
    "Pause on PRI/Upgrade",

    // request/sample
    "Expected CRLF after version",
    "Missing expected CR after header value",

    // request/transfer-encoding
    "Invalid character in chunk size",
    "Invalid character in chunk extensions",
    "Invalid character in chunk extensions quoted value",
    "Request has invalid `Transfer-Encoding`",
    "Content-Length can't be present with Transfer-Encoding",
    "Transfer-Encoding can't be present with Content-Length",
    "Invalid `Transfer-Encoding` header value",
    "Invalid `Transfer-Encoding` header value",
    "Request has invalid `Transfer-Encoding`",
    "Invalid character in chunk size",
    "Invalid character in chunk size",
    "Request has invalid `Transfer-Encoding`",
    "Expected LF after chunk size",
    "Expected LF after chunk data",
    "Invalid character in chunk size",

    // request/invalid
    "Expected SOURCE method for ICE/x.x request",
    "Expected HTTP/, RTSP/ or ICE/",
    "Invalid method for RTSP/x.x request",
    "Invalid method for HTTP/x.x request",
    "Missing expected LF after header value",
    "Missing expected CR after header value",
    "Expected LF after headers",
    "Data after `Connection: close`",
    "Expected LF after CR",
    "Invalid header value char",
    "Invalid header token",
    "Invalid header token",
    "Invalid header token",
    "Expected space after method",
    "Invalid header token",
    "Invalid header token",
    "Invalid header token",
    "Missing expected CR after header value",
    "Invalid HTTP version",
    "Unexpected space after start line",
    "Expected CRLF after version",
    "Unexpected whitespace after header value",

    // request/uri
    "Invalid char in url path",
    "Expected HTTP/, RTSP/ or ICE/",
};

const vector<string> response_error_protocols = {
    // response/connection
    "HTTP/1.1 204 No content\r\nConnection: close\r\n\r\nHTTP/1.1 200 OK",
    "HTTP/1.1 200 No content\r\nContent-Length: 5\r\nConnection: close\r\n\r\n2ad731e3-4dcd-4f70-b871-0ad284b29ffc",

    // response/invalid
    "HTP/1.1 200 OK\r\n\r\n",
    "HTTP/01.1 200 OK\r\n\r\n",
    "HTTP/11.1 200 OK\r\n\r\n",
    "HTTP/1.01 200 OK\r\n\r\n",
    "HTTP/1.1\t200 OK\r\n\r\n",
    "\rHTTP/1.1\t200 OK\r\n\r\n",
    "HTTP/1.1 200 OK\r\nFoo: 1\rBar: 2\r\n\r\n",
    "HTTP/5.6 200 OK\r\n\r\n",
    "HTTP/1.1 200 OK\r\n Host: foo\r\n",
    "HTTP/1.1  200 OK\r\n\r\n",
    "HTTP/1.1 2 OK\r\n\r\n",
    "HTTP/1.1 200 OK\nContent-Length: 0\n\n",
    "HTTP/1.1 200 OK\nFoo: abc\nBar: def\n\nBODY\n",

    // response/sample
    "HTTPER/1.1 200 OK\r\n\r\n",
    "HTTP/1.1 200 OK\nContent-Type: text/html; charset=utf-8\nConnection: close\n\nthese headers are from http://news.ycombinator.com/",
    "HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/6.0\r\nX-Powered-By: ASP.NET\r\nen-US Content-Type: text/xml\r\nContent-Type: text/xml\r\nContent-Length: 16\r\nDate: Fri, 23 Jul 2010 18:45:38 GMT\r\nConnection: keep-alive\r\n\r\n<xml>hello</xml>",

    // response/transfer-encoding
    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n25 \r\nThis is the data in the first chunk\r\n1C\r\nand this is the second one\r\n0 \r\n\r\n",
    "HTTP/1.1 200 OK\r\nHost: localhost\r\nTransfer-encoding: chunked\r\n\r\n2 erfrferferf\r\naa\r\n0 rrrr\r\n\r\n",
    "HTTP/1.1 200 OK\r\nHost: localhost\r\nTransfer-encoding: chunked\r\n\r\n2;\r\naa\r\n0\r\n\r\n",
    "HTTP/1.1 200 OK\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n5;ilovew3=\"abc\";somuchlove=\"def; ghi\r\nhello\r\n6;blahblah;blah\r\n world\r\n0\r\n",
};

const vector<string> response_error_messages = {
    // response/connection
    "Data after `Connection: close`",
    "Data after `Connection: close`",

    // response/invalid
    "Expected HTTP/, RTSP/ or ICE/",
    "Expected dot",
    "Expected dot",
    "Expected space after version",
    "Expected space after version",
    "Expected space after version",
    "Missing expected LF after header value",
    "Invalid HTTP version",
    "Unexpected space after start line",
    "Invalid status code",
    "Invalid status code",
    "Missing expected CR after response line",
    "Missing expected CR after response line",

    // response/sample
    "Expected HTTP/, RTSP/ or ICE/",
    "Missing expected CR after response line",
    "Invalid header token",

    // response/transfer-encoding
    "Invalid character in chunk size",
    "Invalid character in chunk size",
    "Invalid character in chunk extensions",
    "Invalid character in chunk extensions quoted value",
};
// clang-format on

TEST(http_parser, request_error_case) {
    ASSERT_TRUE(request_error_protocols.size() == request_error_messages.size());
    llhttp_t *parser = swoole_http_parser_create(HTTP_REQUEST);
    ON_SCOPE_EXIT {
        swoole_http_destroy_context(parser);
    };

    for (size_t i = 0; i < request_error_protocols.size(); ++i) {
        string error_protocol = request_error_protocols[i];
        swoole_llhttp_parser_execute(parser, &http_parser_settings, error_protocol.c_str(), error_protocol.length());
        ASSERT_STREQ(llhttp_get_error_reason(parser), request_error_messages[i].c_str());
        ASSERT_NE(llhttp_get_errno(parser), HPE_OK);
        llhttp_reset(parser);
    }
}

TEST(http_parser, response_error_case) {
    ASSERT_TRUE(response_error_protocols.size() == response_error_messages.size());
    llhttp_t *parser = swoole_http_parser_create(HTTP_RESPONSE);
    ON_SCOPE_EXIT {
        swoole_http_destroy_context(parser);
    };

    for (size_t i = 0; i < response_error_protocols.size(); ++i) {
        string error_protocol = response_error_protocols[i];
        swoole_llhttp_parser_execute(parser, &http_parser_settings, error_protocol.c_str(), error_protocol.length());
        ASSERT_STREQ(llhttp_get_error_reason(parser), response_error_messages[i].c_str());
        ASSERT_NE(llhttp_get_errno(parser), HPE_OK);
        llhttp_reset(parser);
    }
}

// clang-format off
const vector<string> request_success_case = {
    "PUT /url HTTP/1.1\r\nConnection: keep-alive\r\n\r\n",
    "PUT /url HTTP/1.1\r\nConnection: keep-alive\r\n\r\nPUT /url HTTP/1.1\r\nConnection: keep-alive\r\n\r\n",
    "PUT /url HTTP/1.1\r\nConnection: close\r\n\r\n",
    "PUT /url HTTP/1.1\r\nConnection: close, token, upgrade, token, keep-alive\r\n\r\n",
    "GET /demo HTTP/1.1\r\nHost: example.com\r\nConnection: keep-alive, upgrade\r\nUpgrade: WebSocket\r\n\r\nHot diggity dogg",
    "PUT /url HTTP/1.1\r\nConnection: upgrade\r\nUpgrade: ws\r\n\r\n",
    "PUT /url HTTP/1.1\r\nConnection: upgrade\r\nContent-Length: 4\r\nUpgrade: ws\r\n\r\nabcdefgh",
    "GET /demo HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nSec-WebSocket-Key2: 12998 5 Y3 1  .P00\r\nSec-WebSocket-Protocol: sample\r\nUpgrade: WebSocket\r\nSec-WebSocket-Key1: 4 @1  46546xW%0l 1 5\r\nOrigin: http://example.com\r\n\r\nHot diggity dogg",
    "POST /demo HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: HTTP/2.0\r\nContent-Length: 15\r\n\r\nsweet post body\\Hot diggity dogg",

    "PUT /url HTTP/1.1\r\nContent-Length: 003\r\n\r\nabc",
    "PUT /url HTTP/1.1\r\nContent-Length: 003\r\nOhai: world\r\n\r\nabc",
    "GET /get_funky_content_length_body_hello HTTP/1.0\r\nconTENT-Length: 5\r\n\r\nHELLO",
    "POST / HTTP/1.1\r\nContent-Length:  42 \r\n\r\n",
    "REPORT /test HTTP/1.1\r\n\r\n",
    "CONNECT 0-home0.netscape.com:443 HTTP/1.0\r\nUser-agent: Mozilla/1.1N\r\nProxy-authorization: basic aGVsbG86d29ybGQ=\r\n\r\nsome data\nand yet even more data",
    "CONNECT HOME0.NETSCAPE.COM:443 HTTP/1.0\r\nUser-agent: Mozilla/1.1N\r\nProxy-authorization: basic aGVsbG86d29ybGQ=\r\n\r\n",
    "CONNECT foo.bar.com:443 HTTP/1.0\r\nUser-agent: Mozilla/1.1N\r\nProxy-authorization: basic aGVsbG86d29ybGQ=\r\nContent-Length: 10\r\n\r\nblarfcicle\"",
    "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nST: \"ssdp:all\"\r\n\r\n",
    "PATCH /file.txt HTTP/1.1\r\nHost: www.example.com\r\nContent-Type: application/example\r\nIf-Match: \"e0023aa4e\"\r\nContent-Length: 10\r\n\r\ncccccccccc",
    "PURGE /file.txt HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
    "SEARCH / HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
    "LINK /images/my_dog.jpg HTTP/1.1\r\nHost: example.com\r\nLink: <http://example.com/profiles/joe>; rel=\"tag\"\r\nLink: <http://example.com/profiles/sally>; rel=\"tag\"\r\n\r\n",
    "UNLINK /images/my_dog.jpg HTTP/1.1\r\nHost: example.com\r\nLink: <http://example.com/profiles/sally>; rel=\"tag\"\r\n\r\n",
    "SOURCE /music/sweet/music HTTP/1.1\r\nHost: example.com\r\n\r\n",
    "SOURCE /music/sweet/music ICE/1.0\r\nHost: example.com\r\n\r\n",
    "OPTIONS /music/sweet/music RTSP/1.0\r\nHost: example.com\r\n\r\n",
    "ANNOUNCE /music/sweet/music RTSP/1.0\r\nHost: example.com\r\n\r\n",
    "QUERY /contacts HTTP/1.1\r\nHost: example.org\r\nContent-Type: example/query\r\nAccept: text/csv\r\nContent-Length: 41\r\n\r\nselect surname, givenname, email limit 10",
    "POST / HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc",
    "POST / HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc",
    "POST / HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc",
    "POST / HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc",
    "POST / HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc",
    "POST / HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc",
    "POST / HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc",
    "POST / HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc",
    "POST / HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc",
    "POST / HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc",
    "PUT / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\na\r\n0123456789\r\n0\r\n\r\n",
    "PUT / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\na;foo=bar\r\n0123456789\r\n0\r\n\r\n",
    "PUT / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\na;foo=bar\r\n0123456789\r\n0\r\n\r\n",
    "PUT / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\na\r\n0123456789\r\n0\r\n\r\n",

    "POST /aaa HTTP/1.1\r\nContent-Length: 3\r\n\r\nAAA\r\nPUT /bbb HTTP/1.1\r\nContent-Length: 4\r\n\r\nBBBB\r\nPATCH /ccc HTTP/1.1\r\nContent-Length: 5\r\n\r\nCCCC",
    "OPTIONS /url HTTP/1.1\r\nHeader1: Value1\r\nHeader2:\t Value2\r\n\r\n",
    "HEAD /url HTTP/1.1\r\n\r\n",
    "GET /test HTTP/1.1\r\nUser-Agent: curl/7.18.0 (i486-pc-linux-gnu) libcurl/7.18.0 OpenSSL/0.9.8g zlib/1.2.3.3 libidn/1.1\r\nHost: 0.0.0.0=5000\r\nAccept: */*\r\n\r\n",
    "GET /favicon.ico HTTP/1.1\r\nHost: 0.0.0.0=5000\r\nUser-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9) Gecko/2008061015 Firefox/3.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-us,en;q=0.5\r\nAccept-Encoding: gzip,deflate\r\nAccept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\nKeep-Alive: 300\r\nConnection: keep-alive\r\n\r\n",
    "GET /dumbpack HTTP/1.1\r\naaaaaaaaaaaaa:++++++++++\r\n\r\n",
    "GET /get_no_headers_no_body/world HTTP/1.1\r\n\r\n",
    "GET /get_one_header_no_body HTTP/1.1\r\nAccept: */*\r\n\r\n",
    "GET /test HTTP/1.0\r\nHost: 0.0.0.0:5000\r\nUser-Agent: ApacheBench/2.3\r\nAccept: */*\r\n\r\n",
    "\r\nGET /test HTTP/1.1\r\n\r\n",
    "GET /\r\n\r\n",
    "\r\nGET /url HTTP/1.1\r\nHeader1: Value1\r\n\r\n",
    "GET / HTTP/1.1\r\nTest: DÃ¼sseldorf\r\n\r\n",
    "OPTIONS /url HTTP/1.1\r\nHeader1: Value1\r\nHeader2: \xffValue2\r\n\r\n",
    "GET / HTTP/1.1\r\nX-SSL-Nonsense:   -----BEGIN CERTIFICATE-----\tMIIFbTCCBFWgAwIBAgICH4cwDQYJKoZIhvcNAQEFBQAwcDELMAkGA1UEBhMCVUsx\tETAPBgNVBAoTCGVTY2llbmNlMRIwEAYDVQQLEwlBdXRob3JpdHkxCzAJBgNVBAMT\tAkNBMS0wKwYJKoZIhvcNAQkBFh5jYS1vcGVyYXRvckBncmlkLXN1cHBvcnQuYWMu\tdWswHhcNMDYwNzI3MTQxMzI4WhcNMDcwNzI3MTQxMzI4WjBbMQswCQYDVQQGEwJV\tSzERMA8GA1UEChMIZVNjaWVuY2UxEzARBgNVBAsTCk1hbmNoZXN0ZXIxCzAJBgNV\tBAcTmrsogriqMWLAk1DMRcwFQYDVQQDEw5taWNoYWVsIHBhcmQYJKoZIhvcNAQEB\tBQADggEPADCCAQoCggEBANPEQBgl1IaKdSS1TbhF3hEXSl72G9J+WC/1R64fAcEF\tW51rEyFYiIeZGx/BVzwXbeBoNUK41OK65sxGuflMo5gLflbwJtHBRIEKAfVVp3YR\tgW7cMA/s/XKgL1GEC7rQw8lIZT8RApukCGqOVHSi/F1SiFlPDxuDfmdiNzL31+sL\t0iwHDdNkGjy5pyBSB8Y79dsSJtCW/iaLB0/n8Sj7HgvvZJ7x0fr+RQjYOUUfrePP\tu2MSpFyf+9BbC/aXgaZuiCvSR+8Snv3xApQY+fULK/xY8h8Ua51iXoQ5jrgu2SqR\twgA7BUi3G8LFzMBl8FRCDYGUDy7M6QaHXx1ZWIPWNKsCAwEAAaOCAiQwggIgMAwG\tA1UdEwEB/wQCMAAwEQYJYIZIAYb4QgHTTPAQDAgWgMA4GA1UdDwEB/wQEAwID6DAs\tBglghkgBhvhCAQ0EHxYdVUsgZS1TY2llbmNlIFVzZXIgQ2VydGlmaWNhdGUwHQYD\tVR0OBBYEFDTt/sf9PeMaZDHkUIldrDYMNTBZMIGaBgNVHSMEgZIwgY+AFAI4qxGj\tloCLDdMVKwiljjDastqooXSkcjBwMQswCQYDVQQGEwJVSzERMA8GA1UEChMIZVNj\taWVuY2UxEjAQBgNVBAsTCUF1dGhvcml0eTELMAkGA1UEAxMCQ0ExLTArBgkqhkiG\t9w0BCQEWHmNhLW9wZXJhdG9yQGdyaWQtc3VwcG9ydC5hYy51a4IBADApBgNVHRIE\tIjAggR5jYS1vcGVyYXRvckBncmlkLXN1cHBvcnQuYWMudWswGQYDVR0gBBIwEDAO\tBgwrBgEEAdkvAQEBAQYwPQYJYIZIAYb4QgEEBDAWLmh0dHA6Ly9jYS5ncmlkLXN1\tcHBvcnQuYWMudmT4sopwqlBWsvcHViL2NybC9jYWNybC5jcmwwPQYJYIZIAYb4QgEDBDAWLmh0\tdHA6Ly9jYS5ncmlkLXN1cHBvcnQuYWMudWsvcHViL2NybC9jYWNybC5jcmwwPwYD\tVR0fBDgwNjA0oDKgMIYuaHR0cDovL2NhLmdyaWQt5hYy51ay9wdWIv\tY3JsL2NhY3JsLmNybDANBgkqhkiG9w0BAQUFAAOCAQEAS/U4iiooBENGW/Hwmmd3\tXCy6Zrt08YjKCzGNjorT98g8uGsqYjSxv/hmi0qlnlHs+k/3Iobc3LjS5AMYr5L8\tUO7OSkgFFlLHQyC9JzPfmLCAugvzEbyv4Olnsr8hbxF1MbKZoQxUZtMVu29wjfXk\thTeApBv7eaKCWpSp7MCbvgzm74izKhu3vlDk9w6qVrxePfGgpKPqfHiOoGhFnbTK\twTC6o2xq5y0qZ03JonF7OJspEd3I5zKY3E+ov7/ZhW6DqT8UFvsAdjvQbXyhV8Eu\tYhixw1aKEPzNjNowuIseVogKOLXxWI5vAi5HgXdS0/ES5gDGsABo4fqovUKlgop3\tRA==\t-----END CERTIFICATE-----\r\n\r\n",

    "PUT /url HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
    "PUT /url HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\na\r\n0123456789\r\n0\r\n\r\n",
    "PUT /url HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nA\r\n0123456789\r\n0\r\n\r\n",
    "POST /post_chunked_all_your_base HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n1e\r\nall your base are belong to us\r\n0\r\n\r\n",
    "POST /two_chunks_mult_zero_end HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n000\r\n\r\n",
    "POST /chunked_w_trailing_headers HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\nVary: *\r\nContent-Type: text/plain\r\n\r\n",
    "POST /chunked_w_unicorns_after_length HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5;ilovew3;somuchlove=aretheseparametersfor;another=withvalue\r\nhello\r\n6;blahblah;blah\r\n world\r\n0\r\n\r\n",

    "GET /with_\"lovely\"_quotes?foo=\"bar\" HTTP/1.1\r\n\r\n",
    "GET /test.cgi?foo=bar?baz HTTP/1.1\r\n\r\n",
    "GET http://hypnotoad.org?hail=all HTTP/1.1\r\n\r\n",
    "GET http://hypnotoad.org:1234?hail=all HTTP/1.1\r\n\r\n",
    "GET /test.cgi?query=| HTTP/1.1\r\n\r\n",
    "GET http://hypnotoad.org:1234 HTTP/1.1\r\n\r\n",
    "GET /forums/1/topics/2375?page=1#posts-17408 HTTP/1.1\r\n\r\n",
    "GET http://a%12:b!&*$@hypnotoad.org:1234/toto HTTP/1.1\r\n\r\n"
};
// clang-format on

TEST(http_parser, request_success_case) {
    llhttp_t *parser = swoole_http_parser_create(HTTP_REQUEST);
    ON_SCOPE_EXIT {
        swoole_http_destroy_context(parser);
    };

    HttpContext *ctx = nullptr;
    for (size_t i = 0; i < request_success_case.size(); ++i) {
        string success_protocol = request_success_case[i];
        swoole_llhttp_parser_execute(
            parser, &http_parser_settings, success_protocol.c_str(), success_protocol.length());
        ASSERT_EQ(llhttp_get_errno(parser), HPE_OK);

        ctx = static_cast<HttpContext *>(parser->data);
        ASSERT_EQ(ctx->completed, 1);
        llhttp_reset(parser);
    }
}

// clang-format off
const vector<string> response_success_case = {
    "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Length: 11\r\nProxy-Connection: close\r\nDate: Thu, 31 Dec 2009 20:55:48 +0000\r\n\r\nhello world",
    "HTTP/1.0 200 OK\r\nConnection: keep-alive\r\n\r\nHTTP/1.0 200 OK",
    "HTTP/1.0 204 No content\r\nConnection: keep-alive\r\n\r\nHTTP/1.0 200 OK",
    "HTTP/1.1 200 OK\r\n\r\nHTTP/1.1 200 OK",
    "HTTP/1.1 204 No content\r\n\r\nHTTP/1.1 200 OK",
    "HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: h2c\r\nContent-Length: 4\r\n\r\nbody\\\r\nproto",
    "HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: h2c\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nbo\r\n2\r\ndy\r\n0\r\n\r\nproto",
    "HTTP/1.1 200 OK\r\nConnection: upgrade\r\nUpgrade: h2c\r\n\r\nbody",
    "HTTP/1.1 200 OK\r\nConnection: upgrade\r\nUpgrade: h2c\r\nContent-Length: 4\r\n\r\nbody",
    "HTTP/1.1 200 OK\r\nConnection: upgrade\r\nUpgrade: h2c\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nbo\r\n2\r\ndy\r\n0\r\n\r\n",
    "HTTP/1.1 304 Not Modified\r\nContent-Length: 10\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
    "HTTP/1.1 304 Not Modified\r\nTransfer-Encoding: chunked\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
    "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 404 Not Found\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 14\r\nDate: Fri, 15 Sep 2023 19:47:23 GMT\r\nServer: Python/3.10 aiohttp/4.0.0a2.dev0\r\n\r\n404: Not Found",
    "HTTP/1.1 103 Early Hints\r\nLink: </styles.css>; rel=preload; as=style\r\n\r\nHTTP/1.1 200 OK\r\nDate: Wed, 13 Sep 2023 11:09:41 GMT\r\nConnection: keep-alive\r\nKeep-Alive: timeout=5\r\nContent-Length: 17\r\n\r\nresponse content",

    "HTTP/1.1 200 OK\r\nDate: Tue, 04 Aug 2009 07:59:32 GMT\r\nServer: Apache\r\nX-Powered-By: Servlet/2.5 JSP/2.1\r\nContent-Type: text/xml; charset=utf-8\r\nConnection: close\r\n\r\n<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\">\n  <SOAP-ENV:Body>\n    <SOAP-ENV:Fault>\n       <faultcode>SOAP-ENV:Client</faultcode>\n       <faultstring>Client Error</faultstring>\n    </SOAP-ENV:Fault>\n  </SOAP-ENV:Body>\n</SOAP-ENV:Envelope>",
    "HTTP/1.1 200 OK\r\nContent-Length-X: 0\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nOK\r\n0\r\n\r\n",
    "HTTP/1.1 200 OK\r\nContent-Length: 123\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 456\r\n\r\n",

    "HTTP/1.1 200 OK\r\n\r\n",

    "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc",
    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\na\r\n0123456789\r\n0\r\n\r\n",
    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\na;foo=bar\r\n0123456789\r\n0\r\n\r\n",

    "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nAAA",
    "HTTP/1.1 201 Created\r\nContent-Length: 4\r\n\r\nBBBB",
    "HTTP/1.1 202 Accepted\r\nContent-Length: 5\r\n\r\nCCCC",

    "HTTP/1.1 200 OK\r\nHeader1: Value1\r\nHeader2: Value2\r\nContent-Length: 0\r\n\r\n",
    "RTSP/1.1 200 OK\r\n\r\n",
    "ICE/1.1 200 OK\r\n\r\n",
    "HTTP/1.1 200 OK\r\n\r\n",
    "HTTP/1.1 301 Moved Permanently\r\nLocation: http://www.google.com/\r\nContent-Type: text/html; charset=UTF-8\r\nDate: Sun, 26 Apr 2009 11:11:49 GMT\r\nExpires: Tue, 26 May 2009 11:11:49 GMT\r\nX-$PrototypeBI-Version: 1.6.0.3\r\nCache-Control: public, max-age=2592000\r\nServer: gws\r\nContent-Length: 219\r\n\r\n<HTML><HEAD><meta http-equiv=content-type content=text/html;charset=utf-8>\n<TITLE>301 Moved</TITLE></HEAD><BODY>\n<H1>301 Moved</H1>\nThe document has moved\n<A HREF=\"http://www.google.com/\">here</A>.\r\n</BODY></HTML>",
    "HTTP/1.1 301 MovedPermanently\r\nDate: Wed, 15 May 2013 17:06:33 GMT\r\nServer: Server\r\nx-amz-id-1: 0GPHKXSJQ826RK7GZEB2\r\np3p: policyref=\"http://www.amazon.com/w3c/p3p.xml\",CP=\"CAO DSP LAW CUR ADM IVAo IVDo CONo OTPo OUR DELi PUBi OTRi BUS PHY ONL UNI PUR FIN COM NAV INT DEM CNT STA HEA PRE LOC GOV OTC \"\r\nx-amz-id-2: STN69VZxIFSz9YJLbz1GDbxpbjG6Qjmmq5E3DxRhOUw+Et0p4hr7c/Q8qNcx4oAD\r\nLocation: http://www.amazon.com/Dan-Brown/e/B000AP9DSU/ref=s9_pop_gw_al1?_encoding=UTF8&refinementId=618073011&pf_rd_m=ATVPDKIKX0DER&pf_rd_s=center-2&pf_rd_r=0SHYY5BZXN3KR20BNFAY&pf_rd_t=101&pf_rd_p=1263340922&pf_rd_i=507846\r\nVary: Accept-Encoding,User-Agent\r\nContent-Type: text/html; charset=ISO-8859-1\r\nTransfer-Encoding: chunked\r\n\r\n1\r\n\n\r\n0\r\n\r\n",
    "HTTP/1.1 404 Not Found\r\n\r\n",
    "HTTP/1.1 301\r\n\r\n",
    "HTTP/1.1 200 \r\n\r\n",
    "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\n\r\nthese headers are from http://news.ycombinator.com/",
    "HTTP/1.1 200 OK\r\nServer: DCLK-AdSvr\r\nContent-Type: text/xml\r\nContent-Length: 0\r\nDCLK_imp: v7;x;114750856;0-0;0;17820020;0/0;21603567/21621457/1;;~okv=;dcmt=text/xml;;~cs=o\r\n\r\n",
    "HTTP/1.0 301 Moved Permanently\r\nDate: Thu, 03 Jun 2010 09:56:32 GMT\r\nServer: Apache/2.2.3 (Red Hat)\r\nCache-Control: public\r\nPragma: \r\nLocation: http://www.bonjourmadame.fr/\r\nVary: Accept-Encoding\r\nContent-Length: 0\r\nContent-Type: text/html; charset=UTF-8\r\nConnection: keep-alive\r\n\r\n",
    "HTTP/1.1 200 OK\r\nDate: Tue, 28 Sep 2010 01:14:13 GMT\r\nServer: Apache\r\nCache-Control: no-cache, must-revalidate\r\nExpires: Mon, 26 Jul 1997 05:00:00 GMT\r\n.et-Cookie: PlaxoCS=1274804622353690521; path=/; domain=.plaxo.com\r\nVary: Accept-Encoding\r\n_eep-Alive: timeout=45\r\n_onnection: Keep-Alive\r\nTransfer-Encoding: chunked\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n0\r\n\r\n",
    "HTTP/0.9 200 OK\r\n\r\n",
    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhello world",
    "HTTP/1.1 200 OK\r\nHeader1: Value1\r\nHeader2: Value2\r\nContent-Length: 0\r\n\r\n",

    "HTTP/1.1 200 OK\r\nAccept: */*\r\nTransfer-Encoding: chunked, deflate\r\n\r\nWorld",
    "HTTP/1.1 200 OK\r\nAccept: */*\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\n\r\nWorld",
    "HTTP/1.1 200 OK\r\nAccept: */*\r\nTransfer-Encoding: chunkedchunked\r\n\r\n2\r\nOK\r\n0\r\n\r\n",
    "HTTP/1.1 200 OK\r\nHost: localhost\r\nTransfer-encoding: chunked\r\n\r\n5;ilovew3;somuchlove=aretheseparametersfor\r\nhello\r\n6;blahblah;blah\r\n world\r\n0\r\n\r\n",
    "HTTP/1.1 200 OK\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n5;ilovew3=\"I love; extensions\";somuchlove=\"aretheseparametersfor\";blah;foo=bar\r\nhello\r\n6;blahblah;blah\r\n world\r\n0\r\n",
};

TEST(http_parser, response_success_case) {
    llhttp_t *parser = swoole_http_parser_create(HTTP_RESPONSE);
    ON_SCOPE_EXIT {
        swoole_http_destroy_context(parser);
    };

    HttpContext *ctx = nullptr;
    for (size_t i = 0; i < response_success_case.size(); ++i) {
        string success_protocol = response_success_case[i];
        swoole_llhttp_parser_execute(parser, &http_parser_settings, success_protocol.c_str(), success_protocol.length());
        ASSERT_EQ(llhttp_get_errno(parser), HPE_OK);

        ctx = static_cast<HttpContext *>(parser->data);
        ASSERT_EQ(ctx->completed, 1);
        llhttp_reset(parser);
    }
}
// clang-format on
