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
#include "multipart_parser.h"

struct MppResult {
    std::string data;
    std::string header_field;
    std::string header_value;
    bool header_complete;
    bool body_end;
};

static int multipart_on_header_field(multipart_parser *p, const char *at, size_t length) {
    swoole_trace("on_header_field: at=%.*s, length=%lu", (int) length, at, length);
    auto res = (MppResult *) p->data;
    res->header_field = std::string(at, length);
    return 0;
}

static int multipart_on_header_value(multipart_parser *p, const char *at, size_t length) {
    swoole_trace("on_header_value: at=%.*s, length=%lu", (int) length, at, length);
    auto res = (MppResult *) p->data;
    res->header_value = std::string(at, length);
    return 0;
}

static int multipart_on_data(multipart_parser *p, const char *at, size_t length) {
    swoole_trace("on_data: length=%lu", length);
    auto res = (MppResult *) p->data;
    res->data.append(at, length);
    return 0;
}

static int multipart_on_header_complete(multipart_parser *p) {
    swoole_trace("on_header_complete");
    auto res = (MppResult *) p->data;
    res->header_complete = true;
    return 0;
}

static int multipart_on_data_end(multipart_parser *p) {
    swoole_trace("on_data_end");
    return 0;
}

static int multipart_on_part_begin(multipart_parser *p) {
    swoole_trace("on_part_begin");
    return 0;
}

static int multipart_on_body_end(multipart_parser *p) {
    swoole_trace("on_body_end");
    auto res = (MppResult *) p->data;
    res->body_end = true;
    return 0;
}

static multipart_parser_settings _settings{
    multipart_on_header_field,
    multipart_on_header_value,
    multipart_on_data,
    multipart_on_part_begin,
    multipart_on_header_complete,
    multipart_on_data_end,
    multipart_on_body_end,
};

static const std::string boundary = "--WebKitFormBoundaryeGOz80A8JnaO6kuw";

static multipart_parser *create_parser() {
    return multipart_parser_init(boundary.c_str(), boundary.length(), &_settings);
}

static void create_error(multipart_parser *parser, multipart_error error_reason, const char *error) {
    size_t length = 1024;
    char buf[length];

    parser->error_reason = error_reason;
    int result_len = multipart_parser_error_msg(parser, buf, length);
    ASSERT_GT(result_len, 0);
    buf[result_len] = '\0';

    std::string response(buf, result_len);
    ASSERT_TRUE(response.find(error) != response.npos);
}

TEST(multipart_parser, error_message) {
    size_t length = 1024;
    char buf[length];
    auto parser = create_parser();

    parser->error_reason = MPPE_OK;
    ASSERT_EQ(multipart_parser_error_msg(parser, buf, length), 0);

    parser->error_expected = '\0';
    create_error(parser, MPPE_PAUSED, "parser paused");
    create_error(parser, MPPE_BOUNDARY_END_NO_CRLF, "no CRLF at first boundary end: ");
    create_error(parser, MPPE_BAD_START_BOUNDARY, "first boundary mismatching: ");
    create_error(parser, MPPE_INVALID_HEADER_FIELD_CHAR, "invalid char in header field: ");
    create_error(parser, MPPE_INVALID_HEADER_VALUE_CHAR, "invalid char in header value: ");
    create_error(parser, MPPE_BAD_PART_END, "no next part or final hyphen: expecting CR or '-' ");
    create_error(parser, MPPE_END_BOUNDARY_NO_DASH, "bad final hyphen: ");

    parser->error_expected = '\r';
    create_error(parser, MPPE_PAUSED, "parser paused");
    create_error(parser, MPPE_BOUNDARY_END_NO_CRLF, "no CRLF at first boundary end: ");
    create_error(parser, MPPE_BAD_START_BOUNDARY, "first boundary mismatching: ");
    create_error(parser, MPPE_INVALID_HEADER_FIELD_CHAR, "invalid char in header field: ");
    create_error(parser, MPPE_INVALID_HEADER_VALUE_CHAR, "invalid char in header value: ");
    create_error(parser, MPPE_BAD_PART_END, "no next part or final hyphen: expecting CR or '-' ");
    create_error(parser, MPPE_END_BOUNDARY_NO_DASH, "bad final hyphen: ");

    parser->error_expected = '\n';
    create_error(parser, MPPE_PAUSED, "parser paused");
    create_error(parser, MPPE_BOUNDARY_END_NO_CRLF, "no CRLF at first boundary end: ");
    create_error(parser, MPPE_BAD_START_BOUNDARY, "first boundary mismatching: ");
    create_error(parser, MPPE_INVALID_HEADER_FIELD_CHAR, "invalid char in header field: ");
    create_error(parser, MPPE_INVALID_HEADER_VALUE_CHAR, "invalid char in header value: ");
    create_error(parser, MPPE_BAD_PART_END, "no next part or final hyphen: expecting CR or '-' ");
    create_error(parser, MPPE_END_BOUNDARY_NO_DASH, "bad final hyphen: ");

    parser->error_expected = 'a';
    create_error(parser, MPPE_PAUSED, "parser paused");
    create_error(parser, MPPE_BOUNDARY_END_NO_CRLF, "no CRLF at first boundary end: ");
    create_error(parser, MPPE_BAD_START_BOUNDARY, "first boundary mismatching: ");
    create_error(parser, MPPE_INVALID_HEADER_FIELD_CHAR, "invalid char in header field: ");
    create_error(parser, MPPE_INVALID_HEADER_VALUE_CHAR, "invalid char in header value: ");
    create_error(parser, MPPE_BAD_PART_END, "no next part or final hyphen: expecting CR or '-' ");
    create_error(parser, MPPE_END_BOUNDARY_NO_DASH, "bad final hyphen: ");
}

TEST(multipart_parser, header_field) {
    auto parser = create_parser();
    ssize_t ret;

    // header party
    swoole::String header(1024);
    header.append("--");
    header.append(boundary);
    header.append("\r\n");
    header.append("Content-Disposition: form-data; name=\"test\"\r\n\r\n");
    MppResult result;
    parser->data = &result;

    ret = multipart_parser_execute(parser, header.value(), header.get_length());
    ASSERT_EQ(ret, header.length);

    ASSERT_STREQ(result.header_field.c_str(), "Content-Disposition");
    ASSERT_TRUE(result.header_value.find("test") != result.header_value.npos);

    std::string boundary_str(parser->boundary, parser->boundary_length);
    ASSERT_EQ(multipart_parser_execute(parser, SW_STRL("\r\n")), 2);
    ASSERT_EQ(multipart_parser_execute(parser, boundary_str.c_str(), boundary_str.length()), boundary_str.length());
    ASSERT_EQ(multipart_parser_execute(parser, "--\r\n\r\n", 6), 6);
}

TEST(multipart_parser, header_error) {
    auto parser = create_parser();
    ssize_t ret;

    // header party
    swoole::String header(1024);
    header.append("--");
    header.append(boundary);
    header.append("\r\n");
    header.append("Content-Disposition: form-data; name=\"test\"");
    MppResult result;
    parser->data = &result;

    ret = multipart_parser_execute(parser, header.value(), header.get_length());
    ASSERT_EQ(ret, -1);
    ASSERT_EQ(parser->error_reason, MPPE_HEADER_VALUE_INCOMPLETE);
    ASSERT_EQ(parser->error_expected, '\r');
}

TEST(multipart_parser, data) {
    auto parser = create_parser();
    ssize_t ret;

    // header party
    swoole::String header(1024);
    header.append("--");
    header.append(boundary);
    header.append("\r\n");
    header.append("Content-Disposition: form-data; name=\"test\"\r\n\r\n");
    MppResult result;
    parser->data = &result;
    ret = multipart_parser_execute(parser, header.value(), header.get_length());
    ASSERT_EQ(ret, header.length);

    std::string boundary_str(parser->boundary, parser->boundary_length);

    // data part
    swoole::String data(128);
    data.append_random_bytes(swoole_rand(60, 120), true);
    data.append("\r");
    data.append_random_bytes(swoole_rand(60, 120), true);
    data.append("\r\n");
    data.append_random_bytes(swoole_rand(60, 120), true);
    data.append("\r\n");
    data.append(boundary_str.substr(0, swoole_rand(1, parser->boundary_length - 2)));
    data.append_random_bytes(swoole_rand(60, 120), true);
    ASSERT_EQ(multipart_parser_execute(parser, data.value(), data.get_length()), data.get_length());

    auto append_data = [&]() {
        size_t offset = data.length;
        data.append_random_bytes(swoole_rand(60, 120), true);
        size_t len = data.length - offset;
        ASSERT_EQ(multipart_parser_execute(parser, data.value() + offset, len), len);
    };

    append_data();
    data.append("\r");
    ASSERT_EQ(multipart_parser_execute(parser, SW_STRL("\r")), 1);

    append_data();

    data.append("\r\n");
    ASSERT_EQ(multipart_parser_execute(parser, SW_STRL("\r\n")), 2);

    append_data();

    {
        size_t offset = data.length;
        data.append(boundary_str.substr(0, swoole_rand(1, parser->boundary_length - 2)));
        size_t len = data.length - offset;
        ASSERT_EQ(multipart_parser_execute(parser, data.value() + offset, len), len);
    }

    ASSERT_EQ(multipart_parser_execute(parser, SW_STRL("\r\n")), 2);
    ASSERT_EQ(multipart_parser_execute(parser, boundary_str.c_str(), boundary_str.length()), boundary_str.length());
    ASSERT_EQ(multipart_parser_execute(parser, "--\r\n\r\n", 6), 6);

    ASSERT_MEMEQ(data.value(), result.data.c_str(), result.data.length());

    ASSERT_TRUE(result.header_complete);
    ASSERT_TRUE(result.body_end);
}
