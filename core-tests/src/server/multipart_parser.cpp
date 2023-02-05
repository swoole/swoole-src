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
  | Author: NathanFreeman  <mariasocute@163.com>                         |
  +----------------------------------------------------------------------+
 */
#include "test_core.h"
#include "multipart_parser.h"

using namespace std;

static multipart_parser *create_parser() {
    multipart_parser *parser = new multipart_parser();
    return parser;
}

static void create_error(multipart_parser *parser, multipart_error error_reason, const char *error) {
    size_t length = 1024;
    char buf[length];

    parser->error_reason = error_reason;
    int result_len = multipart_parser_error_msg(parser, buf, length);
    ASSERT_GT(result_len, 0);
    buf[result_len] = '\0';

    string response = string(buf, result_len);
    ASSERT_TRUE(response.find(error) != string::npos);
}

TEST(multipart_parser, error_message) {
    size_t length = 1024;
    char buf[length];
    multipart_parser *parser = create_parser();

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

    delete parser;
}
