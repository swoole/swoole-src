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
#if 0
#include "swoole.h"
#include "tests.h"
#include "Http.h"

static int http_get_path(http_parser *, const char *at, size_t length);

static int http_get_path(http_parser *parser, const char *at, size_t length)
{
    printf("at=%.*s, len=%ld\n", (int) length, at, length);
    return 0;
}

swUnitTest(http_test1)
{
    char *dir = swoole_dirname(__FILE__);
    char file[256];
    sprintf(file, "%s/http/get.txt", dir);

    swString *content = swoole_file_get_contents(file);
    if (!content)
    {
        return -1;
    }

    http_parser parser;
    http_parser_settings setting;
    bzero(&setting, sizeof(setting));
    setting.on_path = http_get_path;

    http_parser_init(&parser, HTTP_REQUEST);

    size_t parse_n = http_parser_execute(&parser, &setting, content->str, content->size);

    printf("parse_n=%ld, finish=%d, content_length=%ld\n", parse_n, parser.nread, parser.content_length);

    free(dir);
    swString_free(content);
    return 0;
}

swUnitTest(http_test2)
{
    char *dir = swoole_dirname(__FILE__);
    char file[256];
    sprintf(file, "%s/http/post.txt", dir);

    swString *content = swoole_file_get_contents(file);
    if (!content)
    {
        return -1;
    }

    http_parser parser;
    http_parser_settings setting;
    bzero(&setting, sizeof(setting));
    setting.on_path = http_get_path;

    http_parser_init(&parser, HTTP_REQUEST);

    size_t parse_n = http_parser_execute(&parser, &setting, content->str, content->size);

    printf("parse_n=%ld, finish=%d, content_length=%ld\n", parse_n, parser.nread, parser.content_length);

    free(dir);
    swString_free(content);
    return 0;
}
#endif