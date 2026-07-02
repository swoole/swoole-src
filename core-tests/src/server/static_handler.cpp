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
*/

#include "test_core.h"

#include "swoole_server.h"

#define private public
#include "swoole_static_handler.h"
#undef private

using namespace swoole;
using namespace swoole::http_server;

TEST(static_handler, set_filename_rejects_path_too_long) {
    Server serv;
    StaticHandler handler(&serv, SW_STRL("/"));

    memset(handler.filename, 'a', sizeof(handler.filename));
    handler.l_filename = PATH_MAX - strlen("/index.html");
    handler.filename[handler.l_filename] = '\0';

    ASSERT_FALSE(handler.set_filename("index.html"));
}

TEST(static_handler, set_filename_accepts_path_with_room_for_null) {
    char dir_template[] = "/tmp/swoole-static-handler-XXXXXX";
    char *dir = mkdtemp(dir_template);
    ASSERT_NE(dir, nullptr);

    std::string index_file = std::string(dir) + "/index.html";
    FILE *fp = fopen(index_file.c_str(), "w");
    ASSERT_NE(fp, nullptr);
    ASSERT_GT(fputs("ok", fp), 0);
    ASSERT_EQ(fclose(fp), 0);

    Server serv;
    StaticHandler handler(&serv, SW_STRL("/"));

    memcpy(handler.filename, dir, strlen(dir) + 1);
    handler.l_filename = strlen(dir);

    ASSERT_TRUE(handler.set_filename("index.html"));
    ASSERT_STREQ(handler.filename, index_file.c_str());

    unlink(index_file.c_str());
    rmdir(dir);
}
