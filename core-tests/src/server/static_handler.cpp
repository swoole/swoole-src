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

#include <regex>

#define private public
#include "swoole_static_handler.h"
#undef private

using namespace swoole;
using namespace swoole::http_server;

TEST(static_handler, rewrite_first_match_does_not_chain) {
    Server serv;
    serv.add_rewrite_rule("/old/", "/new/");
    serv.add_rewrite_rule("/new/", "/final/");

    StaticHandler handler(&serv, SW_STRL("/old/file.html"));
    EXPECT_TRUE(serv.apply_rewrite_rules(&handler));
    EXPECT_EQ(handler.get_request_url(), "/new/file.html");
    EXPECT_EQ(handler.get_original_url(), "/old/file.html");

    StaticHandler miss(&serv, SW_STRL("/missing/file.html"));
    EXPECT_FALSE(serv.apply_rewrite_rules(&miss));
    EXPECT_EQ(miss.get_request_url(), "/missing/file.html");
}

TEST(static_handler, rewrite_regex_replaces_all_captures) {
    Server serv;
    serv.add_rewrite_rule("~([0-9]+)~", "[$1]");

    StaticHandler handler(&serv, SW_STRL("/12/34.html"));
    EXPECT_TRUE(serv.apply_rewrite_rules(&handler));
    EXPECT_EQ(handler.get_request_url(), "/[12]/[34].html");
}

TEST(static_handler, rewrite_unchanged_regex_uses_next_rule) {
    Server serv;
    serv.add_rewrite_rule("~^/same$~", "/same");
    serv.add_rewrite_rule("/same", "/fallback");

    StaticHandler handler(&serv, SW_STRL("/same"));
    EXPECT_TRUE(serv.apply_rewrite_rules(&handler));
    EXPECT_EQ(handler.get_request_url(), "/fallback");
}

TEST(static_handler, rewrite_invalid_regex_is_ignored) {
    Server serv;
    EXPECT_NO_THROW(serv.add_rewrite_rule("~[~", "/invalid"));
    StaticHandler miss(&serv, SW_STRL("/source"));
    EXPECT_FALSE(serv.apply_rewrite_rules(&miss));
    EXPECT_EQ(miss.get_request_url(), "/source");

    serv.add_rewrite_rule("~^/source$~", "/target");
    StaticHandler handler(&serv, SW_STRL("/source"));
    EXPECT_TRUE(serv.apply_rewrite_rules(&handler));
    EXPECT_EQ(handler.get_request_url(), "/target");
}

TEST(static_handler, rewrite_empty_regex_and_literal_pattern) {
    Server serv;
    serv.add_rewrite_rule("/literal.*", "/target");
    serv.add_rewrite_rule("~~", "x");

    StaticHandler literal(&serv, SW_STRL("/literal.*file"));
    EXPECT_TRUE(serv.apply_rewrite_rules(&literal));
    EXPECT_EQ(literal.get_request_url(), "/targetfile");

    StaticHandler empty(&serv, SW_STRL("/a"));
    EXPECT_TRUE(serv.apply_rewrite_rules(&empty));
    EXPECT_EQ(empty.get_request_url(), "x/xax");
}

TEST(static_handler, rewrite_compiled_regex_is_shared_between_threads) {
    Server serv;
    serv.add_rewrite_rule("~^/item/([0-9]+)$~", "/static/$1.html");
    std::vector<std::thread> threads;
    for (int i = 0; i < 4; i++) {
        threads.emplace_back([&serv]() {
            for (int j = 0; j < 64; j++) {
                StaticHandler handler(&serv, SW_STRL("/item/42"));
                EXPECT_TRUE(serv.apply_rewrite_rules(&handler));
                EXPECT_EQ(handler.get_request_url(), "/static/42.html");
            }
        });
    }
    for (auto &thread : threads) {
        thread.join();
    }
}

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
