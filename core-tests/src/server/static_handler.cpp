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

TEST(static_handler, range_errors_discard_complete_and_partial_plans) {
    Server serv;
    StaticHandler handler(&serv, SW_STRL("/asset.txt"));
    handler.file_stat.st_size = 10;
    for (const char *range : {"bytes=word",
                              "bytes=0-1,word",
                              "bytes=0-1,4-5,word",
                              "bytes=0-1,",
                              "bytes=0-1,999999999999999999999999999999999999-",
                              "bytes=10-20",
                              "bytes=8-2"}) {
        SCOPED_TRACE(range);
        handler.parse_range("bytes=0-1,4-5", nullptr);
        ASSERT_EQ(handler.status_code, SW_HTTP_PARTIAL_CONTENT);
        handler.parse_range(range, nullptr);
        EXPECT_EQ(handler.status_code, SW_HTTP_RANGE_NOT_SATISFIABLE);
        EXPECT_TRUE(handler.get_tasks().empty());
        EXPECT_EQ(handler.get_content_length(), 0);
        EXPECT_TRUE(handler.get_end_part().empty());
    }
}

TEST(static_handler, range_boundaries_and_cost_limits) {
    Server serv;
    StaticHandler handler(&serv, SW_STRL("/asset.txt"));
    handler.file_stat.st_size = 100;
    handler.parse_range("bytes=0-0,-1", nullptr);
    ASSERT_EQ(handler.status_code, SW_HTTP_PARTIAL_CONTENT);
    ASSERT_EQ(handler.get_tasks().size(), 2);
    EXPECT_EQ(handler.get_tasks()[0].offset, 0);
    EXPECT_EQ(handler.get_tasks()[1].offset, 99);
    size_t length = handler.get_end_part().length();
    for (const auto &part : handler.get_tasks()) {
        length += strlen(part.part_header) + part.length;
    }
    EXPECT_EQ(handler.get_content_length(), length);
    handler.parse_range("bytes=0-99,0-99", nullptr);
    EXPECT_EQ(handler.status_code, SW_HTTP_OK);
    EXPECT_EQ(handler.get_content_length(), 100);
    std::string ranges = "bytes=0-0";
    for (int i = 0; i < 16; ++i) {
        ranges += ",0-0";
    }
    handler.parse_range(ranges.c_str(), nullptr);
    EXPECT_EQ(handler.status_code, SW_HTTP_OK);
    handler.parse_range("bytes=-0", nullptr);
    EXPECT_EQ(handler.status_code, SW_HTTP_RANGE_NOT_SATISFIABLE);
    handler.file_stat.st_size = 0;
    handler.parse_range("bytes=0-0", nullptr);
    EXPECT_EQ(handler.status_code, SW_HTTP_OK);
    EXPECT_EQ(handler.get_content_length(), 0);
}

TEST(static_handler, http_dates_are_utc_and_strict) {
    const auto date = StaticHandler::get_date();
    ASSERT_EQ(date.length(), 29u);
    EXPECT_EQ(date.substr(25), " GMT");

    Server serv;
    StaticHandler handler(&serv, SW_STRL("/asset.txt"));
    handler.file_stat.st_mtime = 1730000000;
    // timezone_ deliberately differs from the HTTP date's UTC timezone.
    for (long timezone : {0L, 28800L, -18000L}) {
        serv.timezone_ = timezone;
        EXPECT_EQ(handler.get_date_last_modified(), "Sun, 27 Oct 2024 03:33:20 GMT");
        EXPECT_TRUE(handler.is_modified("Sun, 27 Oct 2024 03:33:20 GMT"));
        EXPECT_FALSE(handler.is_modified("Sun, 27 Oct 2024 02:33:20 GMT"));
        EXPECT_FALSE(handler.is_modified("Sun, 31 Feb 2024 03:33:20 GMT"));
        EXPECT_FALSE(handler.is_modified("Sun, 27 Oct 2024 03:33:20 GMT trailing"));
        EXPECT_FALSE(handler.is_modified_range("Sun, 27 Oct 2024 03:33:20 GMT"));
        EXPECT_TRUE(handler.is_modified_range("invalid"));
    }
}

TEST(static_handler, preconditions_and_if_range_share_validators) {
    Server serv;
    StaticHandler handler(&serv, SW_STRL("/asset.txt"));
    handler.file_stat.st_mtime = 1730000000;
    handler.file_stat.st_size = 10;
    const auto tag = handler.get_etag();
    EXPECT_EQ(handler.evaluate_preconditions("*", "", "", ""), SW_HTTP_OK);
    EXPECT_EQ(handler.evaluate_preconditions(tag, "invalid", "", ""), SW_HTTP_OK);
    EXPECT_EQ(handler.evaluate_preconditions("W/" + tag, "", "", ""), SW_HTTP_PRECONDITION_FAILED);
    EXPECT_EQ(handler.evaluate_preconditions("\"other\"", "", "*", ""), SW_HTTP_PRECONDITION_FAILED);
    EXPECT_EQ(handler.evaluate_preconditions("", "", "W/" + tag, ""), SW_HTTP_NOT_MODIFIED);
    EXPECT_EQ(handler.evaluate_preconditions("", "", "\"other\", " + tag, ""), SW_HTTP_NOT_MODIFIED);
    EXPECT_EQ(handler.evaluate_preconditions("", "", "\"other\"", "Sun, 27 Oct 2024 03:33:20 GMT"), SW_HTTP_OK);
    EXPECT_EQ(handler.evaluate_preconditions("", "Sun, 27 Oct 2024 02:33:20 GMT", "", ""), SW_HTTP_PRECONDITION_FAILED);
    EXPECT_FALSE(handler.is_modified_range(tag));
    EXPECT_TRUE(handler.is_modified_range("W/" + tag));
    EXPECT_TRUE(handler.is_modified_range("\"other\""));
    EXPECT_EQ(handler.evaluate_preconditions("", "", "   ", ""), SW_HTTP_OK);
}

TEST(static_handler, queued_ranges_keep_the_opened_file_after_rename) {
    char path[] = "/tmp/swoole-static-snapshot-XXXXXX";
    const int fd = mkstemp(path);
    ASSERT_GE(fd, 0);
    ASSERT_EQ(write(fd, "original", 8), 8);
    close(fd);
    Server serv;
    StaticHandler handler(&serv, SW_STRL("/asset.txt"));
    strcpy(handler.filename, path);
    handler.l_filename = strlen(path);
    ASSERT_TRUE(handler.open_file());
    const std::string moved = std::string(path) + ".old";
    ASSERT_EQ(rename(path, moved.c_str()), 0);
    ASSERT_TRUE(file_put_contents(path, "replacement", 11));
    auto *socket = make_socket(SW_SOCK_TCP, SW_FD_STREAM, 0);
    ASSERT_NE(socket, nullptr);
    ASSERT_EQ(socket->sendfile_async(handler.get_file(), 0, 2), SW_OK);
    ASSERT_EQ(socket->sendfile_async(handler.get_file(), 2, 6), SW_OK);
    auto *first = static_cast<network::SendfileRequest *>(socket->out_buffer->front()->value.ptr);
    EXPECT_EQ(first->get_file().get_fd(), handler.get_file()->get_fd());
    handler.file.reset();
    char bytes[8];
    ASSERT_EQ(first->get_file().pread(bytes, sizeof(bytes), 0), 8);
    EXPECT_EQ(std::string(bytes, sizeof(bytes)), "original");
    socket->free();
    unlink(path);
    unlink(moved.c_str());
}
