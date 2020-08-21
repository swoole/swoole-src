#include "test_core.h"
#include "swoole_log.h"
#include <regex>

using namespace swoole;

const char *file = "/tmp/swoole_log_test.log";

TEST(log, level) {
    sw_logger()->reset();
    sw_logger()->set_level(SW_LOG_NOTICE);
    sw_logger()->open(file);

    sw_logger()->put(SW_LOG_INFO, SW_STRL("hello info"));
    sw_logger()->put(SW_LOG_NOTICE, SW_STRL("hello notice"));
    sw_logger()->put(SW_LOG_WARNING, SW_STRL("hello warning"));

    auto content = swoole_file_get_contents(file);

    sw_logger()->close();
    unlink(file);

    ASSERT_FALSE(content->contains(SW_STRL("hello info")));
    ASSERT_TRUE(content->contains(SW_STRL("hello notice")));
    ASSERT_TRUE(content->contains(SW_STRL("hello warning")));
}

TEST(log, date_format) {
    sw_logger()->reset();
    sw_logger()->set_date_format("day %d of %B in the year %Y. Time: %I:%S %p");
    sw_logger()->open(file);

    sw_logger()->put(SW_LOG_WARNING, SW_STRL("hello world"));
    auto content = swoole_file_get_contents(file);

    sw_logger()->close();
    unlink(file);

    int data[16];
    char *month = nullptr;
    char *am = nullptr;

    int n = std::sscanf(content->value(),
                        "[day %d of %s in the year %d. Time: %d:%d %s @%d.%d]\tWARNING\thello world",
                        data,
                        month,
                        data + 1,
                        data + 2,
                        data + 3,
                        am,
                        data + 4,
                        data + 5);

    ASSERT_TRUE(n);
}

TEST(log, date_format_long_string) {
    sw_logger()->reset();
    sw_logger()->set_level(SW_LOG_ERROR);
    std::unique_ptr<swString> content(swString_new(256));
    auto str = content.get();

    str->repeat("x", 1, 120);
    swString_append_ptr(str, SW_STRL("day %d of %B in the year %Y. Time: %I:%S %p"));

    bool retval = sw_logger()->set_date_format(str->str);

    ASSERT_FALSE(retval);
    ASSERT_EQ(swoole_get_last_error(), SW_ERROR_INVALID_PARAMS);
}

TEST(log, date_with_microseconds) {
    sw_logger()->reset();
    sw_logger()->set_date_with_microseconds(true);
    sw_logger()->open(file);

    sw_logger()->put(SW_LOG_WARNING, SW_STRL("hello world"));
    auto content = swoole_file_get_contents(file);

    sw_logger()->close();
    unlink(file);

    std::regex e("\\[\\S+\\s\\d{2}:\\d{2}:\\d{2}\\<\\.(\\d+)\\>\\s@\\d+\\.\\d+\\]\tWARNING\thello world");
    ASSERT_TRUE(std::regex_search(content->value(), e));
}

TEST(log, rotation) {
    sw_logger()->reset();
    sw_logger()->set_rotation(SW_LOG_ROTATION_DAILY);
    sw_logger()->open(file);

    sw_logger()->put(SW_LOG_WARNING, SW_STRL("hello world"));

    ASSERT_EQ(access(sw_logger()->get_file(), R_OK), -1);
    ASSERT_EQ(errno, ENOENT);
    ASSERT_EQ(access(sw_logger()->get_real_file(), R_OK), 0);

    sw_logger()->close();
    unlink(sw_logger()->get_real_file());
}

TEST(log, redirect) {
    int retval;
    char *p = getenv("GITHUB_ACTIONS");
    if (p) {
        return;
    }

    sw_logger()->reset();
    retval = sw_logger()->open(file);
    ASSERT_EQ(retval, SW_OK);

    retval = sw_logger()->redirect_stdout_and_stderr(1);
    ASSERT_EQ(retval, SW_OK);
    printf("hello world\n");
    auto content = swoole_file_get_contents(file);
    ASSERT_NE(content.get(), nullptr);

    sw_logger()->close();
    retval = sw_logger()->redirect_stdout_and_stderr(0);
    ASSERT_EQ(retval, SW_OK);
    unlink(sw_logger()->get_real_file());

    ASSERT_TRUE(content->contains(SW_STRL("hello world\n")));
}
