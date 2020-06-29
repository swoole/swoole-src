#include "tests.h"
#include <regex>

const char* file = "/tmp/swoole_log_test.log";

TEST(log, level)
{
    swLog_reset();
    swLog_set_level(SW_LOG_NOTICE);
    swLog_open(file);

    swLog_put(SW_LOG_INFO, SW_STRL("hello info"));
    swLog_put(SW_LOG_NOTICE, SW_STRL("hello notice"));
    swLog_put(SW_LOG_WARNING, SW_STRL("hello warning"));

    swoole::String content(swoole_file_get_contents(file));

    swLog_close();
    unlink(file);

    ASSERT_FALSE(swString_contains(content.get(), SW_STRL("hello info")));
    ASSERT_TRUE(swString_contains(content.get(), SW_STRL("hello notice")));
    ASSERT_TRUE(swString_contains(content.get(), SW_STRL("hello warning")));
}

TEST(log, date_format)
{
    swLog_reset();
    swLog_set_date_format("day %d of %B in the year %Y. Time: %I:%S %p");
    swLog_open(file);

    swLog_put(SW_LOG_WARNING, SW_STRL("hello world"));
    swoole::String content(swoole_file_get_contents(file));

    swLog_close();
    unlink(file);

    int data[16];
    char *month = nullptr;
    char *am = nullptr;

    int n = std::sscanf(content.value(), "[day %d of %s in the year %d. Time: %d:%d %s @%d.%d]\tWARNING\thello world", data,
            month, data + 1, data + 2, data + 3, am, data + 4, data + 5);

    ASSERT_TRUE(n);
}

TEST(log, date_format_long_string)
{
    swLog_reset();
    swLog_set_level(SW_LOG_ERROR);
    swoole::String content(swString_new(256));
    auto str = content.get();

    swString_repeat(str, "x", 1, 120);
    swString_append_ptr(str, SW_STRL("day %d of %B in the year %Y. Time: %I:%S %p"));

    int retval = swLog_set_date_format(str->str);

    ASSERT_EQ(retval, SW_ERR);
    ASSERT_EQ(swoole_get_last_error(), SW_ERROR_INVALID_PARAMS);
}

TEST(log, date_with_microseconds)
{
    swLog_reset();
    swLog_set_date_with_microseconds(true);
    swLog_open(file);

    swLog_put(SW_LOG_WARNING, SW_STRL("hello world"));
    swoole::String content(swoole_file_get_contents(file));

    swLog_close();
    unlink(file);

    std::regex e("\\[\\S+\\s\\d{2}:\\d{2}:\\d{2}\\<\\.(\\d+)\\>\\s@\\d+\\.\\d+\\]\tWARNING\thello world");
    ASSERT_TRUE(std::regex_search(content.value(), e));
}

TEST(log, rotation)
{
    swLog_reset();
    swLog_set_rotation(SW_LOG_ROTATION_DAILY);
    swLog_open(file);

    swLog_put(SW_LOG_WARNING, SW_STRL("hello world"));

    ASSERT_EQ(access(swLog_get_file(), R_OK), -1);
    ASSERT_EQ(errno, ENOENT);
    ASSERT_EQ(access(swLog_get_real_file(), R_OK), 0);

    swLog_close();
    unlink(swLog_get_real_file());
}

TEST(log, redirect)
{
    int retval;
    char *p = getenv("GITHUB_ACTIONS");
    if (p)
    {
        return;
    }

    swLog_reset();
    retval = swLog_open(file);
    ASSERT_EQ(retval, SW_OK);

    retval = swLog_redirect_stdout_and_stderr(1);
    ASSERT_EQ(retval, SW_OK);
    printf("hello world\n");
    swoole::String content(swoole_file_get_contents(file));
    ASSERT_NE(content.get(), nullptr);

    swLog_close();
    retval = swLog_redirect_stdout_and_stderr(0);
    ASSERT_EQ(retval, SW_OK);
    unlink(swLog_get_real_file());

    ASSERT_TRUE(swString_contains(content.get(), SW_STRL("hello world\n")));
}
