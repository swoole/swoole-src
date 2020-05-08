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
