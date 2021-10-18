#include "test_core.h"
#include "swoole_file.h"
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

    auto content = file_get_contents(file);

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
    auto content = file_get_contents(file);

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
    std::unique_ptr<String> content(new String(256));
    auto str = content.get();

    str->repeat("x", 1, 120);
    str->append(SW_STRL("day %d of %B in the year %Y. Time: %I:%S %p"));

    bool retval = sw_logger()->set_date_format(str->str);

    ASSERT_FALSE(retval);
    ASSERT_EQ(swoole_get_last_error(), SW_ERROR_INVALID_PARAMS);
}

TEST(log, date_with_microseconds) {
    sw_logger()->reset();
    sw_logger()->set_date_with_microseconds(true);
    sw_logger()->open(file);

    sw_logger()->put(SW_LOG_WARNING, SW_STRL("hello world"));
    auto content = file_get_contents(file);

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
    char *p = getenv("GITHUB_ACTIONS");
    if (p) {
        return;
    }

    sw_logger()->reset();
    ASSERT_TRUE(sw_logger()->open(file));
    ASSERT_TRUE(sw_logger()->redirect_stdout_and_stderr(1));

    printf("hello world\n");
    auto content = file_get_contents(file);
    ASSERT_NE(content.get(), nullptr);

    sw_logger()->close();
    ASSERT_TRUE(sw_logger()->redirect_stdout_and_stderr(0));
    unlink(sw_logger()->get_real_file());

    ASSERT_TRUE(content->contains(SW_STRL("hello world\n")));
}

namespace TestA {
class TestPrettyName {
  public:
    static void fun(bool strip, const char *expect_str);
};

void TestPrettyName::fun(bool strip, const char *expect_str) {
    ASSERT_STREQ(Logger::get_pretty_name(__PRETTY_FUNCTION__, strip).c_str(), expect_str);
}

static void test_pretty_name(bool strip, const char *expect_str) {
    ASSERT_STREQ(Logger::get_pretty_name(__PRETTY_FUNCTION__, strip).c_str(), expect_str);
}

static void test_pretty_name_lambda(bool strip, const char *expect_str) {
    auto fn = [](bool strip, const char *expect_str) {
        ASSERT_STREQ(Logger::get_pretty_name(__PRETTY_FUNCTION__, strip).c_str(), expect_str);
    };
    fn(strip, expect_str);
}

}  // namespace TestA

static void test_pretty_name(bool strip, const char *expect_str) {
    ASSERT_STREQ(Logger::get_pretty_name(__PRETTY_FUNCTION__, strip).c_str(), expect_str);
}

static void test_pretty_name_lambda(bool strip, const char *expect_str) {
    auto fn = [](bool strip, const char *expect_str) {
        ASSERT_STREQ(Logger::get_pretty_name(__PRETTY_FUNCTION__, strip).c_str(), expect_str);
    };
    fn(strip, expect_str);
}

TEST(log, pretty_name) {
    TestA::TestPrettyName::fun(false, "TestA::TestPrettyName::fun");
    TestA::test_pretty_name(false, "TestA::test_pretty_name");
    test_pretty_name(false, "test_pretty_name");

    TestA::TestPrettyName::fun(true, "TestPrettyName::fun");
    TestA::test_pretty_name(true, "test_pretty_name");
    test_pretty_name(true, "test_pretty_name");
}

TEST(log, pretty_name_lambda) {
    TestA::test_pretty_name_lambda(true, "test_pretty_name_lambda");
    test_pretty_name_lambda(true, "test_pretty_name_lambda");

    TestA::test_pretty_name_lambda(false, "TestA::test_pretty_name_lambda");
    test_pretty_name_lambda(false, "test_pretty_name_lambda");
}

TEST(log, ignore_error) {
    sw_logger()->reset();
    sw_logger()->set_level(SW_LOG_NOTICE);
    sw_logger()->open(file);

    const int ignored_errcode = 999999;
    const int errcode = 888888;

    swoole_ignore_error(ignored_errcode);

    swoole_error_log(SW_LOG_WARNING, ignored_errcode, "error 1");
    swoole_error_log(SW_LOG_WARNING, errcode, "error 2");

    auto content = file_get_contents(file);

    sw_logger()->close();
    unlink(file);

    ASSERT_FALSE(content->contains(SW_STRL("error 1")));
    ASSERT_TRUE(content->contains(SW_STRL("error 2")));
}
