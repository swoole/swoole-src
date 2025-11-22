#include "test_core.h"
#include "swoole_util.h"

using namespace std;
using swoole::String;

TEST(string, ltrim) {
    char buf[1024];
    char *ptr_buf;
    strcpy(buf, "  hello world");
    ptr_buf = buf;
    swoole::ltrim(&ptr_buf, strlen(buf));
    ASSERT_EQ(strcmp("hello world", ptr_buf), 0);
    ASSERT_NE(strcmp("  hello world", ptr_buf), 0);

    strcpy(buf, "  ");
    ptr_buf = buf;
    swoole::ltrim(&ptr_buf, strlen(buf));
    ASSERT_EQ(strlen(ptr_buf), 0);

    memcpy(buf, "  a\0b\0", 6);
    ptr_buf = buf;
    swoole::ltrim(&ptr_buf, strlen(buf));
    ASSERT_EQ(strcmp("a", ptr_buf), 0);

    buf[0] = '\0';
    ptr_buf = buf;
    swoole::ltrim(&ptr_buf, strlen(buf));
    ASSERT_EQ(strcmp("", ptr_buf), 0);
}

TEST(string, rtrim) {
    char buf[1024];
    strcpy(buf, "hello world  ");
    swoole::rtrim(buf, strlen(buf));
    ASSERT_EQ(strcmp("hello world", buf), 0);
    ASSERT_NE(strcmp("hello world  ", buf), 0);

    strcpy(buf, "  ");
    swoole::rtrim(buf, strlen(buf));
    ASSERT_EQ(strlen(buf), 0);

    buf[0] = '\0';
    swoole::rtrim(buf, strlen(buf));
    ASSERT_EQ(strcmp("", buf), 0);
}

TEST(string, move_and_copy) {
    String s1(TEST_STR);
    ASSERT_MEMEQ(s1.str, TEST_STR, s1.length);

    String s2(s1);
    ASSERT_MEMEQ(s2.str, TEST_STR, s2.length);
    ASSERT_NE(s1.str, nullptr);

    String s3(std::move(s1));
    ASSERT_MEMEQ(s3.str, TEST_STR, s3.length);
    ASSERT_EQ(s1.str, nullptr);

    String s4;
    s4 = s3;
    ASSERT_MEMEQ(s4.str, TEST_STR, s4.length);
    ASSERT_NE(s3.str, nullptr);

    String s5;
    s5 = std::move(s3);
    ASSERT_MEMEQ(s5.str, TEST_STR, s5.length);
    ASSERT_EQ(s3.str, nullptr);

    String s6(SW_STRL(TEST_STR));
    ASSERT_MEMEQ(s6.str, TEST_STR, s6.length);
}

TEST(string, append) {
    String s1(TEST_STR);
    s1.append(12345678);

    String s2(TEST_STR2);
    s1.append(s2);

    ASSERT_MEMEQ(s1.str, TEST_STR "12345678" TEST_STR2, s1.length);
}

TEST(string, write) {
    String s1;
    s1.reserve(32);

    String s2(TEST_STR);
    s1.repeat(" ", 1, 30);
    s1.write(30, s2);

    auto s3 = s1.substr(30, s2.length);
    ASSERT_MEMEQ(s3.str, TEST_STR, s3.length);
}

TEST(string, repeat) {
    auto end_str = "[end]";
    String s1;
    s1.repeat(SW_STRL("hello\r\n"), 5);
    s1.append(end_str);

    int count = 0;
    auto offset = s1.split(SW_STRL("\r\n"), [&](const char *data, size_t length) -> bool {
        count++;
        EXPECT_MEMEQ(data, "hello\r\n", 7);
        return true;
    });

    ASSERT_EQ(offset, s1.length - strlen(end_str));
    ASSERT_MEMEQ(s1.str + offset, end_str, strlen(end_str));

    ASSERT_EQ(count, 5);
}

TEST(string, release) {
    String s1(TEST_STR);
    ASSERT_MEMEQ(s1.str, TEST_STR, s1.length);

    auto s2 = s1.release();
    ASSERT_EQ(s1.str, nullptr);
    ASSERT_EQ(s1.length, 0);

    ASSERT_MEMEQ(s2, TEST_STR, strlen(TEST_STR));
    sw_free(s2);
}

TEST(string, ub) {
    String s1(TEST_STR);
    String s2(TEST_STR2);

    s1 = s2;
    s1 = s1;

    auto rs = s1.substr(s1.length, 10);
    ASSERT_EQ(rs.str, nullptr);
}

TEST(string, strnpos) {
    {
        string haystack = "hello world";
        string needle = " ";
        int pos;

        pos = swoole_strnpos(haystack.c_str(), haystack.length(), needle.c_str(), needle.length());
        ASSERT_EQ(pos, 5);
    }
    {
        string haystack = "hello world";
        string needle = "*";
        int pos;

        pos = swoole_strnpos(haystack.c_str(), haystack.length(), needle.c_str(), needle.length());
        ASSERT_EQ(-1, pos);
    }
}

TEST(string, strnstr) {
    {
        string haystack = "hello world";
        string needle = " ";
        const char *pos = swoole_strnstr(haystack.c_str(), haystack.length(), needle.c_str(), needle.length());
        ASSERT_EQ(haystack.c_str() + 5, pos);
    }
    {
        string haystack = "hello world";
        string needle = "*";
        const char *pos = swoole_strnstr(haystack.c_str(), haystack.length(), needle.c_str(), needle.length());
        ASSERT_EQ(NULL, pos);
    }
    {
        string haystack = "hello world\r\n";
        string needle = "\r\n\r\n";
        const char *pos = swoole_strnstr(haystack.c_str(), haystack.length(), needle.c_str(), needle.length());
        ASSERT_EQ(NULL, pos);
    }
}

TEST(string, explode) {
    string haystack = "hello world";
    string needle = " ";

    String str;
    str.str = (char *) haystack.c_str();
    str.length = haystack.length();

    int value_1 = 0;

    const char *explode_str = nullptr;
    size_t explode_length = 0;

    str.split(needle.c_str(), needle.length(), [&](const char *data, size_t length) -> int {
        explode_str = data;
        explode_length = length;
        value_1 = 5;
        return false;
    });

    ASSERT_EQ(haystack, explode_str);
    ASSERT_EQ(6, explode_length);
    ASSERT_EQ(5, value_1);
}

TEST(string, explode_2) {
    string haystack = "hello,world,swoole,php,last";
    string needle = ",";

    String str;
    str.str = (char *) haystack.c_str();
    str.length = haystack.length();

    int count = 0;
    vector<string> list;

    size_t n = str.split(needle.c_str(), needle.length(), [&](const char *data, size_t length) -> int {
        list.push_back(string(data, length - 1));
        count++;
        return true;
    });

    ASSERT_EQ(list[0], string("hello"));
    ASSERT_EQ(list[1], string("world"));
    ASSERT_EQ(list[2], string("swoole"));
    ASSERT_EQ(list[3], string("php"));
    ASSERT_EQ("last", string(str.str + n, str.length - n));
    ASSERT_EQ(4, count);
    ASSERT_EQ(list.size(), count);
}

static const int init_size = 1024;
static string test_data = "hello,world,swoole,php,last";

TEST(string, pop_1) {
    auto str = swoole::make_string(init_size);
    std::unique_ptr<String> s(str);

    char *str_1 = str->str;

    const int len_1 = 11;
    str->append(test_data.c_str(), test_data.length());
    str->offset = len_1;
    char *str_2 = str->pop(init_size);

    EXPECT_EQ(str_1, str_2);
    EXPECT_EQ(string("hello,world"), string(str_2, len_1));
    EXPECT_EQ(string(",swoole,php,last"), string(str->str, str->length));
    EXPECT_EQ(init_size, str->size);

    str->allocator->free(str_1);
}

TEST(string, pop_2) {
    auto str = swoole::make_string(init_size);
    std::unique_ptr<String> s(str);

    char *str_1 = str->str;

    const int len_1 = test_data.length();
    str->append(test_data.c_str(), test_data.length());
    str->offset = len_1;
    char *str_2 = str->pop(init_size);

    EXPECT_EQ(str_1, str_2);
    EXPECT_EQ(test_data, string(str_2, len_1));
    EXPECT_EQ(str->length, 0);
    EXPECT_EQ(init_size, str->size);

    str->allocator->free(str_1);
}

TEST(string, reduce_1) {
    auto str = swoole::make_string(init_size);
    std::unique_ptr<String> s(str);

    const int len_1 = 11;
    str->append(test_data.c_str(), test_data.length());
    str->offset = len_1;

    str->reduce(str->offset);

    EXPECT_EQ(string(",swoole,php,last"), string(str->str, str->length));
}

TEST(string, reduce_2) {
    auto str = swoole::make_string(init_size);
    std::unique_ptr<String> s(str);

    str->append(test_data.c_str(), test_data.length());
    str->offset = str->length;

    str->reduce(str->offset);

    EXPECT_EQ(str->length, 0);
}

TEST(string, reduce_3) {
    auto str = swoole::make_string(init_size);
    std::unique_ptr<String> s(str);

    str->append(test_data.c_str(), test_data.length());
    str->offset = 0;

    str->reduce(str->offset);

    EXPECT_EQ(str->length, test_data.length());
}

const auto FORMAT_INT = 999999999999999;
const auto FORMAT_STR = "hello world";

TEST(string, format_1) {
    String str1(1024);
    str1.append_random_bytes(1024, true);

    size_t n = str1.format("str=%s, value=%ld", FORMAT_STR, FORMAT_INT);
    std::string str2("str=hello world, value=999999999999999");

    ASSERT_EQ(str1.get_length(), n);
    ASSERT_MEMEQ(str1.value(), str2.c_str(), n);
}

TEST(string, format_2) {
    String str1(1024);
    str1.append_random_bytes(1024, true);

    std::string str2(str1.value(), str1.get_length());

    size_t n = str1.format_impl(String::FORMAT_APPEND, "str=%s, value=%ld", FORMAT_STR, FORMAT_INT);
    str2 += std::string(str1.value() + str2.length(), n);

    EXPECT_MEMEQ(str1.value(), str2.c_str(), str1.get_length());
}

TEST(string, substr_len) {
    const char *str1 = "hello: swoole & world";
    ASSERT_EQ(swoole::substr_len(str1, strlen(str1), ':', true), 5);
    ASSERT_EQ(swoole::substr_len(str1, strlen(str1), ':', false), 15);
}

TEST(string, starts_with) {
    const char *str1 = "hello world";
    ASSERT_TRUE(swoole::starts_with(str1, strlen(str1), SW_STRL("hello")));
    ASSERT_FALSE(swoole::starts_with(str1, strlen(str1), SW_STRL("php")));
    ASSERT_TRUE(swoole::starts_with(str1, strlen(str1), str1, strlen(str1)));
}

TEST(string, ends_with) {
    const char *str1 = "hello world";
    ASSERT_TRUE(swoole::ends_with(str1, strlen(str1), SW_STRL("world")));
    ASSERT_FALSE(swoole::ends_with(str1, strlen(str1), SW_STRL("php")));
    ASSERT_TRUE(swoole::ends_with(str1, strlen(str1), str1, strlen(str1)));
}

TEST(string, append_number) {
    string data = "hello";
    auto str = swoole::make_string(data.length() + 32);
    str->append(data.c_str(), data.length());
    str->append(123);
    str->set_null_terminated();
    EXPECT_STREQ(str->str, data.append("123").c_str());

    str->print(true);
    str->print(false);

    delete str;
}
