#include "test_core.h"
#include "swoole_util.h"

using namespace std;

TEST(string, rtrim) {
    char buf[1024];
    strcpy(buf, "hello world  ");
    swoole::rtrim(buf, strlen(buf));
    ASSERT_EQ(strcmp("hello world", buf), 0);
    ASSERT_NE(strcmp("hello world  ", buf), 0);

    strcpy(buf, "  ");
    swoole::rtrim(buf, strlen(buf));
    ASSERT_EQ(strlen(buf), 0);
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
        const char *pos;

        pos = swoole_strnstr(haystack.c_str(), haystack.length(), needle.c_str(), needle.length());
        ASSERT_EQ(haystack.c_str() + 5, pos);
    }
    {
        string haystack = "hello world";
        string needle = "*";
        const char *pos;

        pos = swoole_strnstr(haystack.c_str(), haystack.length(), needle.c_str(), needle.length());
        ASSERT_EQ(NULL, pos);
    }
}

TEST(string, explode) {
    string haystack = "hello world";
    string needle = " ";

    swString str;
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

    swString str;
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
    std::unique_ptr<swString> s(str);

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
    std::unique_ptr<swString> s(str);

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
    std::unique_ptr<swString> s(str);

    const int len_1 = 11;
    str->append(test_data.c_str(), test_data.length());
    str->offset = len_1;

    str->reduce(str->offset);

    EXPECT_EQ(string(",swoole,php,last"), string(str->str, str->length));
}

TEST(string, reduce_2) {
    auto str = swoole::make_string(init_size);
    std::unique_ptr<swString> s(str);

    str->append(test_data.c_str(), test_data.length());
    str->offset = str->length;

    str->reduce(str->offset);

    EXPECT_EQ(str->length, 0);
}

TEST(string, reduce_3) {
    auto str = swoole::make_string(init_size);
    std::unique_ptr<swString> s(str);

    str->append(test_data.c_str(), test_data.length());
    str->offset = 0;

    str->reduce(str->offset);

    EXPECT_EQ(str->length, test_data.length());
}

TEST(string, format) {
    swString str(128);

    int a = swoole_rand(1000000, 9000000);

    swString str2(1024);
    str2.append_random_bytes(1024, true);

    str.format("a=%d, b=%.*s\r\n", a, str2.length, str2.str);

    EXPECT_GT(str.size, 1024);
    EXPECT_STREQ(str.str + str.length - 2, "\r\n");
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
