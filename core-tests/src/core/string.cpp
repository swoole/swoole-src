#include "test_core.h"

using namespace std;

TEST(string, rtrim) {
    char buf[1024];
    strcpy(buf, "hello world  ");
    swoole_rtrim(buf, strlen(buf));
    ASSERT_EQ(strcmp("hello world", buf), 0);
    ASSERT_NE(strcmp("hello world  ", buf), 0);

    strcpy(buf, "  ");
    swoole_rtrim(buf, strlen(buf));
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
    swString_clear(&str);
    str.str = (char *) haystack.c_str();
    str.length = haystack.length();

    int value_1 = 0;

    const char *explode_str = nullptr;
    size_t explode_length = 0;

    swoole::string_split(&str, needle.c_str(), needle.length(), [&](char *data, size_t length) -> int {
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
    swString_clear(&str);
    str.str = (char *) haystack.c_str();
    str.length = haystack.length();

    int count = 0;
    vector<string> list;

    size_t n = swoole::string_split(&str, needle.c_str(), needle.length(), [&](char *data, size_t length) -> int {
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
    swoole::String s(str);

    char *str_1 = str->str;

    const int len_1 = 11;
    swString_append_ptr(str, test_data.c_str(), test_data.length());
    str->offset = len_1;
    char *str_2 = swString_pop(str, init_size);

    EXPECT_EQ(str_1, str_2);
    EXPECT_EQ(string("hello,world"), string(str_2, len_1));
    EXPECT_EQ(string(",swoole,php,last"), string(str->str, str->length));
    EXPECT_EQ(init_size, str->size);

    str->allocator->free(str_1);
}

TEST(string, pop_2) {
    auto str = swoole::make_string(init_size);
    swoole::String s(str);

    char *str_1 = str->str;

    const int len_1 = test_data.length();
    swString_append_ptr(str, test_data.c_str(), test_data.length());
    str->offset = len_1;
    char *str_2 = swString_pop(str, init_size);

    EXPECT_EQ(str_1, str_2);
    EXPECT_EQ(test_data, string(str_2, len_1));
    EXPECT_EQ(str->length, 0);
    EXPECT_EQ(init_size, str->size);

    str->allocator->free(str_1);
}

TEST(string, reduce_1) {
    auto str = swoole::make_string(init_size);
    swoole::String s(str);

    const int len_1 = 11;
    swString_append_ptr(str, test_data.c_str(), test_data.length());
    str->offset = len_1;

    swString_reduce(str, str->offset);

    EXPECT_EQ(string(",swoole,php,last"), string(str->str, str->length));
}

TEST(string, reduce_2) {
    auto str = swoole::make_string(init_size);
    swoole::String s(str);

    swString_append_ptr(str, test_data.c_str(), test_data.length());
    str->offset = str->length;

    swString_reduce(str, str->offset);

    EXPECT_EQ(str->length, 0);
}

TEST(string, reduce_3) {
    auto str = swoole::make_string(init_size);
    swoole::String s(str);

    swString_append_ptr(str, test_data.c_str(), test_data.length());
    str->offset = 0;

    swString_reduce(str, str->offset);

    EXPECT_EQ(str->length, test_data.length());
}

TEST(string, format) {
    auto str = swoole::make_string(128);
    swoole::String s(str);

    int a = swoole_rand(1000000, 9000000);

    auto str2 = swoole::make_string(1024);
    swoole::String s2(str2);
    swString_append_random_bytes(str2, 1024, true);

    swString_format(str, "a=%d, b=%.*s\r\n", a, str2->length, str2->str);

    EXPECT_GT(str->size, 1024);
    EXPECT_STREQ(str->str + str->length - 2, "\r\n");
}
