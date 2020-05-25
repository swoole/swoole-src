#include "tests.h"

using namespace std;

TEST(string, rtrim)
{
    char buf[1024];
    strcpy(buf, "hello world  ");
    swoole_rtrim(buf, strlen(buf));
    ASSERT_EQ(strcmp("hello world", buf), 0);
    ASSERT_NE(strcmp("hello world  ", buf), 0);

    strcpy(buf, "  ");
    swoole_rtrim(buf, strlen(buf));
    ASSERT_EQ(strlen(buf), 0);
}

TEST(string, strnpos)
{
    {
        string  haystack= "hello world";
        string needle = " ";
        int pos;

        pos = swoole_strnpos(haystack.c_str(), haystack.length(), needle.c_str(), needle.length());
        ASSERT_EQ(pos, 5);
    }
    {
        string  haystack= "hello world";
        string needle = "*";
        int pos;

        pos = swoole_strnpos(haystack.c_str(), haystack.length(), needle.c_str(), needle.length());
        ASSERT_EQ(-1, pos);
    }
}

TEST(string, strnstr)
{
    {
        string  haystack= "hello world";
        string needle = " ";
        const char *pos;

        pos = swoole_strnstr(haystack.c_str(), haystack.length(), needle.c_str(), needle.length());
        ASSERT_EQ(haystack.c_str() + 5, pos);
    }
    {
        string  haystack= "hello world";
        string needle = "*";
        const char *pos;

        pos = swoole_strnstr(haystack.c_str(), haystack.length(), needle.c_str(), needle.length());
        ASSERT_EQ(NULL, pos);
    }
}

TEST(string, explode)
{
    string  haystack= "hello world";
    string needle = " ";

    swString str;
    swString_clear(&str);
    str.str = (char*) haystack.c_str();
    str.length = haystack.length();

    int value_1 = 0;

    const char *explode_str = nullptr;
    size_t explode_length = 0;

    swoole::string_split(&str, needle.c_str(), needle.length(), [&](char *data, size_t length) -> int
    {
        explode_str = data;
        explode_length = length;
        value_1 = 5;
        return false;
    });

    ASSERT_EQ(haystack, explode_str);
    ASSERT_EQ(6, explode_length);
    ASSERT_EQ(5, value_1);
}

TEST(string, explode_2)
{
    string  haystack= "hello,world,swoole,php,last";
    string needle = ",";

    swString str;
    swString_clear(&str);
    str.str = (char*) haystack.c_str();
    str.length = haystack.length();

    int count = 0;
    vector<string> list;

    size_t n = swoole::string_split(&str, needle.c_str(), needle.length(), [&](char *data, size_t length) -> int
    {
        list.push_back(string(data, length-1));
        count ++;
        return true;
    });

    ASSERT_EQ(list[0], string("hello"));
    ASSERT_EQ(list[1], string("world"));
    ASSERT_EQ(list[2], string("swoole"));
    ASSERT_EQ(list[3], string("php"));
    ASSERT_EQ("last", string(str.str + n, str.length -n));
    ASSERT_EQ(4, count);
    ASSERT_EQ(list.size(), count);
}

TEST(string, atoi)
{
    swoole::String s(SW_STRL("1234567"));
    EXPECT_EQ(swString_to_int(s.get()), 1234567);
    int i = s;
    EXPECT_EQ(i, 1234567);
}

TEST(string, atol)
{
    swoole::String s(SW_STRL("123456789000000000"));
    EXPECT_EQ(swString_to_long(s.get()), 123456789000000000);
    long l = s;
    EXPECT_EQ(l, 123456789000000000);
}

TEST(string, atof)
{
    swoole::String s(SW_STRL("1234567.98765"));
    EXPECT_EQ(swString_to_double(s.get()), 1234567.98765);
    double d = s;
    EXPECT_EQ(d, 1234567.98765);
}
