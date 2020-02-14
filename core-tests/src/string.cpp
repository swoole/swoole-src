#include "tests.h"
#include "swoole_cxx.h"

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
        char haystack[1024];
        uint32_t haystack_length;
        char needle[8];
        uint32_t needle_length;
        int pos;

        strcpy(haystack, "hello world");
        haystack_length = sizeof("hello world") - 1;
        haystack[haystack_length] = 0;
        strcpy(needle, " ");
        needle_length = sizeof(" ") - 1;
        needle[needle_length] = 0;

        pos = swoole_strnpos(haystack, haystack_length, needle, needle_length);
        ASSERT_EQ(pos, 5);
    }
    {
        char haystack[1024];
        uint32_t haystack_length;
        char needle[8];
        uint32_t needle_length;
        int pos;

        strcpy(haystack, "hello world");
        haystack_length = sizeof("hello world") - 1;
        haystack[haystack_length] = 0;
        strcpy(needle, "*");
        needle_length = sizeof("*") - 1;
        needle[needle_length] = 0;

        pos = swoole_strnpos(haystack, haystack_length, needle, needle_length);
        ASSERT_EQ(-1, pos);
    }
}

TEST(string, strnstr)
{
    {
        char haystack[1024];
        uint32_t haystack_length;
        char needle[8];
        uint32_t needle_length;
        const char *pos;

        strcpy(haystack, "hello world");
        haystack_length = sizeof("hello world") - 1;
        haystack[haystack_length] = 0;
        strcpy(needle, " ");
        needle_length = sizeof(" ") - 1;
        needle[needle_length] = 0;

        pos = swoole_strnstr(haystack, haystack_length, needle, needle_length);
        ASSERT_EQ(haystack + 5, pos);
    }
    {
        char haystack[1024];
        uint32_t haystack_length;
        char needle[8];
        uint32_t needle_length;
        const char *pos;

        strcpy(haystack, "hello world");
        haystack_length = sizeof("hello world") - 1;
        haystack[haystack_length] = 0;
        strcpy(needle, "*");
        needle_length = sizeof("*") - 1;
        needle[needle_length] = 0;

        pos = swoole_strnstr(haystack, haystack_length, needle, needle_length);
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

    swoole::string_explode(&str, needle.c_str(), needle.length(), [&](char *data, size_t length) -> int
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

    size_t n = swoole::string_explode(&str, needle.c_str(), needle.length(), [&](char *data, size_t length) -> int
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
