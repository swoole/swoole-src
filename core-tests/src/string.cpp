#include "tests.h"

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

TEST(string, strnaddr)
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

        pos = swoole_strnaddr(haystack, haystack_length, needle, needle_length);
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

        pos = swoole_strnaddr(haystack, haystack_length, needle, needle_length);
        ASSERT_EQ(NULL, pos);
    }
}

TEST(string, explode)
{
    static char *explode_str;
    static size_t explode_length;
    {
        char haystack[1024];
        uint32_t haystack_length;
        char needle[8];
        uint32_t needle_length;
        swString str;
        void *data[3];

        swString_clear(&str);

        strcpy(haystack, "hello world");
        haystack_length = sizeof("hello world") - 1;
        str.str = haystack;
        str.length = haystack_length;
        strcpy(needle, " ");
        needle_length = sizeof(" ") - 1;
        swString_explode(&str, needle, needle_length, [](void **data, int data_size) -> int {
            explode_str = (char *) (data[data_size - 3]);
            explode_length = (size_t) (data[data_size - 2]);
            data[data_size - 1] = (void *)(intptr_t) 5;
            return -1;
        }, data, SW_ARRAY_SIZE(data));
        ASSERT_EQ(haystack, explode_str);
        ASSERT_EQ(6, explode_length);
        ASSERT_EQ(5, (int)(intptr_t) data[SW_ARRAY_SIZE(data) - 1]);
    }
}