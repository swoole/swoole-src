/*
 +----------------------------------------------------------------------+
 | Swoole                                                               |
 +----------------------------------------------------------------------+
 | This source file is subject to version 2.0 of the Apache license,    |
 | that is bundled with this package in the file LICENSE, and is        |
 | available through the world-wide-web at the following url:           |
 | http://www.apache.org/licenses/LICENSE-2.0.html                      |
 | If you did not receive a copy of the Apache2.0 license and are unable|
 | to obtain it through the world-wide-web, please send a note to       |
 | license@swoole.com so we can mail you a copy immediately.            |
 +----------------------------------------------------------------------+
 | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
 +----------------------------------------------------------------------+
 */

#include "swoole_cxx.h"

using swoole::StringExplodeHandler;

swString *swString_new(size_t size)
{
    swString *str = (swString *) sw_malloc(sizeof(swString));
    if (str == NULL)
    {
        swWarn("malloc[1] failed");
        return NULL;
    }

    str->length = 0;
    str->size = size;
    str->offset = 0;
    str->str = (char *) sw_malloc(size);

    if (str->str == NULL)
    {
        swSysWarn("malloc[2](%ld) failed", size);
        sw_free(str);
        return NULL;
    }

    return str;
}

void swString_print(swString *str)
{
    printf(
        "String[length=%zu,size=%zu,offset=%jd]=%.*s\n",
        str->length, str->size, (intmax_t) str->offset, (int) str->length, str->str
    );
}

swString *swString_dup2(swString *src)
{
    swString *dst = swString_new(src->size);
    if (dst)
    {
        swTrace("string dup2.  new=%p, old=%p\n", dst, src);
        dst->length = src->length;
        dst->offset = src->offset;
        memcpy(dst->str, src->str, src->length);
    }

    return dst;
}

swString *swString_dup(const char *src_str, size_t length)
{
    swString *str = swString_new(length);
    if (str)
    {
        str->length = length;
        memcpy(str->str, src_str, length);
    }

    return str;
}

int swString_append(swString *str, const swString *append_str)
{
    size_t new_size = str->length + append_str->length;
    if (new_size > str->size)
    {
        if (swString_extend(str, swoole_size_align(new_size * 2, SwooleG.pagesize)) < 0)
        {
            return SW_ERR;
        }
    }

    memcpy(str->str + str->length, append_str->str, append_str->length);
    str->length += append_str->length;
    return SW_OK;
}

int swString_append_int(swString *str, int value)
{
    char buf[16];
    int s_len = swoole_itoa(buf, value);

    size_t new_size = str->length + s_len;
    if (new_size > str->size)
    {
        if (swString_extend(str, swoole_size_align(new_size * 2, SwooleG.pagesize)) < 0)
        {
            return SW_ERR;
        }
    }

    memcpy(str->str + str->length, buf, s_len);
    str->length += s_len;
    return SW_OK;
}

int swString_append_ptr(swString *str, const char *append_str, size_t length)
{
    size_t new_size = str->length + length;
    if (new_size > str->size)
    {
        if (swString_extend(str, swoole_size_align(new_size * 2, SwooleG.pagesize)) < 0)
        {
            return SW_ERR;
        }
    }

    memcpy(str->str + str->length, append_str, length);
    str->length += length;
    return SW_OK;
}

int swString_write(swString *str, off_t offset, swString *write_str)
{
    size_t new_length = offset + write_str->length;
    if (new_length > str->size)
    {
        if (swString_extend(str, swoole_size_align(new_length * 2, SwooleG.pagesize)) < 0)
        {
            return SW_ERR;
        }
    }

    memcpy(str->str + offset, write_str->str, write_str->length);
    if (new_length > str->length)
    {
        str->length = new_length;
    }

    return SW_OK;
}

int swString_write_ptr(swString *str, off_t offset, const char *write_str, size_t length)
{
    size_t new_length = offset + length;
    if (new_length > str->size)
    {
        if (swString_extend(str, swoole_size_align(new_length * 2, SwooleG.pagesize)) < 0)
        {
            return SW_ERR;
        }
    }

    memcpy(str->str + offset, write_str, length);
    if (new_length > str->length)
    {
        str->length = new_length;
    }

    return SW_OK;
}

int swString_extend(swString *str, size_t new_size)
{
    assert(new_size > str->size);
    char *new_str = (char *) sw_realloc(str->str, new_size);
    if (new_str == NULL)
    {
        swSysWarn("realloc(%ld) failed", new_size);
        return SW_ERR;
    }

    str->str = new_str;
    str->size = new_size;
    return SW_OK;
}

char* swString_alloc(swString *str, size_t __size)
{
    if (str->length + __size > str->size)
    {
        if (swString_extend_align(str, str->length + __size) < 0)
        {
            return NULL;
        }
    }

    char *tmp = str->str + str->length;
    str->length += __size;
    return tmp;
}

/**
 * @return retval
 * 1. less than zero, the execution of the string_split function was terminated prematurely
 * 2. equal to zero, eof was not found in the target string
 * 3. greater than zero, 0 to retval has eof in the target string, and the position of retval is eof
 */
size_t swoole::string_split(swString *str, const char *delimiter, size_t delimiter_length, const StringExplodeHandler &handler)
{
#ifdef SW_LOG_TRACE_OPEN
    static int count;
    count++;
#endif
    const char *start_addr = str->str + str->offset;
    const char *delimiter_addr = swoole_strnstr(start_addr, str->length - str->offset, delimiter, delimiter_length);
    off_t offset = str->offset;
    size_t ret;

    swTraceLog(SW_TRACE_EOF_PROTOCOL, "#[0] count=%d, length=%ld, size=%ld, offset=%ld", count, str->length, str->size, (long) str->offset);

    while (delimiter_addr)
    {
        size_t length = delimiter_addr - start_addr + delimiter_length;
        swTraceLog(SW_TRACE_EOF_PROTOCOL, "#[4] count=%d, length=%d", count, length + offset);
        if (handler((char *) start_addr - offset, length + offset) == false)
        {
            return -1;
        }
        str->offset += length;
        start_addr = str->str + str->offset;
        delimiter_addr = swoole_strnstr(start_addr, str->length - str->offset, delimiter, delimiter_length);
        offset = 0;
    }

    /**
     * not found eof in str
     */
    if (offset == str->offset)
    {
        /**
         * why is str->offset not equal to str->length,
         * because the str->length may contain part of eof and the other part in the next recv
         */
        str->offset = str->length - delimiter_length;
    }

    ret = start_addr - str->str - offset;
    if (ret > 0 && ret < str->length)
    {
        swTraceLog(SW_TRACE_EOF_PROTOCOL, "#[5] count=%d, remaining_length=%zu", count, str->length - str->offset);
    }
    else if (ret >= str->length)
    {
        swTraceLog(SW_TRACE_EOF_PROTOCOL, "#[3] length=%ld, size=%ld, offset=%ld", str->length, str->size, (long) str->offset);
    }

    return ret;
}

uint32_t swoole_utf8_decode(uchar **p, size_t n)
{
    size_t len;
    uint32_t u, i, valid;

    u = **p;

    if (u >= 0xf0)
    {
        u &= 0x07;
        valid = 0xffff;
        len = 3;
    }
    else if (u >= 0xe0)
    {
        u &= 0x0f;
        valid = 0x7ff;
        len = 2;
    }
    else if (u >= 0xc2)
    {
        u &= 0x1f;
        valid = 0x7f;
        len = 1;
    }
    else
    {
        (*p)++;
        return 0xffffffff;
    }

    if (n - 1 < len)
    {
        return 0xfffffffe;
    }

    (*p)++;

    while (len)
    {
        i = *(*p)++;
        if (i < 0x80)
        {
            return 0xffffffff;
        }
        u = (u << 6) | (i & 0x3f);
        len--;
    }

    if (u > valid)
    {
        return u;
    }

    return 0xffffffff;
}

size_t swoole_utf8_length(uchar *p, size_t n)
{
    uchar c, *last;
    size_t len;

    last = p + n;

    for (len = 0; p < last; len++)
    {
        c = *p;
        if (c < 0x80)
        {
            p++;
            continue;
        }
        if (swoole_utf8_decode(&p, n) > 0x10ffff)
        {
            /* invalid UTF-8 */
            return n;
        }
    }
    return len;
}

void swoole_random_string(char *buf, size_t size)
{
    static char characters[] = {
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
        'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
    };
    size_t i = 0;
    for (; i < size; i++)
    {
        buf[i] = characters[swoole_rand(0, sizeof(characters) - 1)];
    }
    buf[i] = '\0';
}

int swString_repeat(swString *src, const char *data, size_t len, size_t n)
{
    if (n <= 0)
    {
        return SW_ERR;
    }
    for (size_t i = 0; i < n; i++)
    {
        swString_append_ptr(src, data, len);
    }
    return SW_OK;
}
