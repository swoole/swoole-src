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

#include "swoole.h"

swString *swString_new(size_t size)
{
    swString *str = sw_malloc(sizeof(swString));
    if (str == NULL)
    {
        swWarn("malloc[1] failed.");
        return NULL;
    }
    bzero(str, sizeof(swString));
    str->size = size;
    str->str = sw_malloc(size);
    if (str->str == NULL)
    {
        swSysError("malloc[2](%ld) failed.", size);
        sw_free(str);
        return NULL;
    }
    return str;
}

void swString_print(swString *str)
{
    printf("String[length=%d,size=%d,offset=%d]=%s\n", (int) str->length, (int) str->size, (int) str->offset,
            str->str);
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

swString *swString_dup(const char *src_str, int length)
{
    swString *str = sw_malloc(sizeof(swString));
    if (str == NULL)
    {
        swWarn("malloc[1] failed.");
        return NULL;
    }

    bzero(str, sizeof(swString));
    str->length = length;
    str->size = length + 1;
    str->str = sw_malloc(str->size);
    if (str->str == NULL)
    {
        swWarn("malloc[2] failed.");
        sw_free(str);
        return NULL;
    }
    memcpy(str->str, src_str, length + 1);
    return str;
}

void swString_free(swString *str)
{
    sw_free(str->str);
    sw_free(str);
}

int swString_append(swString *str, swString *append_str)
{
    int new_size = str->length + append_str->length;
    if (new_size > str->size)
    {
        if (swString_extend(str, swoole_size_align(new_size * 2, sysconf(_SC_PAGESIZE))) < 0)
        {
            return SW_ERR;
        }
    }
    memcpy(str->str + str->length, append_str->str, append_str->length);
    str->length += append_str->length;
    return SW_OK;
}

int swString_append_ptr(swString *str, char *append_str, int length)
{
    int new_size = str->length + length;
    if (new_size > str->size)
    {
        if (swString_extend(str, swoole_size_align(new_size * 2, sysconf(_SC_PAGESIZE))) < 0)
        {
            return SW_ERR;
        }
    }
    memcpy(str->str + str->length, append_str, length);
    str->length += length;
    return SW_OK;
}

int swString_extend(swString *str, size_t new_size)
{
    assert(new_size > str->size);
    char *new_str = sw_realloc(str->str, new_size);
    if (new_str == NULL)
    {
        swSysError("realloc(%ld) failed.", new_size);
        return SW_ERR;
    }
    str->str = new_str;
    str->size = new_size;
    return SW_OK;
}

uint32_t swoole_utf8_decode(u_char **p, size_t n)
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

size_t swoole_utf8_length(u_char *p, size_t n)
{
    u_char c, *last;
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

