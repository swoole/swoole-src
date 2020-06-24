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

swString *swoole::make_string(size_t size, const swAllocator *allocator)
{
    if (allocator == nullptr)
    {
        allocator = &SwooleG.std_allocator;
    }

    size = SW_MEM_ALIGNED_SIZE(size);
    swString *str = (swString *) allocator->malloc(sizeof(*str));
    if (str == nullptr)
    {
        swWarn("malloc[1] failed");
        return nullptr;
    }

    str->length = 0;
    str->size = size;
    str->offset = 0;
    str->str = (char *) allocator->malloc(size);
    str->allocator = allocator;

    if (str->str == nullptr)
    {
        swSysWarn("malloc[2](%ld) failed", size);
        allocator->free(str);
        return nullptr;
    }

    return str;
}

swString *swString_new(size_t size)
{
    return swoole::make_string(size);
}

char *swString_pop_realloc(swString *str, off_t offset, size_t length, size_t init_size)
{
    char *val = str->str;
    size_t size_aligned = length == 0 ? SW_MEM_ALIGNED_SIZE(init_size) : SW_MEM_ALIGNED_SIZE(length);
    char *new_val = (char *) str->allocator->malloc(size_aligned);
    if (new_val == nullptr)
    {
        return nullptr;
    }
    str->str = new_val;
    str->size = size_aligned;
    str->length = length;
    if (length > 0)
    {
        memcpy(new_val, val + offset, length);
    }
    return val;
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
    new_size = SW_MEM_ALIGNED_SIZE(new_size);
    char *new_str = (char *) str->allocator->realloc(str->str, new_size);
    if (new_str == nullptr)
    {
        swSysWarn("realloc(%ld) failed", new_size);
        return SW_ERR;
    }

    str->str = new_str;
    str->size = new_size;
    return SW_OK;
}

char *swString_alloc(swString *str, size_t __size)
{
    if (str->length + __size > str->size)
    {
        if (swString_extend_align(str, str->length + __size) < 0)
        {
            return nullptr;
        }
    }

    char *tmp = str->str + str->length;
    str->length += __size;
    return tmp;
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
