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
 | Author: Tianfeng Han  <rango@swoole.com>                             |
 +----------------------------------------------------------------------+
 */

#include "swoole_string.h"
#include "swoole_base64.h"

#include <memory>

namespace swoole {

char *String::pop(size_t init_size) {
    assert(length >= (size_t) offset);

    char *val = str;
    size_t _length = length - offset;
    size_t alloc_size = SW_MEM_ALIGNED_SIZE(_length == 0 ? init_size : SW_MAX(_length, init_size));

    char *new_val = (char *) allocator->malloc(alloc_size);
    if (new_val == nullptr) {
        return nullptr;
    }

    str = new_val;
    size = alloc_size;
    length = _length;
    if (length > 0) {
        memcpy(new_val, val + offset, length);
    }
    offset = 0;

    return val;
}

/**
 * migrate data to head, [offset, length - offset] -> [0, length - offset]
 */
void String::reduce(off_t _offset) {
    assert(_offset >= 0 && (size_t) _offset <= length);
    if (sw_unlikely(_offset == 0)) {
        return;
    }
    length -= _offset;
    offset = 0;
    if (length == 0) {
        return;
    }
    memmove(str, str + _offset, length);
}

void String::print() {
    printf("String[length=%zu,size=%zu,offset=%jd]=%.*s\n", length, size, (intmax_t) offset, (int) length, str);
}

int String::append(int value) {
    char buf[16];
    int s_len = swoole_itoa(buf, value);

    size_t new_size = length + s_len;
    if (new_size > size) {
        if (!reserve(new_size)) {
            return SW_ERR;
        }
    }

    memcpy(str + length, buf, s_len);
    length += s_len;
    return SW_OK;
}

int String::append(const char *append_str, size_t _length) {
    size_t new_size = length + _length;
    if (new_size > size and !reserve(new_size)) {
        return SW_ERR;
    }

    memcpy(str + length, append_str, _length);
    length += _length;
    return SW_OK;
}

int String::append_random_bytes(size_t _length, bool base64) {
    size_t new_size = length + _length;
    size_t base_encode_size;

    if (base64) {
        base_encode_size = BASE64_ENCODE_OUT_SIZE(_length) + 1;
        new_size += base_encode_size;
    }

    if (new_size > size) {
        if (!reserve(swoole_size_align(new_size * 2, SwooleG.pagesize))) {
            return SW_ERR;
        }
    }

    size_t n = swoole_random_bytes(str + length, _length);
    if (n != _length) {
        return SW_ERR;
    }

    if (base64) {
        std::unique_ptr<char[]> out(new char[base_encode_size]);
        n = base64_encode((uchar *) str + length, _length, out.get());
        memcpy(str + length, out.get(), n);
    }

    length += n;

    return SW_OK;
}

bool String::reserve(size_t new_size) {
    if (size == 0) {
        alloc(new_size, nullptr);
        return true;
    }

    new_size = SW_MEM_ALIGNED_SIZE(new_size);
    char *new_str = (char *) allocator->realloc(str, new_size);
    if (new_str == nullptr) {
        throw std::bad_alloc();
        return false;
    }

    str = new_str;
    size = new_size;

    return true;
}

bool String::repeat(const char *data, size_t len, size_t n) {
    if (n <= 0) {
        return false;
    }
    if (len == 1) {
        if ((size < length + n) && !reserve(length + n)) {
            return false;
        }
        memset(str + length, data[0], n);
        length += n;

        return true;
    }
    for (size_t i = 0; i < n; i++) {
        append(data, len);
    }
    return true;
}

/**
 * @return retval
 * 1. less than zero, the execution of the string_split function was terminated prematurely
 * 2. equal to zero, eof was not found in the target string
 * 3. greater than zero, 0 to retval has eof in the target string, and the position of retval is eof
 */
ssize_t String::split(const char *delimiter, size_t delimiter_length, const StringExplodeHandler &handler) {
#ifdef SW_LOG_TRACE_OPEN
    static int count;
    count++;
#endif
    const char *start_addr = str + offset;
    const char *delimiter_addr = swoole_strnstr(start_addr, length - offset, delimiter, delimiter_length);
    off_t _offset = offset;
    size_t ret;

    swoole_trace_log(SW_TRACE_EOF_PROTOCOL, "#[0] count=%d, length=%ld, size=%ld, offset=%ld", count, length, size, offset);

    while (delimiter_addr) {
        size_t _length = delimiter_addr - start_addr + delimiter_length;
        swoole_trace_log(SW_TRACE_EOF_PROTOCOL, "#[4] count=%d, length=%lu", count, _length + offset);
        if (handler((char *) start_addr - _offset, _length + _offset) == false) {
            return -1;
        }
        offset += _length;
        start_addr = str + offset;
        delimiter_addr = swoole_strnstr(start_addr, length - offset, delimiter, delimiter_length);
        _offset = 0;
    }

    /**
     * not found eof in str
     */
    if (_offset == offset) {
        /**
         * why is offset not equal to length,
         * because the length may contain part of eof and the other part in the next recv
         */
        offset = length - delimiter_length;
    }

    ret = start_addr - str - _offset;
    if (ret > 0 && ret < length) {
        swoole_trace_log(SW_TRACE_EOF_PROTOCOL, "#[5] count=%d, remaining_length=%zu", count, length - offset);
    } else if (ret >= length) {
        swoole_trace_log(SW_TRACE_EOF_PROTOCOL, "#[3] length=%ld, size=%ld, offset=%ld", length, size, offset);
    }

    return ret;
}

}  // namespace swoole
