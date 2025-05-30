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

void String::alloc(size_t _size, const Allocator *_allocator) {
    if (_allocator == nullptr) {
        _allocator = sw_std_allocator();
    }

    _size = SW_MEM_ALIGNED_SIZE(_size);
    length = 0;
    size = _size;
    offset = 0;
    str = (char *) _allocator->malloc(_size);
    allocator = _allocator;

    if (str == nullptr) {
        throw std::bad_alloc();
    }
}

void String::move(String &&src) {
    str = src.str;
    length = src.length;
    offset = src.offset;
    size = src.size;
    allocator = src.allocator;

    src.str = nullptr;
    src.length = 0;
    src.size = 0;
    src.offset = 0;
}

String &String::operator=(const String &src) noexcept {
    if (&src == this) {
        return *this;
    }
    if (allocator && str) {
        allocator->free(str);
    }
    copy(src);
    return *this;
}

void String::copy(const String &src) {
    alloc(src.size, src.allocator);
    memcpy(str, src.str, src.length);
    length = src.length;
    offset = src.offset;
}

String &String::operator=(String &&src) noexcept {
    if (&src == this) {
        return *this;
    }
    if (allocator && str) {
        allocator->free(str);
    }
    move(std::move(src));
    return *this;
}

int String::append(const String &append_str) {
    size_t new_size = length + append_str.length;
    if (new_size > size) {
        if (!reserve(new_size)) {
            return SW_ERR;
        }
    }

    memcpy(str + length, append_str.str, append_str.length);
    length += append_str.length;
    return SW_OK;
}

void String::write(off_t _offset, const String &write_str) {
    write(_offset, write_str.str, write_str.length);
}

void String::write(off_t _offset, const char *write_str, size_t _length) {
    size_t new_length = _offset + _length;
    if (new_length > size) {
        reserve(swoole_size_align(new_length * 2, swoole_pagesize()));
    }

    memcpy(str + _offset, write_str, _length);
    if (new_length > length) {
        length = new_length;
    }
}

bool String::grow(size_t incr_value) {
    length += incr_value;
    if (length == size && !reserve(size * 2)) {
        return false;
    } else {
        return true;
    }
}

String String::substr(size_t offset, size_t len) {
    if (offset + len > length) {
        return String();
    }
    String _substr(len);
    _substr.append(str + offset, len);
    return _substr;
}

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

void String::print(bool print_value) {
    if (print_value) {
        printf("String[length=%zu,size=%zu,offset=%jd]=%.*s\n", length, size, (intmax_t) offset, (int) length, str);
    } else {
        printf("String[length=%zu,size=%zu,offset=%jd]=%p\n", length, size, (intmax_t) offset, str);
    }
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
        if (!reserve(swoole_size_align(new_size * 2, swoole_pagesize()))) {
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

char *String::release() {
    char *tmp = str;
    str = nullptr;
    size = 0;
    length = 0;
    offset = 0;
    return tmp;
}

bool String::repeat(const char *data, size_t len, size_t n) {
    if (n <= 0 || len == 0) {
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

    swoole_trace_log(SW_TRACE_EOF_PROTOCOL,
                     "#[0] count=%d, length=%ld, size=%ld, offset=%jd",
                     count,
                     length,
                     size,
                     (intmax_t) offset);

    while (delimiter_addr) {
        size_t _length = delimiter_addr - start_addr + delimiter_length;
        swoole_trace_log(SW_TRACE_EOF_PROTOCOL, "#[4] count=%d, length=%zu", count, (size_t) (_length + offset));
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
        swoole_trace_log(
            SW_TRACE_EOF_PROTOCOL, "#[5] count=%d, remaining_length=%zu", count, (size_t) (length - offset));
    } else if (ret >= length) {
        swoole_trace_log(
            SW_TRACE_EOF_PROTOCOL, "#[3] length=%ld, size=%zu, offset=%jd", length, size, (intmax_t) offset);
    }

    return ret;
}
}  // namespace swoole
