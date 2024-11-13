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
  |         Twosee  <twose@qq.com>                                       |
  +----------------------------------------------------------------------+
*/

#pragma once

#include "swoole.h"

#include <string>

#define SW_STRINGL(s) s->str, s->length
#define SW_STRINGS(s) s->str, s->size
// copy value
#define SW_STRINGCVL(s) s->str + s->offset, s->length - s->offset
// append value
#define SW_STRINGAVL(s) s->str + s->length, s->size - s->length
/**
 * This function does not automatically expand memory;
 * ensure that the value to be written is less than the actual remaining capacity (size-length).
 * If the size of the value cannot be determined, should use the String::format() function.
 */
#define SW_STRING_FORMAT(s, format, ...) s->length += sw_snprintf(SW_STRINGAVL(s), format, ##__VA_ARGS__)

namespace swoole {

typedef std::function<bool(const char *, size_t)> StringExplodeHandler;

class String {
  private:
    void alloc(size_t _size, const Allocator *_allocator) {
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

    void move(String &&src) {
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

  public:
    size_t length;
    size_t size;
    off_t offset;
    char *str;
    const Allocator *allocator;

    String() {
        length = size = offset = 0;
        str = nullptr;
        allocator = nullptr;
    }

    explicit String(size_t _size, const Allocator *_allocator = nullptr) {
        alloc(_size, _allocator);
    }

    String(const char *_str, size_t _length) {
        alloc(_length + 1, nullptr);
        memcpy(str, _str, _length);
        str[_length] = '\0';
        length = _length;
    }

    String(const std::string &_str) : String(_str.c_str(), _str.length()) {}

    String(String &_str) {
        alloc(_str.size, _str.allocator);
        memcpy(_str.str, str, _str.length);
        length = _str.length;
        offset = _str.offset;
    }

    String(String &&src) {
        move(std::move(src));
    }

    String &operator=(String &src) {
        if (&src == this) {
            return *this;
        }
        if (allocator && str) {
            allocator->free(str);
        }
        alloc(src.size, src.allocator);
        memcpy(src.str, str, src.length);
        length = src.length;
        offset = src.offset;
        return *this;
    }

    String &operator=(String &&src) {
        if (&src == this) {
            return *this;
        }
        if (allocator && str) {
            allocator->free(str);
        }
        move(std::move(src));
        return *this;
    }

    ~String() {
        if (allocator && str) {
            allocator->free(str);
        }
    }

    char *value() {
        return str;
    }

    size_t get_length() {
        return length;
    }

    size_t capacity() {
        return size;
    }

    std::string to_std_string() {
        return std::string(str, length);
    }

    bool contains(const char *needle, size_t l_needle) {
        return swoole_strnstr(str, length, needle, l_needle) != nullptr;
    }

    bool contains(const std::string &needle) {
        return contains(needle.c_str(), needle.size());
    }

    bool grow(size_t incr_value) {
        length += incr_value;
        if (length == size && !reserve(size * 2)) {
            return false;
        } else {
            return true;
        }
    }

    String *substr(size_t offset, size_t len) {
        if (offset + len > length) {
            return nullptr;
        }
        auto _substr = new String(len);
        _substr->append(str + offset, len);
        return _substr;
    }

    bool empty() {
        return str == nullptr || length == 0;
    }

    void clear() {
        length = 0;
        offset = 0;
    }

    bool extend() {
        return extend(size * 2);
    }

    bool extend(size_t new_size) {
        assert(new_size > size);
        return reserve(new_size);
    }

    bool extend_align(size_t _new_size) {
        size_t align_size = SW_MEM_ALIGNED_SIZE(size * 2);
        while (align_size < _new_size) {
            align_size *= 2;
        }
        return reserve(align_size);
    }

    bool reserve(size_t new_size);
    /**
     * Transfer ownership of the string content pointer to the caller, who will capture this memory.
     * The caller must manage and free this memory; it will not free when the string is destructed.
     */
    char *release();
    bool repeat(const char *data, size_t len, size_t n);
    int append(const char *append_str, size_t length);

    int append(const std::string &append_str) {
        return append(append_str.c_str(), append_str.length());
    }

    int append(char c) {
        return append(&c, sizeof(c));
    }

    int append(const String &append_str) {
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

    void write(off_t _offset, String *write_str) {
        size_t new_length = _offset + write_str->length;
        if (new_length > size) {
            reserve(swoole_size_align(new_length * 2, swoole_pagesize()));
        }

        memcpy(str + _offset, write_str->str, write_str->length);
        if (new_length > length) {
            length = new_length;
        }
    }

    void write(off_t _offset, const char *write_str, size_t _length) {
        size_t new_length = _offset + _length;
        if (new_length > size) {
            reserve(swoole_size_align(new_length * 2, swoole_pagesize()));
        }

        memcpy(str + _offset, write_str, _length);
        if (new_length > length) {
            length = new_length;
        }
    }

    void set_null_terminated() {
        if (length == size) {
            extend(length + 1);
        }
        str[length] = '\0';
    }

    int append(int value);

    ssize_t split(const char *delimiter, size_t delimiter_length, const StringExplodeHandler &handler);
    int append_random_bytes(size_t length, bool base64 = false);
    void print(bool print_value = true);

    enum FormatFlag {
        FORMAT_APPEND = 1 << 0,
        FORMAT_GROW = 1 << 1,
    };

    template <typename... Args>
    size_t format_impl(int flags, const char *format, Args... args) {
        size_t _size = sw_snprintf(nullptr, 0, format, args...);
        if (_size == 0) {
            return 0;
        }
        // store \0 terminator
        _size++;

        size_t new_size = (flags & FORMAT_APPEND) ? length + _size : _size;
        if (flags & FORMAT_GROW) {
            size_t align_size = SW_MEM_ALIGNED_SIZE(size * 2);
            while (align_size < new_size) {
                align_size *= 2;
            }
            new_size = align_size;
        }

        size_t n;
        if (flags & FORMAT_APPEND) {
            if (_size > size - length && !reserve(new_size)) {
                return 0;
            }
            n = sw_snprintf(str + length, size - length, format, args...);
            length += n;
        } else {
            if (_size > size && !reserve(new_size)) {
                return 0;
            }
            n = sw_snprintf(str, size, format, args...);
            length = n;
        }

        return n;
    }

    template <typename... Args>
    size_t format(const char *format, Args... args) {
        return format_impl(0, format, args...);
    }

    char *pop(size_t init_size);
    void reduce(off_t offset);
};

inline String *make_string(size_t size, const Allocator *allocator = nullptr) {
    return new String(size, allocator);
}
}  // namespace swoole
