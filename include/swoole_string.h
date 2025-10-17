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
    void alloc(size_t _size, const Allocator *_allocator);
    void move(String &&src);
    void copy(const String &src);

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

    explicit String(const std::string &_str) : String(_str.c_str(), _str.length()) {}

    String(const String &src) {
        copy(src);
    }

    String(String &&src) noexcept {
        move(std::move(src));
    }

    String &operator=(const String &src) noexcept;
    String &operator=(String &&src) noexcept;

    ~String() {
        if (allocator && str) {
            allocator->free(str);
        }
    }

    char *value() const {
        return str;
    }

    size_t get_length() const {
        return length;
    }

    size_t capacity() const {
        return size;
    }

    std::string to_std_string() const {
        return {str, length};
    }

    bool contains(const char *needle, size_t l_needle) const {
        return swoole_strnstr(str, length, needle, l_needle) != nullptr;
    }

    bool contains(const std::string &needle) const {
        return contains(needle.c_str(), needle.size());
    }

    bool starts_with(const char *needle, size_t l_needle) const {
        if (length < l_needle) {
            return false;
        }
        return memcmp(str, needle, l_needle) == 0;
    }

    bool starts_with(const std::string &needle) const {
        return starts_with(needle.c_str(), needle.length());
    }

    bool ends_with(const char *needle, size_t l_needle) const {
        if (length < l_needle) {
            return false;
        }
        return memcmp(str + length - l_needle, needle, l_needle) == 0;
    }

    bool ends_with(const std::string &needle) const {
        return ends_with(needle.c_str(), needle.length());
    }

    bool equals(const char *data, size_t len) const {
        if (length != len) {
            return false;
        }
        return memcmp(str, data, len) == 0;
    }

    bool equals(const std::string &data) const {
        if (length != data.size()) {
            return false;
        }
        return memcmp(str, data.c_str(), length) == 0;
    }

    void grow(size_t incr_value);
    String substr(size_t offset, size_t len) const;

    bool empty() const {
        return str == nullptr || length == 0;
    }

    void clear() {
        length = 0;
        offset = 0;
    }

    void extend() {
        extend(size * 2);
    }

    void extend(size_t new_size) {
        assert(new_size > size);
        reserve(new_size);
    }

    void extend_align(size_t _new_size) {
        size_t align_size = SW_MEM_ALIGNED_SIZE(size * 2);
        while (align_size < _new_size) {
            align_size *= 2;
        }
        reserve(align_size);
    }

    void reserve(size_t new_size);
    /**
     * Transfer ownership of the string content pointer to the caller, who will capture this memory.
     * The caller must manage and free this memory; it will not free when the string is destructed.
     */
    char *release();
    void repeat(const char *data, size_t len, size_t n);
    void append(const char *append_str, size_t length);

    void append(const std::string &append_str) {
        append(append_str.c_str(), append_str.length());
    }

    void append(const char c) {
        append(&c, sizeof(c));
    }

    void append(int value);
    void append(const String &append_str);
    bool append_random_bytes(size_t length, bool base64 = false);

    void write(off_t _offset, const String &write_str);
    void write(off_t _offset, const char *write_str, size_t _length);

    void set_null_terminated() {
        if (length == size) {
            extend(length + 1);
        }
        str[length] = '\0';
    }

    ssize_t split(const char *delimiter, size_t delimiter_length, const StringExplodeHandler &handler);
    void print(bool print_value = true) const;

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
        ++_size;

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
            if (_size > size - length) {
                reserve(new_size);
            }
            n = sw_snprintf(str + length, size - length, format, args...);
            length += n;
        } else {
            if (_size > size) {
                reserve(new_size);
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
