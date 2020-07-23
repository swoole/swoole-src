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
  |         Twosee  <twose@qq.com>                                       |
  +----------------------------------------------------------------------+
*/

#pragma once

#include "swoole.h"

#include <string>

#define SW_STRINGL(s) s->str, s->length
#define SW_STRINGS(s) s->str, s->size
#define SW_STRINGCVL(s) s->str + s->offset, s->length - s->offset

namespace swoole {

typedef std::function<bool(const char *, size_t)> StringExplodeHandler;

class String {
 private:
    void alloc(size_t _size, const swAllocator *_allocator) {
        if (_allocator == nullptr) {
            _allocator = &SwooleG.std_allocator;
        }

        _size = SW_MEM_ALIGNED_SIZE(_size);
        length = 0;
        size = _size;
        offset = 0;
        str = (char *) allocator->malloc(_size);
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
    const swAllocator *allocator;

    String() {
        length = size = offset = 0;
        str = nullptr;
        allocator = nullptr;
    }

    String(size_t _size, const swAllocator *_allocator = nullptr) {
        alloc(_size, _allocator);
    }

    String(const char *_str, size_t _length) {
        alloc(_length, nullptr);
        memcpy(str, _str, _length);
        length = _length;
    }

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
        if (str) {
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
        if (str) {
            allocator->free(str);
        }
        move(std::move(src));
        return *this;
    }

    ~String() {
        if (str) {
            allocator->free(str);
        }
    }

    inline char *value() {
        return str;
    }

    inline size_t get_length() {
        return length;
    }

    inline size_t capacity() {
        return size;
    }

    inline std::string to_std_string() {
        return std::string(str, length);
    }

    inline bool contains(const char *needle, size_t l_needle) {
        return swoole_strnstr(str, length, needle, l_needle) != nullptr;
    }

    int reserve(size_t new_size);
    int repeat(const char *data, size_t len, size_t n);
    int append(const char *append_str, size_t length);

    inline int append(const std::string &append_str) {
        return append(append_str.c_str(), append_str.length());
    }

    inline int append(String &append_str) {
        size_t new_size = length + append_str.length;
        if (new_size > size) {
            if (reserve(new_size) < 0) {
                return SW_ERR;
            }
        }

        memcpy(str + length, append_str.str, append_str.length);
        length += append_str.length;
        return SW_OK;
    }

    int append(int value);

    size_t split(const char *delimiter, size_t delimiter_length, const StringExplodeHandler &handler);
    int append_random_bytes(size_t length, bool base64 = false);
    void print();

    template<typename ... Args>
    inline size_t format(const char *format, Args ... args) {
        size_t _size = sw_snprintf(nullptr, 0, format, args...);
        if (_size == 0) {
            return 0;
        }
        // store \0 terminator
        _size++;
        if (_size > size && reserve(_size) < 0) {
            return 0;
        }
        return (length = sw_snprintf(str, size, format, args...));
    }

    char *pop(size_t init_size);
    void reduce(off_t offset);
};

inline String *make_string(size_t size, const swAllocator *allocator = nullptr) {
    return new String(size, allocator);
}
}

static inline void swString_clear(swString *str) {
    str->length = 0;
    str->offset = 0;
}

static inline void swString_free(swString *str) {
    delete str;
}

inline int swString_append_ptr(swString *str, const char *append_str, size_t length) {
    return str->append(append_str, length);
}

static inline int swString_extend_align(swString *str, size_t _new_size) {
    size_t align_size = SW_MEM_ALIGNED_SIZE(str->size * 2);
    while (align_size < _new_size) {
        align_size *= 2;
    }
    return str->reserve(align_size);
}

static inline int swString_grow(swString *str, size_t incr_value) {
    str->length += incr_value;
    if (str->length == str->size && str->reserve(str->size * 2) < 0) {
        return SW_ERR;
    } else {
        return SW_OK;
    }
}

inline swString *swString_new(size_t size) {
    return new swString(size, nullptr);
}

inline int swString_extend(swString *str, size_t new_size) {
    assert(new_size > str->size);
    return str->reserve(new_size);
}
