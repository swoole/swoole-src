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

struct swString {
    size_t length;
    size_t size;
    off_t offset;
    char *str;
    const swAllocator *allocator;
};

#define SW_STRINGL(s) s->str, s->length
#define SW_STRINGS(s) s->str, s->size
#define SW_STRINGCVL(s) s->str + s->offset, s->length - s->offset

swString *swString_new(size_t size);
swString *swString_dup(const char *src_str, size_t length);
swString *swString_dup2(swString *src);
int swString_repeat(swString *src, const char *data, size_t len, size_t n);
void swString_print(swString *str);
int swString_append(swString *str, const swString *append_str);
int swString_append_ptr(swString *str, const char *append_str, size_t length);

inline int swString_append(swString *str, const std::string append_str) {
    return swString_append_ptr(str, append_str.c_str(), append_str.length());
}

int swString_append_int(swString *str, int value);
int swString_append_random_bytes(swString *str, size_t length);
int swString_write(swString *str, off_t offset, swString *write_str);
int swString_write_ptr(swString *str, off_t offset, const char *write_str, size_t length);
int swString_extend(swString *str, size_t new_size);
void swString_reduce(swString *str, off_t offset);
char *swString_pop(swString *str, size_t init_size);
char *swString_alloc(swString *str, size_t __size);

static inline void swString_clear(swString *str) {
    str->length = 0;
    str->offset = 0;
}

static inline void swString_free(swString *str) {
    if (str->str) {
        str->allocator->free(str->str);
    }
    str->allocator->free(str);
}

static inline int swString_extend_align(swString *str, size_t _new_size) {
    size_t align_size = SW_MEM_ALIGNED_SIZE(str->size * 2);
    while (align_size < _new_size) {
        align_size *= 2;
    }
    return swString_extend(str, align_size);
}

static inline int swString_grow(swString *str, size_t incr_value) {
    str->length += incr_value;
    if (str->length == str->size && swString_extend(str, str->size * 2) < 0) {
        return SW_ERR;
    } else {
        return SW_OK;
    }
}

static inline int swString_contains(swString *str, const char *needle, size_t l_needle) {
    return swoole_strnstr(str->str, str->length, needle, l_needle) != NULL;
}

template<typename ... Args>
inline size_t swString_format(swString *str, const char *format, Args ... args) {
    size_t size = sw_snprintf(nullptr, 0, format, args...);
    if (size == 0) {
        return 0;
    }
    if (size > str->size && swString_extend(str, size) < 0) {
        return 0;
    }
    return (str->length = sw_snprintf(str->str, str->size, format, args...));
}

namespace swoole {

typedef std::function<bool(char *, size_t)> StringExplodeHandler;

swString *make_string(size_t size, const swAllocator *allocator = nullptr);
size_t string_split(swString *str, const char *delimiter, size_t delimiter_length, const StringExplodeHandler &handler);

class String {
  private:
    swString *str;

  public:
    String(const char *_str, size_t length) { str = swString_dup(_str, length); }
    String(swString *_str) { str = _str; }
    String(String &&src) {
        str = src.str;
        src.str = nullptr;
    }
    String(String &src) { str = swString_dup2(src.get()); }
    String &operator=(String &src) {
        if (&src == this) {
            return *this;
        }
        if (str) {
            swString_free(str);
        }
        str = swString_dup2(src.get());
        return *this;
    }
    String &operator=(String &&src) {
        if (&src == this) {
            return *this;
        }
        if (str) {
            swString_free(str);
        }
        str = src.str;
        src.str = nullptr;
        return *this;
    }
    inline char *value() { return str->str; }
    inline size_t length() { return str->length; }
    inline size_t size() { return str->size; }
    inline swString *get() { return str; }
    std::string to_std_string() { return std::string(str->str, str->length); }
    ~String() {
        if (str) {
            swString_free(str);
        }
    }
};
}  // namespace swoole
