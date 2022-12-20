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

#include <stdio.h>
#include <stdarg.h>

#include <string>
#include <memory>
#include <chrono>
#include <set>
#include <vector>
#include <stack>
#include <type_traits>

#define __SCOPEGUARD_CONCATENATE_IMPL(s1, s2) s1##s2
#define __SCOPEGUARD_CONCATENATE(s1, s2) __SCOPEGUARD_CONCATENATE_IMPL(s1, s2)

namespace swoole {

namespace std_string {
template <typename... Args>
inline std::string format(const char *format, Args... args) {
    size_t size = snprintf(nullptr, 0, format, args...) + 1;  // Extra space for '\0'
    std::unique_ptr<char[]> buf(new char[size]);
    snprintf(buf.get(), size, format, args...);
    return std::string(buf.get(), buf.get() + size - 1);  // We don't want the '\0' inside
}

inline std::string vformat(const char *format, va_list args) {
    va_list _args;
    va_copy(_args, args);
    size_t size = vsnprintf(nullptr, 0, format, _args) + 1;  // Extra space for '\0'
    va_end(_args);
    std::unique_ptr<char[]> buf(new char[size]);
    vsnprintf(buf.get(), size, format, args);
    return std::string(buf.get(), buf.get() + size - 1);  // We don't want the '\0' inside
}
}  // namespace std_string

// Keep parameter 'steady' as false for backward compatibility.
template <typename T>
static inline long time(bool steady = false) {
    if (sw_likely(steady)) {
        auto now = std::chrono::steady_clock::now();
        return std::chrono::duration_cast<T>(now.time_since_epoch()).count();
    } else {
        auto now = std::chrono::system_clock::now();
        return std::chrono::duration_cast<T>(now.time_since_epoch()).count();
    }
}

static inline long get_timezone() {
#ifdef __linux__
    return timezone;
#else
    struct timezone tz;
    struct timeval tv;
    gettimeofday(&tv, &tz);
    return tz.tz_minuteswest * 60;
#endif
}

class DeferTask {
  private:
    std::stack<Callback> list_;

  public:
    void add(Callback fn) {
        list_.push(fn);
    }

    ~DeferTask() {
        while (!list_.empty()) {
            auto fn = list_.top();
            fn(nullptr);
            list_.pop();
        }
    }
};

template <typename Fun>
class ScopeGuard {
  public:
    ScopeGuard(Fun &&f) : _fun(std::forward<Fun>(f)), _active(true) {}

    ~ScopeGuard() {
        if (_active) {
            _fun();
        }
    }

    void dismiss() {
        _active = false;
    }

    ScopeGuard() = delete;
    ScopeGuard(const ScopeGuard &) = delete;
    ScopeGuard &operator=(const ScopeGuard &) = delete;

    ScopeGuard(ScopeGuard &&rhs) : _fun(std::move(rhs._fun)), _active(rhs._active) {
        rhs.dismiss();
    }

  private:
    Fun _fun;
    bool _active;
};

namespace detail {
enum class ScopeGuardOnExit {};

template <typename Fun>
inline ScopeGuard<Fun> operator+(ScopeGuardOnExit, Fun &&fn) {
    return ScopeGuard<Fun>(std::forward<Fun>(fn));
}
}  // namespace detail

// Helper macro
#define ON_SCOPE_EXIT                                                                                                  \
    auto __SCOPEGUARD_CONCATENATE(ext_exitBlock_, __LINE__) = swoole::detail::ScopeGuardOnExit() + [&]()

std::string intersection(std::vector<std::string> &vec1, std::set<std::string> &vec2);

static inline size_t ltrim(char **str, size_t len) {
    size_t i;
    for (i = 0; i < len; ++i) {
        if ('\0' != **str && isspace(**str)) {
            ++*str;
        } else {
            break;
        }
    }
    return len - i;
}

static inline size_t rtrim(char *str, size_t len) {
    for (size_t i = len; i > 0;) {
        if (isspace(str[--i])) {
            str[i] = 0;
            len--;
        } else {
            break;
        }
    }
    return len;
}

static inline size_t rtrim(const char *str, size_t len) {
    for (size_t i = len; i > 0;) {
        if (isspace(str[--i])) {
            len--;
        } else {
            break;
        }
    }
    return len;
}

static inline ssize_t substr_len(const char *str, size_t len, char separator, bool before = false) {
    const char *substr = (const char *) memchr(str, separator, len);
    if (substr == nullptr) {
        return -1;
    }
    return before ? substr - str : str + len - substr - 1;
}

static inline bool starts_with(const char *haystack, size_t l_haystack, const char *needle, size_t l_needle) {
    if (l_needle > l_haystack) {
        return false;
    }
    return memcmp(haystack, needle, l_needle) == 0;
}

static inline bool ends_with(const char *haystack, size_t l_haystack, const char *needle, size_t l_needle) {
    if (l_needle > l_haystack) {
        return false;
    }
    return memcmp(haystack + l_haystack - l_needle, needle, l_needle) == 0;
}

}  // namespace swoole
