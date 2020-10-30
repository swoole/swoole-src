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

#include <stdio.h>
#include <stdarg.h>

#include <string>
#include <memory>
#include <chrono>
#include <set>
#include <vector>
#include <stack>
#include <sys/uio.h>

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

template <typename T>
static inline long time(bool steady = false) {
    if (steady) {
        auto now = std::chrono::steady_clock::now();
        return std::chrono::duration_cast<T>(now.time_since_epoch()).count();
    } else {
        auto now = std::chrono::system_clock::now();
        return std::chrono::duration_cast<T>(now.time_since_epoch()).count();
    }
}

static inline int get_iovector_index(const struct iovec *iov, int iovcnt, size_t __n, int &index, size_t &offset_bytes) {
    index = 0;
    offset_bytes = 0;
    int total_bytes = 0;

    for (; index < iovcnt; index++) {
        total_bytes += iov[index].iov_len;
        if (total_bytes >= __n) {
            offset_bytes = iov[index].iov_len - (total_bytes - __n);
            return 0;
        }
    }

    // represents the length of __n greater than total_bytes
    return -1;
}

class DeferFn {
  private:
    using Fn = std::function<void(void)>;
    Fn fn_;
    bool cancelled_ = false;
  public:
    DeferFn(const Fn &fn) :
        fn_(fn) {
    }
    void cancel() {
        cancelled_ = true;
    }
    ~DeferFn() {
        if (!cancelled_) {
            fn_();
        }
    }
};

class StackDeferFn {
  private:
    using Fn = std::function<void(void)>;
    std::stack<Fn> stack_;
  public:
    StackDeferFn() = default;
    ~StackDeferFn() {
        while(!stack_.empty()) {
            auto fn = stack_.top();
            stack_.pop();
            fn();
        }
    }
    void add(const Fn &fn) {
        stack_.emplace(fn);
    }
};

std::string intersection(std::vector<std::string> &vec1, std::set<std::string> &vec2);
}  // namespace swoole
