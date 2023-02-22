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

#pragma once

#include <stddef.h>
#include <stdint.h>
#include <string>
#include <unistd.h>

#define SW_LOG_BUFFER_SIZE (SW_ERROR_MSG_SIZE + 256)
#define SW_LOG_DATE_STRLEN 128
#define SW_LOG_DEFAULT_DATE_FORMAT "%F %T"

enum swLogLevel {
    SW_LOG_DEBUG = 0,
    SW_LOG_TRACE,
    SW_LOG_INFO,
    SW_LOG_NOTICE,
    SW_LOG_WARNING,
    SW_LOG_ERROR,
    SW_LOG_NONE,
};

enum swLogRotationType {
    SW_LOG_ROTATION_SINGLE = 0,
    SW_LOG_ROTATION_MONTHLY,
    SW_LOG_ROTATION_DAILY,
    SW_LOG_ROTATION_HOURLY,
    SW_LOG_ROTATION_EVERY_MINUTE,
};

namespace swoole {
class Logger {
  private:
    bool opened = false;
    // Redirect stdin and stdout to log_fd
    bool redirected = false;
    bool display_backtrace_ = false;
    int stdout_fd = -1;
    int stderr_fd = -1;
    int log_fd = STDOUT_FILENO;
    int log_level = SW_LOG_INFO;
    bool date_with_microseconds = false;
    std::string date_format = SW_LOG_DEFAULT_DATE_FORMAT;
    std::string log_file = "";
    std::string log_real_file;
    int log_rotation = SW_LOG_ROTATION_SINGLE;

  public:
    bool open(const char *logfile);
    void put(int level, const char *content, size_t length);
    void reopen();
    void close(void);
    void reset();
    void set_level(int lv);
    int get_level();
    bool set_date_format(const char *format);
    void set_rotation(int rotation);
    const char *get_real_file();
    const char *get_file();
    bool is_opened();
    bool redirect_stdout_and_stderr(int enable);
    void set_date_with_microseconds(bool enable);
    std::string gen_real_file(const std::string &file);
    static std::string get_pretty_name(const std::string &prettyFunction, bool strip = true);

    void display_backtrace() {
        display_backtrace_ = true;
    }
};
}  // namespace swoole

swoole::Logger *sw_logger();
#define __SW_FUNC__ (swoole::Logger::get_pretty_name(__PRETTY_FUNCTION__).c_str())

#define swoole_info(str, ...)                                                                                          \
    if (SW_LOG_INFO >= swoole_get_log_level()) {                                                                     \
        size_t _sw_error_len = sw_snprintf(sw_error, SW_ERROR_MSG_SIZE, str, ##__VA_ARGS__);                           \
        sw_logger()->put(SW_LOG_INFO, sw_error, _sw_error_len);                                                        \
    }

#define swoole_notice(str, ...)                                                                                        \
    if (SW_LOG_NOTICE >= swoole_get_log_level()) {                                                                   \
        size_t _sw_error_len = sw_snprintf(sw_error, SW_ERROR_MSG_SIZE, str, ##__VA_ARGS__);                           \
        sw_logger()->put(SW_LOG_NOTICE, sw_error, _sw_error_len);                                                      \
    }

#define swoole_sys_notice(str, ...)                                                                                    \
    do {                                                                                                               \
        swoole_set_last_error(errno);                                                                                  \
        if (SW_LOG_ERROR >= swoole_get_log_level()) {                                                                \
            size_t _sw_error_len = sw_snprintf(sw_error,                                                               \
                                               SW_ERROR_MSG_SIZE,                                                      \
                                               "%s(:%d): " str ", Error: %s[%d]",                                      \
                                               __SW_FUNC__,                                                            \
                                               __LINE__,                                                               \
                                               ##__VA_ARGS__,                                                          \
                                               swoole_strerror(errno),                                                 \
                                               errno);                                                                 \
            sw_logger()->put(SW_LOG_NOTICE, sw_error, _sw_error_len);                                                  \
        }                                                                                                              \
    } while (0)

#define swoole_warning(str, ...)                                                                                       \
    do {                                                                                                               \
        if (SW_LOG_WARNING >= swoole_get_log_level()) {                                                              \
            size_t _sw_error_len = sw_snprintf(sw_error, SW_ERROR_MSG_SIZE, "%s(): " str, __SW_FUNC__, ##__VA_ARGS__); \
            sw_logger()->put(SW_LOG_WARNING, sw_error, _sw_error_len);                                                 \
        }                                                                                                              \
    } while (0)

#define swoole_sys_warning(str, ...)                                                                                   \
    do {                                                                                                               \
        swoole_set_last_error(errno);                                                                                  \
        if (SW_LOG_ERROR >= swoole_get_log_level()) {                                                                \
            size_t _sw_error_len = sw_snprintf(sw_error,                                                               \
                                               SW_ERROR_MSG_SIZE,                                                      \
                                               "%s(): " str ", Error: %s[%d]",                                         \
                                               __SW_FUNC__,                                                            \
                                               ##__VA_ARGS__,                                                          \
                                               swoole_strerror(errno),                                                 \
                                               errno);                                                                 \
            sw_logger()->put(SW_LOG_WARNING, sw_error, _sw_error_len);                                                 \
        }                                                                                                              \
    } while (0)

#define swoole_error(str, ...)                                                                                         \
    do {                                                                                                               \
        size_t _sw_error_len = sw_snprintf(sw_error, SW_ERROR_MSG_SIZE, str, ##__VA_ARGS__);                           \
        sw_logger()->put(SW_LOG_ERROR, sw_error, _sw_error_len);                                                       \
        exit(1);                                                                                                       \
    } while (0)

#define swoole_sys_error(str, ...)                                                                                     \
    do {                                                                                                               \
        size_t _sw_error_len = sw_snprintf(sw_error,                                                                   \
                                           SW_ERROR_MSG_SIZE,                                                          \
                                           "%s(): " str ", Error: %s[%d]",                                             \
                                           __SW_FUNC__,                                                                \
                                           ##__VA_ARGS__,                                                              \
                                           swoole_strerror(errno),                                                     \
                                           errno);                                                                     \
        sw_logger()->put(SW_LOG_ERROR, sw_error, _sw_error_len);                                                       \
        exit(1);                                                                                                       \
    } while (0)

#define swoole_fatal_error(code, str, ...)                                                                             \
    do {                                                                                                               \
        SwooleG.fatal_error(code, str, ##__VA_ARGS__);                                                                 \
        exit(255);                                                                                                     \
    } while (0)

#define swoole_error_log(level, error, str, ...)                                                                       \
    do {                                                                                                               \
        swoole_set_last_error(error);                                                                                  \
        if (level >= swoole_get_log_level() && !swoole_is_ignored_error(error)) {                                    \
            size_t _sw_error_len =                                                                                     \
                sw_snprintf(sw_error, SW_ERROR_MSG_SIZE, "%s() (ERRNO %d): " str, __SW_FUNC__, error, ##__VA_ARGS__);  \
            sw_logger()->put(level, sw_error, _sw_error_len);                                                          \
        }                                                                                                              \
    } while (0)

#ifdef SW_DEBUG
#define swoole_debug(str, ...)                                                                                         \
    if (SW_LOG_DEBUG >= swoole_get_log_level()) {                                                                    \
        size_t _sw_error_len =                                                                                         \
            sw_snprintf(sw_error, SW_ERROR_MSG_SIZE, "%s(:%d): " str, __SW_FUNC__, __LINE__, ##__VA_ARGS__);           \
        sw_logger()->put(SW_LOG_DEBUG, sw_error, _sw_error_len);                                                       \
    }

#define swoole_hex_dump(data, length)                                                                                  \
    do {                                                                                                               \
        const char *__data = (data);                                                                                   \
        size_t __length = (length);                                                                                    \
        swoole_debug("+----------+------------+-----------+-----------+------------+------------------+");             \
        for (size_t of = 0; of < __length; of += 16) {                                                                 \
            char hex[16 * 3 + 1];                                                                                      \
            char str[16 + 1];                                                                                          \
            size_t i, hof = 0, sof = 0;                                                                                \
            for (i = of; i < of + 16 && i < __length; i++) {                                                           \
                hof += sprintf(hex + hof, "%02x ", (__data)[i] & 0xff);                                                \
                sof += sprintf(str + sof, "%c", isprint((int) (__data)[i]) ? (__data)[i] : '.');                       \
            }                                                                                                          \
            swoole_debug("| %08zx | %-48s| %-16s |", of, hex, str);                                                    \
        }                                                                                                              \
        swoole_debug("+----------+------------+-----------+-----------+------------+------------------+");             \
    } while (0)
#else
#define swoole_debug(str, ...)
#define swoole_hex_dump(data, length)
#endif

enum swTraceType {
    /**
     * Server
     */
    SW_TRACE_SERVER = 1u << 1,
    SW_TRACE_CLIENT = 1u << 2,
    SW_TRACE_BUFFER = 1u << 3,
    SW_TRACE_CONN = 1u << 4,
    SW_TRACE_EVENT = 1u << 5,
    SW_TRACE_WORKER = 1u << 6,
    SW_TRACE_MEMORY = 1u << 7,
    SW_TRACE_REACTOR = 1u << 8,
    SW_TRACE_PHP = 1u << 9,
    SW_TRACE_HTTP = 1u << 10,
    SW_TRACE_HTTP2 = 1u << 11,
    SW_TRACE_EOF_PROTOCOL = 1u << 12,
    SW_TRACE_LENGTH_PROTOCOL = 1u << 13,
    SW_TRACE_CLOSE = 1u << 14,
    SW_TRACE_WEBSOCKET = 1u << 15,
    /**
     * Client
     */
    SW_TRACE_REDIS_CLIENT = 1u << 16,
    SW_TRACE_MYSQL_CLIENT = 1u << 17,
    SW_TRACE_HTTP_CLIENT = 1u << 18,
    SW_TRACE_AIO = 1u << 19,
    SW_TRACE_SSL = 1u << 20,
    SW_TRACE_NORMAL = 1u << 21,
    /**
     * Coroutine
     */
    SW_TRACE_CHANNEL = 1u << 22,
    SW_TRACE_TIMER = 1u << 23,
    SW_TRACE_SOCKET = 1u << 24,
    SW_TRACE_COROUTINE = 1u << 25,
    SW_TRACE_CONTEXT = 1u << 26,
    SW_TRACE_CO_HTTP_SERVER = 1u << 27,
    SW_TRACE_TABLE = 1u << 28,
    SW_TRACE_CO_CURL = 1u << 29,
    SW_TRACE_CARES = 1u << 30,

    SW_TRACE_ZLIB = 1u << 31,

    SW_TRACE_ALL = 0x7fffffffffffffff
};

#ifdef SW_LOG_TRACE_OPEN
#define swoole_trace_log(what, str, ...)                                                                               \
    if (SW_LOG_TRACE >= swoole_get_log_level() && (what & SwooleG.trace_flags)) {                                    \
        size_t _sw_error_len =                                                                                         \
            sw_snprintf(sw_error, SW_ERROR_MSG_SIZE, "%s(:%d): " str, __SW_FUNC__, __LINE__, ##__VA_ARGS__);           \
        sw_logger()->put(SW_LOG_TRACE, sw_error, _sw_error_len);                                                       \
    }
#else
#define swoole_trace_log(what, str, ...)
#endif

#define swoole_trace(str, ...) swoole_trace_log(SW_TRACE_NORMAL, str, ##__VA_ARGS__)
