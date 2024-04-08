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

#include "swoole.h"

#include <string.h>
#include <fcntl.h>
#include <sys/file.h>

#include <string>
#include <chrono>  // NOLINT [build/c++11]

namespace swoole {

std::string Logger::get_pretty_name(const std::string &pretty_function, bool strip) {
    size_t brackets = pretty_function.find_first_of("(");
    if (brackets == pretty_function.npos) {
        return "";
    }

    size_t begin = pretty_function.substr(0, brackets).rfind(" ") + 1;
    size_t end = brackets - begin;
    if (!strip) {
        return pretty_function.substr(begin, end);
    }

    auto method_name = pretty_function.substr(begin, end);
    size_t count = 0, index = method_name.length();
    while (true) {
        index = method_name.rfind("::", index);
        if (index == method_name.npos) {
            if (count == 1) {
                return method_name.substr(method_name.rfind("::") + 2);
            }
            break;
        }
        count++;
        if (count == 2) {
            return method_name.substr(index + 2);
        }
        index -= 2;
    }

    return method_name;
}

bool Logger::open(const char *_log_file) {
    if (opened) {
        close();
    }

    log_file = _log_file;

    if (log_rotation) {
        log_real_file = gen_real_file(log_file);
    } else {
        log_real_file = log_file;
    }

    log_fd = ::open(log_real_file.c_str(), O_APPEND | O_RDWR | O_CREAT, 0666);
    if (log_fd < 0) {
        printf("open(%s) failed. Error: %s[%d]\n", log_real_file.c_str(), strerror(errno), errno);
        log_fd = STDOUT_FILENO;
        opened = false;
        log_file = "";
        log_real_file = "";

        return false;
    } else {
        opened = true;

        return true;
    }
}

void Logger::close(void) {
    if (opened) {
        ::close(log_fd);
        log_fd = STDOUT_FILENO;
        log_file = "";
        opened = false;
    }
}

int Logger::get_level() {
    return log_level;
}

void Logger::set_level(int level) {
    if (level < SW_LOG_DEBUG) {
        level = SW_LOG_DEBUG;
    }
    if (level > SW_LOG_NONE) {
        level = SW_LOG_NONE;
    }
    log_level = level;
}

void Logger::set_rotation(int _rotation) {
    log_rotation = _rotation;
}

bool Logger::redirect_stdout_and_stderr(int enable) {
    if (enable) {
        if (!opened) {
            swoole_warning("no log file opened");
            return false;
        }
        if (redirected) {
            swoole_warning("has been redirected");
            return false;
        }
        if ((stdout_fd = dup(STDOUT_FILENO)) < 0) {
            swoole_sys_warning("dup(STDOUT_FILENO) failed");
            return false;
        }
        if ((stderr_fd = dup(STDERR_FILENO)) < 0) {
            swoole_sys_warning("dup(STDERR_FILENO) failed");
            return false;
        }
        swoole_redirect_stdout(log_fd);
        redirected = true;
    } else {
        if (!redirected) {
            swoole_warning("no redirected");
            return false;
        }
        if (dup2(stdout_fd, STDOUT_FILENO) < 0) {
            swoole_sys_warning("dup2(STDOUT_FILENO) failed");
        }
        if (dup2(stderr_fd, STDERR_FILENO) < 0) {
            swoole_sys_warning("dup2(STDERR_FILENO) failed");
        }
        ::close(stdout_fd);
        ::close(stderr_fd);
        stdout_fd = -1;
        stderr_fd = -1;
        redirected = false;
    }

    return true;
}

void Logger::reset() {
    date_format = SW_LOG_DEFAULT_DATE_FORMAT;
    date_with_microseconds = false;
    log_rotation = SW_LOG_ROTATION_SINGLE;
    log_level = SW_LOG_INFO;
}

bool Logger::set_date_format(const char *format) {
    char date_str[SW_LOG_DATE_STRLEN];
    time_t now_sec;

    now_sec = ::time(nullptr);
    size_t l_data_str = std::strftime(date_str, sizeof(date_str), format, std::localtime(&now_sec));

    if (l_data_str == 0) {
        swoole_set_last_error(SW_ERROR_INVALID_PARAMS);
        swoole_error_log(
            SW_LOG_WARNING, SW_ERROR_INVALID_PARAMS, "The date format string[length=%ld] is too long", strlen(format));

        return false;
    } else {
        date_format = format;

        return true;
    }
}

void Logger::set_date_with_microseconds(bool enable) {
    date_with_microseconds = enable;
}

/**
 * reopen log file
 */
void Logger::reopen() {
    if (!opened) {
        return;
    }

    std::string new_log_file(log_file);
    close();
    open(new_log_file.c_str());
    /**
     * redirect STDOUT & STDERR to log file
     */
    if (redirected) {
        swoole_redirect_stdout(log_fd);
    }
}

const char *Logger::get_real_file() {
    return log_real_file.c_str();
}

const char *Logger::get_file() {
    return log_file.c_str();
}

std::string Logger::gen_real_file(const std::string &file) {
    char date_str[16];
    auto now_sec = ::time(nullptr);
    const char *fmt;

    switch (log_rotation) {
    case SW_LOG_ROTATION_MONTHLY:
        fmt = "%Y%m";
        break;
    case SW_LOG_ROTATION_HOURLY:
        fmt = "%Y%m%d%H";
        break;
    case SW_LOG_ROTATION_EVERY_MINUTE:
        fmt = "%Y%m%d%H%M";
        break;
    case SW_LOG_ROTATION_DAILY:
    default:
        fmt = "%Y%m%d";
        break;
    }

    size_t l_data_str = std::strftime(date_str, sizeof(date_str), fmt, std::localtime(&now_sec));
    std::string real_file = file + "." + std::string(date_str, l_data_str);

    return real_file;
}

bool Logger::is_opened() {
    return opened;
}

void Logger::put(int level, const char *content, size_t length) {
    const char *level_str;
    char date_str[SW_LOG_DATE_STRLEN];
    char log_str[SW_LOG_BUFFER_SIZE];
    int n;

    if (level < log_level) {
        return;
    }

    switch (level) {
    case SW_LOG_DEBUG:
        level_str = "DEBUG";
        break;
    case SW_LOG_TRACE:
        level_str = "TRACE";
        break;
    case SW_LOG_NOTICE:
        level_str = "NOTICE";
        break;
    case SW_LOG_WARNING:
        level_str = "WARNING";
        break;
    case SW_LOG_ERROR:
        level_str = "ERROR";
        break;
    case SW_LOG_INFO:
    default:
        level_str = "INFO";
        break;
    }

    auto now = std::chrono::system_clock::now();
    auto now_sec = std::chrono::system_clock::to_time_t(now);
    size_t l_data_str = std::strftime(date_str, sizeof(date_str), date_format.c_str(), std::localtime(&now_sec));

    if (log_rotation) {
        std::string tmp = gen_real_file(log_file);
        if (tmp != log_real_file) {
            reopen();
        }
    }

    if (date_with_microseconds) {
        auto now_us = std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch()).count();
        l_data_str += sw_snprintf(
            date_str + l_data_str, SW_LOG_DATE_STRLEN - l_data_str, "<.%lld>", (long long) now_us - now_sec * 1000000);
    }

    char process_flag = '@';
    int process_id = 0;

    switch (swoole_get_process_type()) {
    case SW_PROCESS_MASTER:
        process_flag = '#';
        process_id = swoole_get_thread_id();
        break;
    case SW_PROCESS_MANAGER:
        process_flag = '$';
        break;
    case SW_PROCESS_WORKER:
        process_flag = '*';
        process_id = swoole_get_process_id();
        break;
    case SW_PROCESS_TASKWORKER:
        process_flag = '^';
        process_id = swoole_get_process_id();
        break;
    default:
        break;
    }

    n = sw_snprintf(log_str,
                    SW_LOG_BUFFER_SIZE,
                    "[%.*s %c%d.%d]\t%s\t%.*s\n",
                    static_cast<int>(l_data_str),
                    date_str,
                    process_flag,
                    SwooleG.pid,
                    process_id,
                    level_str,
                    static_cast<int>(length),
                    content);

    if (opened && flock(log_fd, LOCK_EX) == -1) {
        return;
    }
    write(log_fd, log_str, n);
    if (opened && flock(log_fd, LOCK_UN) == -1) {
        return;
    }
    if (display_backtrace_) {
        swoole_print_backtrace();
    }
}
}  // namespace swoole
