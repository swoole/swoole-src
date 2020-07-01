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
  +----------------------------------------------------------------------+
*/

#include "swoole.h"
#include <sys/file.h>
#include <string>
#include <chrono>

#define SW_LOG_BUFFER_SIZE  (SW_ERROR_MSG_SIZE+256)
#define SW_LOG_DATE_STRLEN  128
#define SW_LOG_DEFAULT_DATE_FORMAT  "%F %T"

static struct
{
    bool opened = false;
    /**
     * Redirect stdin and stdout to log_fd
     */
    bool redirected = false;
    int stdout_fd = -1;
    int stderr_fd = -1;
    int log_fd = STDOUT_FILENO;
    int log_level = SW_LOG_INFO;
    bool date_with_microseconds = false;
    std::string date_format = SW_LOG_DEFAULT_DATE_FORMAT;
    std::string log_file = "";
    std::string log_real_file;
    int log_rotation = SW_LOG_ROTATION_SINGLE;
} swLog_G;

static std::string swLog_gen_real_file(const std::string &file);

int swLog_open(const char *_log_file)
{
    if (swLog_G.opened)
    {
        swLog_close();
    }

    swLog_G.log_file = _log_file;

    if (swLog_G.log_rotation)
    {
        swLog_G.log_real_file = swLog_gen_real_file(swLog_G.log_file);
    }
    else
    {
        swLog_G.log_real_file = swLog_G.log_file;
    }

    swLog_G.log_fd = open(swLog_G.log_real_file.c_str(), O_APPEND | O_RDWR | O_CREAT, 0666);
    if (swLog_G.log_fd < 0)
    {
        printf("open(%s) failed. Error: %s[%d]\n", swLog_G.log_real_file.c_str(), strerror(errno), errno);
        swLog_G.log_fd = STDOUT_FILENO;
        swLog_G.opened = false;
        swLog_G.log_file = "";
        swLog_G.log_real_file = "";

        return SW_ERR;
    }
    else
    {
        swLog_G.opened = true;

        return SW_OK;
    }
}

void swLog_close(void)
{
    if (swLog_G.opened)
    {
        close(swLog_G.log_fd);
        swLog_G.log_fd = STDOUT_FILENO;
        swLog_G.log_file = "";
        swLog_G.opened = false;
    }
}

int swLog_get_level()
{
    return swLog_G.log_level;
}

void swLog_set_level(int level)
{
    if (level < SW_LOG_DEBUG)
    {
        level = SW_LOG_DEBUG;
    }
    if (level > SW_LOG_NONE)
    {
        level = SW_LOG_NONE;
    }
    swLog_G.log_level = level;
}

void swLog_set_rotation(int _rotation)
{
    swLog_G.log_rotation = _rotation == 0 ? SW_LOG_ROTATION_SINGLE : SW_LOG_ROTATION_DAILY;
}

int swLog_redirect_stdout_and_stderr(int enable)
{
    if (enable)
    {
        if (!swLog_G.opened)
        {
            swWarn("no log file opened");
            return SW_ERR;
        }
        if (swLog_G.redirected)
        {
            swWarn("has been redirected");
            return SW_ERR;
        }
        if ((swLog_G.stdout_fd = dup(STDOUT_FILENO)) < 0)
        {
            swSysWarn("dup(STDOUT_FILENO) failed");
            return SW_ERR;
        }
        if ((swLog_G.stderr_fd = dup(STDERR_FILENO)) < 0)
        {
            swSysWarn("dup(STDERR_FILENO) failed");
            return SW_ERR;
        }
        swoole_redirect_stdout(swLog_G.log_fd);
        swLog_G.redirected = true;
    }
    else
    {
        if (!swLog_G.redirected)
        {
            swWarn("no redirected");
            return SW_ERR;
        }
        if (dup2(swLog_G.stdout_fd, STDOUT_FILENO) < 0)
        {
            swSysWarn("dup2(STDOUT_FILENO) failed");
        }
        if (dup2(swLog_G.stderr_fd, STDERR_FILENO) < 0)
        {
            swSysWarn("dup2(STDERR_FILENO) failed");
        }
        close(swLog_G.stdout_fd);
        close(swLog_G.stderr_fd);
        swLog_G.stdout_fd = -1;
        swLog_G.stderr_fd = -1;
        swLog_G.redirected = false;
    }

    return SW_OK;
}

void swLog_reset()
{
    swLog_G.date_format = SW_LOG_DEFAULT_DATE_FORMAT;
    swLog_G.date_with_microseconds = false;
    swLog_G.log_rotation = SW_LOG_ROTATION_SINGLE;
    swLog_G.log_level = SW_LOG_INFO;
}

int swLog_set_date_format(const char *format)
{
    char date_str[SW_LOG_DATE_STRLEN];
    time_t now_sec;

    now_sec = time(nullptr);
    size_t l_data_str = std::strftime(date_str, sizeof(date_str), format, std::localtime(&now_sec));

    if (l_data_str == 0)
    {
        swoole_set_last_error(SW_ERROR_INVALID_PARAMS);
        swoole_error_log(SW_LOG_WARNING, SW_ERROR_INVALID_PARAMS, "The date format string[length=%ld] is too long",
                strlen(format));

        return SW_ERR;
    }
    else
    {
        swLog_G.date_format = format;

        return SW_OK;
    }
}

void swLog_set_date_with_microseconds(uchar enable)
{
    swLog_G.date_with_microseconds = enable;
}

/**
 * reopen log file
 */
void swLog_reopen()
{
    if (!swLog_G.opened)
    {
        return;
    }

    std::string new_log_file(swLog_G.log_file);
    swLog_close();
    swLog_open(new_log_file.c_str());
    /**
     * redirect STDOUT & STDERR to log file
     */
    if (swLog_G.redirected)
    {
        swoole_redirect_stdout(swLog_G.log_fd);
    }
}

const char* swLog_get_real_file()
{
    return swLog_G.log_real_file.c_str();
}

const char* swLog_get_file()
{
    return swLog_G.log_file.c_str();
}

static std::string swLog_gen_real_file(const std::string &file)
{
    char date_str[16];
    auto now_sec = time(nullptr);
    size_t l_data_str = std::strftime(date_str, sizeof(date_str), "%Y%m%d", std::localtime(&now_sec));
    std::string real_file = file + "." + std::string(date_str, l_data_str);

    return real_file;
}

int swLog_is_opened()
{
    return swLog_G.opened;
}

void swLog_put(int level, const char *content, size_t length)
{
    const char *level_str;
    char date_str[SW_LOG_DATE_STRLEN];
    char log_str[SW_LOG_BUFFER_SIZE];
    int n;

    if (level < swLog_G.log_level)
    {
        return;
    }

    switch (level)
    {
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
    size_t l_data_str = std::strftime(date_str, sizeof(date_str), swLog_G.date_format.c_str(), std::localtime(&now_sec));

    if (swLog_G.log_rotation)
    {
        std::string tmp = swLog_gen_real_file(swLog_G.log_file);
        if (tmp != swLog_G.log_real_file)
        {
            swLog_reopen();
        }
    }

    if (swLog_G.date_with_microseconds)
    {
        auto now_us = std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch()).count();
        l_data_str += sw_snprintf(date_str + l_data_str, SW_LOG_DATE_STRLEN - l_data_str, "<.%ld>",
                now_us - now_sec * 1000000);
    }

    char process_flag = '@';
    int process_id = 0;

    switch(SwooleG.process_type)
    {
    case SW_PROCESS_MASTER:
        process_flag = '#';
        process_id = SwooleTG.id;
        break;
    case SW_PROCESS_MANAGER:
        process_flag = '$';
        break;
    case SW_PROCESS_WORKER:
        process_flag = '*';
        process_id = SwooleWG.id;
        break;
    case SW_PROCESS_TASKWORKER:
        process_flag = '^';
        process_id = SwooleWG.id;
        break;
    default:
        break;
    }

    n = sw_snprintf(log_str, SW_LOG_BUFFER_SIZE, "[%.*s %c%d.%d]\t%s\t%.*s\n", (int) l_data_str, date_str, process_flag, SwooleG.pid, process_id, level_str, (int) length, content);

    if (swLog_G.opened && flock(swLog_G.log_fd, LOCK_EX) == -1)
    {
        printf("flock(%d, LOCK_EX) failed. Error: %s[%d]\n", swLog_G.log_fd, strerror(errno), errno);
        goto _print;
    }
    if (write(swLog_G.log_fd, log_str, n) < 0)
    {
        _print: printf("write(log_fd=%d, size=%d) failed. Error: %s[%d].\nMessage: %.*s\n", swLog_G.log_fd, n, strerror(errno), errno, n, log_str);
    }
    if (swLog_G.opened && flock(swLog_G.log_fd, LOCK_UN) == -1)
    {
        printf("flock(%d, LOCK_UN) failed. Error: %s[%d]\n", swLog_G.log_fd, strerror(errno), errno);
    }
}
