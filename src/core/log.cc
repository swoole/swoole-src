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
#define SW_LOG_DATE_STRLEN  64
#define SW_LOG_DEFAULT_DATE_FORMAT  "%F %T"

static bool opened = false;
static bool date_with_microseconds = false;
static std::string date_format = SW_LOG_DEFAULT_DATE_FORMAT;
static std::string log_file = "";

int swLog_open(const char *_log_file)
{
    if (opened)
    {
        swLog_close();
    }

    SwooleG.log_fd = open(_log_file, O_APPEND | O_RDWR | O_CREAT, 0666);
    if (SwooleG.log_fd < 0)
    {
        printf("open(%s) failed. Error: %s[%d]\n", _log_file, strerror(errno), errno);
        SwooleG.log_fd = STDOUT_FILENO;
        opened = false;
        return SW_ERR;
    }

    opened = true;
    log_file = _log_file;

    return SW_OK;
}

void swLog_close(void)
{
    if (opened)
    {
        close(SwooleG.log_fd);
        SwooleG.log_fd = STDOUT_FILENO;
        log_file = "";
        opened = false;
    }
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
    SwooleG.log_level = level;
}

void swLog_reset()
{
    date_format = SW_LOG_DEFAULT_DATE_FORMAT;
    date_with_microseconds = false;
    SwooleG.log_level = SW_LOG_INFO;
}

void swLog_set_date_format(const char *format)
{
    date_format = format;
}

void swLog_set_date_with_microseconds(bool enable)
{
    date_with_microseconds = enable;
}

/**
 * reopen log file
 */
void swLog_reopen(enum swBool_type redirect)
{
    if (!opened)
    {
        return;
    }
    std::string new_log_file(log_file);
    swLog_close();
    swLog_open(new_log_file.c_str());
    /**
     * redirect STDOUT & STDERR to log file
     */
    if (redirect)
    {
        swoole_redirect_stdout(SwooleG.log_fd);
    }
}

void swLog_put(int level, const char *content, size_t length)
{
    const char *level_str;
    char date_str[SW_LOG_DATE_STRLEN];
    char log_str[SW_LOG_BUFFER_SIZE];
    int n;

    if (level < SwooleG.log_level)
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
    // case SW_LOG_INFO:
    default:
        level_str = "INFO";
        break;
    }

    auto now = std::chrono::system_clock::now();
    auto now_sec = std::chrono::system_clock::to_time_t(now);
    size_t l_data_str = std::strftime(date_str, sizeof(date_str), date_format.c_str(), std::localtime(&now_sec));

    if (date_with_microseconds)
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

    if (opened && flock(SwooleG.log_fd, LOCK_EX) == -1)
    {
        printf("flock(%d, LOCK_EX) failed. Error: %s[%d]\n", SwooleG.log_fd, strerror(errno), errno);
        goto _print;
    }
    if (write(SwooleG.log_fd, log_str, n) < 0)
    {
        _print: printf("write(log_fd=%d, size=%d) failed. Error: %s[%d].\nMessage: %.*s\n", SwooleG.log_fd, n, strerror(errno), errno, n, log_str);
    }
    if (opened && flock(SwooleG.log_fd, LOCK_UN) == -1)
    {
        printf("flock(%d, LOCK_UN) failed. Error: %s[%d]\n", SwooleG.log_fd, strerror(errno), errno);
    }
}
