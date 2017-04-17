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

#define SW_LOG_BUFFER_SIZE 1024
#define SW_LOG_DATE_STRLEN  64

int swLog_init(char *logfile)
{
    SwooleG.log_fd = open(logfile, O_APPEND| O_RDWR | O_CREAT, 0666);
    if (SwooleG.log_fd < 0)
    {
        printf("open(%s) failed. Error: %s[%d]", logfile, strerror(errno), errno);
        return SW_ERR;
    }
    return SW_OK;
}

void swLog_free(void)
{
    if (SwooleG.log_fd > STDOUT_FILENO)
    {
        close(SwooleG.log_fd);
    }
}

void swLog_put(int level, char *cnt)
{
    const char *level_str;
    char date_str[SW_LOG_DATE_STRLEN];
    char log_str[SW_LOG_BUFFER_SIZE];
    int n;

    switch (level)
    {
    case SW_LOG_DEBUG:
        level_str = "DEBUG";
        break;
    case SW_LOG_NOTICE:
        level_str = "NOTICE";
        break;
    case SW_LOG_ERROR:
        level_str = "ERROR";
        break;
    case SW_LOG_WARNING:
        level_str = "WARNING";
        break;
    case SW_LOG_TRACE:
        level_str = "TRACE";
        break;
    default:
        level_str = "INFO";
        break;
    }

    time_t t;
    struct tm *p;
    t = time(NULL);
    p = localtime(&t);
    snprintf(date_str, SW_LOG_DATE_STRLEN, "%d-%02d-%02d %02d:%02d:%02d", p->tm_year + 1900, p->tm_mon + 1, p->tm_mday, p->tm_hour, p->tm_min, p->tm_sec);

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

    n = snprintf(log_str, SW_LOG_BUFFER_SIZE, "[%s %c%d.%d]\t%s\t%s\n", date_str, process_flag, SwooleG.pid, process_id, level_str, cnt);
    if (write(SwooleG.log_fd, log_str, n) < 0)
    {
        printf("write(log_fd, size=%d) failed. Error: %s[%d].\n", n, strerror(errno), errno);
    }
}
