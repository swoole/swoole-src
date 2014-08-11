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
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
  +----------------------------------------------------------------------+
*/

#include "swoole.h"

#define SW_LOG_BUFFER_SIZE 1024
#define SW_LOG_DATE_STRLEN  64
#define SW_LOG_FORMAT "[%s]\t%s\t%s\n"

int swLog_init(char *logfile)
{
	SwooleG.log_fd = open(logfile, O_APPEND| O_RDWR | O_CREAT, 0666);
	if (SwooleG.log_fd < 0)
	{
		swWarn("open() log file[%s] failed. Error: %s[%d]", logfile, strerror(errno), errno);
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
	case SW_LOG_ERROR:
		level_str = "ERR";
		break;
	case SW_LOG_WARN:
		level_str = "WARN";
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
	snprintf(date_str, SW_LOG_DATE_STRLEN, "%d-%02d-%02d %02d:%02d:%02d", p->tm_year + 1900, p->tm_mon+1, p->tm_mday , p->tm_hour, p->tm_min, p->tm_sec);
	n = snprintf(log_str, SW_LOG_BUFFER_SIZE, SW_LOG_FORMAT, date_str, level_str, cnt);

	if (write(SwooleG.log_fd, log_str, n) < 0)
	{
		//write to log failed.
	}
}

