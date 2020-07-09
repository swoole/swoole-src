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

#pragma once

#include <stddef.h>
#include <stdint.h>

int swLog_open(const char *logfile);
void swLog_put(int level, const char *content, size_t length);
void swLog_reopen();
void swLog_close(void);
void swLog_reset();
void swLog_set_level(int lv);
int swLog_get_level();
int swLog_set_date_format(const char *format);
void swLog_set_rotation(int rotation);
const char *swLog_get_real_file();
const char *swLog_get_file();
int swLog_is_opened();
int swLog_redirect_stdout_and_stderr(bool enable);
void swLog_set_date_with_microseconds(bool enable);
