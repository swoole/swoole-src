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

#include "swoole.h"
#include <signal.h>

typedef void (*swSignalHandler)(int);

struct swSignal {
    swSignalHandler handler;
    uint16_t signo;
    uint16_t active;
};

#ifdef HAVE_SIGNALFD
void swSignalfd_init();
int swSignalfd_setup(swReactor *reactor);
#endif

swSignalHandler swSignal_set(int signo, swSignalHandler func);
swSignalHandler swSignal_get_handler(int signo);
void swSignal_clear(void);
void swSignal_none(void);
char *swSignal_str(int sig);
void swSignal_callback(int signo);
