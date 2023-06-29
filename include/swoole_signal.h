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

#include "swoole.h"

#include <signal.h>

namespace swoole {
typedef void (*SignalHandler)(int);

struct Signal {
    SignalHandler handler;
    uint16_t signo;
    bool activated;
};
}  // namespace swoole

typedef swoole::SignalHandler swSignalHandler;

#ifdef HAVE_SIGNALFD
void swoole_signalfd_init();
bool swoole_signalfd_setup(swoole::Reactor *reactor);
#endif

SW_API swSignalHandler swoole_signal_set(int signo, swSignalHandler func);
SW_API swSignalHandler swoole_signal_set(int signo, swSignalHandler func, int restart, int mask);
SW_API swSignalHandler swoole_signal_get_handler(int signo);

SW_API void swoole_signal_clear(void);
SW_API void swoole_signal_block_all(void);
SW_API char *swoole_signal_to_str(int sig);
SW_API void swoole_signal_callback(int signo);
