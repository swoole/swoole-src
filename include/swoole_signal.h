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
#endif

/**
 * The synchronous blocking IO mode is unsafe for executing PHP code within signal callback functions,
 * such as in the Server's Task worker process or the Manager process.
 * If a new signal is triggered during the execution of a signal function,
 * the recursive execution of the signal function can lead to a crash of the ZendVM.
 * When using `Swoole\Process::signal()` to register a PHP function as a signal handler,
 * it is crucial to set the third parameter to true;
 * this way, the underlying layer will not execute directly but will call
 * `swoole_signal_dispatch()` in a safe manner to execute the PHP signal callback function.
 */
SW_API swSignalHandler swoole_signal_set(int signo, swSignalHandler func, bool safety = false);
SW_API bool swoole_signal_isset(int signo);
SW_API swSignalHandler swoole_signal_set(int signo, swSignalHandler func, int restart, int mask);
SW_API swSignalHandler swoole_signal_get_handler(int signo);
SW_API uint32_t swoole_signal_get_listener_num(void);

SW_API void swoole_signal_clear(void);
SW_API void swoole_signal_block_all(void);
SW_API void swoole_signal_unblock_all(void);
SW_API char *swoole_signal_to_str(int sig);
SW_API void swoole_signal_callback(int signo);

/**
 * Only for synchronously blocked processes.
 * Due to the unreliability of signals,
 * executing complex logic directly within the signal handler function may pose security risks.
 * Therefore, the lower layer only marks memory in the signal handler
 * without directly invoking the application's set signal callback function.
 * Executing `swoole_signal_dispatch` in a safe context will actually call the signal callback function,
 * allowing for the execution of complex code within the callback.
 */
SW_API void swoole_signal_dispatch(void);
