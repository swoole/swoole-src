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

#include <csignal>
#include <vector>

namespace swoole {
class Reactor;
typedef void (*SignalHandler)(int);

struct Signal {
    SignalHandler handler;
    uint16_t signo;
    bool activated;
};

#ifndef _WIN32
/**
 * Handles the given signals with `handler` through sigaction until destroyed, then restores each signal's previous
 * registration, action, signalfd membership and blocked state. A forked child leaving the scope keeps its own state.
 */
class SignalGuard {
  public:
    SignalGuard(const std::vector<int> &signal_numbers, SignalHandler handler);
    ~SignalGuard();

    SignalGuard(const SignalGuard &) = delete;
    SignalGuard &operator=(const SignalGuard &) = delete;

  private:
    struct SavedSignal {
        int signo;
        Signal signal;
        struct sigaction action;
        struct sigaction origin_action;
        bool blocked;
        bool signalfd;
    };
    std::vector<SavedSignal> saved_signals;
    pid_t pid;
};
#endif
}  // namespace swoole

typedef swoole::SignalHandler swSignalHandler;

#ifdef HAVE_SIGNALFD
void swoole_signalfd_init();
#endif
/**
 * Signal APIs come in two layers. Do not mix them for the same signal.
 *
 * swoole_sigaction_set(): the low-level layer, a thin wrapper around sigaction(2).
 *   - It is exported only for backward compatibility. It will no longer be a public API in the next version,
 *     do not use it outside of Swoole.
 *   - Installs `func` into the kernel immediately and returns the previous kernel handler (nullptr on failure).
 *   - `func == nullptr` means SIG_IGN, `func == (SignalHandler) -1` means SIG_DFL.
 *   - `restart` sets SA_RESTART, `mask` blocks all signals while the handler runs.
 *   - Keeps no registry: it does not record the origin action, does not use signalfd/kqueue and does not
 *     touch signal_listener_num. Installing SIG_IGN/SIG_DFL only drops the registry entry of that signal.
 *   - `func` runs in signal context, so it must be async-signal-safe.
 *
 * swoole_signal_set(): the managed layer used by Server, ProcessPool, Process::signal() and System::waitSignal().
 *   - Records `func` in the registry and saves the original sigaction on first registration, so that
 *     `func == nullptr` unregisters the signal and restores that original action.
 *   - Picks the backend: signalfd (or kqueue) when a reactor is available, so `func` runs in the event loop;
 *     otherwise sigaction through swoole_sigaction_set(), where `safety` decides whether `func` runs
 *     in signal context (false) or is deferred to swoole_signal_dispatch() (true).
 *   - To ignore a signal, pass SIG_IGN explicitly. nullptr is not "ignore": for a signal that was never
 *     registered it creates an entry without a handler, and each delivery logs an unregistered-signal warning.
 *   - Cleared as a whole by swoole_signal_clear().
 */
SW_API swSignalHandler swoole_sigaction_set(int signo, swSignalHandler func, bool restart, bool mask);

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
SW_API swSignalHandler swoole_signal_get_handler(int signo);
SW_API uint32_t swoole_signal_get_listener_num();

SW_API void swoole_signal_clear();
void swoole_signal_init_reactor(swoole::Reactor *reactor);
// Returns true only when this call saves and changes the mask; that caller must restore it with unblock_all().
#ifndef _WIN32
SW_API bool swoole_signal_block_all();
SW_API void swoole_signal_unblock_all();
#else
inline bool swoole_signal_block_all() {
    return false;
}
inline void swoole_signal_unblock_all() {}
#endif
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
SW_API void swoole_signal_dispatch();
