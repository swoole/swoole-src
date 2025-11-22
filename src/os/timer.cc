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

#include "swoole_timer.h"
#include "swoole_signal.h"

#include <csignal>
#include <sys/time.h>

namespace swoole {
static int SystemTimer_set(Timer *timer, long next_msec);

void Timer::init_with_system_timer() {
    set = SystemTimer_set;
    close = [](Timer *timer) { SystemTimer_set(timer, -1); };
    swoole_signal_set(SIGALRM, [](int sig) { SwooleG.signal_alarm = true; });
}

static int SystemTimer_set(Timer *timer, long next_msec) {
    itimerval timer_set{};
    if (next_msec > 0) {
        timer_set.it_interval = {next_msec / 1000, static_cast<int>((next_msec % 1000) * 1000)};
        timer_set.it_value = timer_set.it_interval;
    }
    return setitimer(ITIMER_REAL, &timer_set, nullptr) < 0 ? SW_ERR : SW_OK;
}

void realtime_get(timespec *time) {
    auto now = std::chrono::system_clock::now();
    auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch());
    time->tv_sec = ns.count() / SW_NUM_BILLION;
    time->tv_nsec = ns.count() % SW_NUM_BILLION;
}

void realtime_add(timespec *time, const int64_t add_msec) {
    time->tv_sec += add_msec / 1000;
    time->tv_nsec += add_msec % 1000 * SW_NUM_MILLION;
    if (time->tv_nsec >= SW_NUM_BILLION) {
        int secs = time->tv_nsec / SW_NUM_BILLION;
        time->tv_sec += secs;
        time->tv_nsec -= secs * SW_NUM_BILLION;
    }
}
}  // namespace swoole
