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

#include "swoole_timer.h"
#include "swoole_signal.h"
#include "swoole_util.h"
#include "swoole_log.h"

#include <signal.h>
#include <sys/time.h>

static int swSystemTimer_signal_set(swTimer *timer, long next_msec);
static int swSystemTimer_set(swTimer *timer, long new_interval);
static void swSystemTimer_close(swTimer *timer);
static void swSystemTimer_signal_handler(int sig);

using swoole::Timer;

/**
 * create timer
 */
bool Timer::init_system_timer() {
    set = swSystemTimer_set;
    close = swSystemTimer_close;
    swSignal_set(SIGALRM, swSystemTimer_signal_handler);

    return true;
}

/**
 * setitimer
 */
static int swSystemTimer_signal_set(swTimer *timer, long next_msec) {
    struct itimerval timer_set;
    struct timeval now;
    if (gettimeofday(&now, nullptr) < 0) {
        swSysWarn("gettimeofday() failed");
        return SW_ERR;
    }

    if (next_msec > 0) {
        int sec = next_msec / 1000;
        int msec = next_msec % 1000;
        timer_set.it_interval.tv_sec = sec;
        timer_set.it_interval.tv_usec = msec * 1000;
        timer_set.it_value.tv_sec = sec;
        timer_set.it_value.tv_usec = timer_set.it_interval.tv_usec;

        if (timer_set.it_value.tv_usec > 1e6) {
            timer_set.it_value.tv_usec = timer_set.it_value.tv_usec - 1e6;
            timer_set.it_value.tv_sec += 1;
        }
    } else {
        timer_set = {};
    }

    if (setitimer(ITIMER_REAL, &timer_set, nullptr) < 0) {
        swSysWarn("setitimer() failed");
        return SW_ERR;
    }
    return SW_OK;
}

static void swSystemTimer_close(swTimer *timer) {
    swSystemTimer_signal_set(timer, -1);
}

static int swSystemTimer_set(swTimer *timer, long exec_msec) {
    if (exec_msec == 0) {
        exec_msec = 1;
    }
    /**
     * The execution time is later than the current timer time,
     * no need to modify the system timer setting
     */
    if (exec_msec >= timer->next_msec_) {
        return SW_OK;
    }
    timer->next_msec_ = exec_msec;
    return swSystemTimer_signal_set(timer, exec_msec);
}

void swSystemTimer_signal_handler(int sig) {
    SwooleG.signal_alarm = true;
}
