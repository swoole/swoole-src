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

static int swSystemTimer_signal_set(swTimer *timer, long interval);
static int swSystemTimer_set(swTimer *timer, long new_interval);
static void swSystemTimer_close(swTimer *timer);
static void swSystemTimer_signal_handler(int sig);

/**
 * create timer
 */
int swSystemTimer_init(swTimer *timer, long interval) {
    timer->set = swSystemTimer_set;
    timer->close = swSystemTimer_close;
    timer->lasttime = interval;
    if (swSystemTimer_signal_set(timer, interval) < 0) {
        return SW_ERR;
    }
    swSignal_set(SIGALRM, swSystemTimer_signal_handler);
    return SW_OK;
}

/**
 * setitimer
 */
static int swSystemTimer_signal_set(swTimer *timer, long interval) {
    struct itimerval timer_set = {};
    int sec = interval / 1000;
    int msec = interval % 1000;

    struct timeval now;
    if (gettimeofday(&now, nullptr) < 0) {
        swSysWarn("gettimeofday() failed");
        return SW_ERR;
    }

    if (interval > 0) {
        timer_set.it_interval.tv_sec = sec;
        timer_set.it_interval.tv_usec = msec * 1000;

        timer_set.it_value.tv_sec = sec;
        timer_set.it_value.tv_usec = timer_set.it_interval.tv_usec;

        if (timer_set.it_value.tv_usec > 1e6) {
            timer_set.it_value.tv_usec = timer_set.it_value.tv_usec - 1e6;
            timer_set.it_value.tv_sec += 1;
        }
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

static long _next_msec = 0;

static int swSystemTimer_set(swTimer *timer, long exec_msec) {
    if (exec_msec == _next_msec) {
        return SW_OK;
    }
    if (exec_msec == 0) {
        exec_msec = 1;
    }
    _next_msec = exec_msec;
    return swSystemTimer_signal_set(timer, exec_msec);
}

void swSystemTimer_signal_handler(int sig) {
    SwooleG.signal_alarm = 1;
}
