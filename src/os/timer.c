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
#include "server.h"

static int swSystemTimer_signal_set(swTimer *timer, long interval);
static int swSystemTimer_set(swTimer *timer, long new_interval);

/**
 * create timer
 */
int swSystemTimer_init(int interval, int use_pipe)
{
    swTimer *timer = &SwooleG.timer;
    timer->lasttime = interval;

    if (use_pipe)
    {
        if (swPipeNotify_auto(&timer->pipe, 0, 0) < 0)
        {
            return SW_ERR;
        }
        timer->fd = timer->pipe.getFd(&timer->pipe, 0);
        timer->use_pipe = 1;
    }
    else
    {
        timer->fd = 1;
        timer->use_pipe = 0;
    }

    if (swSystemTimer_signal_set(timer, interval) < 0)
    {
        return SW_ERR;
    }
    swSignal_add(SIGALRM, swSystemTimer_signal_handler);
    timer->set = swSystemTimer_set;
    return SW_OK;
}

/**
 * setitimer
 */
static int swSystemTimer_signal_set(swTimer *timer, long interval)
{
    struct itimerval timer_set;
    int sec = interval / 1000;
    int msec = (((float) interval / 1000) - sec) * 1000;

    struct timeval now;
    if (gettimeofday(&now, NULL) < 0)
    {
        swWarn("gettimeofday() failed. Error: %s[%d]", strerror(errno), errno);
        return SW_ERR;
    }
    bzero(&timer_set, sizeof(timer_set));

    if (interval > 0)
    {
        timer_set.it_interval.tv_sec = sec;
        timer_set.it_interval.tv_usec = msec * 1000;

        timer_set.it_value.tv_sec = sec;
        timer_set.it_value.tv_usec = timer_set.it_interval.tv_usec;

        if (timer_set.it_value.tv_usec > 1e6)
        {
            timer_set.it_value.tv_usec = timer_set.it_value.tv_usec - 1e6;
            timer_set.it_value.tv_sec += 1;
        }
    }

    if (setitimer(ITIMER_REAL, &timer_set, NULL) < 0)
    {
        swWarn("setitimer() failed. Error: %s[%d]", strerror(errno), errno);
        return SW_ERR;
    }
    return SW_OK;
}

void swSystemTimer_free(swTimer *timer)
{
    if (timer->use_pipe)
    {
        timer->pipe.close(&timer->pipe);
    }
}

static long current_interval = 0;

static int swSystemTimer_set(swTimer *timer, long new_interval)
{
    if (new_interval == current_interval)
    {
        return SW_OK;
    }
    if (new_interval == 0)
    {
        new_interval = 1;
    }
    current_interval = new_interval;
    return swSystemTimer_signal_set(timer, new_interval);
}

void swSystemTimer_signal_handler(int sig)
{
    SwooleG.signal_alarm = 1;
    uint64_t flag = 1;

    if (SwooleG.timer.use_pipe)
    {
        SwooleG.timer.pipe.write(&SwooleG.timer.pipe, &flag, sizeof(flag));
    }
}
