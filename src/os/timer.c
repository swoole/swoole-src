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
#include "Server.h"

static int swTimer_select(swTimer *timer);
int swTimer_signal_set(swTimer *timer, int interval);
#ifdef HAVE_TIMERFD
int swTimer_timerfd_set(swTimer *timer, int interval);
#endif
/**
 * 创建定时器
 */
int swTimer_create(swTimer *timer, int interval)
{
	timer->interval = interval;
	timer->lasttime = interval;

#ifdef HAVE_TIMERFD
	if(swTimer_timerfd_set(timer, interval) < 0)
	{
		return SW_ERR;
	}
	timer->use_pipe = 0;
#else
	if (swPipeNotify_auto(&timer->pipe, 0, 0) || swTimer_signal_set(timer, interval) < 0)
	{
		return SW_ERR;
	}
	timer->fd = timer->pipe.getFd(&timer->pipe, 0);
	timer->use_pipe = 1;
#endif
	return SW_OK;
}

#ifdef HAVE_TIMERFD
/**
 * timerfd
 */
int swTimer_timerfd_set(swTimer *timer, int interval)
{
	struct timeval now;
	int sec = interval / 1000;
	int msec = (((float) interval / 1000) - sec) * 1000;

	if (gettimeofday(&now, NULL) < 0)
	{
		swWarn("gettimeofday failed");
		return SW_ERR;
	}

	struct itimerspec timer_set;
	bzero(&timer_set, sizeof(timer_set));

	if(timer->fd == 0)
	{
		timer->fd = timerfd_create(CLOCK_REALTIME, TFD_NONBLOCK | TFD_CLOEXEC);
		if (timer->fd < 0)
		{
			swWarn("create timerfd failed. Error: %s[%d]", strerror(errno), errno);
			return SW_ERR;
		}
	}

	timer_set.it_value.tv_sec = now.tv_sec + sec;
	timer_set.it_value.tv_nsec = now.tv_usec + msec * 1000;
	timer_set.it_interval.tv_sec = sec;
	timer_set.it_interval.tv_nsec = msec * 1000 * 1000;

	if (timerfd_settime(timer->fd, TFD_TIMER_ABSTIME, &timer_set, NULL) == -1)
	{
		swWarn("set timer failed. Error: %s[%d]", strerror(errno), errno);
		return SW_ERR;
	}
	return SW_OK;
}
#endif

/**
 * setitimer
 */
int swTimer_signal_set(swTimer *timer, int interval)
{
	struct itimerval timer_set;
	int sec = interval / 1000;
	int msec = (((float) interval / 1000) - sec) * 1000;

	memset(&timer_set, 0, sizeof(timer_set));
	timer_set.it_value.tv_sec = sec;
	timer_set.it_value.tv_usec = msec * 1000;
	timer_set.it_interval.tv_sec = sec;
	timer_set.it_interval.tv_usec = msec * 1000;

	if (setitimer(ITIMER_REAL, &timer_set, NULL) < 0)
	{
		swWarn("set timer failed. Error: %s[%d]", strerror(errno), errno);
		return SW_ERR;
	}
	return SW_OK;
}

void swTimer_del(swTimer *timer, int ms)
{
	swHashMap_del_int(&timer->list, ms);
}

int swTimer_free(swTimer *timer)
{
	swHashMap_destory(&timer->list);
	if (timer->use_pipe)
	{
		return timer->pipe.close(&timer->pipe);
	}
	else
	{
		return close(timer->fd);
	}
}

int swTimer_add(swTimer *timer, int ms)
{
	swTimer_node *node = sw_malloc(sizeof(swTimer_node));
	if (node == NULL)
	{
		swWarn("swTimer_add malloc fail");
		return SW_ERR;
	}
	bzero(node, sizeof(swTimer_node));
	node->lasttime = swTimer_get_ms();
	node->interval = ms;

	if(ms < timer->interval)
	{
		int new_interval = swoole_common_divisor(ms, timer->interval);
		timer->interval = new_interval;
#ifdef HAVE_TIMERFD
		swTimer_timerfd_set(timer, new_interval);
#else
		swTimer_signal_set(timer, new_interval);
#endif
	}
	swHashMap_add_int(&timer->list, ms, node);
	timer->num++;
	return SW_OK;
}

static int swTimer_select(swTimer *timer)
{
	void *tmp = NULL;
	uint64_t key;
	swTimer_node *timer_node;

	uint64_t now_ms = swTimer_get_ms();
	if (now_ms < 0)
	{
		return SW_ERR;
	}

	if (timer->onTimer == NULL)
	{
		swWarn("timer->onTimer is NULL");
		return SW_ERR;
	}

	while (1)
	{
		tmp = swHashMap_foreach_int(&timer->list, &key, (void **)&timer_node, tmp);
		//值为空
		if (timer_node == NULL)
		{
			break;
		}
		//swWarn("Timer=%ld|lasttime=%ld|now=%ld", key, timer_node->lasttime, now_ms);
		if (timer_node->lasttime < now_ms - timer_node->interval)
		{
			timer->onTimer(timer, timer_node->interval);
			timer_node->lasttime += timer_node->interval;
		}
		//遍历结束
		if (tmp == NULL)
		{
			break;
		}
	}
	return SW_OK;
}

int swTimer_event_handler(swReactor *reactor, swEvent *event)
{
	uint64_t exp;
	swTimer *timer = &SwooleG.timer;

	if (read(timer->fd, &exp, sizeof(uint64_t)) < 0)
	{
		return SW_ERR;
	}
	return swTimer_select(timer);
}

void swTimer_signal_handler(int sig)
{
	uint64_t flag = 1;
	switch (sig)
	{
	case SIGALRM:
		if (SwooleG.timer.use_pipe == 1)
		{
			SwooleG.timer.pipe.write(&SwooleG.timer.pipe, &flag, sizeof(flag));
		}
		break;
	default:
		break;
	}
}

SWINLINE uint64_t swTimer_get_ms()
{
	struct timeval now;
	if (gettimeofday(&now, NULL) < 0)
	{
		swWarn("gettimeofday fail.Error: %s[%d]", strerror(errno), errno);
		return SW_ERR;
	}
	return (now.tv_sec * 1000) + (now.tv_usec / 1000);
}
