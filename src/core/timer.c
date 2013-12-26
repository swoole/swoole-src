#include "swoole.h"
#include "Server.h"

int swTimer_start(swTimer *timer, int interval_ms)
{
	struct timeval now;
	if (gettimeofday(&now, NULL) < 0)
	{
		swWarn("malloc fail\n");
		return SW_ERR;
	}
	timer->interval_ms = interval_ms;
	timer->lasttime = interval_ms;

	int sec = interval_ms / 1000;
	int msec = (((float) interval_ms / 1000) - sec) * 1000;
#ifdef HAVE_TIMERFD
	struct itimerspec timer_set;
	memset(&timer_set, 0, sizeof(timer_set));
	timer->fd = timerfd_create(CLOCK_REALTIME, TFD_NONBLOCK | TFD_CLOEXEC);
	if (timer->fd < 0)
	{
		swError("create timerfd fail\n");
		return SW_ERR;
	}
	timer_set.it_value.tv_sec = now.tv_sec + sec;
	timer_set.it_value.tv_nsec = now.tv_usec + msec * 1000;
	timer_set.it_interval.tv_sec = sec;
	timer_set.it_interval.tv_nsec = msec * 1000 * 1000;
	if (timerfd_settime(timer->fd, TFD_TIMER_ABSTIME, &timer_set, NULL) == -1)
	{
		swWarn("set timer fail\n");
		return SW_ERR;
	}
	timer->use_pipe = 0;
#else
	struct itimerval timer_set;
	int ret;
	//eventfd是2.6.26提供的,timerfd是2.6.27提供的
#ifdef HAVE_EVENTFD
	ret = swPipeEventfd_create(&timer->pipe, 0, 0);
#else
	ret = swPipeBase_create(&timer->pipe, 0);
#endif
	if (ret < 0)
	{
		swWarn("create timer pipe fail");
		return SW_ERR;
	}
	memset(&timer_set, 0, sizeof(timer_set));
	timer_set.it_value.tv_sec = sec;
	timer_set.it_value.tv_usec = msec * 1000;
	timer_set.it_interval.tv_sec = sec;
	timer_set.it_interval.tv_usec = msec * 1000;
	if (setitimer(ITIMER_REAL, &timer_set, NULL) < 0)
	{
		swWarn("set timer fail");
		return SW_ERR;
	}
	timer->fd = timer->pipe.getFd(&timer->pipe, 0);
	timer->use_pipe = 1;
#endif
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
	swHashMap_add_int(&timer->list, ms, node);
	timer->num++;
	return SW_OK;
}

int swTimer_select(swTimer *timer, swServer *serv)
{
	void *tmp = NULL;
	uint64_t key;
	swTimer_node *timer_node;

	time_t now_ms = swTimer_get_ms();
	if (now_ms < 0)
	{
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
			serv->onTimer(serv, timer_node->interval);
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

SWINLINE time_t swTimer_get_ms()
{
	struct timeval now;
	if (gettimeofday(&now, NULL) < 0)
	{
		swWarn("gettimeofday fail.Error: %s[%d]", strerror(errno), errno);
		return SW_ERR;
	}
	return (now.tv_sec * 1000) + (now.tv_usec / 1000);
}
