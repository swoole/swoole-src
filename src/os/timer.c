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
#include "Server.h"

#ifdef HAVE_TIMERFD
#include <sys/timerfd.h>
#endif

static int swTimer_signal_set(swTimer *timer, int interval);
static int swTimer_timerfd_set(swTimer *timer, int interval);
static void* swTimer_del(swTimer *timer, int ms, long id);
static void swTimer_free(swTimer *timer);
static long swTimer_add(swTimer *timer, int msec, int interval, void *data);
static int swTimer_set(swTimer *timer, int new_interval);
static long swTimer_addtimeout(swTimer *timer, int timeout_ms, void *data);
static int swTimer_select(swTimer *timer);

/**
 * create timer
 */
int swTimer_init(int interval, int use_pipe)
{
    swTimer *timer = &SwooleG.timer;
    timer->interval = interval;
    timer->lasttime = interval;

#ifndef HAVE_TIMERFD
    SwooleG.use_timerfd = 0;
#endif

    timer->list = swHashMap_new(SW_HASHMAP_INIT_BUCKET_N, free);
    if (!timer->list)
    {
        return SW_ERR;
    }

    if (SwooleG.use_timerfd)
    {
        if (swTimer_timerfd_set(timer, interval) < 0)
        {
            return SW_ERR;
        }
        timer->use_pipe = 0;
    }
    else
    {
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

        if (swTimer_signal_set(timer, interval) < 0)
        {
            return SW_ERR;
        }
        swSignal_add(SIGALRM, swTimer_signal_handler);
    }

    if (timer->fd > 1)
    {
        SwooleG.main_reactor->setHandle(SwooleG.main_reactor, SW_FD_TIMER, swTimer_event_handler);
        SwooleG.main_reactor->add(SwooleG.main_reactor, SwooleG.timer.fd, SW_FD_TIMER);
    }

    timer->add = swTimer_add;
    timer->del = swTimer_del;
    timer->select = swTimer_select;
    timer->free = swTimer_free;
    return SW_OK;
}

/**
 * timerfd
 */
static int swTimer_timerfd_set(swTimer *timer, int interval)
{
#ifdef HAVE_TIMERFD
    struct timeval now;
    int sec = interval / 1000;
    int msec = (((float) interval / 1000) - sec) * 1000;

    if (gettimeofday(&now, NULL) < 0)
    {
        swWarn("gettimeofday() failed. Error: %s[%d]", strerror(errno), errno);
        return SW_ERR;
    }

    struct itimerspec timer_set;
    bzero(&timer_set, sizeof(timer_set));

    if (timer->fd == 0)
    {
        timer->fd = timerfd_create(CLOCK_REALTIME, TFD_NONBLOCK | TFD_CLOEXEC);
        if (timer->fd < 0)
        {
            swWarn("timerfd_create() failed. Error: %s[%d]", strerror(errno), errno);
            return SW_ERR;
        }
    }

    timer_set.it_interval.tv_sec = sec;
    timer_set.it_interval.tv_nsec = msec * 1000 * 1000;

    timer_set.it_value.tv_sec = now.tv_sec + sec;
    timer_set.it_value.tv_nsec = (now.tv_usec * 1000) + timer_set.it_interval.tv_nsec;

    if (timer_set.it_value.tv_nsec > 1e9)
    {
        timer_set.it_value.tv_nsec = timer_set.it_value.tv_nsec - 1e9;
        timer_set.it_value.tv_sec += 1;
    }

    if (timerfd_settime(timer->fd, TFD_TIMER_ABSTIME, &timer_set, NULL) == -1)
    {
        swWarn("timerfd_settime() failed. Error: %s[%d]", strerror(errno), errno);
        return SW_ERR;
    }
    return SW_OK;
#else
    swWarn("kernel not support timerfd.");
    return SW_ERR;
#endif
}

/**
 * setitimer
 */
static int swTimer_signal_set(swTimer *timer, int interval)
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

    memset(&timer_set, 0, sizeof(timer_set));
    timer_set.it_interval.tv_sec = sec;
    timer_set.it_interval.tv_usec = msec * 1000;

    timer_set.it_value.tv_sec = sec;
    timer_set.it_value.tv_usec = timer_set.it_interval.tv_usec;

    if (timer_set.it_value.tv_usec > 1e6)
    {
        timer_set.it_value.tv_usec = timer_set.it_value.tv_usec - 1e6;
        timer_set.it_value.tv_sec += 1;
    }

    if (setitimer(ITIMER_REAL, &timer_set, NULL) < 0)
    {
        swWarn("setitimer() failed. Error: %s[%d]", strerror(errno), errno);
        return SW_ERR;
    }
    return SW_OK;
}

static void* swTimer_del(swTimer *timer, int interval_ms, long id)
{
    swTimer_node *node = swTimer_node_find(&timer->root, interval_ms, id);
    if (!node)
    {
        return NULL;
    }
    if (interval_ms)
    {
        swHashMap_del_int(timer->list, interval_ms);
    }
    node->remove = 1;
    return node->data;
}

static void swTimer_free(swTimer *timer)
{
    swHashMap_free(timer->list);

    if (timer->use_pipe)
    {
        timer->pipe.close(&timer->pipe);
    }
    else if (timer->fd > 2)
    {
        if (close(timer->fd) < 0)
        {
            swSysError("close(%d) failed.", timer->fd);
        }
    }

    if (timer->root)
    {
        swTimer_node_destory(&timer->root);
    }
}

static int swTimer_set(swTimer *timer, int new_interval)
{
    if (SwooleG.use_timerfd)
    {
        return swTimer_timerfd_set(timer, new_interval);
    }
    else
    {
        return swTimer_signal_set(timer, new_interval);
    }
}

static long swTimer_add(swTimer *timer, int msec, int interval, void *data)
{
    if (interval == 0)
    {
        return swTimer_addtimeout(timer, msec, data);
    }
    swTimer_node *node = sw_malloc(sizeof(swTimer_node));
    if (node == NULL)
    {
        swWarn("malloc failed.");
        return SW_ERR;
    }

    bzero(node, sizeof(swTimer_node));
    node->interval = msec;
    if (gettimeofday(&node->lasttime, NULL) < 0)
    {
        swSysError("gettimeofday() failed.");
        return SW_ERR;
    }
    if (msec < timer->interval)
    {
        int new_interval = swoole_common_divisor(msec, timer->interval);
        timer->interval = new_interval;
        swTimer_set(timer, new_interval);
    }
    swHashMap_add_int(timer->list, msec, node, NULL);
    timer->num++;
    return SW_OK;
}

int swTimer_select(swTimer *timer)
{
    uint64_t key;
    swTimer_node *timer_node;
    struct timeval now;

    if (gettimeofday(&now, NULL) < 0)
    {
        swSysError("gettimeofday() failed.");
        return SW_ERR;
    }
    //swWarn("%d.%d", now.tv_sec, now.tv_usec);

    if (timer->onTimeout == NULL)
    {
        swWarn("timer->onTimeout is NULL");
        return SW_ERR;
    }
    /**
     * timeout task list
     */
    uint32_t now_ms = now.tv_sec * 1000 + now.tv_usec / 1000;
    swTimer_node *tmp = timer->root;
    while (tmp)
    {
        if (tmp->exec_msec > now_ms)
        {
            break;
        }
        else
        {
            timer->onTimeout(timer, tmp->data);
            timer->root = tmp->next;
            sw_free(tmp);
            tmp = timer->root;
        }
    }

    if (timer->onTimer == NULL)
    {
        swWarn("timer->onTimer is NULL");
        return SW_ERR;
    }
    uint32_t interval = 0;
    do
    {
        //swWarn("timer foreach start\n----------------------------------------------");
        timer_node = swHashMap_each_int(timer->list, &key);

        //hashmap empty
        if (timer_node == NULL)
        {
            break;
        }
        //the interval time(ms)
        interval = (now.tv_sec - timer_node->lasttime.tv_sec) * 1000 + (now.tv_usec - timer_node->lasttime.tv_usec) / 1000;

        /**
         * deviation 1ms
         */
        if (interval >= timer_node->interval - 1)
        {
            memcpy(&timer_node->lasttime, &now, sizeof(now));
            timer->onTimer(timer, timer_node);
        }
    } while (timer_node);
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
    SwooleG.signal_alarm = 0;
    return swTimer_select(timer);
}

void swTimer_signal_handler(int sig)
{
    SwooleG.signal_alarm = 1;
    uint64_t flag = 1;

    if (SwooleG.timer.use_pipe)
    {
        SwooleG.timer.pipe.write(&SwooleG.timer.pipe, &flag, sizeof(flag));
    }
}

long swTimer_addtimeout(swTimer *timer, int timeout_ms, void *data)
{
    int new_interval = swoole_common_divisor(timeout_ms, timer->interval);
    if (new_interval < timer->interval)
    {
        swTimer_set(timer, new_interval);
        timer->interval = new_interval;
    }

    struct timeval now;
    if (gettimeofday(&now, NULL) < 0)
    {
        swWarn("gettimeofday() failed. Error: %s[%d]", strerror(errno), errno);
        return SW_ERR;
    }

    uint32_t now_ms = now.tv_sec * 1000 + now.tv_usec / 1000;
    swTimer_node *node = sw_malloc(sizeof(swTimer_node));
    if (node == NULL)
    {
        swWarn("malloc(%d) failed. Error: %s[%d]", (int ) sizeof(swTimer_node), strerror(errno), errno);
        return SW_ERR;
    }

    bzero(node, sizeof(swTimer_node));
    node->data = data;
    node->exec_msec = now_ms + timeout_ms;
    node->id = timer->_next_id++;
    swTimer_node_insert(&timer->root, node);

    return node->id;
}

void swTimer_node_insert(swTimer_node **root, swTimer_node *new_node)
{
    new_node->next = NULL;
    new_node->prev = NULL;

    if (*root == NULL)
    {
        *root = new_node;
        return;
    }

    swTimer_node *tmp = *root;
    while (1)
    {
        if (tmp->exec_msec > new_node->exec_msec)
        {
            new_node->prev = tmp->prev;
            new_node->next = tmp;

            if (new_node->prev)
            {
                new_node->prev->next = new_node;
            }

            tmp->prev = new_node;
            if (tmp == *root)
            {
                *root = new_node;
            }
            break;
        }
        else if (tmp->next)
        {
            tmp = tmp->next;
        }
        else
        {
            tmp->next = new_node;
            new_node->prev = tmp;
            break;
        }
    }
}

swTimer_node* swTimer_node_find(swTimer_node **root, int interval_msec, long id)
{
    swTimer_node *tmp = *root;
    while (tmp)
    {
        if (interval_msec < 0)
        {
            if (tmp->id == id)
            {
                return tmp;
            }
        }
        else
        {
            if (tmp->interval == interval_msec)
            {
                return tmp;
            }
        }
        tmp = tmp->next;
    }
    return NULL;
}

void swTimer_node_delete(swTimer_node **root, swTimer_node *node)
{
    swTimer_node *prev = node->prev;
    swTimer_node *next = node->next;

    if (prev == NULL && next == NULL)
    {
        *root = NULL;
        return;
    }
    if (prev == NULL)
    {
        next->prev = NULL;
        *root = next;
        return;
    }
    if (next == NULL)
    {
        prev->next = NULL;
        return;
    }
    prev->next = next;
    next->prev = prev;
}

void swTimer_node_destory(swTimer_node **root)
{
    swTimer_node *tmp, *node = *root;
    while (node)
    {
        tmp = node;
        node = node->next;
        sw_free(tmp);
    }
}

void swTimer_node_print(swTimer_node **root)
{
    swTimer_node *tmp = *root;
    while (tmp)
    {
        printf("TimerNode: when=%d, interval=%d\n", tmp->exec_msec, tmp->interval);
        tmp = tmp->next;
    }
}
