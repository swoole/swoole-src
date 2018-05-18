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

static int swReactorTimer_init(long msec);
static int swReactorTimer_set(swTimer *timer, long exec_msec);
static swTimer_node* swTimer_add(swTimer *timer, int _msec, int interval, void *data, swTimerCallback callback);

int swTimer_now(struct timeval *time)
{
#if defined(SW_USE_MONOTONIC_TIME) && defined(CLOCK_MONOTONIC)
    struct timespec _now;
    if (clock_gettime(CLOCK_MONOTONIC, &_now) < 0)
    {
        swSysError("clock_gettime(CLOCK_MONOTONIC) failed.");
        return SW_ERR;
    }
    time->tv_sec = _now.tv_sec;
    time->tv_usec = _now.tv_nsec / 1000;
#else
    if (gettimeofday(time, NULL) < 0)
    {
        swSysError("gettimeofday() failed.");
        return SW_ERR;
    }
#endif
    return SW_OK;
}

static sw_inline int64_t swTimer_get_relative_msec()
{
    struct timeval now;
    if (swTimer_now(&now) < 0)
    {
        return SW_ERR;
    }
    int64_t msec1 = (now.tv_sec - SwooleG.timer.basetime.tv_sec) * 1000;
    int64_t msec2 = (now.tv_usec - SwooleG.timer.basetime.tv_usec) / 1000;
    return msec1 + msec2;
}

int swTimer_init(long msec)
{
    if (swTimer_now(&SwooleG.timer.basetime) < 0)
    {
        return SW_ERR;
    }


    SwooleG.timer.heap = swHeap_new(1024, SW_MIN_HEAP);
    if (!SwooleG.timer.heap)
    {
        return SW_ERR;
    }

    SwooleG.timer.map = swHashMap_new(SW_HASHMAP_INIT_BUCKET_N, NULL);
    if (!SwooleG.timer.map)
    {
        swHeap_free(SwooleG.timer.heap);
        SwooleG.timer.heap = NULL;
        return SW_ERR;
    }

    SwooleG.timer._current_id = -1;
    SwooleG.timer._next_msec = msec;
    SwooleG.timer._next_id = 1;
    SwooleG.timer.add = swTimer_add;

    if (swIsTaskWorker())
    {
        swSystemTimer_init(msec, SwooleG.use_timer_pipe);
    }
    else
    {
        swReactorTimer_init(msec);
    }

    return SW_OK;
}

void swTimer_free(swTimer *timer)
{
    if (timer->heap)
    {
        swHeap_free(timer->heap);
    }
}

static int swReactorTimer_init(long exec_msec)
{
    SwooleG.main_reactor->check_timer = SW_TRUE;
    SwooleG.main_reactor->timeout_msec = exec_msec;
    SwooleG.timer.set = swReactorTimer_set;
    SwooleG.timer.fd = -1;
    return SW_OK;
}

static int swReactorTimer_set(swTimer *timer, long exec_msec)
{
    SwooleG.main_reactor->timeout_msec = exec_msec;
    return SW_OK;
}

static swTimer_node* swTimer_add(swTimer *timer, int _msec, int interval, void *data, swTimerCallback callback)
{
    swTimer_node *tnode = sw_malloc(sizeof(swTimer_node));
    if (!tnode)
    {
        swSysError("malloc(%ld) failed.", sizeof(swTimer_node));
        return NULL;
    }

    int64_t now_msec = swTimer_get_relative_msec();
    if (now_msec < 0)
    {
        sw_free(tnode);
        return NULL;
    }

    tnode->data = data;
    tnode->type = SW_TIMER_TYPE_KERNEL;
    tnode->exec_msec = now_msec + _msec;
    tnode->interval = interval ? _msec : 0;
    tnode->remove = 0;
    tnode->callback = callback;

    if (timer->_next_msec < 0 || timer->_next_msec > _msec)
    {
        timer->set(timer, _msec);
        timer->_next_msec = _msec;
    }

    tnode->id = timer->_next_id++;
    if (unlikely(tnode->id < 0))
    {
        tnode->id = 1;
        timer->_next_id = 2;
    }
    timer->num++;

    tnode->heap_node = swHeap_push(timer->heap, tnode->exec_msec, tnode);
    if (tnode->heap_node == NULL)
    {
        sw_free(tnode);
        return NULL;
    }
    swHashMap_add_int(timer->map, tnode->id, tnode);
    return tnode;
}

int swTimer_del(swTimer *timer, swTimer_node *tnode)
{
    if (tnode->remove)
    {
        return SW_FALSE;
    }
    if (SwooleG.timer._current_id > 0 && tnode->id == SwooleG.timer._current_id)
    {
        tnode->remove = 1;
        return SW_TRUE;
    }
    if (swHashMap_del_int(timer->map, tnode->id) < 0)
    {
        return SW_ERR;
    }
    if (tnode->heap_node)
    {
        //remove from min-heap
        swHeap_remove(timer->heap, tnode->heap_node);
        sw_free(tnode->heap_node);
    }
    sw_free(tnode);
    timer->num --;
    return SW_TRUE;
}

int swTimer_select(swTimer *timer)
{
    int64_t now_msec = swTimer_get_relative_msec();
    if (now_msec < 0)
    {
        return SW_ERR;
    }

    swTimer_node *tnode = NULL;
    swHeap_node *tmp;
    long timer_id;

    while ((tmp = swHeap_top(timer->heap)))
    {
        tnode = tmp->data;
        if (tnode->exec_msec > now_msec)
        {
            break;
        }

        timer_id = timer->_current_id = tnode->id;
        if (!tnode->remove)
        {
            tnode->callback(timer, tnode);
        }
        timer->_current_id = -1;

        //persistent timer
        if (tnode->interval > 0 && !tnode->remove)
        {
            while (tnode->exec_msec <= now_msec)
            {
                tnode->exec_msec += tnode->interval;
            }
            swHeap_change_priority(timer->heap, tnode->exec_msec, tmp);
            continue;
        }

        timer->num--;
        swHeap_pop(timer->heap);
        swHashMap_del_int(timer->map, timer_id);
        sw_free(tnode);
    }

    if (!tnode || !tmp)
    {
        timer->_next_msec = -1;
        timer->set(timer, -1);
    }
    else
    {
        timer->set(timer, tnode->exec_msec - now_msec);
    }
    return SW_OK;
}
