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

static int swTimer_init(swTimer *timer, long msec);

int swTimer_now(struct timeval *time)
{
#if defined(SW_USE_MONOTONIC_TIME) && defined(CLOCK_MONOTONIC)
    struct timespec _now;
    if (clock_gettime(CLOCK_MONOTONIC, &_now) < 0)
    {
        swSysWarn("clock_gettime(CLOCK_MONOTONIC) failed");
        return SW_ERR;
    }
    time->tv_sec = _now.tv_sec;
    time->tv_usec = _now.tv_nsec / 1000;
#else
    if (gettimeofday(time, NULL) < 0)
    {
        swSysWarn("gettimeofday() failed");
        return SW_ERR;
    }
#endif
    return SW_OK;
}

static int swReactorTimer_set(swTimer *timer, long exec_msec)
{
    timer->reactor->timeout_msec = exec_msec;
    return SW_OK;
}

static void swReactorTimer_close(swTimer *timer)
{
    if (SwooleG.main_reactor)
    {
        SwooleG.main_reactor->check_timer = SW_FALSE;
        swReactorTimer_set(timer, -1);
    }
}

static int swReactorTimer_init(swReactor *reactor, swTimer *timer, long exec_msec)
{
    reactor->check_timer = SW_TRUE;
    reactor->timeout_msec = exec_msec;
    timer->reactor = reactor;
    timer->set = swReactorTimer_set;
    timer->close = swReactorTimer_close;

    swReactor_add_destroy_callback(reactor, (swCallback) swTimer_free, timer);

    return SW_OK;
}

static int swTimer_init(swTimer *timer, long msec)
{
    if (swTimer_now(&timer->basetime) < 0)
    {
        return SW_ERR;
    }

    timer->heap = swHeap_new(1024, SW_MIN_HEAP);
    if (!timer->heap)
    {
        return SW_ERR;
    }

    timer->map = swHashMap_new(SW_HASHMAP_INIT_BUCKET_N, NULL);
    if (!timer->map)
    {
        swHeap_free(timer->heap);
        timer->heap = NULL;
        return SW_ERR;
    }

    timer->_current_id = -1;
    timer->_next_msec = msec;
    timer->_next_id = 1;
    timer->round = 0;

    int ret;
    if (SwooleG.main_reactor)
    {
        ret = swReactorTimer_init(SwooleG.main_reactor, timer, msec);
    }
    else
    {
        ret = swSystemTimer_init(timer, msec);
    }
    if (sw_likely(ret == SW_OK))
    {
        timer->initialized = 1;
    }
    else
    {
        swTimer_free(timer);
    }
    return ret;
}

static void swTimer_node_dtor(void *data)
{
    swTimer_node *tnode = (swTimer_node *) data;
    sw_free(tnode);
}

void swTimer_free(swTimer *timer)
{
    if (timer->close)
    {
        timer->close(timer);
    }
    if (timer->heap)
    {
        swHeap_free(timer->heap);
    }
    if (timer->map)
    {
        timer->map->dtor = swTimer_node_dtor;
        swHashMap_free(timer->map);
    }
    memset(timer, 0, sizeof(swTimer));
}

swTimer_node* swTimer_add(swTimer *timer, long _msec, int interval, void *data, swTimerCallback callback)
{
    if (sw_unlikely(!timer->initialized))
    {
        if (sw_unlikely(swTimer_init(timer, _msec) != SW_OK))
        {
            return NULL;
        }
    }

    if (sw_unlikely(_msec <= 0))
    {
        swoole_error_log(SW_LOG_WARNING, SW_ERROR_INVALID_PARAMS, "msec value[%ld] is invalid", _msec);
        return NULL;
    }

    swTimer_node *tnode = sw_malloc(sizeof(swTimer_node));
    if (sw_unlikely(!tnode))
    {
        swSysWarn("malloc(%ld) failed", sizeof(swTimer_node));
        return NULL;
    }

    int64_t now_msec = swTimer_get_relative_msec();
    if (sw_unlikely(now_msec < 0))
    {
        sw_free(tnode);
        return NULL;
    }

    tnode->data = data;
    tnode->type = SW_TIMER_TYPE_KERNEL;
    tnode->exec_msec = now_msec + _msec;
    tnode->interval = interval ? _msec : 0;
    tnode->removed = 0;
    tnode->callback = callback;
    tnode->round = timer->round;
    tnode->dtor = NULL;

    if (timer->_next_msec < 0 || timer->_next_msec > _msec)
    {
        timer->set(timer, _msec);
        timer->_next_msec = _msec;
    }

    tnode->id = timer->_next_id++;
    if (sw_unlikely(tnode->id < 0))
    {
        tnode->id = 1;
        timer->_next_id = 2;
    }

    tnode->heap_node = swHeap_push(timer->heap, tnode->exec_msec, tnode);
    if (sw_unlikely(tnode->heap_node == NULL))
    {
        sw_free(tnode);
        return NULL;
    }
    if (sw_unlikely(swHashMap_add_int(timer->map, tnode->id, tnode) != SW_OK))
    {
        sw_free(tnode);
        return NULL;
    }
    timer->num++;
    swTraceLog(SW_TRACE_TIMER, "id=%ld, exec_msec=%" PRId64 ", msec=%ld, round=%" PRIu64 ", exist=%u", tnode->id, tnode->exec_msec, _msec, tnode->round, timer->num);
    return tnode;
}

enum swBool_type swTimer_del(swTimer *timer, swTimer_node *tnode)
{
    if (sw_unlikely(!tnode || tnode->removed))
    {
        return SW_FALSE;
    }
    if (sw_unlikely(timer->_current_id > 0 && tnode->id == timer->_current_id))
    {
        tnode->removed = 1;
        swTraceLog(SW_TRACE_TIMER, "set-remove: id=%ld, exec_msec=%" PRId64 ", round=%" PRIu64 ", exist=%u", tnode->id, tnode->exec_msec, tnode->round, timer->num);
        return SW_TRUE;
    }
    if (sw_unlikely(swHashMap_del_int(timer->map, tnode->id) < 0))
    {
        return SW_FALSE;
    }
    if (tnode->heap_node)
    {
        swHeap_remove(timer->heap, tnode->heap_node);
        sw_free(tnode->heap_node);
    }
    if (tnode->dtor)
    {
        tnode->dtor(tnode);
    }
    timer->num--;
    swTraceLog(SW_TRACE_TIMER, "id=%ld, exec_msec=%" PRId64 ", round=%" PRIu64 ", exist=%u", tnode->id, tnode->exec_msec, tnode->round, timer->num);
    sw_free(tnode);
    return SW_TRUE;
}

int swTimer_select(swTimer *timer)
{
    swTimer_node *tnode = NULL;
    swHeap_node *tmp;
    int64_t now_msec = swTimer_get_relative_msec();

    if (sw_unlikely(now_msec < 0))
    {
        return SW_ERR;
    }

    swTraceLog(SW_TRACE_TIMER, "timer msec=%" PRId64 ", round=%" PRId64, now_msec, timer->round);
    while ((tmp = swHeap_top(timer->heap)))
    {
        tnode = tmp->data;
        if (tnode->exec_msec > now_msec || tnode->round == timer->round)
        {
            break;
        }

        timer->_current_id = tnode->id;
        if (!tnode->removed)
        {
            swTraceLog(SW_TRACE_TIMER, "id=%ld, exec_msec=%" PRId64 ", round=%" PRIu64 ", exist=%u", tnode->id, tnode->exec_msec, tnode->round, timer->num - 1);
            tnode->callback(timer, tnode);
        }
        timer->_current_id = -1;

        //persistent timer
        if (tnode->interval > 0 && !tnode->removed)
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
        swHashMap_del_int(timer->map, tnode->id);
        sw_free(tnode);
    }

    if (!tnode || !tmp)
    {
        timer->_next_msec = -1;
        timer->set(timer, -1);
    }
    else
    {
        long next_msec = tnode->exec_msec - now_msec;
        if (next_msec <= 0)
        {
            next_msec = 1;
        }
        timer->set(timer, next_msec);
    }
    timer->round++;

    return SW_OK;
}
