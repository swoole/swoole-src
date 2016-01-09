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

static sw_inline int64_t swTimer_get_relative_msec()
{
    struct timeval now;
    if (gettimeofday(&now, NULL) < 0)
    {
        swSysError("gettimeofday() failed.");
        return SW_ERR;
    }
    int64_t msec1 = (now.tv_sec - SwooleG.timer.basetime.tv_sec) * 1000;
    int64_t msec2 = (now.tv_usec - SwooleG.timer.basetime.tv_usec) / 1000;
    return msec1 + msec2;
}

int swTimer_init(long msec)
{
    if (SwooleGS->start && !swIsWorker() && !swIsTaskWorker())
    {
        swWarn("cannot use timer.");
        return SW_ERR;
    }

    if (gettimeofday(&SwooleG.timer.basetime, NULL) < 0)
    {
        swSysError("gettimeofday() failed.");
        return SW_ERR;
    }

    SwooleG.timer.queue = swLinkedList_new(1, NULL);
    if (!SwooleG.timer.queue)
    {
        return SW_ERR;
    }

    SwooleG.timer.map = swHashMap_new(1024, NULL);
    if (!SwooleG.timer.map)
    {
        return SW_ERR;
    }

    SwooleG.timer._current_id = -1;
    SwooleG.timer._next_msec = msec;
    SwooleG.timer._next_id = 1;

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
    if (timer->queue)
    {
        swLinkedList_free(timer->queue);
    }
    if (timer->map)
    {
        swHashMap_free(timer->map);
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

long swTimer_add(swTimer *timer, int _msec, int interval, void *data)
{
    swTimer_node *tnode = sw_malloc(sizeof(swTimer_node));
    if (!tnode)
    {
        swSysError("malloc(%ld) failed.", sizeof(swTimer_node));
        return SW_ERR;
    }

    int64_t now_msec = swTimer_get_relative_msec();
    if (now_msec < 0)
    {
        return SW_ERR;
    }

    tnode->data = data;
    tnode->exec_msec = now_msec + _msec;
    tnode->interval = interval ? _msec : 0;
    tnode->remove = 0;

    if (timer->_next_msec > _msec)
    {
        timer->set(timer, _msec);
    }

    tnode->id = timer->_next_id++;
    timer->num++;

    swLinkedList_node *lnode = swLinkedList_insert(timer->queue, tnode->exec_msec, tnode);
    if (!lnode)
    {
        sw_free(tnode);
        return SW_ERR;
    }
    tnode->lnode = lnode;
    swHashMap_add_int(timer->map, tnode->id, tnode);
    return tnode->id;
}

swTimer_node* swTimer_get(swTimer *timer, long id)
{
    return swHashMap_find_int(timer->map, id);
}

void swTimer_del(swTimer *timer, swTimer_node *node)
{
    swHashMap_del_int(timer->map, node->id);
    swLinkedList_remove_node(timer->queue, node->lnode);
    sw_free(node);
}

int swTimer_select(swTimer *timer)
{
    int64_t now_msec = swTimer_get_relative_msec();
    if (now_msec < 0)
    {
        return SW_ERR;
    }

    swLinkedList_node *tmp;
    swTimer_node *node;

    while (1)
    {
        tmp = timer->queue->head;
        if (!tmp)
        {
            break;
        }
        node = tmp->data;
        if (node->exec_msec > now_msec)
        {
            break;
        }

        //remove from list
        swLinkedList_remove_node(timer->queue, tmp);

        //tick timer
        if (node->interval > 0)
        {
            timer->onTick(timer, node);
            if (!node->remove)
            {
                int64_t _now_msec = swTimer_get_relative_msec();
                if (_now_msec > 0)
                {
                    node->exec_msec = _now_msec + node->interval;
                }
                else
                {
                    node->exec_msec = now_msec + node->interval;
                }
                swLinkedList_insert(timer->queue, node->exec_msec, node);
            }
        }
        //after timer
        else
        {
            timer->onAfter(timer, node);
        }
    }

    long next_msec;
    if (timer->queue->head == NULL)
    {
        next_msec = -1;
    }
    else
    {
        swTimer_node *node = timer->queue->head->data;
        next_msec = node->exec_msec - now_msec;
    }
    return timer->set(timer, next_msec);
}
