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

static long swEventTimer_add(swTimer *timer, int _msec, int interval, void *data);
static void* swEventTimer_del(swTimer *timer, int _msec, int id);
static int swEventTimer_select(swTimer *timer);
static void swEventTimer_free(swTimer *timer);

static sw_inline int swEventTimer_get_relative_msec()
{
    struct timeval now;
    if (gettimeofday(&now, NULL) < 0)
    {
        swSysError("gettimeofday() failed.");
        return SW_ERR;
    }
    int msec1 = (now.tv_sec - SwooleG.timer.basetime.tv_sec) * 1000;
    int msec2 = (now.tv_usec - SwooleG.timer.basetime.tv_usec) / 1000;
    return msec1 + msec2;
}

int swEventTimer_init()
{
    if (gettimeofday(&SwooleG.timer.basetime, NULL) < 0)
    {
        swSysError("gettimeofday() failed.");
        return SW_ERR;
    }

    SwooleG.timer.fd = 1;
    SwooleG.timer.add = swEventTimer_add;
    SwooleG.timer.del = swEventTimer_del;
    SwooleG.timer.select = swEventTimer_select;
    SwooleG.timer.free = swEventTimer_free;

    SwooleG.main_reactor->check_timer = SW_TRUE;

    return SW_OK;
}

static void swEventTimer_free(swTimer *timer)
{
    if (timer->root)
    {
        swTimer_node_destory(&timer->root);
    }
}

static long swEventTimer_add(swTimer *timer, int _msec, int interval, void *data)
{
    swTimer_node *node = sw_malloc(sizeof(swTimer_node));
    if (!node)
    {
        swSysError("malloc(%d) failed.", (int )sizeof(swTimer_node));
        return SW_ERR;
    }

    int now_msec = swEventTimer_get_relative_msec();
    if (now_msec < 0)
    {
        return SW_ERR;
    }

    node->data = data;
    node->exec_msec = now_msec + _msec;
    node->interval = interval ? _msec : 0;
    node->remove = 0;

    if (SwooleG.main_reactor->timeout_msec > _msec)
    {
        SwooleG.main_reactor->timeout_msec = _msec;
    }

    swTimer_node_insert(&timer->root, node);
    node->id = timer->_next_id++;

    return node->id;
}

static void* swEventTimer_del(swTimer *timer, int _msec, int id)
{
    swTimer_node *del = swTimer_node_find(&timer->root, _msec, id);
    if (del)
    {
        del->remove = 1;
        void *data = del->data;
        del->data = NULL;
        return data;
    }
    else
    {
        return NULL;
    }
}

static int swEventTimer_select(swTimer *timer)
{
    int now_msec = swEventTimer_get_relative_msec();
    if (now_msec < 0)
    {
        return SW_ERR;
    }

    swTimer_node *tmp = timer->root;
    swTimer_node *free_node = NULL;

    while (tmp)
    {
        if (tmp->exec_msec > now_msec)
        {
            break;
        }
        else
        {
            if (!tmp->remove)
            {
                if (tmp->interval > 0)
                {
                    timer->onTimer(timer, tmp);
                }
                else
                {
                    timer->onTimeout(timer, tmp);
                }
            }

            timer->root = tmp->next;
            if (timer->root)
            {
                timer->root->prev = NULL;
            }

            if (tmp->interval > 0 && !tmp->remove)
            {
                tmp->exec_msec += tmp->interval;
                swTimer_node_insert(&timer->root, tmp);
            }
            else
            {
                free_node = tmp;
            }

            tmp = timer->root;
            if (free_node)
            {
                sw_free(free_node);
            }
        }
    }

    if (timer->root == NULL)
    {
        SwooleG.main_reactor->timeout_msec = -1;
    }
    else
    {
        SwooleG.main_reactor->timeout_msec = timer->root->exec_msec - now_msec;
    }
    return SW_OK;
}
