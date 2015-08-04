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
static void* swEventTimer_del(swTimer *timer, int _msec, long id);
static int swEventTimer_select(swTimer *timer);
static void swEventTimer_free(swTimer *timer);

static sw_inline void* swEventTimer_remove(swTimer *timer, swTimer_node *delete_node)
{
    if (delete_node->remove)
    {
        return NULL;
    }
    if (swArray_append(timer->delete_list, &delete_node) < 0)
    {
        return NULL;
    }
    delete_node->remove = 1;
    return delete_node->data;
}

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

    SwooleG.timer.delete_list = swArray_new(1024, sizeof(void *));
    if (SwooleG.timer.delete_list == NULL)
    {
        return SW_ERR;
    }

    SwooleG.timer.insert_list = swArray_new(1024, sizeof(void *));
    if (SwooleG.timer.insert_list == NULL)
    {
        return SW_ERR;
    }

    SwooleG.timer._delete_id = -1;
    SwooleG.timer._current_id = -1;
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
    if (interval)
    {
        node->restart = 1;
    }

    if (SwooleG.main_reactor->timeout_msec > _msec)
    {
        SwooleG.main_reactor->timeout_msec = _msec;
    }

    node->id = timer->_next_id++;
    timer->num ++;

    if (timer->lock)
    {
        swArray_append(timer->insert_list, &node);
    }
    else
    {
        swTimer_node_insert(&timer->root, node);
    }

    return node->id;
}

static void* swEventTimer_del(swTimer *timer, int _msec, long id)
{
    swTimer_node *delete_node = swTimer_node_find(&timer->root, _msec, id);
    if (!delete_node)
    {
        return NULL;
    }
    delete_node->restart = 0;
    return swEventTimer_remove(timer, delete_node);
}

static int swEventTimer_select(swTimer *timer)
{
    int now_msec = swEventTimer_get_relative_msec();
    if (now_msec < 0)
    {
        return SW_ERR;
    }

    swTimer_node *tmp = timer->root;
    int i;

    /**
     * cannot update the timer queue
     */
    timer->lock = 1;
    while (tmp)
    {
        if (tmp->exec_msec > now_msec)
        {
            break;
        }

        if (tmp->remove)
        {
            tmp = tmp->next;
            continue;
        }

        if (tmp->interval > 0)
        {
            timer->onTimer(timer, tmp);
            if (!tmp->remove)
            {
                tmp->restart = 1;
                int _now_msec = swEventTimer_get_relative_msec();
                if (_now_msec > 0)
                {
                    tmp->exec_msec = _now_msec + tmp->interval;
                }
                else
                {
                    tmp->exec_msec = now_msec + tmp->interval;
                }
            }
        }
        else
        {
            timer->onTimeout(timer, tmp);
        }

        swEventTimer_remove(timer, tmp);
        tmp = tmp->next;
    }
    timer->lock = 0;

    if (timer->delete_list->item_num > 0)
    {
        for (i = 0; i < timer->delete_list->item_num; i++)
        {
            tmp = *((swTimer_node **) swArray_fetch(timer->delete_list, i));
            if (tmp)
            {
                swTimer_node_delete(&timer->root, tmp);
                if (tmp->restart)
                {
                    tmp->remove = 0;
                    swTimer_node_insert(&timer->root, tmp);
                }
                else
                {
                    sw_free(tmp);
                    timer->num--;
                }
            }
        }
        swArray_clear(timer->delete_list);
    }

    if (timer->insert_list->item_num > 0)
    {
        for (i = 0; i < timer->insert_list->item_num; i++)
        {
            tmp = *((swTimer_node **) swArray_fetch(timer->insert_list, i));
            if (tmp)
            {
                swTimer_node_insert(&timer->root, tmp);
            }
        }
        swArray_clear(timer->insert_list);
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
