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

#ifdef SW_USE_TIMEWHEEL

swTimeWheel* swTimeWheel_new(uint16_t size)
{
    swTimeWheel *tw = sw_malloc(sizeof(swTimeWheel));
    if (!tw)
    {
        swWarn("malloc(%ld) failed.", sizeof(swTimeWheel));
        return NULL;
    }

    tw->size = size;
    tw->current = 0;
    tw->wheel = sw_calloc(size, sizeof(void*));
    if (tw->wheel == NULL)
    {
        swWarn("malloc(%ld) failed.", sizeof(void*) * size);
        sw_free(tw);
        return NULL;
    }

    int i;
    for (i = 0; i < size; i++)
    {
        tw->wheel[i] = swHashMap_new(16, NULL);
        if (tw->wheel[i] == NULL)
        {
            swTimeWheel_free(tw);
            return NULL;
        }
    }
    return tw;
}

void swTimeWheel_free(swTimeWheel *tw)
{
    int i;
    for (i = 0; i < tw->size; i++)
    {
        if (tw->wheel[i] != NULL)
        {
            swHashMap_free(tw->wheel[i]);
            tw->wheel[i] = NULL;
        }
    }
    sw_free(tw->wheel);
    sw_free(tw);
}

void swTimeWheel_forward(swTimeWheel *tw, swReactor *reactor)
{
    swHashMap *set = tw->wheel[tw->current];
    tw->current = tw->current == tw->size - 1 ? 0 : tw->current + 1;

    swTraceLog(SW_TRACE_REACTOR, "current=%d.", tw->current);

    swConnection *conn;
    uint64_t fd;

    while (1)
    {
        conn = swHashMap_each_int(set, &fd);
        if (conn == NULL)
        {
            break;
        }

        conn->close_force = 1;
        conn->close_notify = 1;
        conn->close_wait = 1;
        conn->close_actively = 1;

        //notify to reactor thread
        if (conn->removed)
        {
            reactor->close(reactor, (int) fd);
        }
        else
        {
            reactor->set(reactor, fd, SW_FD_TCP | SW_EVENT_WRITE);
        }
    }
}

void swTimeWheel_add(swTimeWheel *tw, swConnection *conn)
{
    uint16_t index = tw->current == 0 ? tw->size - 1 : tw->current - 1;
    swHashMap *new_set = tw->wheel[index];
    swHashMap_add_int(new_set, conn->fd, conn);

    conn->timewheel_index = index;

    swTraceLog(SW_TRACE_REACTOR, "current=%d, fd=%d, index=%d.", tw->current, conn->fd, index);
}

void swTimeWheel_update(swTimeWheel *tw, swConnection *conn)
{
    uint16_t new_index = swTimeWheel_new_index(tw);
    swHashMap *new_set = tw->wheel[new_index];
    swHashMap_add_int(new_set, conn->fd, conn);

    swHashMap *old_set = tw->wheel[conn->timewheel_index];
    swHashMap_del_int(old_set, conn->fd);

    swTraceLog(SW_TRACE_REACTOR, "current=%d, fd=%d, old_index=%d, new_index=%d.", tw->current, conn->fd, new_index, conn->timewheel_index);

    conn->timewheel_index = new_index;
}

void swTimeWheel_remove(swTimeWheel *tw, swConnection *conn)
{
    swHashMap *set = tw->wheel[conn->timewheel_index];
    swHashMap_del_int(set, conn->fd);
    swTraceLog(SW_TRACE_REACTOR, "current=%d, fd=%d.", tw->current, conn->fd);
}

#endif
