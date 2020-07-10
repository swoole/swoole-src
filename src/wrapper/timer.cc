/**
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

#include "swoole_api.h"
#include "swoole_timer.h"
#include "swoole_log.h"

using namespace std;
using namespace swoole;

#ifdef __MACH__
swTimer* sw_timer()
{
    return SwooleTG.timer;
}
#endif

swTimer_node *swTimer_add(swTimer *timer, long _msec, int interval, void *data, swTimerCallback callback);

swTimer_node *swoole_timer_add(long ms, uchar persistent, swTimerCallback callback, void *private_data)
{
    if (sw_unlikely(SwooleTG.timer == nullptr))
    {
        SwooleTG.timer = (swTimer *) sw_malloc(sizeof(swTimer));
        if (sw_unlikely(SwooleTG.timer == nullptr))
        {
            return nullptr;
        }
        if (sw_unlikely(swTimer_init(SwooleTG.timer, ms) != SW_OK))
        {
            sw_free(SwooleTG.timer);
            SwooleTG.timer = nullptr;
            return nullptr;
        }
    }
    return swTimer_add(SwooleTG.timer, ms, persistent, private_data, callback);
}

bool swoole_timer_del(swTimer_node* tnode)
{
    return swTimer_del(SwooleTG.timer, tnode);
}

long swoole_timer_after(long ms, swTimerCallback callback, void *private_data)
{
    if (ms <= 0)
    {
        swWarn("Timer must be greater than 0");
        return SW_ERR;
    }
    swTimer_node *tnode = swoole_timer_add(ms, SW_FALSE, callback, private_data);
    if (tnode == nullptr)
    {
        return SW_ERR;
    }
    else
    {
        return tnode->id;
    }
}

long swoole_timer_tick(long ms, swTimerCallback callback, void *private_data)
{
    if (ms <= 0)
    {
        swWarn("Timer must be greater than 0");
        return SW_ERR;
    }
    swTimer_node *tnode = swoole_timer_add(ms, SW_TRUE, callback, private_data);
    if (tnode == nullptr)
    {
        return SW_ERR;
    }
    else
    {
        return tnode->id;
    }
}

bool swoole_timer_exists(long timer_id)
{
    if (!SwooleTG.timer)
    {
        swWarn("no timer");
        return false;
    }
    swTimer_node *tnode = swTimer_get(SwooleTG.timer, timer_id);
    return (tnode && !tnode->removed);
}

bool swoole_timer_clear(long timer_id)
{
    return swTimer_del(SwooleTG.timer, swTimer_get(SwooleTG.timer, timer_id));
}

swTimer_node *swoole_timer_get(long timer_id)
{
    if (!SwooleTG.timer)
    {
        swWarn("no timer");
        return nullptr;
    }
    return swTimer_get(SwooleTG.timer, timer_id);
}

void swoole_timer_free()
{
    if (!SwooleTG.timer)
    {
        return;
    }
    swTimer_free(SwooleTG.timer);
    sw_free(SwooleTG.timer);
    SwooleTG.timer = nullptr;
}

int swoole_timer_select()
{
    if (!SwooleTG.timer)
    {
        return SW_ERR;
    }
    return swTimer_select(SwooleTG.timer);
}
