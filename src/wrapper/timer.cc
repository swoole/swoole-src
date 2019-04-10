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

#include "api.h"
#include "wrapper/base.hpp"
#include "server.h"

using namespace std;
using namespace swoole;

long swoole_timer_add(long ms, uchar persistent, swTimerCallback callback, void *private_data)
{
    if (ms <= 0)
    {
        swWarn("Timer must be greater than 0");
        return SW_ERR;
    }

    swTimer_node *tnode = swTimer_add(&SwooleG.timer, ms, persistent, private_data, callback);
    if (tnode == nullptr)
    {
        swWarn("addtimer failed");
        return SW_ERR;
    }
    else
    {
        return tnode->id;
    }
}

long swoole_timer_after(long ms, swTimerCallback callback, void *private_data)
{
    return swoole_timer_add(ms, SW_FALSE, callback, private_data);
}

long swoole_timer_tick(long ms, swTimerCallback callback, void *private_data)
{
    return swoole_timer_add(ms, SW_TRUE, callback, private_data);
}

uchar swoole_timer_exists(long timer_id)
{
    if (!SwooleG.timer.initialized)
    {
        swWarn("no timer");
        return false;
    }
    auto tnode = swTimer_get(&SwooleG.timer, timer_id);
    return (tnode && !tnode->removed);
}

uchar swoole_timer_clear(long timer_id)
{
    return swTimer_del(&SwooleG.timer, swTimer_get(&SwooleG.timer, timer_id));
}

