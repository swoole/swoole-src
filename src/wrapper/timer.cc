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
#include "wrapper/base.hpp"
#include "server.h"

using namespace std;
using namespace swoole;

#ifdef SW_CO_MT
#define sw_timer()           (&SwooleTG.timer)
#else
#define sw_timer()           (&SwooleG.timer)
#endif

swTimer_node* swoole_timer_add(long ms, uchar persistent, swTimerCallback callback, void *private_data)
{
    return swTimer_add(sw_timer(), ms, persistent, private_data, callback);
}

uchar swoole_timer_del(swTimer_node* tnode)
{
    return swTimer_del(sw_timer(), tnode);
}

long swoole_timer_after(long ms, swTimerCallback callback, void *private_data)
{
    if (ms <= 0)
    {
        swWarn("Timer must be greater than 0");
        return SW_ERR;
    }
    swTimer_node *tnode = swoole_timer_add( ms, SW_FALSE, callback, private_data);
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
    swTimer_node *tnode = swoole_timer_add( ms, SW_TRUE, callback, private_data);
    if (tnode == nullptr)
    {
        return SW_ERR;
    }
    else
    {
        return tnode->id;
    }
}

uchar swoole_timer_exists(long timer_id)
{
    if (!SwooleG.timer.initialized)
    {
        swWarn("no timer");
        return false;
    }
    swTimer_node *tnode = swTimer_get(sw_timer(), timer_id);
    return (tnode && !tnode->removed);
}

uchar swoole_timer_clear(long timer_id)
{
    return swTimer_del(sw_timer(), swTimer_get(sw_timer(), timer_id));
}

swTimer_node* swoole_timer_get(long timer_id)
{
    if (!SwooleG.timer.initialized)
    {
        swWarn("no timer");
        return nullptr;
    }
    return swTimer_get(sw_timer(), timer_id);
}
