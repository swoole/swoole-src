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

#include "timer.hpp"

using namespace std;

namespace swoole
{
    Timer::Timer(long ms)
    {
        id = Timer::add(ms, this, true);
        interval = true;
    }

    Timer::Timer(long ms, bool _interval)
    {
        id = Timer::add(ms, this, _interval);
        interval = _interval;
    }

    void Timer::init(int msec)
    {
        swTimer_init(msec);
    }

    void Timer::_onAfter(swTimer *timer, swTimer_node *tnode)
    {
        timer->_current_id = tnode->id;
        Timer *_this = (Timer *) tnode->data;
        _this->callback();
        timer->_current_id = -1;
        Timer::del(tnode);
    }

    void Timer::_onTick(swTimer *timer, swTimer_node *tnode)
    {
        timer->_current_id = tnode->id;
        Timer *_this = (Timer *) tnode->data;
        _this->callback();
        timer->_current_id = -1;
        if (tnode->remove)
        {
            Timer::del(tnode);
        }
    }

    long Timer::add(int ms, Timer *object, bool tick)
    {
        if (SwooleG.serv && swIsMaster())
        {
            swWarn("cannot use timer in master process.");
            return SW_ERR;
        }
        if (ms > 86400000)
        {
            swWarn("The given parameters is too big.");
            return SW_ERR;
        }
        if (ms <= 0)
        {
            swWarn("Timer must be greater than 0");
            return SW_ERR;
        }

        if (!swIsTaskWorker())
        {
            check_reactor();
        }
        if (SwooleG.timer.fd == 0)
        {
            Timer::init(ms);
        }

        swTimerCallback timer_func;
        if (tick)
        {
            timer_func = Timer::_onTick;
        }
        else
        {
            timer_func =  Timer::_onAfter;
        }

        swTimer_node *tnode = SwooleG.timer.add(&SwooleG.timer, ms, tick, (void *) object, timer_func);
        if (tnode == NULL)
        {
            swWarn("addtimer failed.");
            return SW_ERR;
        }
        else
        {
            object->setNode(tnode);
            timer_map[tnode->id] = object;
            return tnode->id;
        }
    }

    bool Timer::del(swTimer_node *tnode)
    {
        if (!SwooleG.timer.set)
        {
            swWarn("no timer");
            return false;
        }
        if (timer_map.erase(tnode->id) == 0)
        {
            return false;
        }
        if (Timer::del(tnode) < 0)
        {
            return false;
        }
        else
        {
            swTimer_del(&SwooleG.timer, tnode);
            return true;
        }
    }

    bool Timer::clear(long id)
    {
        map<long, Timer *>::iterator iter  = timer_map.find(id);
        if (iter == timer_map.end())
        {
            return false;
        }

        swTimer_node *tnode = iter->second->getNode();
        if (tnode->id == SwooleG.timer._current_id)
        {
            tnode->remove = 1;
            return true;
        }
        else
        {
            return Timer::del(tnode);
        }
    }


    bool Timer::exists(long id)
    {
        if (!SwooleG.timer.set)
        {
            swWarn("no timer");
            return false;
        }
        return timer_map.find(id) == timer_map.end();
    }
}
