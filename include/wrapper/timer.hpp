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

#ifndef SWOOLE_CPP_TIMER_HPP
#define SWOOLE_CPP_TIMER_HPP

#include "Base.hpp"

#include <map>

using namespace std;

namespace swoole
{
    class Timer
    {
    public:
        Timer(long ms, bool interval);
        Timer(long ms);
        ~Timer()
        {
            clear();
        }

        swTimer_node *getNode()
        {
            return m_tnode;
        }

        void setNode(swTimer_node *tnode)
        {
            m_tnode = tnode;
        }

        void clear()
        {
            if (m_tnode)
            {
                Timer::del(m_tnode);
                m_tnode = NULL;
                id = -1;
                interval = 0;
            }
        }

        static void _onAfter(swTimer *timer, swTimer_node *tnode);
        static void _onTick(swTimer *timer, swTimer_node *tnode);
        static void init(int msec);

        static bool clear(long id);
        static bool exists(long id);

    protected:
        virtual void callback(void) = 0;
        static long add(int ms, Timer *object, bool tick);
        static bool del(swTimer_node *tnode);

        bool interval;
        long id;
        swTimer_node* m_tnode;
    };

    static map<long, Timer *> timer_map;
}
#endif //SWOOLE_CPP_TIMER_HPP
