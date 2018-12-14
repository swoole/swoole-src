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

#include <list>

using namespace std;

struct defer_task
{
    swCallback callback;
    void *data;
};

static void do_defer_tasks(swReactor *reactor);
static int add_defer_task(swReactor *reactor, swCallback callback, void *data);

static void swReactor_defer_timer_callback(swTimer *timer, swTimer_node *tnode)
{
    defer_task *cb = (defer_task *) tnode->data;
    cb->callback(cb->data);
    delete cb;
}

void swReactor_defer_task_create(swReactor *reactor)
{
    reactor->defer = add_defer_task;
    reactor->defer_tasks = new std::list<defer_task *>;
    reactor->do_defer_tasks = do_defer_tasks;
}

void swReactor_defer_task_destroy(swReactor *reactor)
{
    list<defer_task *> *tasks = (list<defer_task *> *) reactor->defer_tasks;
    delete tasks;
}

static void do_defer_tasks(swReactor *reactor)
{
    list<defer_task *> *tasks = (list<defer_task *> *) reactor->defer_tasks;
    while (tasks->size() > 0)
    {
        defer_task *task = tasks->front();
        tasks->pop_front();
        task->callback(task->data);
        delete task;
    }
}

static int add_defer_task(swReactor *reactor, swCallback callback, void *data)
{
    defer_task *new_task = new defer_task;
    list<defer_task *> *tasks = (list<defer_task *> *) reactor->defer_tasks;
    new_task->callback = callback;
    new_task->data = data;
    if (unlikely(reactor->start == 0))
    {
        swTimer_add(&SwooleG.timer, 1, 0, (void*) new_task, swReactor_defer_timer_callback);
    }
    else
    {
        tasks->push_back(new_task);
    }
    return SW_OK;
}
