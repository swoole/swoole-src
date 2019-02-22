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

#include "coroutine.h"
#include "async.h"

using namespace swoole;

size_t Coroutine::stack_size = SW_DEFAULT_C_STACK_SIZE;
size_t Coroutine::call_stack_size = 0;
Coroutine* Coroutine::call_stack[SW_MAX_CORO_NESTING_LEVEL];
long Coroutine::last_cid = 0;
uint64_t Coroutine::peak_num = 0;
coro_php_yield_t  Coroutine::on_yield = nullptr;
coro_php_resume_t Coroutine::on_resume = nullptr;
coro_php_close_t  Coroutine::on_close = nullptr;

std::unordered_map<long, Coroutine*> Coroutine::coroutines;

long Coroutine::create(coroutine_func_t fn, void* args)
{
    if (unlikely(call_stack_size == SW_MAX_CORO_NESTING_LEVEL))
    {
        swWarn("reaches the max coroutine nesting level %d", SW_MAX_CORO_NESTING_LEVEL);
        return SW_CORO_ERR_LIMIT;
    }
    return (new Coroutine(fn, args))->run();
}

void Coroutine::yield()
{
    state = SW_CORO_WAITING;
    if (on_yield)
    {
        on_yield(task);
    }
    call_stack_size--;
    ctx.SwapOut();
}

void Coroutine::resume()
{
    state = SW_CORO_RUNNING;
    if (on_resume)
    {
        on_resume(task);
    }
    Coroutine::call_stack[call_stack_size++] = this;
    ctx.SwapIn();
    if (ctx.end)
    {
        close();
    }
}

void Coroutine::yield_naked()
{
    state = SW_CORO_WAITING;
    call_stack_size--;
    ctx.SwapOut();
}

void Coroutine::resume_naked()
{
    state = SW_CORO_RUNNING;
    Coroutine::call_stack[call_stack_size++] = this;
    ctx.SwapIn();
    if (ctx.end)
    {
        close();
    }
}

void Coroutine::close()
{
    state = SW_CORO_END;
    if (on_close)
    {
        on_close(task);
    }
    call_stack_size--;
    coroutines.erase(cid);
    delete this;
}

Coroutine* Coroutine::get_current()
{
    return likely(call_stack_size > 0) ? call_stack[call_stack_size - 1] : nullptr;
}

void* Coroutine::get_current_task()
{
    Coroutine* co = get_current();
    return likely(co) ? co->get_task() : nullptr;
}

long Coroutine::get_current_cid()
{
    Coroutine* co = get_current();
    return likely(co) ? co->get_cid() : -1;
}

Coroutine* Coroutine::get_by_cid(long cid)
{
    auto i = coroutines.find(cid);
    return likely(i != coroutines.end()) ? i->second : nullptr;
}

void* Coroutine::get_task_by_cid(long cid)
{
    Coroutine *co = get_by_cid(cid);
    return likely(co) ? co->get_task() : nullptr;
}

void Coroutine::print_list()
{
    for (auto i = coroutines.begin(); i != coroutines.end(); i++)
    {
        const char *state;
        switch(i->second->state){
        case SW_CORO_INIT:
            state = "[INIT]";
            break;
        case SW_CORO_WAITING:
            state = "[WAITING]";
            break;
        case SW_CORO_RUNNING:
            state = "[RUNNING]";
            break;
        case SW_CORO_END:
            state = "[END]";
            break;
        default:
            assert(0);
            return;
        }
        printf("Coroutine\t%ld\t%s\n", i->first, state);
    }
}

void Coroutine::set_on_yield(coro_php_yield_t func)
{
    on_yield = func;
}

void Coroutine::set_on_resume(coro_php_resume_t func)
{
    on_resume = func;
}

void Coroutine::set_on_close(coro_php_close_t func)
{
    on_close = func;
}

/**
 * for gdb
 */
static std::unordered_map<long, Coroutine*>::iterator _gdb_iterator;

void swoole_coro_iterator_reset()
{
    _gdb_iterator = Coroutine::coroutines.begin();
}

Coroutine* swoole_coro_iterator_each()
{
    if (_gdb_iterator == Coroutine::coroutines.end())
    {
        return nullptr;
    }
    else
    {
        Coroutine *co = _gdb_iterator->second;
        _gdb_iterator++;
        return co;
    }
}

Coroutine* swoole_coro_get(long cid)
{
    auto i = Coroutine::coroutines.find(cid);
    if (i == Coroutine::coroutines.end())
    {
        return nullptr;
    }
    else
    {
        return i->second;
    }
}

size_t swoole_coro_count()
{
    return Coroutine::coroutines.size();
}
