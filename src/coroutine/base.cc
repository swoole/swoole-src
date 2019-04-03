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
Coroutine* Coroutine::current = nullptr;
long Coroutine::last_cid = 0;
uint64_t Coroutine::peak_num = 0;
coro_php_yield_t  Coroutine::on_yield = nullptr;
coro_php_resume_t Coroutine::on_resume = nullptr;
coro_php_close_t  Coroutine::on_close = nullptr;

std::unordered_map<long, Coroutine*> Coroutine::coroutines;

void Coroutine::yield()
{
    state = SW_CORO_WAITING;
    if (on_yield)
    {
        on_yield(task);
    }
    current = origin;
    ctx.SwapOut();
}

void Coroutine::resume()
{
    state = SW_CORO_RUNNING;
    if (on_resume)
    {
        on_resume(task);
    }
    origin = current;
    current = this;
    ctx.SwapIn();
    if (ctx.end)
    {
        close();
    }
}

void Coroutine::yield_naked()
{
    state = SW_CORO_WAITING;
    current = origin;
    ctx.SwapOut();
}

void Coroutine::resume_naked()
{
    state = SW_CORO_RUNNING;
    origin = current;
    current = this;
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
#ifndef SW_NO_USE_ASM_CONTEXT
    swTraceLog(SW_TRACE_CONTEXT, "coroutine#%ld stack memory use less than %ld bytes", get_cid(), ctx.get_stack_usage());
#endif
    current = origin;
    coroutines.erase(cid);
    delete this;
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


extern "C"
{
/**
 * for C
 */
uint8_t swoole_coroutine_is_in()
{
    return !!Coroutine::get_current();
}
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
