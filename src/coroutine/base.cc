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
#include "coroutine_c_api.h"

using namespace swoole;

size_t Coroutine::stack_size = SW_DEFAULT_C_STACK_SIZE;
Coroutine* Coroutine::current = nullptr;
long Coroutine::last_cid = 0;
uint64_t Coroutine::peak_num = 0;
sw_coro_on_swap_t Coroutine::on_yield = nullptr;
sw_coro_on_swap_t Coroutine::on_resume = nullptr;
sw_coro_on_swap_t Coroutine::on_close = nullptr;
sw_coro_bailout_t Coroutine::on_bailout = nullptr;

std::unordered_map<long, Coroutine*> Coroutine::coroutines;

void Coroutine::yield()
{
    SW_ASSERT(current == this || on_bailout != nullptr);
    state = SW_CORO_WAITING;
    if (likely(on_yield))
    {
        on_yield(task);
    }
    current = origin;
    ctx.swap_out();
}

void Coroutine::resume()
{
    SW_ASSERT(current != this);
    if (unlikely(on_bailout))
    {
        return;
    }
    state = SW_CORO_RUNNING;
    if (likely(on_resume))
    {
        on_resume(task);
    }
    origin = current;
    current = this;
    ctx.swap_in();
    check_end();
}

void Coroutine::yield_naked()
{
    SW_ASSERT(current == this);
    state = SW_CORO_WAITING;
    current = origin;
    ctx.swap_out();
}

void Coroutine::resume_naked()
{
    SW_ASSERT(current != this);
    if (unlikely(on_bailout))
    {
        return;
    }
    state = SW_CORO_RUNNING;
    origin = current;
    current = this;
    ctx.swap_in();
    check_end();
}

void Coroutine::close()
{
    SW_ASSERT(current == this);
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
            abort();
            return;
        }
        printf("Coroutine\t%ld\t%s\n", i->first, state);
    }
}

void Coroutine::set_on_yield(sw_coro_on_swap_t func)
{
    on_yield = func;
}

void Coroutine::set_on_resume(sw_coro_on_swap_t func)
{
    on_resume = func;
}

void Coroutine::set_on_close(sw_coro_on_swap_t func)
{
    on_close = func;
}

void Coroutine::bailout(sw_coro_bailout_t func)
{
    Coroutine *co = current;
    if (!co)
    {
        // marks that it can no longer resume any coroutine
        on_bailout = (sw_coro_bailout_t) -1;
        return;
    }
    if (!func)
    {
        swError("bailout without bailout function");
    }
    on_bailout = func;
    // find the coroutine which is closest to the main
    while (co->origin)
    {
        co = co->origin;
    }
    // it will jump to main context directly (it also breaks contexts)
    co->yield();
    // expect that never here
    exit(1);
}

uint8_t swoole_coroutine_is_in()
{
    return !!Coroutine::get_current();
}

long swoole_coroutine_get_current_id()
{
    return Coroutine::get_current_cid();
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
