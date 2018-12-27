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

#pragma once

#include "swoole.h"
#include "context.h"

#include <string>
#include <unordered_map>

#define SW_DEFAULT_MAX_CORO_NUM              3000
#define SW_DEFAULT_STACK_SIZE                8192
#define SW_DEFAULT_SOCKET_CONNECT_TIMEOUT    1
#define SW_DEFAULT_SOCKET_TIMEOUT            -1

#define CORO_END         0
#define CORO_LIMIT      -1
#define CORO_INVALID    -2

typedef enum
{
    SW_CORO_INIT = 0,
    SW_CORO_WAITING,
    SW_CORO_RUNNING,
    SW_CORO_END,
} sw_coro_state;

typedef void (*coro_php_create_t)();
typedef void (*coro_php_yield_t)(void*);
typedef void (*coro_php_resume_t)(void*);
typedef void (*coro_php_close_t)();

namespace swoole
{
class Coroutine
{
private:
    long cid;
    void *task;
    swoole::Context ctx;

public:
    sw_coro_state state;

    Coroutine(long _cid, size_t stack_size, coroutine_func_t fn, void *private_data) :
            ctx(stack_size, fn, private_data)
    {
        cid = _cid;
        task = nullptr;
        state = SW_CORO_INIT;
    }

    void resume();
    void yield();

    void resume_naked();
    void yield_naked();

    void release();

    inline void set_task(void *_task)
    {
        task = _task;
    }

    inline long get_cid()
    {
        return cid;
    }

    inline void* get_task()
    {
        return task;
    }

    static long create(coroutine_func_t fn, void* args = nullptr);
    static int sleep(double sec);
    static swString* read_file(const char *file, int lock);
    static ssize_t write_file(const char *file, char *buf, size_t length, int lock, int flags);
    static std::string gethostbyname(const std::string &hostname, int domain, float timeout = -1);
};

struct CoroutineG
{
    int stack_size;
    int call_stack_size;
    long last_cid;
    Coroutine* call_stack[SW_MAX_CORO_NESTING_LEVEL];
    coro_php_yield_t onYield; /* before php yield coro */
    coro_php_resume_t onResume; /* before php resume coro */
    coro_php_close_t onClose; /* before php close coro */
    std::unordered_map<long, Coroutine*> coroutines;

    CoroutineG()
    {
        stack_size = SW_DEFAULT_C_STACK_SIZE;
        call_stack_size = 0;
        last_cid = 1;
        onYield = nullptr;
        onResume = nullptr;
        onClose = nullptr;
    }

    inline size_t count()
    {
        return coroutines.size();
    }
};
}

/* co task */
void* coroutine_get_current_task();
void* coroutine_get_task_by_cid(long cid);
/* get coroutine */
swoole::Coroutine* coroutine_get_current();
swoole::Coroutine* coroutine_get_by_id(long cid);
/* get cid */
long coroutine_get_current_cid();
void coroutine_set_stack_size(int stack_size);
/* callback */
void coroutine_set_onYield(coro_php_yield_t func);
void coroutine_set_onResume(coro_php_resume_t func);
void coroutine_set_onResumeBack(coro_php_resume_t func);
void coroutine_set_onClose(coro_php_close_t func);
void coroutine_print_list();

inline static long coroutine_get_cid(swoole::Coroutine* co)
{
    return co ? co->get_cid() : -1;
}

void internal_coro_yield(void *arg);
void internal_coro_resume(void *arg);

extern swoole::CoroutineG swCoroG;
