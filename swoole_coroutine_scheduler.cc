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
  | Author: Xinyu Zhu  <xyzhu1120@gmail.com>                             |
  |         shiguangqi <shiguangqi2008@gmail.com>                        |
  |         Tianfeng Han  <mikan.tenny@gmail.com>                        |
  +----------------------------------------------------------------------+
 */

#include "swoole_coroutine_scheduler.h"
#include "ext/spl/spl_array.h"
#include "zend_builtin_functions.h"
#include "coroutine_c_api.h"

#include <unordered_map>

using namespace std;
using swoole::coroutine::System;
using swoole::coroutine::Socket;
using swoole::Coroutine;
using swoole::PHPCoroutine;

static zend_class_entry *swoole_coroutine_iterator_ce;
static zend_class_entry *swoole_coroutine_context_ce;

static unordered_map<long, Coroutine *> user_yield_coros;

void swoole_coroutine_scheduler_init(int module_number)
{
    SW_INIT_CLASS_ENTRY_BASE(swoole_coroutine_iterator, "Swoole\\Coroutine\\Iterator", NULL, "Co\\Iterator", NULL, spl_ce_ArrayIterator);
    SW_INIT_CLASS_ENTRY_BASE(swoole_coroutine_context, "Swoole\\Coroutine\\Context", NULL, "Co\\Context", NULL, spl_ce_ArrayObject);
}

PHP_FUNCTION(swoole_coroutine_create)
{
    zend_fcall_info fci = empty_fcall_info;
    zend_fcall_info_cache fci_cache = empty_fcall_info_cache;

    ZEND_PARSE_PARAMETERS_START(1, -1)
        Z_PARAM_FUNC(fci, fci_cache)
        Z_PARAM_VARIADIC('*', fci.params, fci.param_count)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (unlikely(SWOOLE_G(req_status) == PHP_SWOOLE_CALL_USER_SHUTDOWNFUNC_BEGIN))
    {
        zend_function *func = (zend_function *) EG(current_execute_data)->prev_execute_data->func;
        if (func->common.function_name && unlikely(memcmp(ZSTR_VAL(func->common.function_name), ZEND_STRS("__destruct")) == 0))
        {
            swoole_php_fatal_error(E_ERROR, "can not use coroutine in __destruct after php_request_shutdown");
            RETURN_FALSE;
        }
    }

    long cid = PHPCoroutine::create(&fci_cache, fci.param_count, fci.params);
    if (likely(cid > 0))
    {
        RETURN_LONG(cid);
    }
    else
    {
        RETURN_FALSE;
    }
}

PHP_FUNCTION(swoole_coroutine_defer)
{
    zend_fcall_info fci = empty_fcall_info;
    zend_fcall_info_cache fci_cache = empty_fcall_info_cache;
    php_swoole_fci *defer_fci;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_FUNC(fci, fci_cache)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    Coroutine::get_current_safe();
    defer_fci = (php_swoole_fci *) emalloc(sizeof(php_swoole_fci));
    defer_fci->fci = fci;
    defer_fci->fci_cache = fci_cache;
    sw_fci_cache_persist(&defer_fci->fci_cache);
    PHPCoroutine::defer(defer_fci);
}

PHP_METHOD(swoole_coroutine_scheduler, set)
{
    zval *zset = NULL;
    HashTable *vht = NULL;
    zval *ztmp;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_ARRAY(zset)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    vht = Z_ARRVAL_P(zset);
    if (php_swoole_array_get_value(vht, "max_coroutine", ztmp))
    {
        zend_long max_num = zval_get_long(ztmp);
        PHPCoroutine::set_max_num(max_num <= 0 ? SW_DEFAULT_MAX_CORO_NUM : max_num);
    }
    if (php_swoole_array_get_value(vht, "c_stack_size", ztmp) || php_swoole_array_get_value(vht, "stack_size", ztmp))
    {
        Coroutine::set_stack_size(zval_get_long(ztmp));
    }
    if (php_swoole_array_get_value(vht, "socket_connect_timeout", ztmp))
    {
        double t = zval_get_double(ztmp);
        if (t != 0) { Socket::default_connect_timeout = t; }
    }
    if (php_swoole_array_get_value(vht, "socket_timeout", ztmp))
    {
        double t = zval_get_double(ztmp);
        if (t != 0) { Socket::default_read_timeout = Socket::default_write_timeout = t; }
    }
    if (php_swoole_array_get_value(vht, "socket_read_timeout", ztmp))
    {
        double t = zval_get_double(ztmp);
        if (t != 0) { Socket::default_read_timeout = t; }
    }
    if (php_swoole_array_get_value(vht, "socket_write_timeout", ztmp))
    {
        double t = zval_get_double(ztmp);
        if (t != 0) { Socket::default_write_timeout = t; }
    }
    if (php_swoole_array_get_value(vht, "log_level", ztmp))
    {
        zend_long level = zval_get_long(ztmp);
        SwooleG.log_level = (uint32_t) (level < 0 ? UINT32_MAX : level);
    }
    if (php_swoole_array_get_value(vht, "trace_flags", ztmp))
    {
        SwooleG.trace_flags = (uint32_t) SW_MAX(0, zval_get_long(ztmp));
    }
    if (php_swoole_array_get_value(vht, "dns_cache_expire", ztmp))
    {
        System::set_dns_cache_expire((time_t) zval_get_long(ztmp));
    }
    if (php_swoole_array_get_value(vht, "dns_cache_capacity", ztmp))
    {
        System::set_dns_cache_capacity((size_t) zval_get_long(ztmp));
    }
    if (php_swoole_array_get_value(vht, "display_errors", ztmp))
    {
        SWOOLE_G(display_errors) = zval_is_true(ztmp);
    }
}

PHP_METHOD(swoole_coroutine_scheduler, stats)
{
    array_init(return_value);
    if (SwooleG.main_reactor)
    {
        add_assoc_long_ex(return_value, ZEND_STRL("event_num"), SwooleG.main_reactor->event_num);
        add_assoc_long_ex(return_value, ZEND_STRL("signal_listener_num"), SwooleG.main_reactor->signal_listener_num);
    }
    add_assoc_long_ex(return_value, ZEND_STRL("aio_task_num"), SwooleAIO.task_num);
    add_assoc_long_ex(return_value, ZEND_STRL("c_stack_size"), Coroutine::get_stack_size());
    add_assoc_long_ex(return_value, ZEND_STRL("coroutine_num"), Coroutine::count());
    add_assoc_long_ex(return_value, ZEND_STRL("coroutine_peak_num"), Coroutine::get_peak_num());
    add_assoc_long_ex(return_value, ZEND_STRL("coroutine_last_cid"), Coroutine::get_last_cid());
}

PHP_METHOD(swoole_coroutine_scheduler, getCid)
{
    RETURN_LONG(PHPCoroutine::get_cid());
}

PHP_METHOD(swoole_coroutine_scheduler, getPcid)
{
    RETURN_LONG(PHPCoroutine::get_pcid());
}

PHP_METHOD(swoole_coroutine_scheduler, getContext)
{
    zend_long cid = 0;

    ZEND_PARSE_PARAMETERS_START(0, 1)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(cid)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    php_coro_task *task = (php_coro_task *) (EXPECTED(cid == 0) ? Coroutine::get_current_task() : Coroutine::get_task_by_cid(cid));
    if (UNEXPECTED(!task))
    {
        RETURN_NULL();
    }
    if (UNEXPECTED(!task->context))
    {
        object_init_ex(return_value, swoole_coroutine_context_ce);
        task->context = Z_OBJ_P(return_value);
    }
    GC_ADDREF(task->context);
    RETURN_OBJ(task->context);
}

PHP_METHOD(swoole_coroutine_scheduler, exists)
{
    zend_long cid;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_LONG(cid)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    RETURN_BOOL(Coroutine::get_by_cid(cid) != nullptr);
}

PHP_METHOD(swoole_coroutine_scheduler, resume)
{
    long cid;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "l", &cid) == FAILURE)
    {
        RETURN_FALSE;
    }

    auto coroutine_iterator = user_yield_coros.find(cid);
    if (coroutine_iterator == user_yield_coros.end())
    {
        swoole_php_fatal_error(E_WARNING, "you can not resume the coroutine which is in IO operation or non-existent");
        RETURN_FALSE;
    }

    Coroutine* co = coroutine_iterator->second;
    user_yield_coros.erase(cid);
    co->resume();
    RETURN_TRUE;
}

PHP_METHOD(swoole_coroutine_scheduler, yield)
{
    Coroutine* co = Coroutine::get_current_safe();
    user_yield_coros[co->get_cid()] = co;
    co->yield();
    RETURN_TRUE;
}

PHP_METHOD(swoole_coroutine_scheduler, getBackTrace)
{
    zend_long cid = 0;
    zend_long options = DEBUG_BACKTRACE_PROVIDE_OBJECT;
    zend_long limit = 0;

    ZEND_PARSE_PARAMETERS_START(0, 3)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(cid)
        Z_PARAM_LONG(options)
        Z_PARAM_LONG(limit)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (!cid || cid == PHPCoroutine::get_cid())
    {
        zend_fetch_debug_backtrace(return_value, 0, options, limit);
    }
    else
    {
        php_coro_task *task = (php_coro_task *) PHPCoroutine::get_task_by_cid(cid);
        if (UNEXPECTED(!task))
        {
            RETURN_FALSE;
        }
        zend_execute_data *ex_backup = EG(current_execute_data);
        EG(current_execute_data) = task->execute_data;
        zend_fetch_debug_backtrace(return_value, 0, options, limit);
        EG(current_execute_data) = ex_backup;
    }
}

PHP_METHOD(swoole_coroutine_scheduler, list)
{
    zval zlist;
    array_init(&zlist);
    for (auto &co : Coroutine::coroutines) {
        add_next_index_long(&zlist, co.second->get_cid());
    }
    object_init_ex(return_value, swoole_coroutine_iterator_ce);
    sw_zend_call_method_with_1_params(
        return_value,
        swoole_coroutine_iterator_ce,
        &swoole_coroutine_iterator_ce->constructor,
        (const char *) "__construct",
        NULL,
        &zlist
    );
    zval_ptr_dtor(&zlist);
}
