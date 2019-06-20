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
#include <queue>

using namespace std;
using swoole::coroutine::System;
using swoole::coroutine::Socket;
using swoole::Coroutine;
using swoole::PHPCoroutine;

struct scheduler_task_t
{
    zend_long count;
    zend_fcall_info fci;
    zend_fcall_info_cache fci_cache;
};

struct scheduler_t
{
    queue<scheduler_task_t*> *list;
    zend_object std;
};

static zend_class_entry *swoole_coroutine_iterator_ce;
static zend_class_entry *swoole_coroutine_context_ce;
static zend_class_entry *swoole_coroutine_scheduler_ce;
static zend_object_handlers swoole_coroutine_scheduler_handlers;

static unordered_map<long, Coroutine *> user_yield_coros;

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_scheduler_add, 0, 0, 1)
    ZEND_ARG_CALLABLE_INFO(0, func, 0)
    ZEND_ARG_VARIADIC_INFO(0, params)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_scheduler_parallel, 0, 0, 1)
    ZEND_ARG_INFO(0, n)
    ZEND_ARG_CALLABLE_INFO(0, func, 0)
    ZEND_ARG_VARIADIC_INFO(0, params)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_scheduler_set, 0, 0, 1)
    ZEND_ARG_ARRAY_INFO(0, settings, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_scheduler_create, 0, 0, 1)
    ZEND_ARG_CALLABLE_INFO(0, func, 0)
    ZEND_ARG_VARIADIC_INFO(0, params)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_scheduler_resume, 0, 0, 1)
    ZEND_ARG_INFO(0, cid)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_scheduler_exists, 0, 0, 1)
    ZEND_ARG_INFO(0, cid)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_scheduler_getContext, 0, 0, 0)
    ZEND_ARG_INFO(0, cid)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_scheduler_defer, 0, 0, 1)
    ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_scheduler_getBackTrace, 0, 0, 0)
    ZEND_ARG_INFO(0, cid)
    ZEND_ARG_INFO(0, options)
    ZEND_ARG_INFO(0, limit)
ZEND_END_ARG_INFO()

static PHP_METHOD(swoole_coroutine_scheduler, add);
static PHP_METHOD(swoole_coroutine_scheduler, parallel);
static PHP_METHOD(swoole_coroutine_scheduler, start);

static sw_inline scheduler_t* scheduler_get_object(zend_object *obj)
{
    return (scheduler_t *) ((char *) obj - swoole_coroutine_scheduler_handlers.offset);
}

static zend_object *scheduler_create_object(zend_class_entry *ce)
{
    scheduler_t *s = (scheduler_t *) ecalloc(1, sizeof(scheduler_t) + zend_object_properties_size(ce));
    zend_object_std_init(&s->std, ce);
    object_properties_init(&s->std, ce);
    s->std.handlers = &swoole_coroutine_scheduler_handlers;
    return &s->std;
}

static void scheduler_free_object(zend_object *object)
{
    scheduler_t *s = scheduler_get_object(object);
    if (s->list)
    {
        while(!s->list->empty())
        {
            scheduler_task_t *task = s->list->front();
            s->list->pop();
            sw_zend_fci_cache_discard(&task->fci_cache);
            sw_zend_fci_params_discard(&task->fci);
            efree(task);
        }
        delete s->list;
        s->list = nullptr;
    }
    zend_object_std_dtor(&s->std);
}

static const zend_function_entry swoole_coroutine_scheduler_methods[] =
{
    PHP_ME(swoole_coroutine_scheduler, add, arginfo_swoole_coroutine_scheduler_add, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_coroutine_scheduler, parallel, arginfo_swoole_coroutine_scheduler_parallel, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_coroutine_scheduler, set, arginfo_swoole_coroutine_scheduler_set, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_coroutine_scheduler, start, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

void swoole_coroutine_scheduler_init(int module_number)
{
    SW_INIT_CLASS_ENTRY_BASE(swoole_coroutine_iterator, "Swoole\\Coroutine\\Iterator", NULL, "Co\\Iterator", NULL, spl_ce_ArrayIterator);
    SW_INIT_CLASS_ENTRY_BASE(swoole_coroutine_context, "Swoole\\Coroutine\\Context", NULL, "Co\\Context", NULL, spl_ce_ArrayObject);

    SW_INIT_CLASS_ENTRY(swoole_coroutine_scheduler, "Swoole\\Coroutine\\Scheduler", NULL, "Co\\Scheduler", swoole_coroutine_scheduler_methods);
    SW_SET_CLASS_SERIALIZABLE(swoole_coroutine_scheduler, zend_class_serialize_deny, zend_class_unserialize_deny);
    SW_SET_CLASS_CLONEABLE(swoole_coroutine_scheduler, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_coroutine_scheduler, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CREATE_WITH_ITS_OWN_HANDLERS(swoole_coroutine_scheduler);
    SW_SET_CLASS_CUSTOM_OBJECT(swoole_coroutine_scheduler, scheduler_create_object, scheduler_free_object, scheduler_t, std);
    swoole_coroutine_scheduler_ce->ce_flags |= ZEND_ACC_FINAL;

    zend_declare_property_null(swoole_coroutine_scheduler_ce, ZEND_STRL("_list"), ZEND_ACC_PRIVATE);
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
            php_swoole_fatal_error(E_ERROR, "can not use coroutine in __destruct after php_request_shutdown");
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
    sw_zend_fci_cache_persist(&defer_fci->fci_cache);
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
        php_swoole_fatal_error(E_WARNING, "you can not resume the coroutine which is in IO operation or non-existent");
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

static void scheduler_add_task(scheduler_t *s, scheduler_task_t *task)
{
    if (!s->list)
    {
        s->list = new queue<scheduler_task_t*>;
    }
    sw_zend_fci_cache_persist(&task->fci_cache);
    sw_zend_fci_params_persist(&task->fci);
    s->list->push(task);
}

static PHP_METHOD(swoole_coroutine_scheduler, add)
{
    scheduler_task_t *task = (scheduler_task_t *) ecalloc(1, sizeof(scheduler_task_t));

    ZEND_PARSE_PARAMETERS_START(1, -1)
        Z_PARAM_FUNC(task->fci, task->fci_cache)
        Z_PARAM_VARIADIC('*', task->fci.params, task->fci.param_count)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    task->count = 1;
    scheduler_add_task(scheduler_get_object(Z_OBJ_P(getThis())), task);
}

static PHP_METHOD(swoole_coroutine_scheduler, parallel)
{
    scheduler_task_t *task = (scheduler_task_t *) ecalloc(1, sizeof(scheduler_task_t));
    zend_long count;

    ZEND_PARSE_PARAMETERS_START(2, -1)
        Z_PARAM_LONG(count)
        Z_PARAM_FUNC(task->fci, task->fci_cache)
        Z_PARAM_VARIADIC('*', task->fci.params, task->fci.param_count)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    task->count = count;
    scheduler_add_task(scheduler_get_object(Z_OBJ_P(getThis())), task);
}

static PHP_METHOD(swoole_coroutine_scheduler, start)
{
    php_swoole_reactor_init();

    scheduler_t *s = scheduler_get_object(Z_OBJ_P(getThis()));
    while (!s->list->empty())
    {
        scheduler_task_t *task = s->list->front();
        s->list->pop();
        for (zend_long i = 0; i < task->count; i++)
        {
            PHPCoroutine::create(&task->fci_cache, task->fci.param_count, task->fci.params);
        }
        sw_zend_fci_cache_discard(&task->fci_cache);
        sw_zend_fci_params_discard(&task->fci);
        efree(task);
    }

    php_swoole_event_wait();
    delete s->list;
    s->list = nullptr;
}

PHP_METHOD(swoole_coroutine_scheduler, enableScheduler)
{
    RETURN_BOOL(PHPCoroutine::enable_scheduler());
}

PHP_METHOD(swoole_coroutine_scheduler, disableScheduler)
{
    RETURN_BOOL(PHPCoroutine::disable_scheduler());
}
