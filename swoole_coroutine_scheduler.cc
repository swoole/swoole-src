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
#include "coroutine_c_api.h"

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
    bool started;
    zend_object std;
};

static zend_class_entry *swoole_coroutine_scheduler_ce;
static zend_object_handlers swoole_coroutine_scheduler_handlers;

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
    SW_INIT_CLASS_ENTRY(swoole_coroutine_scheduler, "Swoole\\Coroutine\\Scheduler", NULL, "Co\\Scheduler", swoole_coroutine_scheduler_methods);
    SW_SET_CLASS_SERIALIZABLE(swoole_coroutine_scheduler, zend_class_serialize_deny, zend_class_unserialize_deny);
    SW_SET_CLASS_CLONEABLE(swoole_coroutine_scheduler, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_coroutine_scheduler, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CREATE_WITH_ITS_OWN_HANDLERS(swoole_coroutine_scheduler);
    SW_SET_CLASS_CUSTOM_OBJECT(swoole_coroutine_scheduler, scheduler_create_object, scheduler_free_object, scheduler_t, std);
    swoole_coroutine_scheduler_ce->ce_flags |= ZEND_ACC_FINAL;

    zend_declare_property_null(swoole_coroutine_scheduler_ce, ZEND_STRL("_list"), ZEND_ACC_PRIVATE);
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
    /**
     * Runtime: hook php function
     */
    if (php_swoole_array_get_value(vht, "hook_flags", ztmp))
    {
        PHPCoroutine::enable_hook(zval_get_long(ztmp));
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
    scheduler_t *s = scheduler_get_object(Z_OBJ_P(ZEND_THIS));
    if (s->started)
    {
        php_swoole_fatal_error(E_WARNING, "scheduler is running, unable to execute %s->add", SW_Z_OBJCE_NAME_VAL_P(ZEND_THIS));
        RETURN_FALSE;
    }

    scheduler_task_t *task = (scheduler_task_t *) ecalloc(1, sizeof(scheduler_task_t));

    ZEND_PARSE_PARAMETERS_START(1, -1)
        Z_PARAM_FUNC(task->fci, task->fci_cache)
        Z_PARAM_VARIADIC('*', task->fci.params, task->fci.param_count)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    task->count = 1;
    scheduler_add_task(s, task);
}

static PHP_METHOD(swoole_coroutine_scheduler, parallel)
{
    scheduler_t *s = scheduler_get_object(Z_OBJ_P(ZEND_THIS));
    if (s->started)
    {
        php_swoole_fatal_error(E_WARNING, "scheduler is running, unable to execute %s->parallel", SW_Z_OBJCE_NAME_VAL_P(ZEND_THIS));
        RETURN_FALSE;
    }

    scheduler_task_t *task = (scheduler_task_t *) ecalloc(1, sizeof(scheduler_task_t));
    zend_long count;

    ZEND_PARSE_PARAMETERS_START(2, -1)
        Z_PARAM_LONG(count)
        Z_PARAM_FUNC(task->fci, task->fci_cache)
        Z_PARAM_VARIADIC('*', task->fci.params, task->fci.param_count)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    task->count = count;
    scheduler_add_task(s, task);
}

static PHP_METHOD(swoole_coroutine_scheduler, start)
{
    scheduler_t *s = scheduler_get_object(Z_OBJ_P(ZEND_THIS));

    if (SwooleG.main_reactor)
    {
        php_swoole_fatal_error(E_WARNING, "eventLoop has already been created. unable to start %s", SW_Z_OBJCE_NAME_VAL_P(ZEND_THIS));
        RETURN_FALSE;
    }
    if (s->started)
    {
        php_swoole_fatal_error(E_WARNING, "scheduler is started, unable to execute %s->start", SW_Z_OBJCE_NAME_VAL_P(ZEND_THIS));
        RETURN_FALSE;
    }
    if (php_swoole_reactor_init() < 0)
    {
        RETURN_FALSE;
    }

    s->started = true;

    if (!s->list)
    {
        php_swoole_fatal_error(E_WARNING, "no coroutine task");
        RETURN_FALSE;
    }

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
    s->started = false;
    RETURN_TRUE;
}
