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

#include "php_swoole_cxx.h"

#include <queue>

using swoole::Reactor;
using swoole::Coroutine;
using swoole::PHPCoroutine;
using swoole::coroutine::Socket;
using swoole::coroutine::System;

struct SchedulerTask {
    zend_long count;
    zend_fcall_info fci;
    zend_fcall_info_cache fci_cache;
};

struct SchedulerObject {
    std::queue<SchedulerTask *> *list;
    bool started;
    zend_object std;
};

static zend_class_entry *swoole_coroutine_scheduler_ce;
static zend_object_handlers swoole_coroutine_scheduler_handlers;

SW_EXTERN_C_BEGIN
static PHP_METHOD(swoole_coroutine_scheduler, add);
static PHP_METHOD(swoole_coroutine_scheduler, parallel);
static PHP_METHOD(swoole_coroutine_scheduler, start);
SW_EXTERN_C_END

static sw_inline SchedulerObject *scheduler_get_object(zend_object *obj) {
    return (SchedulerObject *) ((char *) obj - swoole_coroutine_scheduler_handlers.offset);
}

static zend_object *scheduler_create_object(zend_class_entry *ce) {
    SchedulerObject *s = (SchedulerObject *) zend_object_alloc(sizeof(SchedulerObject), ce);
    zend_object_std_init(&s->std, ce);
    object_properties_init(&s->std, ce);
    s->std.handlers = &swoole_coroutine_scheduler_handlers;
    return &s->std;
}

static void scheduler_free_object(zend_object *object) {
    SchedulerObject *s = scheduler_get_object(object);
    if (s->list) {
        while (!s->list->empty()) {
            SchedulerTask *task = s->list->front();
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

// clang-format off
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

static const zend_function_entry swoole_coroutine_scheduler_methods[] = {
    PHP_ME(swoole_coroutine_scheduler, add, arginfo_swoole_coroutine_scheduler_add, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_coroutine_scheduler, parallel, arginfo_swoole_coroutine_scheduler_parallel, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_coroutine_scheduler, set, arginfo_swoole_coroutine_scheduler_set, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_coroutine_scheduler, getOptions, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_coroutine_scheduler, start, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

// clang-format on

void php_swoole_coroutine_scheduler_minit(int module_number) {
    SW_INIT_CLASS_ENTRY(swoole_coroutine_scheduler,
                        "Swoole\\Coroutine\\Scheduler",
                        nullptr,
                        "Co\\Scheduler",
                        swoole_coroutine_scheduler_methods);
    SW_SET_CLASS_NOT_SERIALIZABLE(swoole_coroutine_scheduler);
    SW_SET_CLASS_CLONEABLE(swoole_coroutine_scheduler, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_coroutine_scheduler, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CREATE_WITH_ITS_OWN_HANDLERS(swoole_coroutine_scheduler);
    SW_SET_CLASS_CUSTOM_OBJECT(
        swoole_coroutine_scheduler, scheduler_create_object, scheduler_free_object, SchedulerObject, std);
    swoole_coroutine_scheduler_ce->ce_flags |= ZEND_ACC_FINAL;
}

static zend_fcall_info_cache exit_condition_fci_cache;
static bool exit_condition_cleaner;

static bool php_swoole_coroutine_reactor_can_exit(Reactor *reactor, size_t &event_num) {
    zval retval;
    int success;

    SW_ASSERT(exit_condition_fci_cache.function_handler);
    ZVAL_NULL(&retval);
    success = sw_zend_call_function_ex(nullptr, &exit_condition_fci_cache, 0, nullptr, &retval);
    if (UNEXPECTED(success != SUCCESS)) {
        php_swoole_fatal_error(E_ERROR, "Coroutine can_exit callback handler error");
    }
    if (UNEXPECTED(EG(exception))) {
        zend_exception_error(EG(exception), E_ERROR);
    }
    return !(Z_TYPE_P(&retval) == IS_FALSE);
}

void php_swoole_set_coroutine_option(zend_array *vht) {
    zval *ztmp;
    if (php_swoole_array_get_value(vht, "max_coro_num", ztmp) ||
            php_swoole_array_get_value(vht, "max_coroutine", ztmp)) {
        zend_long max_num = zval_get_long(ztmp);
        PHPCoroutine::set_max_num(max_num <= 0 ? SW_DEFAULT_MAX_CORO_NUM : max_num);
    }
    if (php_swoole_array_get_value(vht, "enable_deadlock_check", ztmp)) {
        PHPCoroutine::set_deadlock_check(zval_is_true(ztmp));
    }
    if (php_swoole_array_get_value(vht, "hook_flags", ztmp)) {
        PHPCoroutine::set_hook_flags(zval_get_long(ztmp));
    }
    if (php_swoole_array_get_value(vht, "enable_preemptive_scheduler", ztmp)) {
        PHPCoroutine::enable_preemptive_scheduler(zval_is_true(ztmp));
    }
    if (php_swoole_array_get_value(vht, "c_stack_size", ztmp) || php_swoole_array_get_value(vht, "stack_size", ztmp)) {
        Coroutine::set_stack_size(zval_get_long(ztmp));
    }
    if (PHPCoroutine::options) {
        zend_hash_merge(PHPCoroutine::options, vht, zval_add_ref, true);
    } else {
        PHPCoroutine::options = zend_array_dup(vht);
    }
}

PHP_METHOD(swoole_coroutine_scheduler, set) {
    zval *zset = nullptr;
    HashTable *vht = nullptr;
    zval *ztmp;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_ARRAY(zset)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    vht = Z_ARRVAL_P(zset);
    php_swoole_set_global_option(vht);
    php_swoole_set_coroutine_option(vht);

    if (php_swoole_array_get_value(vht, "dns_cache_expire", ztmp)) {
        System::set_dns_cache_expire((time_t) zval_get_long(ztmp));
    }
    if (php_swoole_array_get_value(vht, "dns_cache_capacity", ztmp)) {
        System::set_dns_cache_capacity((size_t) zval_get_long(ztmp));
    }
    if (php_swoole_array_get_value(vht, "max_concurrency", ztmp)) {
        PHPCoroutine::set_max_concurrency((uint32_t) SW_MAX(1, zval_get_long(ztmp)));
    }
    /* Reactor can exit */
    if ((ztmp = zend_hash_str_find(vht, ZEND_STRL("exit_condition")))) {
        char *func_name;
        if (exit_condition_fci_cache.function_handler) {
            sw_zend_fci_cache_discard(&exit_condition_fci_cache);
            exit_condition_fci_cache.function_handler = nullptr;
        }
        if (!ZVAL_IS_NULL(ztmp)) {
            if (!sw_zend_is_callable_ex(ztmp, nullptr, 0, &func_name, nullptr, &exit_condition_fci_cache, nullptr)) {
                php_swoole_fatal_error(E_ERROR, "exit_condition '%s' is not callable", func_name);
            } else {
                efree(func_name);
                sw_zend_fci_cache_persist(&exit_condition_fci_cache);
                if (!exit_condition_cleaner) {
                    php_swoole_register_rshutdown_callback(
                        [](void *data) {
                            if (exit_condition_fci_cache.function_handler) {
                                sw_zend_fci_cache_discard(&exit_condition_fci_cache);
                                exit_condition_fci_cache.function_handler = nullptr;
                            }
                        },
                        nullptr);
                    exit_condition_cleaner = true;
                }
                SwooleG.user_exit_condition = php_swoole_coroutine_reactor_can_exit;
                if (sw_reactor()) {
                    sw_reactor()->set_exit_condition(Reactor::EXIT_CONDITION_USER_AFTER_DEFAULT,
                                                     SwooleG.user_exit_condition);
                }
            }
        } else {
            if (sw_reactor()) {
                sw_reactor()->remove_exit_condition(Reactor::EXIT_CONDITION_USER_AFTER_DEFAULT);
                SwooleG.user_exit_condition = nullptr;
            }
        }
    }
}

PHP_METHOD(swoole_coroutine_scheduler, getOptions) {
    if (!PHPCoroutine::options) {
        return;
    }
    RETURN_ARR(zend_array_dup(PHPCoroutine::options));
}

static void scheduler_add_task(SchedulerObject *s, SchedulerTask *task) {
    if (!s->list) {
        s->list = new std::queue<SchedulerTask *>;
    }
    sw_zend_fci_cache_persist(&task->fci_cache);
    sw_zend_fci_params_persist(&task->fci);
    s->list->push(task);
}

static PHP_METHOD(swoole_coroutine_scheduler, add) {
    SchedulerObject *s = scheduler_get_object(Z_OBJ_P(ZEND_THIS));
    if (s->started) {
        php_swoole_fatal_error(
            E_WARNING, "scheduler is running, unable to execute %s->add", SW_Z_OBJCE_NAME_VAL_P(ZEND_THIS));
        RETURN_FALSE;
    }

    SchedulerTask *task = (SchedulerTask *) ecalloc(1, sizeof(SchedulerTask));

    ZEND_PARSE_PARAMETERS_START(1, -1)
    Z_PARAM_FUNC(task->fci, task->fci_cache)
    Z_PARAM_VARIADIC('*', task->fci.params, task->fci.param_count)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    task->count = 1;
    scheduler_add_task(s, task);
}

static PHP_METHOD(swoole_coroutine_scheduler, parallel) {
    SchedulerObject *s = scheduler_get_object(Z_OBJ_P(ZEND_THIS));
    if (s->started) {
        php_swoole_fatal_error(
            E_WARNING, "scheduler is running, unable to execute %s->parallel", SW_Z_OBJCE_NAME_VAL_P(ZEND_THIS));
        RETURN_FALSE;
    }

    SchedulerTask *task = (SchedulerTask *) ecalloc(1, sizeof(SchedulerTask));
    zend_long count;

    ZEND_PARSE_PARAMETERS_START(2, -1)
    Z_PARAM_LONG(count)
    Z_PARAM_FUNC(task->fci, task->fci_cache)
    Z_PARAM_VARIADIC('*', task->fci.params, task->fci.param_count)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    task->count = count;
    scheduler_add_task(s, task);
}

static PHP_METHOD(swoole_coroutine_scheduler, start) {
    SchedulerObject *s = scheduler_get_object(Z_OBJ_P(ZEND_THIS));

    if (SwooleTG.reactor) {
        php_swoole_fatal_error(
            E_WARNING, "eventLoop has already been created. unable to start %s", SW_Z_OBJCE_NAME_VAL_P(ZEND_THIS));
        RETURN_FALSE;
    }
    if (s->started) {
        php_swoole_fatal_error(
            E_WARNING, "scheduler is started, unable to execute %s->start", SW_Z_OBJCE_NAME_VAL_P(ZEND_THIS));
        RETURN_FALSE;
    }
    if (php_swoole_reactor_init() < 0) {
        RETURN_FALSE;
    }

    s->started = true;

    if (!s->list) {
        php_swoole_fatal_error(E_WARNING, "no coroutine task");
        RETURN_FALSE;
    }

    while (!s->list->empty()) {
        SchedulerTask *task = s->list->front();
        s->list->pop();
        for (zend_long i = 0; i < task->count; i++) {
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
