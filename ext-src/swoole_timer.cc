/*
 +----------------------------------------------------------------------+
 | Swoole                                                               |
 +----------------------------------------------------------------------+
 | Copyright (c) 2012-2015 The Swoole Group                             |
 +----------------------------------------------------------------------+
 | This source file is subject to version 2.0 of the Apache license,    |
 | that is bundled with this package in the file LICENSE, and is        |
 | available through the world-wide-web at the following url:           |
 | http://www.apache.org/licenses/LICENSE-2.0.html                      |
 | If you did not receive a copy of the Apache2.0 license and are unable|
 | to obtain it through the world-wide-web, please send a note to       |
 | license@swoole.com so we can mail you a copy immediately.            |
 +----------------------------------------------------------------------+
 | Author: Tianfeng Han  <rango@swoole.com>                             |
 +----------------------------------------------------------------------+
 */

#include "php_swoole_cxx.h"

#include "swoole_server.h"

#include "ext/spl/spl_array.h"

using swoole::Timer;
using swoole::TimerNode;
using zend::Function;

zend_class_entry *swoole_timer_ce;
static zend_object_handlers swoole_timer_handlers;

static zend_class_entry *swoole_timer_iterator_ce;

SW_EXTERN_C_BEGIN
static PHP_FUNCTION(swoole_timer_set);
static PHP_FUNCTION(swoole_timer_after);
static PHP_FUNCTION(swoole_timer_tick);
static PHP_FUNCTION(swoole_timer_exists);
static PHP_FUNCTION(swoole_timer_info);
static PHP_FUNCTION(swoole_timer_stats);
static PHP_FUNCTION(swoole_timer_list);
static PHP_FUNCTION(swoole_timer_clear);
static PHP_FUNCTION(swoole_timer_clear_all);
SW_EXTERN_C_END

// clang-format off
ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_timer_set, 0, 0, 1)
    ZEND_ARG_ARRAY_INFO(0, settings, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_timer_after, 0, 0, 2)
    ZEND_ARG_INFO(0, ms)
    ZEND_ARG_CALLABLE_INFO(0, callback, 0)
    ZEND_ARG_VARIADIC_INFO(0, params)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_timer_tick, 0, 0, 2)
    ZEND_ARG_INFO(0, ms)
    ZEND_ARG_CALLABLE_INFO(0, callback, 0)
    ZEND_ARG_VARIADIC_INFO(0, params)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_timer_exists, 0, 0, 1)
    ZEND_ARG_INFO(0, timer_id)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_timer_info, 0, 0, 1)
    ZEND_ARG_INFO(0, timer_id)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_timer_clear, 0, 0, 1)
    ZEND_ARG_INFO(0, timer_id)
ZEND_END_ARG_INFO()

static const zend_function_entry swoole_timer_methods[] =
{
    ZEND_FENTRY(set, ZEND_FN(swoole_timer_set), arginfo_swoole_timer_set,
                ZEND_ACC_PUBLIC | ZEND_ACC_STATIC | ZEND_ACC_DEPRECATED)
    ZEND_FENTRY(tick, ZEND_FN(swoole_timer_tick), arginfo_swoole_timer_tick, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    ZEND_FENTRY(after, ZEND_FN(swoole_timer_after), arginfo_swoole_timer_after, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    ZEND_FENTRY(exists, ZEND_FN(swoole_timer_exists), arginfo_swoole_timer_exists, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    ZEND_FENTRY(info, ZEND_FN(swoole_timer_info), arginfo_swoole_timer_info, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    ZEND_FENTRY(stats, ZEND_FN(swoole_timer_stats), arginfo_swoole_void, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    ZEND_FENTRY(list, ZEND_FN(swoole_timer_list), arginfo_swoole_void, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    ZEND_FENTRY(clear, ZEND_FN(swoole_timer_clear), arginfo_swoole_timer_clear, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    ZEND_FENTRY(clearAll, ZEND_FN(swoole_timer_clear_all), arginfo_swoole_void, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_FE_END
};
// clang-format on

void php_swoole_timer_minit(int module_number) {
    SW_INIT_CLASS_ENTRY(swoole_timer, "Swoole\\Timer", "swoole_timer", nullptr, swoole_timer_methods);
    SW_SET_CLASS_CREATE(swoole_timer, sw_zend_create_object_deny);

    SW_INIT_CLASS_ENTRY_BASE(swoole_timer_iterator,
                             "Swoole\\Timer\\Iterator",
                             "swoole_timer_iterator",
                             nullptr,
                             nullptr,
                             spl_ce_ArrayIterator);

    SW_FUNCTION_ALIAS(&swoole_timer_ce->function_table, "set", CG(function_table), "swoole_timer_set");
    SW_FUNCTION_ALIAS(&swoole_timer_ce->function_table, "after", CG(function_table), "swoole_timer_after");
    SW_FUNCTION_ALIAS(&swoole_timer_ce->function_table, "tick", CG(function_table), "swoole_timer_tick");
    SW_FUNCTION_ALIAS(&swoole_timer_ce->function_table, "exists", CG(function_table), "swoole_timer_exists");
    SW_FUNCTION_ALIAS(&swoole_timer_ce->function_table, "info", CG(function_table), "swoole_timer_info");
    SW_FUNCTION_ALIAS(&swoole_timer_ce->function_table, "stats", CG(function_table), "swoole_timer_stats");
    SW_FUNCTION_ALIAS(&swoole_timer_ce->function_table, "list", CG(function_table), "swoole_timer_list");
    SW_FUNCTION_ALIAS(&swoole_timer_ce->function_table, "clear", CG(function_table), "swoole_timer_clear");
    SW_FUNCTION_ALIAS(&swoole_timer_ce->function_table, "clearAll", CG(function_table), "swoole_timer_clear_all");

    SW_REGISTER_LONG_CONSTANT("SWOOLE_TIMER_MIN_MS", SW_TIMER_MIN_MS);
    SW_REGISTER_DOUBLE_CONSTANT("SWOOLE_TIMER_MIN_SEC", SW_TIMER_MIN_SEC);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_TIMER_MAX_MS", SW_TIMER_MAX_MS);
    SW_REGISTER_DOUBLE_CONSTANT("SWOOLE_TIMER_MAX_SEC", SW_TIMER_MAX_SEC);
}

static void timer_dtor(TimerNode *tnode) {
    Function *fci = (Function *) tnode->data;
    sw_zend_fci_params_discard(&fci->fci);
    sw_zend_fci_cache_discard(&fci->fci_cache);
    efree(fci);
}

bool php_swoole_timer_clear(TimerNode *tnode) {
    return swoole_timer_del(tnode);
}

bool php_swoole_timer_clear_all() {
    if (UNEXPECTED(!SwooleTG.timer)) {
        return false;
    }

    size_t num = SwooleTG.timer->count(), index = 0;
    TimerNode **list = (TimerNode **) emalloc(num * sizeof(TimerNode *));
    for (auto &kv : SwooleTG.timer->get_map()) {
        TimerNode *tnode = kv.second;
        if (tnode->type == TimerNode::TYPE_PHP) {
            list[index++] = tnode;
        }
    }

    while (index--) {
        swoole_timer_del(list[index]);
    }

    efree(list);

    return true;
}

static void timer_callback(Timer *timer, TimerNode *tnode) {
    Function *fci = (Function *) tnode->data;

    if (UNEXPECTED(!fci->call(nullptr, php_swoole_is_enable_coroutine()))) {
        php_swoole_error(E_WARNING, "%s->onTimeout handler error", ZSTR_VAL(swoole_timer_ce->name));
    }
    if (!tnode->interval || tnode->removed) {
        timer_dtor(tnode);
    }
}

static void timer_add(INTERNAL_FUNCTION_PARAMETERS, bool persistent) {
    zend_long ms;
    Function *fci = (Function *) ecalloc(1, sizeof(Function));
    TimerNode *tnode;

    ZEND_PARSE_PARAMETERS_START(2, -1)
    Z_PARAM_LONG(ms)
    Z_PARAM_FUNC(fci->fci, fci->fci_cache)
    Z_PARAM_VARIADIC('*', fci->fci.params, fci->fci.param_count)
    ZEND_PARSE_PARAMETERS_END_EX(goto _failed);

    if (UNEXPECTED(ms < SW_TIMER_MIN_MS)) {
        php_swoole_fatal_error(E_WARNING, "Timer must be greater than or equal to " ZEND_TOSTR(SW_TIMER_MIN_MS));
    _failed:
        efree(fci);
        RETURN_FALSE;
    }

    // no server || user worker || task process with async mode
    if (!sw_server() || sw_server()->is_user_worker() ||
        (sw_server()->is_task_worker() && sw_server()->task_enable_coroutine)) {
        php_swoole_check_reactor();
    }

    tnode = swoole_timer_add((long) ms, persistent, timer_callback, fci);
    if (UNEXPECTED(!tnode)) {
        php_swoole_fatal_error(E_WARNING, "add timer failed");
        goto _failed;
    }
    tnode->type = TimerNode::TYPE_PHP;
    tnode->destructor = timer_dtor;
    if (persistent) {
        if (fci->fci.param_count > 0) {
            uint32_t i;
            zval *params = (zval *) ecalloc(fci->fci.param_count + 1, sizeof(zval));
            for (i = 0; i < fci->fci.param_count; i++) {
                ZVAL_COPY(&params[i + 1], &fci->fci.params[i]);
            }
            fci->fci.params = params;
        } else {
            fci->fci.params = (zval *) emalloc(sizeof(zval));
        }
        fci->fci.param_count += 1;
        ZVAL_LONG(fci->fci.params, tnode->id);
    } else {
        sw_zend_fci_params_persist(&fci->fci);
    }
    sw_zend_fci_cache_persist(&fci->fci_cache);
    RETURN_LONG(tnode->id);
}

static PHP_FUNCTION(swoole_timer_set) {
    zval *zset = nullptr;
    zval *ztmp;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_ARRAY(zset)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    HashTable *vht = Z_ARRVAL_P(zset);

    if (php_swoole_array_get_value(vht, "enable_coroutine", ztmp)) {
        SWOOLE_G(enable_coroutine) = zval_is_true(ztmp);
    }
}

static PHP_FUNCTION(swoole_timer_after) {
    timer_add(INTERNAL_FUNCTION_PARAM_PASSTHRU, false);
}

static PHP_FUNCTION(swoole_timer_tick) {
    timer_add(INTERNAL_FUNCTION_PARAM_PASSTHRU, true);
}

static PHP_FUNCTION(swoole_timer_exists) {
    if (UNEXPECTED(!SwooleTG.timer)) {
        RETURN_FALSE;
    } else {
        zend_long id;
        TimerNode *tnode;

        ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_LONG(id)
        ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

        tnode = swoole_timer_get(id);
        RETURN_BOOL(tnode && !tnode->removed);
    }
}

static PHP_FUNCTION(swoole_timer_info) {
    if (UNEXPECTED(!SwooleTG.timer)) {
        RETURN_FALSE;
    } else {
        zend_long id;
        TimerNode *tnode;

        ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_LONG(id)
        ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

        tnode = swoole_timer_get(id);
        if (UNEXPECTED(!tnode)) {
            RETURN_NULL();
        }
        array_init(return_value);
        add_assoc_long(return_value, "exec_msec", tnode->exec_msec);
        add_assoc_long(return_value, "exec_count", tnode->exec_count);
        add_assoc_long(return_value, "interval", tnode->interval);
        add_assoc_long(return_value, "round", tnode->round);
        add_assoc_bool(return_value, "removed", tnode->removed);
    }
}

static PHP_FUNCTION(swoole_timer_stats) {
    array_init(return_value);
    if (SwooleTG.timer) {
        add_assoc_bool(return_value, "initialized", 1);
        add_assoc_long(return_value, "num", SwooleTG.timer->count());
        add_assoc_long(return_value, "round", SwooleTG.timer->get_round());
    } else {
        add_assoc_bool(return_value, "initialized", 0);
        add_assoc_long(return_value, "num", 0);
        add_assoc_long(return_value, "round", 0);
    }
}

static PHP_FUNCTION(swoole_timer_list) {
    zval zlist;
    array_init(&zlist);
    if (EXPECTED(SwooleTG.timer)) {
        for (auto &kv : SwooleTG.timer->get_map()) {
            TimerNode *tnode = kv.second;
            if (tnode->type == TimerNode::TYPE_PHP) {
                add_next_index_long(&zlist, tnode->id);
            }
        }
    }
    object_init_ex(return_value, swoole_timer_iterator_ce);
    sw_zend_call_method_with_1_params(
        return_value, swoole_timer_iterator_ce, &swoole_timer_iterator_ce->constructor, "__construct", nullptr, &zlist);
    zval_ptr_dtor(&zlist);
}

static PHP_FUNCTION(swoole_timer_clear) {
    if (UNEXPECTED(!SwooleTG.timer)) {
        RETURN_FALSE;
    } else {
        zend_long id;

        ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_LONG(id)
        ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

        TimerNode *tnode = swoole_timer_get(id);
        if (!tnode || tnode->type != TimerNode::TYPE_PHP) {
            RETURN_FALSE;
        }
        RETURN_BOOL(swoole_timer_del(tnode));
    }
}

static PHP_FUNCTION(swoole_timer_clear_all) {
    RETURN_BOOL(php_swoole_timer_clear_all());
}
