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
 | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
 +----------------------------------------------------------------------+
 */

#include "php_swoole.h"
#ifdef SW_COROUTINE
#include "swoole_coroutine.h"
#endif

enum swoole_timer_type
{
    SW_TIMER_TICK, SW_TIMER_AFTER,
};

typedef struct _swTimer_callback
{
    int type;
    int interval;
    zval* callback;
    zend_fcall_info_cache *fci_cache;
    zval* data;
    zval _callback;
    zend_fcall_info_cache _fci_cache;
    zval _data;
} swTimer_callback;

static int php_swoole_del_timer(swTimer_node *tnode);

void php_swoole_clear_all_timer()
{
    if (!SwooleG.timer.map)
    {
        return;
    }
    uint64_t timer_id;
    //kill user process
    while (1)
    {
        swTimer_node *tnode = (swTimer_node *) swHashMap_each_int(SwooleG.timer.map, &timer_id);
        if (tnode == NULL)
        {
            break;
        }
        if (tnode->type != SW_TIMER_TYPE_PHP)
        {
            continue;
        }
        php_swoole_del_timer(tnode);
        swTimer_del(&SwooleG.timer, tnode);
    }
}

long php_swoole_add_timer(long ms, zval *callback, zval *param, int persistent)
{
    if (ms <= 0)
    {
        swoole_php_fatal_error(E_WARNING, "Timer must be greater than 0");
        return SW_ERR;
    }

    if (!(SwooleG.serv && swIsTaskWorker() && SwooleG.serv->task_async == 0))
    {
        php_swoole_check_reactor();
    }

    swTimer_callback *cb = (swTimer_callback *) emalloc(sizeof(swTimer_callback));
    char *func_name = NULL;
    if (!sw_zend_is_callable_ex(callback, NULL, 0, &func_name, NULL, &cb->_fci_cache, NULL))
    {
        swoole_php_fatal_error(E_ERROR, "function '%s' is not callable", func_name);
        return SW_ERR;
    }
    efree(func_name);

    cb->_callback = *callback;
    cb->callback = &cb->_callback;
    cb->fci_cache = &cb->_fci_cache;
    if (param)
    {
        cb->_data = *param;
        cb->data = &cb->_data;
    }
    else
    {
        cb->data = NULL;
    }

    swTimerCallback timer_func;
    if (persistent)
    {
        cb->type = SW_TIMER_TICK;
        timer_func = php_swoole_onInterval;
    }
    else
    {
        cb->type = SW_TIMER_AFTER;
        timer_func = php_swoole_onTimeout;
    }

    Z_TRY_ADDREF_P(cb->callback);
    if (cb->data)
    {
        Z_TRY_ADDREF_P(cb->data);
    }

    swTimer_node *tnode = swTimer_add(&SwooleG.timer, ms, persistent, cb, timer_func);
    if (tnode == NULL)
    {
        swoole_php_fatal_error(E_WARNING, "add timer failed.");
        return SW_ERR;
    }
    else
    {
        tnode->type = SW_TIMER_TYPE_PHP;
        return tnode->id;
    }
}

static int php_swoole_del_timer(swTimer_node *tnode)
{
    swTimer_callback *cb = (swTimer_callback *) tnode->data;
    if (!cb)
    {
        return SW_ERR;
    }
    if (cb->callback)
    {
        zval_ptr_dtor(cb->callback);
    }
    if (cb->data)
    {
        zval_ptr_dtor(cb->data);
    }
    efree(cb);
    return SW_OK;
}

void php_swoole_onTimeout(swTimer *timer, swTimer_node *tnode)
{
    swTimer_callback *cb = (swTimer_callback *) tnode->data;
    zval args[1];
    int argc = 0;

    if (cb->data)
    {
        argc = 1;
        args[0] = *cb->data;
    }

    if (SwooleG.enable_coroutine)
    {
        if (sw_coro_create(cb->fci_cache, argc, args) < 0)
        {
            swoole_php_fatal_error(E_WARNING, "create onTimer coroutine error.");
        }
    }
    else
    {
        zval _retval, *retval = &_retval;
        if (sw_call_user_function_fast_ex(NULL, cb->fci_cache, retval, argc, args) == FAILURE)
        {
            swoole_php_fatal_error(E_WARNING, "onTimeout handler error.");
        }
        zval_ptr_dtor(retval);
    }

    php_swoole_del_timer(tnode);
}

void php_swoole_onInterval(swTimer *timer, swTimer_node *tnode)
{
    zval *ztimer_id;
    swTimer_callback *cb = (swTimer_callback *) tnode->data;

    SW_MAKE_STD_ZVAL(ztimer_id);
    ZVAL_LONG(ztimer_id, tnode->id);

    zval args[2];
    int argc = 1;
    args[0] = *ztimer_id;
    if (cb->data)
    {
        argc = 2;
        Z_TRY_ADDREF_P(cb->data);
        args[1] = *cb->data;
    }

    if (SwooleG.enable_coroutine)
    {
        if (sw_coro_create(cb->fci_cache, argc, args) < 0)
        {
            swoole_php_fatal_error(E_WARNING, "create onInterval coroutine error.");
            return;
        }
    }
    else
    {
        zval _retval, *retval = &_retval;
        if (sw_call_user_function_fast_ex(NULL, cb->fci_cache, retval, argc, args) == FAILURE)
        {
            swoole_php_fatal_error(E_WARNING, "onInterval handler error.");
        }
        zval_ptr_dtor(retval);
    }

    if (tnode->remove)
    {
        php_swoole_del_timer(tnode);
    }
}

PHP_FUNCTION(swoole_timer_tick)
{
    long after_ms;
    zval *callback;
    zval *param = NULL;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "lz|z", &after_ms, &callback, &param) == FAILURE)
    {
        RETURN_FALSE;
    }

    long timer_id = php_swoole_add_timer(after_ms, callback, param, 1);
    if (timer_id < 0)
    {
        RETURN_FALSE;
    }
    else
    {
        RETURN_LONG(timer_id);
    }
}

PHP_FUNCTION(swoole_timer_after)
{
    long after_ms;
    zval *callback;
    zval *param = NULL;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "lz|z", &after_ms, &callback, &param) == FAILURE)
    {
        RETURN_FALSE;
    }

    long timer_id = php_swoole_add_timer(after_ms, callback, param, 0);
    if (timer_id < 0)
    {
        RETURN_FALSE;
    }
    else
    {
        RETURN_LONG(timer_id);
    }
}

PHP_FUNCTION(swoole_timer_clear)
{
    if (!SwooleG.timer.initialized)
    {
        swoole_php_error(E_WARNING, "no timer");
        RETURN_FALSE;
    }

    long id;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "l", &id) == FAILURE)
    {
        RETURN_FALSE;
    }

    swTimer_node *tnode = swTimer_get(&SwooleG.timer, id);
    if (tnode == NULL)
    {
        swoole_php_error(E_WARNING, "timer#%ld is not found.", id);
        RETURN_FALSE;
    }
    if (tnode->remove)
    {
        RETURN_FALSE;
    }
    //current timer, cannot remove here.
    if (SwooleG.timer._current_id > 0 && tnode->id == SwooleG.timer._current_id)
    {
        tnode->remove = 1;
        RETURN_TRUE;
    }
    //remove timer
    if (php_swoole_del_timer(tnode) < 0)
    {
        RETURN_FALSE;
    }
    if (swTimer_del(&SwooleG.timer, tnode) == SW_FALSE)
    {
        RETURN_FALSE;
    }
    else
    {
        RETURN_TRUE;
    }
}

PHP_FUNCTION(swoole_timer_exists)
{
    if (!SwooleG.timer.set)
    {
        swoole_php_error(E_WARNING, "no timer");
        RETURN_FALSE;
    }

    long id;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "l", &id) == FAILURE)
    {
        RETURN_FALSE;
    }

    swTimer_node *tnode = swTimer_get(&SwooleG.timer, id);
    if (tnode == NULL)
    {
       RETURN_FALSE;
    }
    if (tnode->remove)
    {
        RETURN_FALSE;
    }
    RETURN_TRUE;
}
