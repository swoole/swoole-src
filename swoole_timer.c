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
    zval* callback;
    zval* data;
#if PHP_MAJOR_VERSION >= 7
    zval _callback;
    zval _data;
#endif
#ifdef SW_COROUTINE
    zend_fcall_info_cache *func_cache;
#endif
    int interval;
    int type;
} swTimer_callback;

static int php_swoole_del_timer(swTimer_node *tnode TSRMLS_DC);

void php_swoole_clear_all_timer()
{
    if (!SwooleG.timer.map)
    {
        return;
    }
    SWOOLE_GET_TSRMLS;
    uint64_t timer_id;
    //kill user process
    while (1)
    {
        swTimer_node *tnode = swHashMap_each_int(SwooleG.timer.map, &timer_id);
        if (tnode == NULL)
        {
            break;
        }
        if (tnode->type != SW_TIMER_TYPE_PHP)
        {
            continue;
        }
        php_swoole_del_timer(tnode TSRMLS_CC);
        swTimer_del(&SwooleG.timer, tnode);
    }
}

long php_swoole_add_timer(int ms, zval *callback, zval *param, int persistent TSRMLS_DC)
{
    if (ms > SW_TIMER_MAX_VALUE)
    {
        swoole_php_fatal_error(E_WARNING, "The given parameters is too big.");
        return SW_ERR;
    }
    if (ms <= 0)
    {
        swoole_php_fatal_error(E_WARNING, "Timer must be greater than 0");
        return SW_ERR;
    }

    char *func_name = NULL;

    zend_fcall_info_cache *func_cache = emalloc(sizeof(zend_fcall_info_cache));
    if (!sw_zend_is_callable_ex(callback, NULL, 0, &func_name, NULL, func_cache, NULL TSRMLS_CC))
    {
        efree(func_cache);
        efree(func_name);
        swoole_php_fatal_error(E_ERROR, "Function '%s' is not callable", func_name);
        return SW_ERR;
    }
    efree(func_name);

    if (!swIsTaskWorker())
    {
        php_swoole_check_reactor();
    }

    php_swoole_check_timer(ms);
    swTimer_callback *cb = emalloc(sizeof(swTimer_callback));

    cb->data = &cb->_data;
    cb->callback = &cb->_callback;
    memcpy(cb->callback, callback, sizeof(zval));
    if (param)
    {
        memcpy(cb->data, param, sizeof(zval));
    }
    else
    {
        cb->data = NULL;
    }


    if (SwooleG.enable_coroutine)
    {
        cb->func_cache = func_cache;
    }
    else
    {
        efree(func_cache);
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

    sw_zval_add_ref(&cb->callback);
    if (cb->data)
    {
        sw_zval_add_ref(&cb->data);
    }

    swTimer_node *tnode = SwooleG.timer.add(&SwooleG.timer, ms, persistent, cb, timer_func);
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

static int php_swoole_del_timer(swTimer_node *tnode TSRMLS_DC)
{
    swTimer_callback *cb = tnode->data;
    if (!cb)
    {
        return SW_ERR;
    }
    if (cb->callback)
    {
        sw_zval_ptr_dtor(&cb->callback);
    }
    if (cb->data)
    {
        sw_zval_ptr_dtor(&cb->data);
    }
    if (SwooleG.enable_coroutine && cb->func_cache)
    {
        efree(cb->func_cache);
    }
    efree(cb);
    return SW_OK;
}

void php_swoole_onTimeout(swTimer *timer, swTimer_node *tnode)
{
    swTimer_callback *cb = tnode->data;
    zval *retval = NULL;

    if (SwooleG.enable_coroutine)
    {
        zval *args[2];
        int argc;

        if (NULL == cb->data)
        {
            argc = 0;
            args[0] = NULL;
        }
        else
        {
            argc = 1;
            args[0] = cb->data;
        }
        int ret = coro_create(cb->func_cache, args, argc, &retval, NULL, NULL);
        if (CORO_LIMIT == ret)
        {
            swoole_php_fatal_error(E_WARNING, "swoole_timer: coroutine limit");
            return;
        }
    }
    else
    {
        zval **args[2];
        int argc;

        if (NULL == cb->data)
        {
            argc = 0;
            args[0] = NULL;
        }
        else
        {
            argc = 1;
            args[0] = &cb->data;
        }

        if (sw_call_user_function_ex(EG(function_table), NULL, cb->callback, &retval, argc, args, 0, NULL TSRMLS_CC) == FAILURE)
        {
            swoole_php_fatal_error(E_WARNING, "swoole_timer: onTimeout handler error");
            return;
        }
    }

    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }
    if (retval)
    {
        sw_zval_ptr_dtor(&retval);
    }
    php_swoole_del_timer(tnode TSRMLS_CC);
}

void php_swoole_onInterval(swTimer *timer, swTimer_node *tnode)
{
    zval *retval = NULL;
    int argc = 1;

    zval *ztimer_id;

    swTimer_callback *cb = tnode->data;

    SW_MAKE_STD_ZVAL(ztimer_id);
    ZVAL_LONG(ztimer_id, tnode->id);

    if (SwooleG.enable_coroutine)
    {
        zval *args[2];
        if (cb->data)
        {
            argc = 2;
            sw_zval_add_ref(&cb->data);
            args[1] = cb->data;
        }
        args[0] = ztimer_id;

        int ret = coro_create(cb->func_cache, args, argc, &retval, NULL, NULL);
        if (CORO_LIMIT == ret)
        {
            swoole_php_fatal_error(E_WARNING, "swoole_timer: coroutine limit");
            return;
        }
    }
    else
    {
        zval **args[2];
        if (cb->data)
        {
            argc = 2;
            sw_zval_add_ref(&cb->data);
            args[1] = &cb->data;
        }
        args[0] = &ztimer_id;

        if (sw_call_user_function_ex(EG(function_table), NULL, cb->callback, &retval, argc, args, 0, NULL TSRMLS_CC) == FAILURE)
        {
            swoole_php_fatal_error(E_WARNING, "swoole_timer: onTimerCallback handler error");
            return;
        }
    }

    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }
    if (retval != NULL)
    {
        sw_zval_ptr_dtor(&retval);
    }
    sw_zval_ptr_dtor(&ztimer_id);

    if (tnode->remove)
    {
        php_swoole_del_timer(tnode TSRMLS_CC);
    }
}

void php_swoole_check_timer(int msec)
{
    if (SwooleG.timer.fd == 0)
    {
        swTimer_init(msec);
    }
}

PHP_FUNCTION(swoole_timer_tick)
{
    long after_ms;
    zval *callback;
    zval *param = NULL;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "lz|z", &after_ms, &callback, &param) == FAILURE)
    {
        return;
    }

    long timer_id = php_swoole_add_timer(after_ms, callback, param, 1 TSRMLS_CC);
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

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "lz|z", &after_ms, &callback, &param) == FAILURE)
    {
        return;
    }

    long timer_id = php_swoole_add_timer(after_ms, callback, param, 0 TSRMLS_CC);
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
    if (!SwooleG.timer.set)
    {
        swoole_php_error(E_WARNING, "no timer");
        RETURN_FALSE;
    }

    long id;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &id) == FAILURE)
    {
        return;
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
    if (php_swoole_del_timer(tnode TSRMLS_CC) < 0)
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
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &id) == FAILURE)
    {
        return;
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
