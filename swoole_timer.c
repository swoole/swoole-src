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

enum swoole_timer_type
{
    SW_TIMER_TICK, SW_TIMER_AFTER, SW_TIMER_INTERVAL,
};

typedef struct _swTimer_callback
{
    zval* callback;
    zval* data;
#if PHP_MAJOR_VERSION >= 7
    zval _callback;
    zval _data;
#endif
    int interval;
    int type;
} swTimer_callback;

static void php_swoole_onTimeout(swTimer *timer, swTimer_node *event);
static void php_swoole_onTimerInterval(swTimer *timer, swTimer_node *event);
static long php_swoole_add_timer(int ms, zval *callback, zval *param, int is_tick TSRMLS_DC);
static int php_swoole_del_timer(long id TSRMLS_DC);

static long php_swoole_add_timer(int ms, zval *callback, zval *param, int is_tick TSRMLS_DC)
{
    if (ms > 86400000)
    {
        swoole_php_fatal_error(E_WARNING, "The given parameters is too big.");
        return SW_ERR;
    }

    char *func_name = NULL;
    if (!sw_zend_is_callable(callback, 0, &func_name TSRMLS_CC))
    {
        swoole_php_fatal_error(E_ERROR, "Function '%s' is not callable", func_name);
        efree(func_name);
        return SW_ERR;
    }
    efree(func_name);

    if (SwooleGS->start > 0 && swIsTaskWorker())
    {
        swoole_php_error(E_WARNING, "cannot use swoole_server->after in task worker.");
    }

    swTimer_callback *cb = emalloc(sizeof(swTimer_callback));

#if PHP_MAJOR_VERSION >= 7
    cb->data = &cb->_data;
    cb->callback = &cb->_callback;
    memcpy(cb->callback, callback, sizeof(zval));
    if (param)
    {
        memcpy(cb->data, param, sizeof(zval));
    }
#else
    cb->data = param;
    cb->callback = callback;
#endif

    if (is_tick)
    {
        cb->type = SW_TIMER_TICK;
    }
    else
    {
        cb->type = SW_TIMER_AFTER;
    }

    php_swoole_check_reactor();
    php_swoole_check_timer(ms);

    sw_zval_add_ref(&cb->callback);
    if (cb->data)
    {
        sw_zval_add_ref(&cb->data);
    }

    return SwooleG.timer.add(&SwooleG.timer, ms, is_tick, cb);
}

static int php_swoole_del_timer(long id TSRMLS_DC)
{
    swTimer_callback *cb = SwooleG.timer.del(&SwooleG.timer, -1, id);
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
    efree(cb);
    return SW_OK;
}

static void php_swoole_onTimeout(swTimer *timer, swTimer_node *event)
{
    swTimer_callback *cb = event->data;
    zval *retval = NULL;
#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    zval **args[1];
    int argc = 0;

    if (cb->data)
    {
        args[0] = &cb->data;
        argc = 1;
    }

    timer->_current_id = event->id;
    if (sw_call_user_function_ex(EG(function_table), NULL, cb->callback, &retval, argc, args, 0, NULL TSRMLS_CC) == FAILURE)
    {
        swoole_php_fatal_error(E_WARNING, "swoole_timer: onTimeout handler error");
        return;
    }
    timer->_current_id = -1;

    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }

    if (retval)
    {
        sw_zval_ptr_dtor(&retval);
    }
    cb = event->data;
    if (cb)
    {
        if (cb->data)
        {
            sw_zval_ptr_dtor(&cb->data);
        }
        sw_zval_ptr_dtor(&cb->callback);
        efree(cb);
    }
}

static void php_swoole_onTimerInterval(swTimer *timer, swTimer_node *event)
{
#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    zval *retval = NULL;
    zval **args[2];
    int argc = 1;

    zval *ztimer_id;

    swTimer_callback *cb = event->data;

    //server->addtimer
    if (cb == NULL && SwooleG.serv)
    {
        SwooleG.serv->onTimer(SwooleG.serv, event->interval);
        return;
    }

    if (cb->type == SW_TIMER_TICK)
    {
        SW_MAKE_STD_ZVAL(ztimer_id);
        ZVAL_LONG(ztimer_id, event->id);

        if (cb->data)
        {
            argc = 2;
            sw_zval_add_ref(&cb->data);
            args[1] = &cb->data;
        }
    }
    else
    {
        SW_MAKE_STD_ZVAL(ztimer_id);
        ZVAL_LONG(ztimer_id, event->interval);
    }
    args[0] = &ztimer_id;

    timer->_current_id = event->id;
    if (sw_call_user_function_ex(EG(function_table), NULL, cb->callback, &retval, argc, args, 0, NULL TSRMLS_CC) == FAILURE)
    {
        swoole_php_fatal_error(E_WARNING, "swoole_timer: onTimerCallback handler error");
        return;
    }
    timer->_current_id = -1;

    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }

    if (retval != NULL)
    {
        sw_zval_ptr_dtor(&retval);
    }

    if (SwooleG.timer._delete_id == event->id)
    {
        php_swoole_del_timer(SwooleG.timer._delete_id  TSRMLS_CC);
        SwooleG.timer._delete_id = -1;
    }
    sw_zval_ptr_dtor(&ztimer_id);
}

void php_swoole_check_timer(int msec)
{
    if (SwooleG.timer.fd == 0)
    {
        if (!SwooleG.main_reactor)
        {
            swTimer_init(msec, SwooleG.use_timer_pipe);
        }
        else
        {
            swEventTimer_init();
            SwooleG.main_reactor->timeout_msec = msec;
        }

        SwooleG.timer.interval = msec;
        SwooleG.timer.onTimeout = php_swoole_onTimeout;
        SwooleG.timer.onTimer = php_swoole_onTimerInterval;
    }
}

PHP_FUNCTION(swoole_timer_add)
{
    long interval;
    zval *callback;

    if (swIsMaster())
    {
        swoole_php_fatal_error(E_WARNING, "swoole_timer_add can not use in swoole_server. Please use swoole_server->addtimer");
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "lz", &interval, &callback) == FAILURE)
    {
        return;
    }

    if (interval > 86400000)
    {
        swoole_php_fatal_error(E_WARNING, "The given parameters is too big.");
        RETURN_FALSE;
    }

    swTimer_callback *cb = emalloc(sizeof(swTimer_callback));
#if PHP_MAJOR_VERSION >= 7
    cb->callback = &cb->_callback;
    memcpy(cb->callback, callback, sizeof(zval));
#else
    cb->callback = callback;
#endif
    cb->data = NULL;
    cb->type = SW_TIMER_INTERVAL;
    sw_zval_add_ref(&callback);

    char *func_name = NULL;
    if (!sw_zend_is_callable(cb->callback, 0, &func_name TSRMLS_CC))
    {
        swoole_php_fatal_error(E_WARNING, "Function '%s' is not callable", func_name);
        efree(func_name);
        RETURN_FALSE;
    }
    efree(func_name);

    cb->interval = (int) interval;

    php_swoole_check_reactor();
    php_swoole_check_timer(interval);

    if (SwooleG.timer.add(&SwooleG.timer, interval, 1, cb) < 0)
    {
        RETURN_FALSE;
    }

    RETURN_TRUE;
}

PHP_FUNCTION(swoole_timer_del)
{
    long interval;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &interval) == FAILURE)
    {
        return;
    }

    if (SwooleG.timer.fd == 0)
    {
        swoole_php_fatal_error(E_WARNING, "no timer.");
        RETURN_FALSE;
    }

    swTimer_callback *callback = SwooleG.timer.del(&SwooleG.timer, (int) interval, -1);

    if (SwooleGS->start > 0)
    {
        RETURN_TRUE;
    }

    if (!callback)
    {
        RETURN_FALSE;
    }
    efree(callback);

    RETURN_TRUE;
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

    php_swoole_check_reactor();
    php_swoole_check_timer(after_ms);

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

    php_swoole_check_reactor();
    php_swoole_check_timer(after_ms);

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
    if (!SwooleG.timer.del)
    {
        swoole_php_error(E_WARNING, "no timer");
        RETURN_FALSE;
    }

    long id;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &id) == FAILURE)
    {
        return;
    }

    if (id == SwooleG.timer._current_id)
    {
        SwooleG.timer._delete_id = id;
        RETURN_TRUE;
    }
    else
    {
        if (php_swoole_del_timer(id TSRMLS_CC) < 0)
        {
            RETURN_FALSE;
        }
        else
        {
            RETURN_TRUE;
        }
    }
}
