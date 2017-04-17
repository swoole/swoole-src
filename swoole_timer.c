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
    int interval;
    int type;
} swTimer_callback;

#ifdef SW_COROUTINE
swHashMap *timer_map;
#else
static swHashMap *timer_map;
#endif

static void php_swoole_onTimeout(swTimer *timer, swTimer_node *tnode);
static void php_swoole_onInterval(swTimer *timer, swTimer_node *tnode);
#ifdef SW_COROUTINE
int php_swoole_del_timer_coro(swTimer_node *tnode TSRMLS_DC);
#endif
static long php_swoole_add_timer(int ms, zval *callback, zval *param, int is_tick TSRMLS_DC);
static int php_swoole_del_timer(swTimer_node *tnode TSRMLS_DC);

#ifdef SW_COROUTINE
int php_swoole_add_timer_coro(int ms, int cli_fd, long *timeout_id, void* param, swLinkedList_node **node TSRMLS_DC) //void *
{
    if (SwooleG.serv && swIsMaster())
    {
        swoole_php_fatal_error(E_WARNING, "cannot use timer in master process.");
        return SW_ERR;
    }
    if (ms > 86400000)
    {
        swoole_php_fatal_error(E_WARNING, "The given parameters is too big.");
        return SW_ERR;
    }
    if (ms <= 0)
    {
        swoole_php_fatal_error(E_WARNING, "Timer must be greater than 0");
        return SW_ERR;
    }

    if (!swIsTaskWorker())
    {
        php_swoole_check_reactor();
    }

    php_swoole_check_timer(ms);

	if (unlikely(SwooleWG.delayed_coro_timeout_list == NULL))
	{
		SwooleWG.delayed_coro_timeout_list = swLinkedList_new(2, NULL);
		if (SwooleWG.delayed_coro_timeout_list == NULL)
		{
			swoole_php_fatal_error(E_WARNING, "New swLinkedList failed.");
			return SW_ERR;
		}
	}

    swTimer_coro_callback *scc = emalloc(sizeof(swTimer_coro_callback));
    scc->ms = ms;
    scc->data = param;
    scc->cli_fd = cli_fd;
    scc->timeout_id = timeout_id;

    if (swLinkedList_append(SwooleWG.delayed_coro_timeout_list, (void *)scc) == SW_ERR)
    {
        efree(scc);
        swoole_php_fatal_error(E_WARNING, "Append to swTimer_coro_callback_list failed.");
        return SW_ERR;
    }
    if (node != NULL) {
        *node = SwooleWG.delayed_coro_timeout_list->tail;
    }

    return SW_OK;
}
int php_swoole_clear_timer_coro(long id TSRMLS_DC)
{
    if (id < 0)
    {
        swoole_php_error(E_WARNING, "no timer id");
        return SW_ERR;
    }

    if (!SwooleG.timer.set)
    {
        swoole_php_error(E_WARNING, "no timer");
        return SW_ERR;
    }

    swTimer_node *tnode = swHashMap_find_int(timer_map, id);
    if (tnode == NULL)
    {
        swoole_php_error(E_WARNING, "timer#%ld is not found.", id);
        return SW_ERR;
    }

    //current timer, cannot remove here.
    if (tnode->id == SwooleG.timer._current_id)
    {
        tnode->remove = 1;
        return SW_OK;
    }

    if (php_swoole_del_timer_coro(tnode TSRMLS_CC) < 0)
    {
        return SW_ERR;
    }
    else
    {
        swTimer_del(&SwooleG.timer, tnode);
		SwooleG.timer.num--;
        return SW_OK;
    }
}

int php_swoole_del_timer_coro(swTimer_node *tnode TSRMLS_DC)
{

    if (swHashMap_del_int(timer_map, tnode->id) < 0)
    {
        return SW_ERR;
    }
    tnode->id = -1;

    swTimer_coro_callback *scc = tnode->data;
    if (!scc)
    {
        return SW_ERR;
    }

    efree(scc);
    return SW_OK;
}
#endif

static long php_swoole_add_timer(int ms, zval *callback, zval *param, int is_tick TSRMLS_DC)
{
    if (SwooleG.serv && swIsMaster())
    {
        swoole_php_fatal_error(E_WARNING, "cannot use timer in master process.");
        return SW_ERR;
    }
    if (ms > 86400000)
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
    if (!sw_zend_is_callable(callback, 0, &func_name TSRMLS_CC))
    {
        swoole_php_fatal_error(E_ERROR, "Function '%s' is not callable", func_name);
        efree(func_name);
        return SW_ERR;
    }
    efree(func_name);

    if (!swIsTaskWorker())
    {
        php_swoole_check_reactor();
    }

    php_swoole_check_timer(ms);
    swTimer_callback *cb = emalloc(sizeof(swTimer_callback));

#if PHP_MAJOR_VERSION >= 7
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

    sw_zval_add_ref(&cb->callback);
    if (cb->data)
    {
        sw_zval_add_ref(&cb->data);
    }

    swTimer_node *tnode = swTimer_add(&SwooleG.timer, ms, is_tick, cb);
    if (tnode == NULL)
    {
        swoole_php_fatal_error(E_WARNING, "addtimer failed.");
        return SW_ERR;
    }
    else
    {
        swHashMap_add_int(timer_map, tnode->id, tnode);
        return tnode->id;
    }
}

static int php_swoole_del_timer(swTimer_node *tnode TSRMLS_DC)
{
    if (swHashMap_del_int(timer_map, tnode->id) < 0)
    {
        return SW_ERR;
    }
    tnode->id = -1;
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
    efree(cb);
    return SW_OK;
}

static void php_swoole_onTimeout(swTimer *timer, swTimer_node *tnode)
{
#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

#ifdef SW_COROUTINE
    if (tnode->type == SW_TIMER_TYPE_CORO)
    {
        swTimer_coro_callback *scc = tnode->data;
        if (SwooleWG.coro_timeout_list == NULL)
        {
            SwooleWG.coro_timeout_list = swLinkedList_new(1, NULL);
        }
        
        // del the reactor handle
        if(swLinkedList_append(SwooleWG.coro_timeout_list, scc->data) == SW_OK)
        {
			if (SwooleG.main_reactor->del(SwooleG.main_reactor, scc->cli_fd) == SW_ERR)
			{
				swSysError("reactor->del(%d) failed.", scc->cli_fd);
			}
        }
        
        php_swoole_del_timer_coro(tnode TSRMLS_CC);
        sw_free(tnode);
    }
    else
#endif
    {
        swTimer_callback *cb = tnode->data;
        zval *retval = NULL;
        zval **args[1];
        int argc = 0;

        if (cb->data)
        {
            args[0] = &cb->data;
            argc = 1;
        }

        timer->_current_id = tnode->id;
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
        php_swoole_del_timer(tnode TSRMLS_CC);
    }
}

static void php_swoole_onInterval(swTimer *timer, swTimer_node *tnode)
{
#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    zval *retval = NULL;
    zval **args[2];
    int argc = 1;

    zval *ztimer_id;

    swTimer_callback *cb = tnode->data;

    SW_MAKE_STD_ZVAL(ztimer_id);
    ZVAL_LONG(ztimer_id, tnode->id);

    if (cb->data)
    {
        argc = 2;
        sw_zval_add_ref(&cb->data);
        args[1] = &cb->data;
    }

    args[0] = &ztimer_id;

    timer->_current_id = tnode->id;
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
        SwooleG.timer.onAfter = php_swoole_onTimeout;
        SwooleG.timer.onTick = php_swoole_onInterval;

        timer_map = swHashMap_new(SW_HASHMAP_INIT_BUCKET_N, NULL);
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

    swTimer_node *tnode = swHashMap_find_int(timer_map, id);
    if (tnode == NULL)
    {
        swoole_php_error(E_WARNING, "timer#%ld is not found.", id);
        RETURN_FALSE;
    }

    //current timer, cannot remove here.
    if (tnode->id == SwooleG.timer._current_id)
    {
        if (0 == tnode->remove)  //To avoid repeat delete
        {
            tnode->remove = 1;
            RETURN_TRUE;
        }
        else
        {
            RETURN_FALSE;
        }
    }

    if (php_swoole_del_timer(tnode TSRMLS_CC) < 0)
    {
        RETURN_FALSE;
    }
    else
    {
        swTimer_del(&SwooleG.timer, tnode);
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

    swTimer_node *tnode = swHashMap_find_int(timer_map, id);
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
