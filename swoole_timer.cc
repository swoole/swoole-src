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
#include "swoole_coroutine.h"

using namespace swoole;

static void php_swoole_del_timer(swTimer_node *tnode)
{
    php_swoole_fci *fci = (php_swoole_fci *) tnode->data;
    sw_fci_params_discard(&fci->fci);
    sw_fci_cache_discard(&fci->fci_cache);
    efree(fci);
}

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
        if (!tnode)
        {
            break;
        }
        if (tnode->type == SW_TIMER_TYPE_PHP)
        {
            swTimer_del_ex(&SwooleG.timer, tnode, php_swoole_del_timer);
        }
    }
}

static void php_swoole_onTimeout(swTimer *timer, swTimer_node *tnode)
{
    php_swoole_fci *fci = (php_swoole_fci *) tnode->data;

    if (SwooleG.enable_coroutine)
    {
        if (PHPCoroutine::create(&fci->fci_cache, fci->fci.param_count, fci->fci.params) < 0)
        {
            swoole_php_fatal_error(E_WARNING, "create onTimer coroutine error");
        }
    }
    else
    {
        zval retval;
        if (sw_call_user_function_fast_ex(NULL, &fci->fci_cache, &retval, fci->fci.param_count, fci->fci.params) == FAILURE)
        {
            swoole_php_fatal_error(E_WARNING, "onTimeout handler error");
        }
        zval_ptr_dtor(&retval);
    }

    if (!tnode->interval || tnode->remove)
    {
        php_swoole_del_timer(tnode);
    }
}

static void php_swoole_add_timer(INTERNAL_FUNCTION_PARAMETERS, bool persistent)
{
    zend_long ms;
    php_swoole_fci *fci = (php_swoole_fci *) emalloc(sizeof(php_swoole_fci));
    swTimer_node *tnode;

    ZEND_PARSE_PARAMETERS_START(2, -1)
        Z_PARAM_LONG(ms)
        Z_PARAM_FUNC(fci->fci, fci->fci_cache)
        Z_PARAM_VARIADIC('*', fci->fci.params, fci->fci.param_count)
    ZEND_PARSE_PARAMETERS_END_EX(goto _failed);

    if (UNEXPECTED(ms <= 0))
    {
        swoole_php_fatal_error(E_WARNING, "Timer must be greater than 0");
        _failed:
        efree(fci);
        RETURN_FALSE;
    }

    // no server || user worker || task process with async mode
    if (!SwooleG.serv || swIsUserWorker() || (swIsTaskWorker() && SwooleG.serv->task_enable_coroutine))
    {
        php_swoole_check_reactor();
    }

    tnode = swTimer_add(&SwooleG.timer, ms, persistent, fci, php_swoole_onTimeout);
    if (UNEXPECTED(!tnode))
    {
        swoole_php_fatal_error(E_WARNING, "add timer failed");
        goto _failed;
    }
    tnode->type = SW_TIMER_TYPE_PHP;
    if (persistent)
    {
        if (fci->fci.param_count > 0)
        {
            uint32_t i;
            zval *params = (zval *) ecalloc(fci->fci.param_count + 1, sizeof(zval));
            for (i = 0; i < fci->fci.param_count; i++)
            {
                ZVAL_COPY(&params[i + 1], &fci->fci.params[i]);
            }
            fci->fci.params = params;
        }
        else
        {
            fci->fci.params = (zval *) emalloc(sizeof(zval));
        }
        fci->fci.param_count += 1;
        ZVAL_LONG(fci->fci.params, tnode->id);
    }
    else
    {
        sw_fci_params_persist(&fci->fci);
    }
    sw_fci_cache_persist(&fci->fci_cache);
    RETURN_LONG(tnode->id);
}

PHP_FUNCTION(swoole_timer_tick)
{
    php_swoole_add_timer(INTERNAL_FUNCTION_PARAM_PASSTHRU, true);
}

PHP_FUNCTION(swoole_timer_after)
{
    php_swoole_add_timer(INTERNAL_FUNCTION_PARAM_PASSTHRU, false);
}

PHP_FUNCTION(swoole_timer_clear)
{
    if (!SwooleG.timer.initialized)
    {
        swoole_php_error(E_WARNING, "no timer");
        RETURN_FALSE;
    }
    else
    {
        zend_long id;
        swTimer_node *tnode;

        ZEND_PARSE_PARAMETERS_START(1, 1)
            Z_PARAM_LONG(id)
        ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

        tnode = swTimer_get_ex(&SwooleG.timer, id, SW_TIMER_TYPE_PHP);
        RETURN_BOOL(swTimer_del_ex(&SwooleG.timer, tnode, php_swoole_del_timer));
    }
}

PHP_FUNCTION(swoole_timer_exists)
{
    if (!SwooleG.timer.initialized)
    {
        RETURN_FALSE;
    }
    else
    {
        zend_long id;
        swTimer_node *tnode;

        ZEND_PARSE_PARAMETERS_START(1, 1)
            Z_PARAM_LONG(id)
        ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

        tnode = swTimer_get(&SwooleG.timer, id);
        RETURN_BOOL(tnode && !tnode->remove);
    }
}
