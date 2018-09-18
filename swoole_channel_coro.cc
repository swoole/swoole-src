/*
 +----------------------------------------------------------------------+
 | Swoole                                                               |
 +----------------------------------------------------------------------+
 | Copyright (c) 2012-2018 The Swoole Group                             |
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
 |         Tianfeng Han <rango@swoole.com>                              |
 +----------------------------------------------------------------------+
 */

#include "php_swoole.h"

#ifdef SW_COROUTINE
#include "swoole_coroutine.h"
#include "channel.h"

using namespace swoole;

static PHP_METHOD(swoole_channel_coro, __construct);
static PHP_METHOD(swoole_channel_coro, __destruct);
static PHP_METHOD(swoole_channel_coro, push);
static PHP_METHOD(swoole_channel_coro, pop);
static PHP_METHOD(swoole_channel_coro, close);
static PHP_METHOD(swoole_channel_coro, stats);
static PHP_METHOD(swoole_channel_coro, length);
static PHP_METHOD(swoole_channel_coro, isEmpty);
static PHP_METHOD(swoole_channel_coro, isFull);

static zend_class_entry swoole_channel_coro_ce;
static zend_class_entry *swoole_channel_coro_class_entry_ptr;

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_channel_coro_construct, 0, 0, 0)
    ZEND_ARG_INFO(0, size)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_channel_coro_push, 0, 0, 1)
    ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_channel_coro_pop, 0, 0, 1)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_void, 0, 0, 0)
ZEND_END_ARG_INFO()

static const zend_function_entry swoole_channel_coro_methods[] =
{
    PHP_ME(swoole_channel_coro, __construct, arginfo_swoole_channel_coro_construct, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_ME(swoole_channel_coro, __destruct, arginfo_swoole_void, ZEND_ACC_PUBLIC | ZEND_ACC_DTOR)
    PHP_ME(swoole_channel_coro, push, arginfo_swoole_channel_coro_push, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_channel_coro, pop,  arginfo_swoole_channel_coro_pop,  ZEND_ACC_PUBLIC)
    PHP_ME(swoole_channel_coro, isEmpty, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_channel_coro, isFull, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_channel_coro, close, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_channel_coro, stats, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_channel_coro, length, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

void swoole_channel_coro_init(int module_number TSRMLS_DC)
{
    INIT_CLASS_ENTRY(swoole_channel_coro_ce, "Swoole\\Coroutine\\Channel", swoole_channel_coro_methods);
    swoole_channel_coro_class_entry_ptr = zend_register_internal_class(&swoole_channel_coro_ce);

    if (SWOOLE_G(use_shortname))
    {
        sw_zend_register_class_alias("chan", swoole_channel_coro_class_entry_ptr);
    }

    zend_declare_property_long(swoole_channel_coro_class_entry_ptr, SW_STRL("capacity")-1, 0, ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_channel_coro_class_entry_ptr, SW_STRL("errCode")-1, 0, ZEND_ACC_PUBLIC);
}

static PHP_METHOD(swoole_channel_coro, __construct)
{
    zend_long capacity = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "|l", &capacity) == FAILURE)
    {
        RETURN_FALSE;
    }
    if (capacity <= 0)
    {
        capacity = 1;
    }

    php_swoole_check_reactor();

    Channel *chan = new Channel(capacity);
    zend_update_property_long(swoole_channel_coro_class_entry_ptr, getThis(), ZEND_STRL("capacity"), capacity);

    swoole_set_object(getThis(), chan);
}

static PHP_METHOD(swoole_channel_coro, __destruct)
{
    SW_PREVENT_USER_DESTRUCT;

    Channel *chan = (Channel *) swoole_get_object(getThis());
    while (chan->length() > 0)
    {
        zval *data = (zval *) chan->pop_data();
        if (data)
        {
            sw_zval_free(data);
        }
    }
    delete chan;
    swoole_set_object(getThis(), NULL);
}

static PHP_METHOD(swoole_channel_coro, push)
{
    coro_check(TSRMLS_C);

    Channel *chan = (Channel *) swoole_get_object(getThis());
    if (chan->closed)
    {
        zend_update_property_long(swoole_channel_coro_class_entry_ptr, getThis(), SW_STRL("errCode")-1, -2);
        RETURN_FALSE;
    }

    zval *zdata;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "z", &zdata) == FAILURE)
    {
        RETURN_FALSE;
    }

    Z_TRY_ADDREF_P(zdata);
    if (chan->push(sw_zval_dup(zdata)))
    {
        RETURN_TRUE;
    }
    else
    {
        Z_TRY_DELREF_P(zdata);
        RETURN_FALSE;
    }
}

static PHP_METHOD(swoole_channel_coro, pop)
{
    coro_check(TSRMLS_C);

    Channel *chan = (Channel *) swoole_get_object(getThis());
    if (chan->closed)
    {
        zend_update_property_long(swoole_channel_coro_class_entry_ptr, getThis(), SW_STRL("errCode")-1, -2);
        RETURN_FALSE;
    }

    double timeout = -1;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "|d", &timeout) == FAILURE)
    {
        RETURN_FALSE;
    }
    zval *data = (zval *) chan->pop(timeout);
    if (data)
    {
        RETVAL_ZVAL(data, 0, 0);
        efree(data);
    }
    else
    {
        zend_update_property_long(swoole_channel_coro_class_entry_ptr, getThis(), SW_STRL("errCode")-1, chan->closed ? -2 : -1);
        RETURN_FALSE;
    }
}

static PHP_METHOD(swoole_channel_coro, close)
{
    Channel *chan = (Channel *) swoole_get_object(getThis());
    RETURN_BOOL(chan->close());
}

static PHP_METHOD(swoole_channel_coro, length)
{
    Channel *chan = (Channel *) swoole_get_object(getThis());
    RETURN_LONG(chan->length());
}

static PHP_METHOD(swoole_channel_coro, isEmpty)
{
    Channel *chan = (Channel *) swoole_get_object(getThis());
    RETURN_BOOL(chan->is_empty());
}

static PHP_METHOD(swoole_channel_coro, isFull)
{
    Channel *chan = (Channel *) swoole_get_object(getThis());
    RETURN_BOOL(chan->is_full());
}

static PHP_METHOD(swoole_channel_coro, stats)
{
    Channel *chan = (Channel *) swoole_get_object(getThis());
    array_init(return_value);
    sw_add_assoc_long_ex(return_value, ZEND_STRS("consumer_num"), chan->consumer_num());
    sw_add_assoc_long_ex(return_value, ZEND_STRS("producer_num"), chan->producer_num());
    if (chan)
    {
        sw_add_assoc_long_ex(return_value, ZEND_STRS("queue_num"), chan->length());
    }
}

#endif
