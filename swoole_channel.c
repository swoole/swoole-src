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


static PHP_METHOD(swoole_channel, __construct);
static PHP_METHOD(swoole_channel, __destruct);
static PHP_METHOD(swoole_channel, push);
static PHP_METHOD(swoole_channel, pop);
static PHP_METHOD(swoole_channel, stats);

static zend_class_entry swoole_channel_ce;
zend_class_entry *swoole_channel_class_entry_ptr;

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_channel_construct, 0, 0, 1)
    ZEND_ARG_INFO(0, size)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_channel_push, 0, 0, 1)
    ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_void, 0, 0, 0)
ZEND_END_ARG_INFO()

static const zend_function_entry swoole_channel_methods[] =
{
    PHP_ME(swoole_channel, __construct, arginfo_swoole_channel_construct, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_ME(swoole_channel, __destruct, arginfo_swoole_void, ZEND_ACC_PUBLIC | ZEND_ACC_DTOR)
    PHP_ME(swoole_channel, push, arginfo_swoole_channel_push, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_channel, pop, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_channel, stats, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

void swoole_channel_init(int module_number TSRMLS_DC)
{
    SWOOLE_INIT_CLASS_ENTRY(swoole_channel_ce, "swoole_channel", "Swoole\\Channel", swoole_channel_methods);
    swoole_channel_class_entry_ptr = zend_register_internal_class(&swoole_channel_ce TSRMLS_CC);
    SWOOLE_CLASS_ALIAS(swoole_channel, "Swoole\\Channel");
}

static PHP_METHOD(swoole_channel, __construct)
{
    long size;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &size) == FAILURE)
    {
        RETURN_FALSE;
    }

    swChannel *chan = swChannel_new(size, SW_BUFFER_SIZE_STD, SW_CHAN_LOCK | SW_CHAN_SHM);
    if (chan == NULL)
    {
        zend_throw_exception(swoole_exception_class_entry_ptr, "cahnnel create failed.", SW_ERROR_MALLOC_FAIL TSRMLS_CC);
        RETURN_FALSE;
    }
    swoole_set_object(getThis(), chan);
}

static PHP_METHOD(swoole_channel, __destruct)
{
    swoole_set_object(getThis(), NULL);
}

static PHP_METHOD(swoole_channel, push)
{
    swChannel *chan = swoole_get_object(getThis());
    zval *zdata;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &zdata) == FAILURE)
    {
        RETURN_FALSE;
    }

    swEventData buf;
    php_swoole_task_pack(&buf, zdata TSRMLS_CC);

    SW_CHECK_RETURN(swChannel_push(chan, &buf, sizeof(buf.info) + buf.info.len));
}

static PHP_METHOD(swoole_channel, pop)
{
    swChannel *chan = swoole_get_object(getThis());
    swEventData buf;

    int n = swChannel_pop(chan, &buf, sizeof(buf));
    if (n < 0)
    {
        RETURN_FALSE;
    }

    zval *ret_data = php_swoole_task_unpack(&buf TSRMLS_CC);
    RETVAL_ZVAL(ret_data, 0, NULL);
    efree(ret_data);
}

static PHP_METHOD(swoole_channel, stats)
{
    swChannel *chan = swoole_get_object(getThis());
    array_init(return_value);

    sw_add_assoc_long_ex(return_value, ZEND_STRS("queue_num"), chan->num);
    sw_add_assoc_long_ex(return_value, ZEND_STRS("queue_bytes"), chan->bytes);
}
