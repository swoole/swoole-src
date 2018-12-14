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
static PHP_METHOD(swoole_channel, peek);
static PHP_METHOD(swoole_channel, stats);

static zend_class_entry swoole_channel_ce;
zend_class_entry *swoole_channel_ce_ptr;
static zend_object_handlers swoole_channel_handlers;

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
    PHP_ME(swoole_channel, __construct, arginfo_swoole_channel_construct, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_channel, __destruct, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_channel, push, arginfo_swoole_channel_push, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_channel, pop, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_channel, peek, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_channel, stats, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

void swoole_channel_init(int module_number)
{
    SWOOLE_INIT_CLASS_ENTRY(swoole_channel, "Swoole\\Channel", "swoole_channel", NULL, swoole_channel_methods);
    SWOOLE_SET_CLASS_SERIALIZABLE(swoole_channel, zend_class_serialize_deny, zend_class_unserialize_deny);
    SWOOLE_SET_CLASS_CLONEABLE(swoole_channel, zend_class_clone_deny);
    SWOOLE_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_channel, zend_class_unset_property_deny);
}

static PHP_METHOD(swoole_channel, __construct)
{
    long size;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "l", &size) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (size < SW_BUFFER_SIZE_STD)
    {
        size = SW_BUFFER_SIZE_STD;
    }

    swChannel *chan = swChannel_new(size, SW_BUFFER_SIZE_STD, SW_CHAN_LOCK | SW_CHAN_SHM);
    if (chan == NULL)
    {
        zend_throw_exception(swoole_exception_ce_ptr, "failed to create channel.", SW_ERROR_MALLOC_FAIL);
        RETURN_FALSE;
    }
    swoole_set_object(getThis(), chan);
}

static PHP_METHOD(swoole_channel, __destruct)
{
    SW_PREVENT_USER_DESTRUCT;

    swoole_set_object(getThis(), NULL);
}

static PHP_METHOD(swoole_channel, push)
{
    swChannel *chan = swoole_get_object(getThis());
    zval *zdata;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "z", &zdata) == FAILURE)
    {
        RETURN_FALSE;
    }

    swEventData buf;
    if (php_swoole_task_pack(&buf, zdata) < 0)
    {
        RETURN_FALSE;
    }
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

    zval *ret_data = php_swoole_task_unpack(&buf);
    if (ret_data == NULL)
    {
        RETURN_FALSE;
    }

    RETVAL_ZVAL(ret_data, 0, NULL);
    efree(ret_data);
}

static PHP_METHOD(swoole_channel, peek)
{
    swChannel *chan = swoole_get_object(getThis());
    swEventData buf;

    int n = swChannel_peek(chan, &buf, sizeof(buf));
    if (n < 0)
    {
        RETURN_FALSE;
    }

    swTask_type(&buf) |= SW_TASK_PEEK;
    zval *ret_data = php_swoole_task_unpack(&buf);
    if (ret_data == NULL)
    {
        RETURN_FALSE;
    }

    RETVAL_ZVAL(ret_data, 0, NULL);
    efree(ret_data);
}

static PHP_METHOD(swoole_channel, stats)
{
    swChannel *chan = swoole_get_object(getThis());
    array_init(return_value);

    add_assoc_long_ex(return_value, ZEND_STRL("queue_num"), chan->num);
    add_assoc_long_ex(return_value, ZEND_STRL("queue_bytes"), chan->bytes);
}
