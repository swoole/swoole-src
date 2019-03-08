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

static zend_class_entry swoole_channel_coro_ce;
static zend_class_entry *swoole_channel_coro_ce_ptr;
static zend_object_handlers swoole_channel_coro_handlers;

typedef struct
{
    Channel *chan;
    zend_object std;
} channel_coro;

static PHP_METHOD(swoole_channel_coro, __construct);
static PHP_METHOD(swoole_channel_coro, push);
static PHP_METHOD(swoole_channel_coro, pop);
static PHP_METHOD(swoole_channel_coro, close);
static PHP_METHOD(swoole_channel_coro, stats);
static PHP_METHOD(swoole_channel_coro, length);
static PHP_METHOD(swoole_channel_coro, isEmpty);
static PHP_METHOD(swoole_channel_coro, isFull);

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_channel_coro_construct, 0, 0, 0)
    ZEND_ARG_INFO(0, size)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_channel_coro_push, 0, 0, 1)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_channel_coro_pop, 0, 0, 0)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_void, 0, 0, 0)
ZEND_END_ARG_INFO()

static const zend_function_entry swoole_channel_coro_methods[] =
{
    PHP_ME(swoole_channel_coro, __construct, arginfo_swoole_channel_coro_construct, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_channel_coro, push, arginfo_swoole_channel_coro_push, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_channel_coro, pop,  arginfo_swoole_channel_coro_pop,  ZEND_ACC_PUBLIC)
    PHP_ME(swoole_channel_coro, isEmpty, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_channel_coro, isFull, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_channel_coro, close, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_channel_coro, stats, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_channel_coro, length, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

enum swChannelErrorCode
{
    SW_CHANNEL_OK = 0,
    SW_CHANNEL_TIMEOUT = -1,
    SW_CHANNEL_CLOSED = -2,
};

static sw_inline channel_coro* swoole_channel_coro_fetch_object(zend_object *obj)
{
    return (channel_coro *) ((char *) obj - swoole_channel_coro_handlers.offset);
}

static sw_inline Channel * swoole_get_channel(zval *zobject)
{
    Channel *chan = swoole_channel_coro_fetch_object(Z_OBJ_P(zobject))->chan;
    if (UNEXPECTED(!chan))
    {
        swoole_php_fatal_error(E_ERROR, "you must call Channel constructor first.");
    }
    return chan;
}

static void swoole_channel_coro_free_object(zend_object *object)
{
    channel_coro *chan_t = swoole_channel_coro_fetch_object(object);
    Channel *chan = chan_t->chan;
    if (chan)
    {
        while (chan->length() > 0)
        {
            zval *data = (zval *) chan->pop_data();
            if (data)
            {
                sw_zval_free(data);
            }
        }
        delete chan;
    }
    zend_object_std_dtor(&chan_t->std);
}

static zend_object *swoole_channel_coro_create_object(zend_class_entry *ce)
{
    channel_coro *chan_t = (channel_coro *) ecalloc(1, sizeof(channel_coro) + zend_object_properties_size(ce));
    zend_object_std_init(&chan_t->std, ce);
    object_properties_init(&chan_t->std, ce);
    chan_t->std.handlers = &swoole_channel_coro_handlers;
    return &chan_t->std;
}

void swoole_channel_coro_init(int module_number)
{
    SWOOLE_INIT_CLASS_ENTRY(swoole_channel_coro, "Swoole\\Coroutine\\Channel", NULL, "Co\\Channel", swoole_channel_coro_methods);
    SWOOLE_SET_CLASS_SERIALIZABLE(swoole_channel_coro, zend_class_serialize_deny, zend_class_unserialize_deny);
    SWOOLE_SET_CLASS_CLONEABLE(swoole_channel_coro, zend_class_clone_deny);
    SWOOLE_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_channel_coro, zend_class_unset_property_deny);
    SWOOLE_SET_CLASS_CUSTOM_OBJECT(swoole_channel_coro, swoole_channel_coro_create_object, swoole_channel_coro_free_object, channel_coro, std);
    if (SWOOLE_G(use_shortname))
    {
        SWOOLE_CLASS_ALIAS("Chan", swoole_channel_coro);
    }

    zend_declare_property_long(swoole_channel_coro_ce_ptr, ZEND_STRL("capacity"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_channel_coro_ce_ptr, ZEND_STRL("errCode"), 0, ZEND_ACC_PUBLIC);

    SWOOLE_DEFINE(CHANNEL_OK);
    SWOOLE_DEFINE(CHANNEL_TIMEOUT);
    SWOOLE_DEFINE(CHANNEL_CLOSED);
}

static PHP_METHOD(swoole_channel_coro, __construct)
{
    zend_long capacity = 1;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "|l", &capacity) == FAILURE)
    {
        RETURN_FALSE;
    }
    if (capacity <= 0)
    {
        capacity = 1;
    }

    php_swoole_check_reactor();

    channel_coro *chan_t = swoole_channel_coro_fetch_object(Z_OBJ_P(getThis()));
    chan_t->chan = new Channel(capacity);
    zend_update_property_long(swoole_channel_coro_ce_ptr, getThis(), ZEND_STRL("capacity"), capacity);
}

static PHP_METHOD(swoole_channel_coro, push)
{
    Channel *chan = swoole_get_channel(getThis());
    if (chan->is_closed())
    {
        zend_update_property_long(swoole_channel_coro_ce_ptr, getThis(), ZEND_STRL("errCode"), SW_CHANNEL_CLOSED);
        RETURN_FALSE;
    }
    else
    {
        zend_update_property_long(swoole_channel_coro_ce_ptr, getThis(), ZEND_STRL("errCode"), SW_CHANNEL_OK);
    }

    zval *zdata;
    double timeout = -1;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "z|d", &zdata, &timeout) == FAILURE)
    {
        RETURN_FALSE;
    }

    Z_TRY_ADDREF_P(zdata);
    zdata = sw_zval_dup(zdata);
    if (chan->push(zdata, timeout))
    {
        RETURN_TRUE;
    }
    else
    {
        zend_update_property_long(swoole_channel_coro_ce_ptr, getThis(), ZEND_STRL("errCode"), chan->is_closed() ? SW_CHANNEL_CLOSED : SW_CHANNEL_TIMEOUT);
        Z_TRY_DELREF_P(zdata);
        efree(zdata);
        RETURN_FALSE;
    }
}

static PHP_METHOD(swoole_channel_coro, pop)
{
    Channel *chan = swoole_get_channel(getThis());
    if (chan->is_closed())
    {
        zend_update_property_long(swoole_channel_coro_ce_ptr, getThis(), ZEND_STRL("errCode"), SW_CHANNEL_CLOSED);
        RETURN_FALSE;
    }
    else
    {
        zend_update_property_long(swoole_channel_coro_ce_ptr, getThis(), ZEND_STRL("errCode"), SW_CHANNEL_OK);
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
        zend_update_property_long(swoole_channel_coro_ce_ptr, getThis(), ZEND_STRL("errCode"), chan->is_closed() ? SW_CHANNEL_CLOSED : SW_CHANNEL_TIMEOUT);
        RETURN_FALSE;
    }
}

static PHP_METHOD(swoole_channel_coro, close)
{
    Channel *chan = swoole_get_channel(getThis());
    RETURN_BOOL(chan->close());
}

static PHP_METHOD(swoole_channel_coro, length)
{
    Channel *chan = swoole_get_channel(getThis());
    RETURN_LONG(chan->length());
}

static PHP_METHOD(swoole_channel_coro, isEmpty)
{
    Channel *chan = swoole_get_channel(getThis());
    RETURN_BOOL(chan->is_empty());
}

static PHP_METHOD(swoole_channel_coro, isFull)
{
    Channel *chan = swoole_get_channel(getThis());
    RETURN_BOOL(chan->is_full());
}

static PHP_METHOD(swoole_channel_coro, stats)
{
    Channel *chan = swoole_get_channel(getThis());
    array_init(return_value);
    add_assoc_long_ex(return_value, ZEND_STRL("consumer_num"), chan->consumer_num());
    add_assoc_long_ex(return_value, ZEND_STRL("producer_num"), chan->producer_num());
    add_assoc_long_ex(return_value, ZEND_STRL("queue_num"), chan->length());
}

#endif
