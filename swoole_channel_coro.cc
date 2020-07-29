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

#include "php_swoole_cxx.h"

#include "coroutine_channel.h"

using swoole::coroutine::Channel;

static zend_class_entry *swoole_channel_coro_ce;
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

static sw_inline channel_coro* php_swoole_channel_coro_fetch_object(zend_object *obj)
{
    return (channel_coro *) ((char *) obj - swoole_channel_coro_handlers.offset);
}

static sw_inline Channel * php_swoole_get_channel(zval *zobject)
{
    Channel *chan = php_swoole_channel_coro_fetch_object(Z_OBJ_P(zobject))->chan;
    if (UNEXPECTED(!chan))
    {
        php_swoole_fatal_error(E_ERROR, "you must call Channel constructor first");
    }
    return chan;
}

static void php_swoole_channel_coro_dtor_object(zend_object *object)
{
    zend_objects_destroy_object(object);

    channel_coro *chan_coro = php_swoole_channel_coro_fetch_object(object);
    Channel *chan = chan_coro->chan;
    if (chan)
    {
        chan->close();
        zval *data;
        while ((data = (zval *) chan->pop_data()))
        {
            sw_zval_free(data);
        }
        delete chan;
        chan_coro->chan = nullptr;
    }
}

static void php_swoole_channel_coro_free_object(zend_object *object)
{
    channel_coro *chan_coro = php_swoole_channel_coro_fetch_object(object);
    Channel *chan = chan_coro->chan;
    if (chan)
    {
        delete chan;
    }
    zend_object_std_dtor(object);
}

static zend_object *php_swoole_channel_coro_create_object(zend_class_entry *ce)
{
    channel_coro *chan_t = (channel_coro *) zend_object_alloc(sizeof(channel_coro), ce);
    zend_object_std_init(&chan_t->std, ce);
    object_properties_init(&chan_t->std, ce);
    chan_t->std.handlers = &swoole_channel_coro_handlers;
    return &chan_t->std;
}

void php_swoole_channel_coro_minit(int module_number)
{
    SW_INIT_CLASS_ENTRY(swoole_channel_coro, "Swoole\\Coroutine\\Channel", NULL, "Co\\Channel", swoole_channel_coro_methods);
    SW_SET_CLASS_SERIALIZABLE(swoole_channel_coro, zend_class_serialize_deny, zend_class_unserialize_deny);
    SW_SET_CLASS_CLONEABLE(swoole_channel_coro, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_channel_coro, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CUSTOM_OBJECT(swoole_channel_coro, php_swoole_channel_coro_create_object, php_swoole_channel_coro_free_object, channel_coro, std);
    SW_SET_CLASS_DTOR(swoole_channel_coro, php_swoole_channel_coro_dtor_object);
    if (SWOOLE_G(use_shortname))
    {
        SW_CLASS_ALIAS("Chan", swoole_channel_coro);
    }

    zend_declare_property_long(swoole_channel_coro_ce, ZEND_STRL("capacity"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_channel_coro_ce, ZEND_STRL("errCode"), 0, ZEND_ACC_PUBLIC);

    SW_REGISTER_LONG_CONSTANT("SWOOLE_CHANNEL_OK", SW_CHANNEL_OK);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_CHANNEL_TIMEOUT", SW_CHANNEL_TIMEOUT);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_CHANNEL_CLOSED", SW_CHANNEL_CLOSED);
}

static PHP_METHOD(swoole_channel_coro, __construct)
{
    zend_long capacity = 1;

    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 0, 1)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(capacity)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (capacity <= 0)
    {
        capacity = 1;
    }

    channel_coro *chan_t = php_swoole_channel_coro_fetch_object(Z_OBJ_P(ZEND_THIS));
    chan_t->chan = new Channel(capacity);
    zend_update_property_long(swoole_channel_coro_ce, ZEND_THIS, ZEND_STRL("capacity"), capacity);
}

static PHP_METHOD(swoole_channel_coro, push)
{
    Channel *chan = php_swoole_get_channel(ZEND_THIS);
    if (chan->is_closed())
    {
        zend_update_property_long(swoole_channel_coro_ce, ZEND_THIS, ZEND_STRL("errCode"), SW_CHANNEL_CLOSED);
        RETURN_FALSE;
    }
    else
    {
        zend_update_property_long(swoole_channel_coro_ce, ZEND_THIS, ZEND_STRL("errCode"), SW_CHANNEL_OK);
    }

    zval *zdata;
    double timeout = -1;

    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 2)
        Z_PARAM_ZVAL(zdata)
        Z_PARAM_OPTIONAL
        Z_PARAM_DOUBLE(timeout)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    Z_TRY_ADDREF_P(zdata);
    zdata = sw_zval_dup(zdata);
    if (chan->push(zdata, timeout))
    {
        RETURN_TRUE;
    }
    else
    {
        zend_update_property_long(swoole_channel_coro_ce, ZEND_THIS, ZEND_STRL("errCode"), chan->is_closed() ? SW_CHANNEL_CLOSED : SW_CHANNEL_TIMEOUT);
        Z_TRY_DELREF_P(zdata);
        efree(zdata);
        RETURN_FALSE;
    }
}

static PHP_METHOD(swoole_channel_coro, pop)
{
    Channel *chan = php_swoole_get_channel(ZEND_THIS);
    if (chan->is_closed())
    {
        zend_update_property_long(swoole_channel_coro_ce, ZEND_THIS, ZEND_STRL("errCode"), SW_CHANNEL_CLOSED);
        RETURN_FALSE;
    }
    else
    {
        zend_update_property_long(swoole_channel_coro_ce, ZEND_THIS, ZEND_STRL("errCode"), SW_CHANNEL_OK);
    }

    double timeout = -1;

    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 0, 1)
        Z_PARAM_OPTIONAL
        Z_PARAM_DOUBLE(timeout)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    zval *zdata = (zval *) chan->pop(timeout);
    if (zdata)
    {
        RETVAL_ZVAL(zdata, 0, 0);
        efree(zdata);
    }
    else
    {
        zend_update_property_long(swoole_channel_coro_ce, ZEND_THIS, ZEND_STRL("errCode"), chan->is_closed() ? SW_CHANNEL_CLOSED : SW_CHANNEL_TIMEOUT);
        RETURN_FALSE;
    }
}

static PHP_METHOD(swoole_channel_coro, close)
{
    Channel *chan = php_swoole_get_channel(ZEND_THIS);
    RETURN_BOOL(chan->close());
}

static PHP_METHOD(swoole_channel_coro, length)
{
    Channel *chan = php_swoole_get_channel(ZEND_THIS);
    RETURN_LONG(chan->length());
}

static PHP_METHOD(swoole_channel_coro, isEmpty)
{
    Channel *chan = php_swoole_get_channel(ZEND_THIS);
    RETURN_BOOL(chan->is_empty());
}

static PHP_METHOD(swoole_channel_coro, isFull)
{
    Channel *chan = php_swoole_get_channel(ZEND_THIS);
    RETURN_BOOL(chan->is_full());
}

static PHP_METHOD(swoole_channel_coro, stats)
{
    Channel *chan = php_swoole_get_channel(ZEND_THIS);
    array_init(return_value);
    add_assoc_long_ex(return_value, ZEND_STRL("consumer_num"), chan->consumer_num());
    add_assoc_long_ex(return_value, ZEND_STRL("producer_num"), chan->producer_num());
    add_assoc_long_ex(return_value, ZEND_STRL("queue_num"), chan->length());
}

