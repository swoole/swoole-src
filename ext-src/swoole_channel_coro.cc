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

#include "swoole_coroutine_channel.h"

BEGIN_EXTERN_C()
#include "stubs/php_swoole_channel_coro_arginfo.h"
END_EXTERN_C()

using PHPChannel = swoole::coroutine::ChannelImpl<zval>;

static zend_class_entry *swoole_channel_coro_ce;
static zend_object_handlers swoole_channel_coro_handlers;

struct ChannelObject {
    PHPChannel *chan;
    zend_object std;
};

SW_EXTERN_C_BEGIN
static PHP_METHOD(swoole_channel_coro, __construct);
static PHP_METHOD(swoole_channel_coro, push);
static PHP_METHOD(swoole_channel_coro, pop);
static PHP_METHOD(swoole_channel_coro, close);
static PHP_METHOD(swoole_channel_coro, stats);
static PHP_METHOD(swoole_channel_coro, length);
static PHP_METHOD(swoole_channel_coro, isEmpty);
static PHP_METHOD(swoole_channel_coro, isFull);
SW_EXTERN_C_END

// clang-format off
static const zend_function_entry swoole_channel_coro_methods[] =
{
    PHP_ME(swoole_channel_coro, __construct, arginfo_class_Swoole_Coroutine_Channel___construct, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_channel_coro, push,        arginfo_class_Swoole_Coroutine_Channel_push,        ZEND_ACC_PUBLIC)
    PHP_ME(swoole_channel_coro, pop,         arginfo_class_Swoole_Coroutine_Channel_pop,         ZEND_ACC_PUBLIC)
    PHP_ME(swoole_channel_coro, isEmpty,     arginfo_class_Swoole_Coroutine_Channel_isEmpty,     ZEND_ACC_PUBLIC)
    PHP_ME(swoole_channel_coro, isFull,      arginfo_class_Swoole_Coroutine_Channel_isFull,      ZEND_ACC_PUBLIC)
    PHP_ME(swoole_channel_coro, close,       arginfo_class_Swoole_Coroutine_Channel_close,       ZEND_ACC_PUBLIC)
    PHP_ME(swoole_channel_coro, stats,       arginfo_class_Swoole_Coroutine_Channel_stats,       ZEND_ACC_PUBLIC)
    PHP_ME(swoole_channel_coro, length,      arginfo_class_Swoole_Coroutine_Channel_length,      ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

static ChannelObject *channel_coro_fetch_object(zend_object *obj) {
    return reinterpret_cast<ChannelObject *>(reinterpret_cast<char *>(obj) - swoole_channel_coro_handlers.offset);
}

static PHPChannel *channel_coro_get_ptr(const zval *zobject) {
    PHPChannel *chan = channel_coro_fetch_object(Z_OBJ_P(zobject))->chan;
    if (UNEXPECTED(!chan)) {
        swoole_fatal_error(SW_ERROR_WRONG_OPERATION, "must call constructor first");
    }
    return chan;
}

static void channel_coro_dtor_object(zend_object *object) {
    zend_objects_destroy_object(object);

    ChannelObject *chan_object = channel_coro_fetch_object(object);
    PHPChannel *chan = chan_object->chan;
    if (chan) {
        zval data;
        while (chan->pop_data(&data)) {
            zval_ptr_dtor(&data);
        }
        delete chan;
        chan_object->chan = nullptr;
    }
}

static void channel_coro_free_object(zend_object *object) {
    auto *chan_object = channel_coro_fetch_object(object);
    delete chan_object->chan;
    zend_object_std_dtor(object);
}

static zend_object *channel_coro_create_object(zend_class_entry *ce) {
    auto *chan_object = static_cast<ChannelObject *>(zend_object_alloc(sizeof(ChannelObject), ce));
    zend_object_std_init(&chan_object->std, ce);
    object_properties_init(&chan_object->std, ce);
    chan_object->std.handlers = &swoole_channel_coro_handlers;
    return &chan_object->std;
}

void php_swoole_channel_coro_minit(int module_number) {
    SW_INIT_CLASS_ENTRY(swoole_channel_coro, "Swoole\\Coroutine\\Channel", "Co\\Channel", swoole_channel_coro_methods);
    SW_SET_CLASS_NOT_SERIALIZABLE(swoole_channel_coro);
    SW_SET_CLASS_CLONEABLE(swoole_channel_coro, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_channel_coro, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CUSTOM_OBJECT(
        swoole_channel_coro, channel_coro_create_object, channel_coro_free_object, ChannelObject, std);
    SW_SET_CLASS_DTOR(swoole_channel_coro, channel_coro_dtor_object);
    if (SWOOLE_G(use_shortname)) {
        SW_CLASS_ALIAS("Chan", swoole_channel_coro);
    }

    zend_declare_property_long(swoole_channel_coro_ce, ZEND_STRL("capacity"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_channel_coro_ce, ZEND_STRL("errCode"), 0, ZEND_ACC_PUBLIC);

    SW_REGISTER_LONG_CONSTANT("SWOOLE_CHANNEL_OK", PHPChannel::ERROR_OK);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_CHANNEL_TIMEOUT", PHPChannel::ERROR_TIMEOUT);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_CHANNEL_CLOSED", PHPChannel::ERROR_CLOSED);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_CHANNEL_CANCELED", PHPChannel::ERROR_CANCELED);
}

static PHP_METHOD(swoole_channel_coro, __construct) {
    zend_long capacity = 1;

    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 0, 1)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(capacity)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (UNEXPECTED(capacity <= 0)) {
        capacity = 1;
    }

    ChannelObject *chan_t = channel_coro_fetch_object(Z_OBJ_P(ZEND_THIS));
    if (UNEXPECTED(chan_t->chan)) {
        swoole_fatal_error(SW_ERROR_WRONG_OPERATION, "channel has already been constructed");
        RETURN_FALSE;
    }
    chan_t->chan = new PHPChannel(capacity);
    zend_update_property_long(swoole_channel_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("capacity"), capacity);
}

static PHP_METHOD(swoole_channel_coro, push) {
    PHPChannel *chan = channel_coro_get_ptr(ZEND_THIS);
    zval *zdata;
    double timeout = -1;

    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 2)
    Z_PARAM_ZVAL(zdata)
    Z_PARAM_OPTIONAL
    Z_PARAM_DOUBLE(timeout)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (EXPECTED(chan->wait_push(timeout))) {
        zval data;
        ZVAL_COPY(&data, zdata);
        if (EXPECTED(chan->push_data(data))) {
            RETURN_TRUE;
        }
        zval_ptr_dtor(&data);
        zend_update_property_long(
            swoole_channel_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("errCode"), chan->get_error());
        RETURN_FALSE;
    } else {
        zend_update_property_long(
            swoole_channel_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("errCode"), chan->get_error());
        RETURN_FALSE;
    }
}

static PHP_METHOD(swoole_channel_coro, pop) {
    PHPChannel *chan = channel_coro_get_ptr(ZEND_THIS);
    double timeout = -1;

    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 0, 1)
    Z_PARAM_OPTIONAL
    Z_PARAM_DOUBLE(timeout)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    zval zdata;
    if (EXPECTED(chan->pop(&zdata, timeout))) {
        RETVAL_ZVAL(&zdata, 0, 0);
    } else {
        zend_update_property_long(
            swoole_channel_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("errCode"), chan->get_error());
        RETURN_FALSE;
    }
}

static PHP_METHOD(swoole_channel_coro, close) {
    PHPChannel *chan = channel_coro_get_ptr(ZEND_THIS);
    RETURN_BOOL(chan->close());
}

static PHP_METHOD(swoole_channel_coro, length) {
    PHPChannel *chan = channel_coro_get_ptr(ZEND_THIS);
    RETURN_LONG(chan->length());
}

static PHP_METHOD(swoole_channel_coro, isEmpty) {
    PHPChannel *chan = channel_coro_get_ptr(ZEND_THIS);
    RETURN_BOOL(chan->is_empty());
}

static PHP_METHOD(swoole_channel_coro, isFull) {
    PHPChannel *chan = channel_coro_get_ptr(ZEND_THIS);
    RETURN_BOOL(chan->is_full());
}

static PHP_METHOD(swoole_channel_coro, stats) {
    PHPChannel *chan = channel_coro_get_ptr(ZEND_THIS);
    array_init(return_value);
    add_assoc_long_ex(return_value, ZEND_STRL("consumer_num"), chan->consumer_num());
    add_assoc_long_ex(return_value, ZEND_STRL("producer_num"), chan->producer_num());
    add_assoc_long_ex(return_value, ZEND_STRL("queue_num"), chan->length());
}
