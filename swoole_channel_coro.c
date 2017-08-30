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

#if PHP_MAJOR_VERSION >= 7
#define swChannel_empty(q) (q->num == 0)
#define swChannel_full(q) ((q->head == q->tail) && (q->tail_tag != q->head_tag))

enum channel_property
{
    channel_producer_waiting_list = 0,
    channel_consumer_waiting_list = 1,
};

static PHP_METHOD(swoole_channel_coro, __construct);
static PHP_METHOD(swoole_channel_coro, __destruct);
static PHP_METHOD(swoole_channel_coro, push);
static PHP_METHOD(swoole_channel_coro, pop);
static PHP_METHOD(swoole_channel_coro, stats);

static zend_class_entry swoole_channel_coro_ce;
zend_class_entry *swoole_channel_coro_class_entry_ptr;

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_channel_coro_construct, 0, 0, 1)
    ZEND_ARG_INFO(0, size)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_channel_coro_push, 0, 0, 1)
    ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_void, 0, 0, 0)
ZEND_END_ARG_INFO()

static const zend_function_entry swoole_channel_coro_methods[] =
{
    PHP_ME(swoole_channel_coro, __construct, arginfo_swoole_channel_coro_construct, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_ME(swoole_channel_coro, __destruct, arginfo_swoole_void, ZEND_ACC_PUBLIC | ZEND_ACC_DTOR)
    PHP_ME(swoole_channel_coro, push, arginfo_swoole_channel_coro_push, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_channel_coro, pop, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_channel_coro, stats, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

#define APPEND_YIELD(coro_list, zdata) \
        php_context *context = emalloc(sizeof(php_context)); \
        context->coro_params = zdata; \
        coro_save(context); \
        swLinkedList_append(coro_list, context); \
        coro_yield();

void swoole_channel_coro_init(int module_number TSRMLS_DC)
{
    SWOOLE_INIT_CLASS_ENTRY(swoole_channel_coro_ce, "swoole_channel_coro", "Swoole\\Coro\\Channel", swoole_channel_coro_methods);
    swoole_channel_coro_class_entry_ptr = zend_register_internal_class(&swoole_channel_coro_ce TSRMLS_CC);
    SWOOLE_CLASS_ALIAS(swoole_channel_coro, "Swoole\\Coro\\Channel");
}

static void swoole_channel_onResume(php_context *ctx)
{
    zval *zdata = &ctx->coro_params;
    zval *retval = NULL;
    int ret = coro_resume(ctx, zdata, &retval);
    if (ret == CORO_END && retval)
    {
        sw_zval_ptr_dtor(&retval);
    }
    sw_zval_ptr_dtor(&zdata);
}

static sw_inline int swoole_channel_try_resume_consumer(zval *object, zval *zdata)
{
    swLinkedList *coro_list = swoole_get_property(object, channel_consumer_waiting_list);
    if (coro_list->num != 0)
    {
        php_context *next = (php_context*)swLinkedList_pop(coro_list);
        next->onTimeout = swoole_channel_onResume;
        ZVAL_COPY(&(next->coro_params), zdata);
        swLinkedList_append(SwooleWG.coro_timeout_list, next);
        return 0;
    }
    return -1;
}

static sw_inline int swoole_channel_try_resume_producer(zval *object, zval *zdata_ptr)
{
    swLinkedList *coro_list = swoole_get_property(object, channel_producer_waiting_list);
    if (coro_list->num != 0)
    {
        php_context *next = (php_context*)swLinkedList_pop(coro_list);
        next->onTimeout = swoole_channel_onResume;
        *zdata_ptr = next->coro_params;
        ZVAL_TRUE(&next->coro_params);
        swLinkedList_append(SwooleWG.coro_timeout_list, next);
        return 0;
    }
    return -1;
}

static PHP_METHOD(swoole_channel_coro, __construct)
{
    long capacity = 0, max_size, size;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|l", &capacity) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (capacity != 0)
    {
        max_size = capacity * sizeof(zval);
        size = sizeof(swChannel) + max_size + capacity * sizeof(int);

        swChannel *chan = swChannel_new(size, max_size, 0);
        if (chan == NULL)
        {
            zend_throw_exception(swoole_exception_class_entry_ptr, "failed to create channel.", SW_ERROR_MALLOC_FAIL TSRMLS_CC);
            RETURN_FALSE;
        }
        swoole_set_object(getThis(), chan);
    }
    else
    {
        swoole_set_object(getThis(), NULL);
    }

    swLinkedList *producer_list = swLinkedList_new(2, NULL);
    swLinkedList *consumer_list = swLinkedList_new(2, NULL);
    if (producer_list == NULL || consumer_list == NULL)
    {
        RETURN_FALSE;
    }
    swoole_set_property(getThis(), channel_producer_waiting_list, producer_list);
    swoole_set_property(getThis(), channel_consumer_waiting_list, consumer_list);
}

static PHP_METHOD(swoole_channel_coro, __destruct)
{
    swLinkedList *list = swoole_get_property(getThis(), channel_consumer_waiting_list);
    swLinkedList_free(list);
    list = swoole_get_property(getThis(), channel_producer_waiting_list);
    swLinkedList_free(list);
    swoole_set_object(getThis(), NULL);
}

static PHP_METHOD(swoole_channel_coro, push)
{
    swChannel *chan = NULL;
    zval *zdata = NULL, *retval = NULL;
    int ret;
    swLinkedList *producer_list = swoole_get_property(getThis(), channel_producer_waiting_list);

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &zdata) == FAILURE)
    {
        RETURN_FALSE;
    }

    chan = swoole_get_object(getThis());
    if (chan == NULL)
    {
        ret = swoole_channel_try_resume_consumer(getThis(), zdata);
        if (ret == 0)
        {
            RETURN_TRUE;
        }
        APPEND_YIELD(producer_list, *zdata);
    }
    if (swChannel_empty(chan))
    {
        ret = swoole_channel_try_resume_consumer(getThis(), zdata);
        if (ret ==0)
        {
            RETURN_TRUE;
        }
    }

    if (swChannel_full(chan))
    {
        APPEND_YIELD(producer_list, *zdata);
    }

    SW_CHECK_RETURN(swChannel_in(chan, zdata, sizeof(zval)));
}

static PHP_METHOD(swoole_channel_coro, pop)
{
    int ret;
    swChannel *chan = swoole_get_object(getThis());
    zval zdata;

    if (chan == NULL)
    {
        ret = swoole_channel_try_resume_producer(getThis(), &zdata);
        if (ret == 0)
        {
            RETURN_ZVAL(&zdata, 0, NULL);
        }
        else
        {
            swLinkedList *coro_list = swoole_get_property(getThis(), channel_consumer_waiting_list);
            APPEND_YIELD(coro_list, zdata);
        }
    }

    if (swChannel_full(chan))
    {
        ret = swoole_channel_try_resume_producer(getThis(), &zdata);
        if (ret == 0)
        {
            RETURN_ZVAL(&zdata, 0, NULL);
        }
    }

    int n = swChannel_out(chan, &zdata, sizeof(zdata));
    if (n < 0)
    {
        swLinkedList *coro_list = swoole_get_property(getThis(), channel_consumer_waiting_list);
        APPEND_YIELD(coro_list, zdata);
    }

    RETURN_ZVAL(&zdata, 0, NULL);
}

static PHP_METHOD(swoole_channel_coro, stats)
{
    swChannel *chan = swoole_get_object(getThis());
    array_init(return_value);

    sw_add_assoc_long_ex(return_value, ZEND_STRS("queue_num"), chan->num);
    sw_add_assoc_long_ex(return_value, ZEND_STRS("queue_bytes"), chan->bytes);
}
#endif
