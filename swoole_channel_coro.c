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
 | Author: Xinyu Zhu  <xyzhu1120@gmail.com>                             |
 +----------------------------------------------------------------------+
 */


#include "php_swoole.h"
#include "swoole_coroutine.h"

#define CHANNEL_CORO_PROPERTY_INDEX 0

typedef struct
{
    swLinkedList *producer_list;
    swLinkedList *consumer_list;
    int closed;
} channel_coro_property;

typedef struct
{
    swLinkedList *list;
    swLinkedList_node *node;
} channel_select_node;

typedef struct
{
    channel_select_node *consumer_node_ptr;
    int ch_size;
    int status;
} channel_select_instance;

typedef struct
{
    php_context context;
    int is_select;
    swLinkedList *node_list;
    channel_select_instance *select_instance;
    int removed;
} channel_node;

static PHP_METHOD(swoole_channel_coro, __construct);
static PHP_METHOD(swoole_channel_coro, __destruct);
static PHP_METHOD(swoole_channel_coro, push);
static PHP_METHOD(swoole_channel_coro, pop);
static PHP_METHOD(swoole_channel_coro, close);
static PHP_METHOD(swoole_channel_coro, stats);
static PHP_METHOD(swoole_channel_coro, length);
static PHP_METHOD(swoole_channel_coro, isEmpty);
static PHP_METHOD(swoole_channel_coro, isFull);
static PHP_METHOD(swoole_channel_coro, select);

static zend_class_entry swoole_channel_coro_ce;
zend_class_entry *swoole_channel_coro_class_entry_ptr;

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_channel_coro_construct, 0, 0, 1)
    ZEND_ARG_INFO(0, size)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_channel_coro_push, 0, 0, 1)
    ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_channel_coro_select, 0, 0, 3)
    ZEND_ARG_INFO(0, read_list)
    ZEND_ARG_INFO(0, write_list)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_void, 0, 0, 0)
ZEND_END_ARG_INFO()

static const zend_function_entry swoole_channel_coro_methods[] =
{
    PHP_ME(swoole_channel_coro, __construct, arginfo_swoole_channel_coro_construct, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_ME(swoole_channel_coro, __destruct, arginfo_swoole_void, ZEND_ACC_PUBLIC | ZEND_ACC_DTOR)
    PHP_ME(swoole_channel_coro, push, arginfo_swoole_channel_coro_push, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_channel_coro, pop, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_channel_coro, isEmpty, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_channel_coro, isFull, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_channel_coro, close, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_channel_coro, stats, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_channel_coro, length, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_channel_coro, select, arginfo_swoole_channel_coro_select, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_FE_END
};

#define APPEND_YIELD(coro_list, zdata) \
        channel_node *node = emalloc(sizeof(channel_node)); \
        memset(node, 0, sizeof(channel_node)); \
        ZVAL_COPY_VALUE(&(node->context.coro_params), &zdata); \
        coro_save(&node->context); \
        swLinkedList_append(coro_list, node); \
        coro_yield();

void swoole_channel_coro_init(int module_number TSRMLS_DC)
{
    SWOOLE_INIT_CLASS_ENTRY(swoole_channel_coro_ce, "swoole_channel_coro", "Swoole\\Coroutine\\Channel", swoole_channel_coro_methods);
    swoole_channel_coro_class_entry_ptr = zend_register_internal_class(&swoole_channel_coro_ce TSRMLS_CC);
    SWOOLE_CLASS_ALIAS(swoole_channel_coro, "Swoole\\Coroutine\\Channel");

    if (SWOOLE_G(use_shortname))
    {
        zend_register_class_alias("chan", swoole_channel_coro_class_entry_ptr);
    }
}

static void swoole_channel_onResume(php_context *ctx)
{
    int i;
    channel_node *node = (channel_node *)ctx;
    if (node->is_select)
    {
        channel_select_instance *select = node->select_instance;
        for (i = 0; i < select->ch_size; ++i)
        {
            if (((channel_node *)(select->consumer_node_ptr[i].node->data))->removed == 1)
            {
                continue;
            }
            swLinkedList_remove_node(select->consumer_node_ptr[i].list, select->consumer_node_ptr[i].node);
        }
        efree(select->consumer_node_ptr);
    }
    zval *zdata = &ctx->coro_params;
    zval *retval = NULL;
    int ret = coro_resume(ctx, zdata, &retval);
    if (ret == CORO_END && retval)
    {
        sw_zval_ptr_dtor(&retval);
    }
    sw_zval_ptr_dtor(&zdata);
    efree(ctx);
}

static sw_inline int swoole_channel_try_resume_consumer(zval *object, channel_coro_property *property, zval *zdata)
{
    swLinkedList *coro_list = property->consumer_list;
    if (coro_list->num != 0)
    {
        channel_node *next = (channel_node *) swLinkedList_pop(coro_list);
        next->context.onTimeout = swoole_channel_onResume;
        next->removed = 1;
        Z_TRY_ADDREF_P(zdata);
        ZVAL_COPY_VALUE(&(next->context.coro_params), zdata);
        swLinkedList_append(SwooleWG.coro_timeout_list, next);
        return 0;
    }
    return -1;
}

static sw_inline int swoole_channel_try_resume_producer(zval *object, channel_coro_property *property, zval *zdata_ptr)
{
    swLinkedList *coro_list = property->producer_list;
    if (coro_list->num != 0)
    {
        channel_node *next = (channel_node *)swLinkedList_pop(coro_list);
        next->context.onTimeout = swoole_channel_onResume;
        next->removed = 1;
        *zdata_ptr = next->context.coro_params;
        ZVAL_TRUE(&next->context.coro_params);
        swLinkedList_append(SwooleWG.coro_timeout_list, next);
        return 0;
    }
    return -1;
}

static sw_inline void try_resume_producer_defer(zval *object, channel_coro_property *property, swChannel *chan)
{
    swLinkedList *coro_list = property->producer_list;
    if (coro_list->num != 0)
    {
        channel_node *next = (channel_node *) swLinkedList_pop(coro_list);
        next->context.onTimeout = swoole_channel_onResume;
        next->removed = 1;
        zval *zdata = &next->context.coro_params;
        if (swChannel_in(chan, zdata, sizeof(zval)) < 0)
        {
            ZVAL_FALSE(zdata);
        }
        else
        {
            Z_TRY_ADDREF_P(zdata);
            ZVAL_TRUE(zdata);
        }
        swLinkedList_append(SwooleWG.coro_timeout_list, next);
    }
}

static sw_inline int swoole_channel_try_resume_all(zval *object, channel_coro_property *property)
{
    swLinkedList *coro_list = property->producer_list;
    while (coro_list->num != 0)
    {
        channel_node *next = (channel_node *)swLinkedList_pop(coro_list);
        next->context.onTimeout = swoole_channel_onResume;
        next->removed = 1;
        ZVAL_FALSE(&next->context.coro_params);
        swLinkedList_append(SwooleWG.coro_timeout_list, next);
    }
    coro_list = property->consumer_list;
    while (coro_list->num != 0)
    {
        channel_node *next = (channel_node*)swLinkedList_pop(coro_list);
        next->context.onTimeout = swoole_channel_onResume;
        next->removed = 1;
        ZVAL_FALSE(&next->context.coro_params);
        swLinkedList_append(SwooleWG.coro_timeout_list, next);
    }
    return 0;
}

static PHP_METHOD(swoole_channel_coro, __construct)
{
    long capacity = 0, size;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|l", &capacity) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (capacity > 0)
    {
        size = swChannel_compute_size(capacity, sizeof(zval));
        swChannel *chan = swChannel_new(size, sizeof(zval), 0);
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

    channel_coro_property *property = (channel_coro_property *) sw_malloc(sizeof(channel_coro_property));
    property->producer_list = swLinkedList_new(2, NULL);
    if (property->producer_list == NULL)
    {
        zend_throw_exception(swoole_exception_class_entry_ptr, "failed to create producer_list.", SW_ERROR_MALLOC_FAIL TSRMLS_CC);
        RETURN_FALSE;
    }
    property->consumer_list = swLinkedList_new(2, NULL);
    if (property->consumer_list == NULL)
    {
        zend_throw_exception(swoole_exception_class_entry_ptr, "failed to create consumer_list.", SW_ERROR_MALLOC_FAIL TSRMLS_CC);
        RETURN_FALSE;
    }
    property->closed = 0;

    swoole_set_property(getThis(), CHANNEL_CORO_PROPERTY_INDEX, property);
}

static PHP_METHOD(swoole_channel_coro, __destruct)
{
    channel_coro_property *property = swoole_get_property(getThis(), CHANNEL_CORO_PROPERTY_INDEX);
    swLinkedList_free(property->consumer_list);
    swLinkedList_free(property->producer_list);

    swChannel *chan = swoole_get_object(getThis());
    if (chan)
    {
        swChannel_free(chan);
    }
    swoole_set_object(getThis(), NULL);
}

static PHP_METHOD(swoole_channel_coro, push)
{
    swChannel *chan = NULL;
    zval *zdata = NULL;
    int ret;
    channel_coro_property *property = swoole_get_property(getThis(), CHANNEL_CORO_PROPERTY_INDEX);
    if (property->closed)
    {
        RETURN_FALSE;
    }
    swLinkedList *producer_list = property->producer_list;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &zdata) == FAILURE)
    {
        RETURN_FALSE;
    }

    chan = swoole_get_object(getThis());
    if (chan == NULL)
    {
        ret = swoole_channel_try_resume_consumer(getThis(), property, zdata);
        if (ret == 0)
        {
            RETURN_TRUE;
        }
        APPEND_YIELD(producer_list, *zdata);
        return;
    }

    if (swChannel_empty(chan))
    {
        ret = swoole_channel_try_resume_consumer(getThis(), property, zdata);
        if (ret == 0)
        {
            RETURN_TRUE;
        }
    }

    if (swChannel_full(chan))
    {
        APPEND_YIELD(producer_list, *zdata);
    }
    else
    {
        Z_TRY_ADDREF_P(zdata);
        SW_CHECK_RETURN(swChannel_in(chan, zdata, sizeof(zval)));
    }
}

static PHP_METHOD(swoole_channel_coro, pop)
{
    int ret;
    swChannel *chan = swoole_get_object(getThis());
    zval zdata;

    channel_coro_property *property = swoole_get_property(getThis(), CHANNEL_CORO_PROPERTY_INDEX);
    if (chan == NULL)
    {
        ret = swoole_channel_try_resume_producer(getThis(), property, &zdata);
        if (ret == 0)
        {
            RETURN_ZVAL(&zdata, 0, NULL);
        }
        else
        {
            APPEND_YIELD(property->consumer_list, zdata);
        }
    }

    if (swChannel_out(chan, &zdata, sizeof(zdata)) < 0)
    {
        APPEND_YIELD(property->consumer_list, zdata);
    }
    else
    {
        try_resume_producer_defer(getThis(), property, chan);
        Z_TRY_DELREF(zdata);
        RETURN_ZVAL(&zdata, 0, NULL);
    }
}

static PHP_METHOD(swoole_channel_coro, close)
{
    channel_coro_property *property = swoole_get_property(getThis(), CHANNEL_CORO_PROPERTY_INDEX);
    if (property->closed)
    {
        RETURN_TRUE;
    }
    property->closed = 1;
    swoole_channel_try_resume_all(getThis(), property);
    RETURN_TRUE;
}

static PHP_METHOD(swoole_channel_coro, length)
{
    swChannel *chan = swoole_get_object(getThis());
    RETURN_LONG(chan->num);
}

static PHP_METHOD(swoole_channel_coro, isEmpty)
{
    swChannel *chan = swoole_get_object(getThis());
    RETURN_BOOL(swChannel_empty(chan));
}

static PHP_METHOD(swoole_channel_coro, isFull)
{
    swChannel *chan = swoole_get_object(getThis());
    RETURN_BOOL(swChannel_full(chan));
}

static PHP_METHOD(swoole_channel_coro, stats)
{
    swChannel *chan = swoole_get_object(getThis());
    array_init(return_value);

    sw_add_assoc_long_ex(return_value, ZEND_STRS("queue_num"), chan->num);
    sw_add_assoc_long_ex(return_value, ZEND_STRS("queue_bytes"), chan->bytes);
}

static PHP_METHOD(swoole_channel_coro, select)
{
    zval *read_list, *write_list, *item;
    zval readable, writable;
    zend_long timeout = 0;
    swChannel *chan = NULL;
    int i = 0;
    channel_coro_property *property = NULL;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zz|l", &read_list, &write_list, &timeout) == FAILURE)
    {
        RETURN_FALSE;
    }

    array_init(&readable);
    HashTable *arr = Z_ARRVAL_P(read_list);
    SW_HASHTABLE_FOREACH_START(arr, item)
        chan = swoole_get_object(item);
        if (chan != NULL && chan->num > 0)
        {
            add_next_index_zval(&readable, item);
        }
        else if (chan == NULL)
        {
            property = swoole_get_property(item, CHANNEL_CORO_PROPERTY_INDEX);
            if (property->producer_list->num > 0)
            {
                add_next_index_zval(&readable, item);
            }
        }
    SW_HASHTABLE_FOREACH_END();

    if (zend_hash_num_elements(Z_ARRVAL(readable)) == 0)
    {
        channel_select_instance *select_instance = (channel_select_instance*)emalloc(sizeof(channel_select_instance));
        select_instance->ch_size = zend_hash_num_elements(Z_ARRVAL_P(read_list));
        select_instance->consumer_node_ptr = (channel_select_node *)emalloc(select_instance->ch_size * sizeof(channel_select_node));
        channel_node *node= emalloc(sizeof(channel_node));
        node->is_select = 1;
        node->select_instance = select_instance;
        coro_save(&node->context);
        SW_HASHTABLE_FOREACH_START(arr, item)
            property = swoole_get_property(item, CHANNEL_CORO_PROPERTY_INDEX);
            swLinkedList_append(property->consumer_list, node);
            select_instance->consumer_node_ptr[i].list = property->consumer_list;
            select_instance->consumer_node_ptr[i].node = property->consumer_list->tail;
        SW_HASHTABLE_FOREACH_END();

        coro_yield();
    }
    else
    {
        RETURN_ZVAL(&readable, 0, NULL);
    }
}
