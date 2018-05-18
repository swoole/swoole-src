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

enum
{
    CHANNEL_CORO_PROPERTY_INDEX = 0, CHANNEL_CORO_PROPERTY_TMP_DATA = 1,
};

enum ChannelSelectOpcode
{
    CHANNEL_SELECT_WRITE = 0, CHANNEL_SELECT_READ = 1,
};

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
} channel_selector_node;

typedef struct
{
    swTimer_node *timer;
    zval *read_list;
    zval *write_list;
    channel_selector_node *node_list;
    zval readable;
    zval writable;
    uint16_t count;
    zval object;
    enum ChannelSelectOpcode opcode;
} channel_selector;

typedef struct _channel_node
{
    php_context context;
    channel_selector *selector;
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
static zend_class_entry *swoole_channel_coro_class_entry_ptr;

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_channel_coro_construct, 0, 0, 1)
    ZEND_ARG_INFO(0, size)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_channel_coro_push, 0, 0, 1)
    ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_channel_coro_select, 0, 0, 3)
    ZEND_ARG_ARRAY_INFO(1, read_list, 1)
    ZEND_ARG_ARRAY_INFO(1, write_list, 1)
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
    INIT_CLASS_ENTRY(swoole_channel_coro_ce, "Swoole\\Coroutine\\Channel", swoole_channel_coro_methods);
    swoole_channel_coro_class_entry_ptr = zend_register_internal_class(&swoole_channel_coro_ce TSRMLS_CC);

    if (SWOOLE_G(use_shortname))
    {
        sw_zend_register_class_alias("chan", swoole_channel_coro_class_entry_ptr);
    }

    zend_declare_property_long(swoole_channel_coro_class_entry_ptr, SW_STRL("capacity")-1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);
}

static void channel_selector_clear(channel_selector *selector, swLinkedList_node *_node)
{
    int i;
    for (i = 0; i < selector->count; i++)
    {
        if (_node == selector->node_list[i].node)
        {
            continue;
        }
        swLinkedList_remove_node(selector->node_list[i].list, selector->node_list[i].node);
    }
    efree(selector->node_list);
}

static void channel_selector_onTimeout(swTimer *timer, swTimer_node *tnode)
{
    zval *retval = NULL;
    zval *result = NULL;
    SW_MAKE_STD_ZVAL(result);
    ZVAL_BOOL(result, 0);

    channel_node *node = tnode->data;
    channel_selector *selector = node->selector;

    zval_ptr_dtor(selector->read_list);
    ZVAL_COPY_VALUE(selector->read_list, &selector->readable);

    if (selector->write_list)
    {
        zval_ptr_dtor(selector->write_list);
        ZVAL_COPY_VALUE(selector->write_list, &selector->writable);
    }

    php_context *context = (php_context *) node;
    channel_selector_clear(selector, NULL);

    int ret = coro_resume(context, result, &retval);
    if (ret == CORO_END && retval)
    {
        sw_zval_ptr_dtor(&retval);
    }
    sw_zval_ptr_dtor(&result);
    efree(selector);
    efree(node);
}

static void swoole_channel_onResume(php_context *ctx)
{
    channel_node *node = (channel_node *) ctx;
    zval *zdata = &ctx->coro_params;
    zval *retval = NULL;

    if (node->selector)
    {
        channel_selector *selector = node->selector;

        if (selector->timer)
        {
            swTimer_del(&SwooleG.timer, selector->timer);
            selector->timer = NULL;
        }

        if (selector->opcode == CHANNEL_SELECT_WRITE)
        {
            swChannel *chan = swoole_get_object(&selector->object);
            if (chan)
            {
                swChannel_in(chan, zdata, sizeof(zval));
            }
            else
            {
                zval *tmp_data = emalloc(sizeof(zval));
                *tmp_data = *zdata;
                swoole_set_property(&selector->object, CHANNEL_CORO_PROPERTY_TMP_DATA, tmp_data);
            }

            zval_ptr_dtor(selector->read_list);
            Z_TRY_ADDREF_P(&selector->object);
            add_next_index_zval(&selector->readable, &selector->object);

            ZVAL_COPY_VALUE(selector->read_list, &selector->readable);

            if (selector->write_list)
            {
                zval_ptr_dtor(selector->write_list);
                ZVAL_COPY_VALUE(selector->write_list, &selector->writable);
            }
        }
        else
        {
            zval_ptr_dtor(selector->read_list);
            ZVAL_COPY_VALUE(selector->read_list, &selector->readable);

            zval_ptr_dtor(selector->write_list);
            Z_TRY_ADDREF_P(&selector->object);
            add_next_index_zval(&selector->writable, &selector->object);
            ZVAL_COPY_VALUE(selector->write_list, &selector->writable);
        }

        SW_MAKE_STD_ZVAL(zdata);
        ZVAL_BOOL(zdata, 1);
        efree(selector);
    }

    int ret = coro_resume(ctx, zdata, &retval);
    if (ret == CORO_END && retval)
    {
        sw_zval_ptr_dtor(&retval);
    }
    sw_zval_ptr_dtor(&zdata);
    efree(ctx);
}

static int swoole_channel_try_resume_consumer(zval *object, channel_coro_property *property, zval *zdata)
{
    swLinkedList *coro_list = property->consumer_list;
    swLinkedList_node *node;
    channel_node *next;

    if (coro_list->num != 0)
    {
        node = coro_list->head;
        next = (channel_node *) swLinkedList_shift(coro_list);
        if (next == NULL)
        {
            return -1;
        }
        next->context.onTimeout = swoole_channel_onResume;
        if (next->selector)
        {
            next->selector->object = *object;
            next->selector->opcode = CHANNEL_SELECT_WRITE;
            channel_selector_clear(next->selector, node);
        }
        Z_TRY_ADDREF_P(zdata);
        ZVAL_COPY_VALUE(&(next->context.coro_params), zdata);
        swLinkedList_append(SwooleWG.coro_timeout_list, next);
        return 0;
    }
    return -1;
}

static int swoole_channel_try_resume_producer(zval *object, channel_coro_property *property, zval *zdata_ptr)
{
    swLinkedList *coro_list = property->producer_list;
    swLinkedList_node *node;
    channel_node *next;

    if (coro_list->num != 0)
    {
        node = coro_list->head;
        next = (channel_node *) swLinkedList_shift(coro_list);
        next->context.onTimeout = swoole_channel_onResume;
        if (next->selector)
        {
            next->selector->object = *object;
            next->selector->opcode = CHANNEL_SELECT_WRITE;
            channel_selector_clear(next->selector, node);
        }
        *zdata_ptr = next->context.coro_params;
        ZVAL_TRUE(&next->context.coro_params);
        swLinkedList_append(SwooleWG.coro_timeout_list, next);
        return 0;
    }
    else
    {
        zval *tmp_data = swoole_get_property(object, CHANNEL_CORO_PROPERTY_TMP_DATA);
        *zdata_ptr = *tmp_data;
        efree(tmp_data);
        return 0;
    }
    return -1;
}

static void try_resume_producer_defer(zval *object, channel_coro_property *property, swChannel *chan)
{
    swLinkedList *coro_list = property->producer_list;
    swLinkedList_node *node;
    channel_node *next;

    if (coro_list->num != 0)
    {
        node = coro_list->head;
        next = (channel_node *) swLinkedList_shift(coro_list);
        next->context.onTimeout = swoole_channel_onResume;
        if (next->selector)
        {
            next->selector->object = *object;
            next->selector->opcode = CHANNEL_SELECT_WRITE;
            channel_selector_clear(next->selector, node);
        }
        else
        {
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
        }

        swLinkedList_append(SwooleWG.coro_timeout_list, next);
    }
}

static sw_inline int swoole_channel_try_resume_all(zval *object, channel_coro_property *property)
{
    swLinkedList *coro_list = property->producer_list;
    swLinkedList_node *node;
    channel_node *next;

    while (coro_list->num != 0)
    {
        node = coro_list->head;
        next = (channel_node *) swLinkedList_shift(coro_list);
        next->context.onTimeout = swoole_channel_onResume;
        if (next->selector)
        {
            next->selector->object = *object;
            next->selector->opcode = CHANNEL_SELECT_READ;
            channel_selector_clear(next->selector, node);
        }
        ZVAL_FALSE(&next->context.coro_params);
        swLinkedList_append(SwooleWG.coro_timeout_list, next);
    }

    coro_list = property->consumer_list;
    while (coro_list->num != 0)
    {
        node = coro_list->head;
        next = (channel_node*) swLinkedList_shift(coro_list);
        next->context.onTimeout = swoole_channel_onResume;
        if (next->selector)
        {
            next->selector->object = *object;
            next->selector->opcode = CHANNEL_SELECT_WRITE;
            channel_selector_clear(next->selector, node);
        }
        ZVAL_FALSE(&next->context.coro_params);
        swLinkedList_append(SwooleWG.coro_timeout_list, next);
    }

    return 0;
}

static PHP_METHOD(swoole_channel_coro, __construct)
{
    long capacity = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|l", &capacity) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (capacity > 0)
    {
        swChannel *chan = swChannel_new((sizeof(zval) + sizeof(int)) * capacity, sizeof(zval), 0);
        if (chan == NULL)
        {
            zend_throw_exception(swoole_exception_class_entry_ptr, "failed to create channel.", SW_ERROR_MALLOC_FAIL TSRMLS_CC);
            RETURN_FALSE;
        }
        swoole_set_object(getThis(), chan);
        chan->max_num = capacity;
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

    zend_update_property_long(swoole_channel_coro_class_entry_ptr, getThis(), ZEND_STRL("capacity"), capacity TSRMLS_CC);

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
    coro_check(TSRMLS_C);

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
    coro_check(TSRMLS_C);

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
    channel_coro_property *property = swoole_get_property(getThis(), CHANNEL_CORO_PROPERTY_INDEX);

    swChannel *chan = swoole_get_object(getThis());
    array_init(return_value);

    sw_add_assoc_long_ex(return_value, ZEND_STRS("consumer_num"), property->consumer_list->num);
    sw_add_assoc_long_ex(return_value, ZEND_STRS("producer_num"), property->producer_list->num);

    if (chan)
    {
        sw_add_assoc_long_ex(return_value, ZEND_STRS("queue_num"), chan->num);
        sw_add_assoc_long_ex(return_value, ZEND_STRS("queue_bytes"), chan->bytes);
    }
}

static PHP_METHOD(swoole_channel_coro, select)
{
    coro_check(TSRMLS_C);

    zval *read_list, *write_list = NULL, *item;
    zval readable, writable;
    double timeout = 0;
    zend_bool need_yield = 1;
    swChannel *chan = NULL;
    channel_coro_property *property = NULL;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "a!a!d", &read_list, &write_list, &timeout) == FAILURE)
    {
        RETURN_FALSE;
    }

    array_init(&readable);

    SW_HASHTABLE_FOREACH_START(Z_ARRVAL_P(read_list), item)
        if (Z_TYPE_P(item) != IS_OBJECT || !instanceof_function(Z_OBJCE_P(item), swoole_channel_coro_class_entry_ptr TSRMLS_CC))
        {
            zend_throw_exception_ex(swoole_exception_class_entry_ptr, errno TSRMLS_CC, "object is not instanceof Swoole\\Coroutine\\Channel.");
            return;
        }
        chan = swoole_get_object(item);
        if (chan != NULL && chan->num > 0)
        {
            Z_ADDREF_P(item);
            add_next_index_zval(&readable, item);
            need_yield = 0;
        }
        else if (chan == NULL)
        {
            property = swoole_get_property(item, CHANNEL_CORO_PROPERTY_INDEX);
            if (property->producer_list->num > 0)
            {
                Z_ADDREF_P(item);
                add_next_index_zval(&readable, item);
                need_yield = 0;
            }
        }
    SW_HASHTABLE_FOREACH_END();

    if (write_list)
    {
        array_init(&writable);

        SW_HASHTABLE_FOREACH_START(Z_ARRVAL_P(write_list), item)
            if (Z_TYPE_P(item) != IS_OBJECT || !instanceof_function(Z_OBJCE_P(item), swoole_channel_coro_class_entry_ptr TSRMLS_CC))
            {
                zend_throw_exception_ex(swoole_exception_class_entry_ptr, errno TSRMLS_CC, "object is not instanceof Swoole\\Coroutine\\Channel.");
                return;
            }
            chan = swoole_get_object(item);
            if (chan != NULL && chan->num < chan->max_num)
            {
                Z_ADDREF_P(item);
                add_next_index_zval(&writable, item);
                need_yield = 0;
            }
            else if (chan == NULL)
            {
                property = swoole_get_property(item, CHANNEL_CORO_PROPERTY_INDEX);
                if (property->consumer_list->num > 0)
                {
                    Z_ADDREF_P(item);
                    add_next_index_zval(&writable, item);
                    need_yield = 0;
                }
            }
        SW_HASHTABLE_FOREACH_END();
    }

    if (need_yield)
    {
        channel_selector *selector = (channel_selector*) emalloc(sizeof(channel_selector));
        memset(selector, 0, sizeof(channel_selector));

        selector->count = php_swoole_array_length(read_list);
        if (write_list)
        {
            selector->count += php_swoole_array_length(write_list);
        }
        selector->node_list = ecalloc(selector->count, sizeof(channel_selector_node));

        selector->read_list = read_list;
        selector->readable = readable;

        channel_node *node = emalloc(sizeof(channel_node));
        memset(node, 0, sizeof(channel_node));
        node->selector = selector;

        int i = 0;
        SW_HASHTABLE_FOREACH_START(Z_ARRVAL_P(read_list), item)
            property = swoole_get_property(item, CHANNEL_CORO_PROPERTY_INDEX);
            swLinkedList_append(property->consumer_list, node);
            selector->node_list[i].list = property->consumer_list;
            selector->node_list[i].node = property->consumer_list->tail;
            i++;
        SW_HASHTABLE_FOREACH_END();

        if (write_list)
        {
            selector->write_list = write_list;
            selector->writable = writable;

            SW_HASHTABLE_FOREACH_START(Z_ARRVAL_P(write_list), item)
                property = swoole_get_property(item, CHANNEL_CORO_PROPERTY_INDEX);
                swLinkedList_append(property->producer_list, node);
                selector->node_list[i].list = property->producer_list;
                selector->node_list[i].node = property->producer_list->tail;
                i++;
            SW_HASHTABLE_FOREACH_END();
        }

        if (timeout > 0)
        {
            int ms = (int) (timeout * 1000);
            php_swoole_check_reactor();
            php_swoole_check_timer(ms);
            selector->timer = SwooleG.timer.add(&SwooleG.timer, ms, 0, node, channel_selector_onTimeout);
        }

        coro_save(&node->context);
        coro_yield();
    }
    else
    {
        zval_ptr_dtor(read_list);
        ZVAL_COPY_VALUE(read_list, &readable);

        if (write_list)
        {
            zval_ptr_dtor(write_list);
            ZVAL_COPY_VALUE(write_list, &writable);
        }

        RETURN_TRUE;
    }
}
#endif
