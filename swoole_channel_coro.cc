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
#include <queue>

using namespace std;

enum ChannelSelectOpcode
{
    CHANNEL_SELECT_WRITE = 0, CHANNEL_SELECT_READ = 1,
};

typedef struct
{
    swLinkedList *producer_list;
    swLinkedList *consumer_list;
    bool closed;
    int capacity;
    queue<zval> *data_queue;
} channel;

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

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_channel_coro_construct, 0, 0, 0)
    ZEND_ARG_INFO(0, size)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_channel_coro_push, 0, 0, 1)
    ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_channel_coro_select, 0, 0, 2)
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
    if (selector->timer)
    {
        swTimer_del(&SwooleG.timer, selector->timer);
        selector->timer = NULL;
    }
}

static void channel_selector_onTimeout(swTimer *timer, swTimer_node *tnode)
{
    zval *retval = NULL;
    zval *result = NULL;
    SW_MAKE_STD_ZVAL(result);
    ZVAL_BOOL(result, 0);

    channel_node *node = (channel_node *) tnode->data;
    channel_selector *selector = (channel_selector *) node->selector;

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

static inline bool channel_isEmpty(channel *chan)
{
    return chan->data_queue->size() == 0;
}

static inline bool channel_isFull(channel *chan)
{
    return chan->data_queue->size() == chan->capacity;
}

static int channel_onNotify(swReactor *reactor, swEvent *event)
{
    uint64_t notify;
    while (read(COROG.chan_pipe->getFd(COROG.chan_pipe, 0), &notify, sizeof(notify)) > 0);
    coro_handle_timeout();
    SwooleG.main_reactor->del(SwooleG.main_reactor, COROG.chan_pipe->getFd(COROG.chan_pipe, 0));
    return 0;
}

static void channel_notify(channel_node *node)
{
    swLinkedList_append(SwooleWG.coro_timeout_list, node);
    if (!swReactor_handle_isset(SwooleG.main_reactor, PHP_SWOOLE_FD_CHAN_PIPE))
    {
        swReactor_setHandle(SwooleG.main_reactor, PHP_SWOOLE_FD_CHAN_PIPE, channel_onNotify);

    }
    int pfd = COROG.chan_pipe->getFd(COROG.chan_pipe, 0);
    swConnection *_socket = swReactor_get(SwooleG.main_reactor, pfd);
    if (_socket && _socket->events == 0)
    {
        SwooleG.main_reactor->add(SwooleG.main_reactor, pfd, PHP_SWOOLE_FD_CHAN_PIPE | SW_EVENT_READ);
    }
    uint64_t flag = 1;
    COROG.chan_pipe->write(COROG.chan_pipe, &flag, sizeof(flag));
}

static void swoole_channel_onResume(php_context *ctx)
{
    channel_node *node = (channel_node *) ctx;
    zval *zdata = NULL;
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
            zval_ptr_dtor(selector->write_list);
            Z_TRY_ADDREF_P(&selector->object);
            add_next_index_zval(&selector->writable, &selector->object);
            ZVAL_COPY_VALUE(selector->write_list, &selector->writable);
            if (selector->read_list)
            {
                zval_ptr_dtor(selector->read_list);
                ZVAL_COPY_VALUE(selector->read_list, &selector->readable);
            }
        }
        else
        {
            //read
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
        SW_MAKE_STD_ZVAL(zdata);
        ZVAL_BOOL(zdata, 1);
        efree(selector);
    }

    swDebug("channel onResume, cid=%d", coroutine_get_cid());

    int ret = coro_resume(ctx, zdata, &retval);
    if (ret == CORO_END && retval)
    {
        sw_zval_ptr_dtor(&retval);
    }
    if (zdata)
    {
        zval_ptr_dtor(zdata);
    }
    efree(ctx);
}

static int swoole_channel_try_resume_producer(zval *object, channel *property)
{
    swLinkedList *coro_list = property->producer_list;
    channel_node *node;

    if (coro_list->num != 0)
    {
        node = (channel_node *) coro_list->head->data;
        if (node == NULL)
        {
            return -1;
        }
        node->context.onTimeout = swoole_channel_onResume;
        if (node->selector)
        {
            node->selector->object = *object;
            node->selector->opcode = CHANNEL_SELECT_WRITE;
            channel_selector_clear(node->selector, coro_list->head);
        }
        swLinkedList_shift(coro_list);
        channel_notify(node);
        return 0;
    }
    return -1;
}

static sw_inline int swoole_channel_try_resume_all(zval *object, channel *property)
{
    swLinkedList *coro_list = property->producer_list;
    swLinkedList_node *next;
    channel_node *node;

    while (coro_list->num != 0)
    {
        next = coro_list->head;
        node = (channel_node *) swLinkedList_shift(coro_list);
        node->context.onTimeout = swoole_channel_onResume;
        ZVAL_FALSE(&node->context.coro_params);
        if (node->selector)
        {
            node->selector->object = *object;
            node->selector->opcode = CHANNEL_SELECT_READ;
            channel_selector_clear(node->selector, next);
        }
        channel_notify(node);
    }

    coro_list = property->consumer_list;
    while (coro_list->num != 0)
    {
        next = coro_list->head;
        node = (channel_node*) swLinkedList_shift(coro_list);
        node->context.onTimeout = swoole_channel_onResume;
        ZVAL_FALSE(&node->context.coro_params);
        if (node->selector)
        {
            node->selector->object = *object;
            node->selector->opcode = CHANNEL_SELECT_WRITE;
            channel_selector_clear(node->selector, next);
        }
        channel_notify(node);
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
    if (capacity <= 0)
    {
        capacity = 1;
    }

    if (COROG.chan_pipe == NULL)
    {
        COROG.chan_pipe = (swPipe *) emalloc(sizeof(swPipe));
        if (swPipeNotify_auto(COROG.chan_pipe, 1, 1) < 0)
        {
            zend_throw_exception(swoole_exception_class_entry_ptr, "failed to create eventfd.", SW_ERROR_SYSTEM_CALL_FAIL TSRMLS_CC);
            RETURN_FALSE;
        }
    }

    channel *chan = (channel *) sw_malloc(sizeof(channel));
    if (chan == NULL)
    {
        zend_throw_exception(swoole_exception_class_entry_ptr, "failed to create property.", SW_ERROR_MALLOC_FAIL TSRMLS_CC);
        RETURN_FALSE;
    }

    chan->data_queue = new queue<zval>;
    chan->producer_list = swLinkedList_new(2, NULL);
    if (chan->producer_list == NULL)
    {
        zend_throw_exception(swoole_exception_class_entry_ptr, "failed to create producer_list.", SW_ERROR_MALLOC_FAIL TSRMLS_CC);
        RETURN_FALSE;
    }
    chan->consumer_list = swLinkedList_new(2, NULL);
    if (chan->consumer_list == NULL)
    {
        zend_throw_exception(swoole_exception_class_entry_ptr, "failed to create consumer_list.", SW_ERROR_MALLOC_FAIL TSRMLS_CC);
        RETURN_FALSE;
    }
    chan->closed = false;
    chan->capacity = capacity;

    zend_update_property_long(swoole_channel_coro_class_entry_ptr, getThis(), ZEND_STRL("capacity"), capacity TSRMLS_CC);

    swoole_set_object(getThis(), chan);
}

static PHP_METHOD(swoole_channel_coro, __destruct)
{
    SW_PREVENT_USER_DESTRUCT;

    channel *chan = (channel *) swoole_get_object(getThis());
    chan->closed = true;

    swDebug("destruct, producer_count=%d, consumer_count=%d", chan->producer_list->num, chan->consumer_list->num);

    /** resume and free the coroutine **/
    swLinkedList *coro_list = chan->producer_list;
    channel_node *node;
    while (coro_list->num != 0 && (node = (channel_node *) swLinkedList_shift(coro_list)))
    {
        swoole_channel_onResume(&node->context);
    }
    coro_list = chan->consumer_list;
    while (coro_list->num != 0 && (node = (channel_node *) swLinkedList_shift(coro_list)))
    {
        swoole_channel_onResume(&node->context);
    }

    sw_free(chan->consumer_list);
    sw_free(chan->producer_list);
    delete chan->data_queue;
    swoole_set_object(getThis(), NULL);
}

static PHP_METHOD(swoole_channel_coro, push)
{
    coro_check(TSRMLS_C);

    channel *chan = (channel *) swoole_get_object(getThis());
    if (chan->closed)
    {
        RETURN_FALSE;
    }
    swLinkedList *producer_list = chan->producer_list;

    zval *zdata;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &zdata) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (channel_isFull(chan))
    {
        channel_node *node = (channel_node *) emalloc(sizeof(channel_node));
        memset(node, 0, sizeof(channel_node));
        coro_save(&node->context);
        swLinkedList_append(producer_list, node);
        coro_yield();
    }

    if (channel_isFull(chan) && chan->closed)
    {
        RETURN_FALSE;
    }

    Z_TRY_ADDREF_P(zdata);
    chan->data_queue->push(*zdata);

    swDebug("TYPE=%d, count=%d", Z_TYPE_P(zdata), chan->data_queue->size());

    if (chan->consumer_list->num != 0)
    {
        swLinkedList_node *head = chan->consumer_list->head;
        channel_node *node = (channel_node *) swLinkedList_shift(chan->consumer_list);
        node->context.onTimeout = swoole_channel_onResume;
        if (node->selector)
        {
            node->selector->object = *getThis();
            node->selector->opcode = CHANNEL_SELECT_READ;
            channel_selector_clear(node->selector, chan->consumer_list->head);
        }
        channel_notify(node);

        node = (channel_node *) emalloc(sizeof(channel_node));
        memset(node, 0, sizeof(channel_node));
        coro_save(&node->context);
        swLinkedList_append(producer_list, node);
        coro_yield();
    }

    RETURN_TRUE;
}

static PHP_METHOD(swoole_channel_coro, pop)
{
    coro_check(TSRMLS_C);

    channel *chan = (channel *) swoole_get_object(getThis());
    if (chan->closed)
    {
        RETURN_FALSE;
    }

    if (channel_isEmpty(chan))
    {
        channel_node *node = (channel_node *) emalloc(sizeof(channel_node));
        memset(node, 0, sizeof(channel_node));
        coro_save(&node->context);
        swLinkedList_append(chan->consumer_list, node);
        swoole_channel_try_resume_producer(getThis(), chan);
        coro_yield();
    }

    if (channel_isEmpty(chan) && chan->closed)
    {
        RETURN_FALSE;
    }

    assert(chan->data_queue->size() > 0);

    zval zdata = chan->data_queue->front();
    chan->data_queue->pop();

    swDebug("TYPE=%d, count=%d", Z_TYPE(zdata), chan->data_queue->size());

    swoole_channel_try_resume_producer(getThis(), chan);
    RETURN_ZVAL(&zdata, 0, NULL);
}

static PHP_METHOD(swoole_channel_coro, close)
{
    channel *chan = (channel *) swoole_get_object(getThis());
    if (chan->closed)
    {
        RETURN_TRUE;
    }
    chan->closed = true;
    swoole_channel_try_resume_all(getThis(), chan);
    RETURN_TRUE;
}

static PHP_METHOD(swoole_channel_coro, length)
{
    channel *chan = (channel *) swoole_get_object(getThis());
    RETURN_LONG(chan->data_queue->size());
}

static PHP_METHOD(swoole_channel_coro, isEmpty)
{
    channel *chan = (channel *) swoole_get_object(getThis());
    RETURN_BOOL(channel_isEmpty(chan));
}

static PHP_METHOD(swoole_channel_coro, isFull)
{
    channel *chan = (channel *) swoole_get_object(getThis());
    RETURN_BOOL(channel_isFull(chan));
}

static PHP_METHOD(swoole_channel_coro, stats)
{
    channel *chan = (channel *) swoole_get_object(getThis());
    array_init(return_value);

    sw_add_assoc_long_ex(return_value, ZEND_STRS("consumer_num"), chan->consumer_list->num);
    sw_add_assoc_long_ex(return_value, ZEND_STRS("producer_num"), chan->producer_list->num);

    if (chan)
    {
        sw_add_assoc_long_ex(return_value, ZEND_STRS("queue_num"), chan->data_queue->size());
    }
}

static PHP_METHOD(swoole_channel_coro, select)
{
    coro_check(TSRMLS_C);

    zval *read_list, *write_list = NULL, *item;
    zval readable, writable;
    double timeout = 0;
    zend_bool need_yield = 1;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "a!a!|d", &read_list, &write_list, &timeout) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (read_list)
    {
        array_init(&readable);

        SW_HASHTABLE_FOREACH_START(Z_ARRVAL_P(read_list), item)
            if (Z_TYPE_P(item) != IS_OBJECT || !instanceof_function(Z_OBJCE_P(item), swoole_channel_coro_class_entry_ptr TSRMLS_CC))
            {
                zend_throw_exception_ex(swoole_exception_class_entry_ptr, errno TSRMLS_CC, "object is not instanceof Swoole\\Coroutine\\Channel.");
                return;
            }
            channel *chan = (channel *) swoole_get_object(item);
            if (!channel_isEmpty(chan))
            {
                Z_ADDREF_P(item);
                add_next_index_zval(&readable, item);
                need_yield = 0;
            }
        SW_HASHTABLE_FOREACH_END();
    }

    if (write_list)
    {
        array_init(&writable);

        SW_HASHTABLE_FOREACH_START(Z_ARRVAL_P(write_list), item)
            if (Z_TYPE_P(item) != IS_OBJECT || !instanceof_function(Z_OBJCE_P(item), swoole_channel_coro_class_entry_ptr TSRMLS_CC))
            {
                zend_throw_exception_ex(swoole_exception_class_entry_ptr, errno TSRMLS_CC, "object is not instanceof Swoole\\Coroutine\\Channel.");
                return;
            }
            channel *chan = (channel *) swoole_get_object(item);
            if (!channel_isFull(chan))
            {
                Z_ADDREF_P(item);
                add_next_index_zval(&writable, item);
                need_yield = 0;
            }
        SW_HASHTABLE_FOREACH_END();
    }

    if (need_yield && (read_list || write_list))
    {
        channel_selector *selector = (channel_selector*) emalloc(sizeof(channel_selector));
        memset(selector, 0, sizeof(channel_selector));

        if (read_list)
        {
            selector->count = php_swoole_array_length(read_list);
        }
        if (write_list)
        {
            selector->count += php_swoole_array_length(write_list);
        }
        selector->node_list = (channel_selector_node *) ecalloc(selector->count, sizeof(channel_selector_node));
        int i = 0;
        channel_node *node = (channel_node *) emalloc(sizeof(channel_node));
        memset(node, 0, sizeof(channel_node));
        node->selector = selector;
        if (read_list)
        {
            selector->read_list = read_list;
            selector->readable = readable;

            SW_HASHTABLE_FOREACH_START(Z_ARRVAL_P(read_list), item)
                channel *chan = (channel *) swoole_get_object(item);
                swLinkedList_append(chan->consumer_list, node);
                selector->node_list[i].list = chan->consumer_list;
                selector->node_list[i].node = chan->consumer_list->tail;
                i++;
            SW_HASHTABLE_FOREACH_END();
        }

        if (write_list)
        {
            selector->write_list = write_list;
            selector->writable = writable;

            SW_HASHTABLE_FOREACH_START(Z_ARRVAL_P(write_list), item)
                channel *chan = (channel *) swoole_get_object(item);
                swLinkedList_append(chan->producer_list, node);
                selector->node_list[i].list = chan->producer_list;
                selector->node_list[i].node = chan->producer_list->tail;
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
        if (read_list)
        {
            zval_ptr_dtor(read_list);
            ZVAL_COPY_VALUE(read_list, &readable);
        }


        if (write_list)
        {
            zval_ptr_dtor(write_list);
            ZVAL_COPY_VALUE(write_list, &writable);
        }

        RETURN_TRUE;
    }
}
#endif
