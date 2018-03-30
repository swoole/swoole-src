/*
  +----------------------------------------------------------------------+
  | Swoole                                                               |
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

static PHP_METHOD(swoole_msgqueue, __construct);
static PHP_METHOD(swoole_msgqueue, __destruct);
static PHP_METHOD(swoole_msgqueue, push);
static PHP_METHOD(swoole_msgqueue, pop);
static PHP_METHOD(swoole_msgqueue, stats);

static zend_class_entry swoole_msgqueue_ce;
zend_class_entry *swoole_msgqueue_class_entry_ptr;

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_msgqueue_construct, 0, 0, 1)
    ZEND_ARG_INFO(0, len)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_msgqueue_push, 0, 0, 1)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_INFO(0, type)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_msgqueue_pop, 0, 0, 0)
    ZEND_ARG_INFO(0, type)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_void, 0, 0, 0)
ZEND_END_ARG_INFO()

static const zend_function_entry swoole_msgqueue_methods[] =
{
    PHP_ME(swoole_msgqueue, __construct, arginfo_swoole_msgqueue_construct, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_ME(swoole_msgqueue, __destruct, arginfo_swoole_void, ZEND_ACC_PUBLIC | ZEND_ACC_DTOR)
    PHP_ME(swoole_msgqueue, push, arginfo_swoole_msgqueue_push, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_msgqueue, pop, arginfo_swoole_msgqueue_pop, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_msgqueue, stats, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

void swoole_msgqueue_init(int module_number TSRMLS_DC)
{
    SWOOLE_INIT_CLASS_ENTRY(swoole_msgqueue_ce, "swoole_msgqueue", "Swoole\\MsgQueue", swoole_msgqueue_methods);
    swoole_msgqueue_class_entry_ptr = zend_register_internal_class(&swoole_msgqueue_ce TSRMLS_CC);
    SWOOLE_CLASS_ALIAS(swoole_msgqueue, "Swoole\\MsgQueue");
}

static PHP_METHOD(swoole_msgqueue, __construct)
{
    long key;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &key) == FAILURE)
    {
        RETURN_FALSE;
    }

    swMsgQueue *queue = emalloc(sizeof(swRingQueue));
    if (queue == NULL)
    {
        zend_throw_exception(swoole_exception_class_entry_ptr, "failed to create MsgQueue.", SW_ERROR_MALLOC_FAIL TSRMLS_CC);
        RETURN_FALSE;
    }
    if (swMsgQueue_create(queue, 1, key, 0))
    {
        zend_throw_exception(swoole_exception_class_entry_ptr, "failed to init MsgQueue.", SW_ERROR_MALLOC_FAIL TSRMLS_CC);
        RETURN_FALSE;
    }
    swoole_set_object(getThis(), queue);
}

static PHP_METHOD(swoole_msgqueue, __destruct)
{
    swRingQueue *queue = swoole_get_object(getThis());
    efree(queue);
    swoole_set_object(getThis(), NULL);
}

static PHP_METHOD(swoole_msgqueue, push)
{
    char *data;
    zend_size_t length;
    long type = 1;

    if (zend_parse_parameters(ZEND_NUM_ARGS()TSRMLS_CC, "s|l", &data, &length, &type) == FAILURE)
    {
        RETURN_FALSE;
    }

    swQueue_data *in = (swQueue_data *) emalloc(length + sizeof(long) + 1);
    in->mtype = type;
    memcpy(in->mdata, data, length + 1);

    swRingQueue *queue = swoole_get_object(getThis());
    int ret = swMsgQueue_push(queue, in, length);
    efree(in);
    SW_CHECK_RETURN(ret);
}

static PHP_METHOD(swoole_msgqueue, pop)
{
    long type = 1;
    swQueue_data out;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|l", &type) == FAILURE)
    {
        RETURN_FALSE;
    }

    swRingQueue *queue = swoole_get_object(getThis());
    out.mtype = type;
    int length = swMsgQueue_pop(queue, &out, sizeof(out.mdata));
    if (length < 0)
    {
        RETURN_FALSE;
    }
    RETURN_STRINGL(out.mdata, length);
}

static PHP_METHOD(swoole_msgqueue, stats)
{
    swRingQueue *queue = swoole_get_object(getThis());
    int queue_num = -1;
    int queue_bytes = -1;
    if (swMsgQueue_stat(queue, &queue_num, &queue_bytes) == 0)
    {
        array_init(return_value);
        sw_add_assoc_long_ex(return_value, ZEND_STRS("queue_num"), queue_num);
        sw_add_assoc_long_ex(return_value, ZEND_STRS("queue_bytes"), queue_bytes);
    }
    else
    {
        RETURN_FALSE;
    }
}
