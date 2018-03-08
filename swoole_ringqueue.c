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
 | Author: Xinyu Zhu  <xyzhu1120@gmail.com>                        |
 +----------------------------------------------------------------------+
 */


#include "php_swoole.h"

static PHP_METHOD(swoole_ringqueue, __construct);
static PHP_METHOD(swoole_ringqueue, __destruct);
static PHP_METHOD(swoole_ringqueue, push);
static PHP_METHOD(swoole_ringqueue, pop);
static PHP_METHOD(swoole_ringqueue, count);
static PHP_METHOD(swoole_ringqueue, isFull);
static PHP_METHOD(swoole_ringqueue, isEmpty);

static zend_class_entry swoole_ringqueue_ce;
zend_class_entry *swoole_ringqueue_class_entry_ptr;

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_ringqueue_construct, 0, 0, 1)
    ZEND_ARG_INFO(0, len)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_ringqueue_push, 0, 0, 1)
    ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_void, 0, 0, 0)
ZEND_END_ARG_INFO()

static const zend_function_entry swoole_ringqueue_methods[] =
{
    PHP_ME(swoole_ringqueue, __construct, arginfo_swoole_ringqueue_construct, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_ME(swoole_ringqueue, __destruct, arginfo_swoole_void, ZEND_ACC_PUBLIC | ZEND_ACC_DTOR)
    PHP_ME(swoole_ringqueue, push, arginfo_swoole_ringqueue_push, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_ringqueue, pop, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_ringqueue, count, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_ringqueue, isFull, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_ringqueue, isEmpty, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

void swoole_ringqueue_init(int module_number TSRMLS_DC)
{
    SWOOLE_INIT_CLASS_ENTRY(swoole_ringqueue_ce, "swoole_ringqueue", "Swoole\\RingQueue", swoole_ringqueue_methods);
    swoole_ringqueue_class_entry_ptr = zend_register_internal_class(&swoole_ringqueue_ce TSRMLS_CC);
    SWOOLE_CLASS_ALIAS(swoole_ringqueue, "Swoole\\RingQueue");
}

static PHP_METHOD(swoole_ringqueue, __construct)
{
    long len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &len) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (len < 0)
    {
        len = SW_RINGQUEUE_LEN;
    }

    swRingQueue *queue = emalloc(sizeof(swRingQueue));
    if (queue == NULL)
    {
        zend_throw_exception(swoole_exception_class_entry_ptr, "failed to create ringqueue.", SW_ERROR_MALLOC_FAIL TSRMLS_CC);
        RETURN_FALSE;
    }
    if (swRingQueue_init(queue, len))
    {
        zend_throw_exception(swoole_exception_class_entry_ptr, "failed to init ringqueue.", SW_ERROR_MALLOC_FAIL TSRMLS_CC);
        RETURN_FALSE;
    }
    swoole_set_object(getThis(), queue);
}

static PHP_METHOD(swoole_ringqueue, __destruct)
{
    swRingQueue *queue = swoole_get_object(getThis());
    efree(queue);
    swoole_set_object(getThis(), NULL);
}

static PHP_METHOD(swoole_ringqueue, push)
{
    swRingQueue *queue = swoole_get_object(getThis());
    zval *zdata;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &zdata) == FAILURE)
    {
        RETURN_FALSE;
    }

    zdata = sw_zval_dup(zdata);
    if (swRingQueue_push(queue, zdata) < 0)
    {
        efree(zdata);
        RETURN_FALSE;
    }
    else
    {
        Z_TRY_ADDREF_P(zdata);
        RETURN_TRUE;
    }
}

static PHP_METHOD(swoole_ringqueue, pop)
{
    swRingQueue *queue = swoole_get_object(getThis());
    zval *zdata;

    int n = swRingQueue_pop(queue, (void**)&zdata);
    if (n < 0)
    {
        RETURN_FALSE;
    }
    RETVAL_ZVAL(zdata, 0, 0);
    efree(zdata);
}

static PHP_METHOD(swoole_ringqueue, isFull)
{
    swRingQueue *queue = swoole_get_object(getThis());
    RETURN_BOOL(swRingQueue_full(queue));
}

static PHP_METHOD(swoole_ringqueue, isEmpty)
{
    swRingQueue *queue = swoole_get_object(getThis());
    RETURN_BOOL(swRingQueue_empty(queue));
}

static PHP_METHOD(swoole_ringqueue, count)
{
    swRingQueue *queue = swoole_get_object(getThis());
    RETURN_LONG(swRingQueue_count(queue));
}
