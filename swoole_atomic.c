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

static PHP_METHOD(swoole_atomic, __construct);
static PHP_METHOD(swoole_atomic, add);
static PHP_METHOD(swoole_atomic, sub);
static PHP_METHOD(swoole_atomic, get);
static PHP_METHOD(swoole_atomic, set);
static PHP_METHOD(swoole_atomic, cmpset);

static zend_class_entry swoole_atomic_ce;
zend_class_entry *swoole_atomic_class_entry_ptr;

static const zend_function_entry swoole_atomic_methods[] =
{
    PHP_ME(swoole_atomic, __construct, NULL, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_ME(swoole_atomic, add, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_atomic, sub, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_atomic, get, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_atomic, set, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_atomic, cmpset, NULL, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

void swoole_atomic_init(int module_number TSRMLS_DC)
{
    INIT_CLASS_ENTRY(swoole_atomic_ce, "swoole_atomic", swoole_atomic_methods);
    swoole_atomic_class_entry_ptr = zend_register_internal_class(&swoole_atomic_ce TSRMLS_CC);
}

PHP_METHOD(swoole_atomic, __construct)
{
    long value = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|l", &value) == FAILURE)
    {
        RETURN_FALSE;
    }

    sw_atomic_t *atomic = SwooleG.memory_pool->alloc(SwooleG.memory_pool, sizeof(sw_atomic_t));
    *atomic = (sw_atomic_t) value;
    swoole_set_object(getThis(), (void*) atomic);

    RETURN_TRUE;
}

PHP_METHOD(swoole_atomic, add)
{
    long add_value = 1;
    sw_atomic_t *atomic = swoole_get_object(getThis());

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|l", &add_value) == FAILURE)
    {
        RETURN_FALSE;
    }

    RETURN_LONG(sw_atomic_fetch_add(atomic, (uint32_t) add_value));
}

PHP_METHOD(swoole_atomic, sub)
{
    long sub_value = 1;
    sw_atomic_t *atomic = swoole_get_object(getThis());

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|l", &sub_value) == FAILURE)
    {
        RETURN_FALSE;
    }

    RETURN_LONG(sw_atomic_fetch_sub(atomic, (uint32_t) sub_value));
}

PHP_METHOD(swoole_atomic, get)
{
    sw_atomic_t *atomic = swoole_get_object(getThis());
    RETURN_LONG(*atomic);
}

PHP_METHOD(swoole_atomic, set)
{
    sw_atomic_t *atomic = swoole_get_object(getThis());
    long set_value;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &set_value) == FAILURE)
    {
        RETURN_FALSE;
    }
    *atomic = (uint32_t) set_value;
}

PHP_METHOD(swoole_atomic, cmpset)
{
    long cmp_value, set_value;
    sw_atomic_t *atomic = swoole_get_object(getThis());

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ll", &cmp_value, &set_value) == FAILURE)
    {
        RETURN_FALSE;
    }

    RETURN_BOOL(sw_atomic_cmp_set(atomic, (sw_atomic_t) cmp_value, (sw_atomic_t) set_value));
}
