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
static PHP_METHOD(swoole_atomic, wait);
static PHP_METHOD(swoole_atomic, wakeup);

static PHP_METHOD(swoole_atomic_long, __construct);
static PHP_METHOD(swoole_atomic_long, add);
static PHP_METHOD(swoole_atomic_long, sub);
static PHP_METHOD(swoole_atomic_long, get);
static PHP_METHOD(swoole_atomic_long, set);
static PHP_METHOD(swoole_atomic_long, cmpset);

#ifdef HAVE_FUTEX
#include <linux/futex.h>
#include <syscall.h>

static sw_inline int swoole_futex_wait(sw_atomic_t *atomic, double timeout)
{
    if (sw_atomic_cmp_set(atomic, 1, 0))
    {
        return SW_OK;
    }

    int ret;
    struct timespec _timeout;

    if (timeout > 0)
    {

        _timeout.tv_sec = (long) timeout;
        _timeout.tv_nsec = (timeout - _timeout.tv_sec) * 1000 * 1000 * 1000;
        ret = syscall(SYS_futex, atomic, FUTEX_WAIT, 0, &_timeout, NULL, 0);
    }
    else
    {
        ret = syscall(SYS_futex, atomic, FUTEX_WAIT, 0, NULL, NULL, 0);
    }
    if (ret == SW_OK)
    {
        *atomic = 0;
    }
    return ret;
}

static sw_inline int swoole_futex_wakeup(sw_atomic_t *atomic, int n)
{
    if (sw_atomic_cmp_set(atomic, 0, 1))
    {
        return syscall(SYS_futex, atomic, FUTEX_WAKE, n, NULL, NULL, 0);
    }
    else
    {
        return SW_OK;
    }
}
#endif

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_atomic_construct, 0, 0, 0)
    ZEND_ARG_INFO(0, value)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_atomic_add, 0, 0, 0)
    ZEND_ARG_INFO(0, add_value)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_atomic_sub, 0, 0, 0)
    ZEND_ARG_INFO(0, sub_value)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_atomic_get, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_atomic_set, 0, 0, 1)
    ZEND_ARG_INFO(0, value)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_atomic_cmpset, 0, 0, 2)
    ZEND_ARG_INFO(0, cmp_value)
    ZEND_ARG_INFO(0, new_value)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_atomic_wait, 0, 0, 0)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_atomic_waitup, 0, 0, 0)
    ZEND_ARG_INFO(0, count)
ZEND_END_ARG_INFO()

static zend_class_entry swoole_atomic_ce;
zend_class_entry *swoole_atomic_class_entry_ptr;

static zend_class_entry swoole_atomic_long_ce;
zend_class_entry *swoole_atomic_long_class_entry_ptr;

static const zend_function_entry swoole_atomic_methods[] =
{
    PHP_ME(swoole_atomic, __construct, arginfo_swoole_atomic_construct, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_ME(swoole_atomic, add, arginfo_swoole_atomic_add, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_atomic, sub, arginfo_swoole_atomic_sub, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_atomic, get, arginfo_swoole_atomic_get, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_atomic, set, arginfo_swoole_atomic_set, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_atomic, wait, arginfo_swoole_atomic_wait, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_atomic, wakeup, arginfo_swoole_atomic_waitup, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_atomic, cmpset, arginfo_swoole_atomic_cmpset, ZEND_ACC_PUBLIC)
    PHP_FALIAS(__sleep, swoole_unsupport_serialize, NULL)
    PHP_FALIAS(__wakeup, swoole_unsupport_serialize, NULL)
    PHP_FE_END
};

static const zend_function_entry swoole_atomic_long_methods[] =
{
    PHP_ME(swoole_atomic_long, __construct, arginfo_swoole_atomic_construct, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_ME(swoole_atomic_long, add, arginfo_swoole_atomic_add, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_atomic_long, sub, arginfo_swoole_atomic_sub, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_atomic_long, get, arginfo_swoole_atomic_get, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_atomic_long, set, arginfo_swoole_atomic_set, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_atomic_long, cmpset, arginfo_swoole_atomic_cmpset, ZEND_ACC_PUBLIC)
    PHP_FALIAS(__sleep, swoole_unsupport_serialize, NULL)
    PHP_FALIAS(__wakeup, swoole_unsupport_serialize, NULL)
    PHP_FE_END
};

void swoole_atomic_init(int module_number TSRMLS_DC)
{
    SWOOLE_INIT_CLASS_ENTRY(swoole_atomic_ce, "swoole_atomic", "Swoole\\Atomic", swoole_atomic_methods);
    swoole_atomic_class_entry_ptr = zend_register_internal_class(&swoole_atomic_ce TSRMLS_CC);
    SWOOLE_CLASS_ALIAS(swoole_atomic, "Swoole\\Atomic");

    SWOOLE_INIT_CLASS_ENTRY(swoole_atomic_long_ce, "swoole_atomic_long", "Swoole\\Atomic\\Long", swoole_atomic_long_methods);
    swoole_atomic_long_class_entry_ptr = zend_register_internal_class(&swoole_atomic_long_ce TSRMLS_CC);
    SWOOLE_CLASS_ALIAS(swoole_atomic_long, "Swoole\\Atomic\\Long");
}

PHP_METHOD(swoole_atomic, __construct)
{
    long value = 0;

#ifdef FAST_ZPP
    ZEND_PARSE_PARAMETERS_START(0, 1)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(value)
    ZEND_PARSE_PARAMETERS_END();
#else
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|l", &value) == FAILURE)
    {
        RETURN_FALSE;
    }
#endif

    sw_atomic_t *atomic = SwooleG.memory_pool->alloc(SwooleG.memory_pool, sizeof(sw_atomic_t));
    if (atomic == NULL)
    {
        zend_throw_exception(swoole_exception_class_entry_ptr, "global memory allocation failure.", SW_ERROR_MALLOC_FAIL TSRMLS_CC);
        RETURN_FALSE;
    }
    *atomic = (sw_atomic_t) value;
    swoole_set_object(getThis(), (void*) atomic);

    RETURN_TRUE;
}

PHP_METHOD(swoole_atomic, add)
{
    long add_value = 1;
    sw_atomic_t *atomic = swoole_get_object(getThis());

#ifdef FAST_ZPP
    ZEND_PARSE_PARAMETERS_START(0, 1)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(add_value)
    ZEND_PARSE_PARAMETERS_END();
#else
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|l", &add_value) == FAILURE)
    {
        RETURN_FALSE;
    }
#endif
    RETURN_LONG(sw_atomic_add_fetch(atomic, (uint32_t ) add_value));
}

PHP_METHOD(swoole_atomic, sub)
{
    long sub_value = 1;
    sw_atomic_t *atomic = swoole_get_object(getThis());

#ifdef FAST_ZPP
    ZEND_PARSE_PARAMETERS_START(0, 1)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(sub_value)
    ZEND_PARSE_PARAMETERS_END();
#else
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|l", &sub_value) == FAILURE)
    {
        RETURN_FALSE;
    }
#endif
    RETURN_LONG(sw_atomic_sub_fetch(atomic, (uint32_t ) sub_value));
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

#ifdef FAST_ZPP
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_LONG(set_value)
    ZEND_PARSE_PARAMETERS_END();
#else
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &set_value) == FAILURE)
    {
        RETURN_FALSE;
    }
#endif
    *atomic = (uint32_t) set_value;
}

PHP_METHOD(swoole_atomic, cmpset)
{
    long cmp_value, set_value;
    sw_atomic_t *atomic = swoole_get_object(getThis());

#ifdef FAST_ZPP
    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_LONG(cmp_value)
        Z_PARAM_LONG(set_value)
    ZEND_PARSE_PARAMETERS_END();
#else
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ll", &cmp_value, &set_value) == FAILURE)
    {
        RETURN_FALSE;
    }
#endif

    RETURN_BOOL(sw_atomic_cmp_set(atomic, (sw_atomic_t) cmp_value, (sw_atomic_t) set_value));
}

PHP_METHOD(swoole_atomic, wait)
{
    double timeout = 1.0;
    sw_atomic_t *atomic = swoole_get_object(getThis());

#ifdef FAST_ZPP
    ZEND_PARSE_PARAMETERS_START(0, 1)
        Z_PARAM_OPTIONAL
        Z_PARAM_DOUBLE(timeout)
    ZEND_PARSE_PARAMETERS_END();
#else
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|d", &timeout) == FAILURE)
    {
        RETURN_FALSE;
    }
#endif

#ifdef HAVE_FUTEX
    SW_CHECK_RETURN(swoole_futex_wait(atomic, timeout));
#else
    timeout = timeout <= 0 ? SW_MAX_INT : timeout;
    while (timeout > 0)
    {
        if (sw_atomic_cmp_set(atomic, 1, 0))
        {
            RETURN_TRUE;
        }
        else
        {
            usleep(1000);
            timeout -= 0.001;
        }
    }
#endif
}

PHP_METHOD(swoole_atomic, wakeup)
{
    long n = 1;
    sw_atomic_t *atomic = swoole_get_object(getThis());

#ifdef FAST_ZPP
    ZEND_PARSE_PARAMETERS_START(0, 1)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(n)
    ZEND_PARSE_PARAMETERS_END();
#else
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|l", &n) == FAILURE)
    {
        RETURN_FALSE;
    }
#endif

#ifdef HAVE_FUTEX
    SW_CHECK_RETURN(swoole_futex_wakeup(atomic, (int ) n));
#else
    *atomic = 1;
#endif
}

PHP_METHOD(swoole_atomic_long, __construct)
{
    long value = 0;

#ifdef FAST_ZPP
    ZEND_PARSE_PARAMETERS_START(0, 1)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(value)
    ZEND_PARSE_PARAMETERS_END();
#else
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|l", &value) == FAILURE)
    {
        RETURN_FALSE;
    }
#endif

    sw_atomic_long_t *atomic = SwooleG.memory_pool->alloc(SwooleG.memory_pool, sizeof(sw_atomic_long_t));
    if (atomic == NULL)
    {
        zend_throw_exception(swoole_exception_class_entry_ptr, "global memory allocation failure.", SW_ERROR_MALLOC_FAIL TSRMLS_CC);
        RETURN_FALSE;
    }
    *atomic = (sw_atomic_long_t) value;
    swoole_set_object(getThis(), (void*) atomic);

    RETURN_TRUE;
}

PHP_METHOD(swoole_atomic_long, add)
{
    long add_value = 1;
    sw_atomic_long_t *atomic = swoole_get_object(getThis());

#ifdef FAST_ZPP
    ZEND_PARSE_PARAMETERS_START(0, 1)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(add_value)
    ZEND_PARSE_PARAMETERS_END();
#else
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|l", &add_value) == FAILURE)
    {
        RETURN_FALSE;
    }
#endif

    RETURN_LONG(sw_atomic_add_fetch(atomic, (sw_atomic_long_t ) add_value));
}

PHP_METHOD(swoole_atomic_long, sub)
{
    long sub_value = 1;
    sw_atomic_long_t *atomic = swoole_get_object(getThis());

#ifdef FAST_ZPP
    ZEND_PARSE_PARAMETERS_START(0, 1)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(sub_value)
    ZEND_PARSE_PARAMETERS_END();
#else
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|l", &sub_value) == FAILURE)
    {
        RETURN_FALSE;
    }
#endif

    RETURN_LONG(sw_atomic_sub_fetch(atomic, (sw_atomic_long_t ) sub_value));
}

PHP_METHOD(swoole_atomic_long, get)
{
    sw_atomic_long_t *atomic = swoole_get_object(getThis());
    RETURN_LONG(*atomic);
}

PHP_METHOD(swoole_atomic_long, set)
{
    sw_atomic_long_t *atomic = swoole_get_object(getThis());
    long set_value;

#ifdef FAST_ZPP
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_LONG(set_value)
    ZEND_PARSE_PARAMETERS_END();
#else
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &set_value) == FAILURE)
    {
        RETURN_FALSE;
    }
#endif
    *atomic = (sw_atomic_long_t) set_value;
}

PHP_METHOD(swoole_atomic_long, cmpset)
{
    long cmp_value, set_value;
    sw_atomic_long_t *atomic = swoole_get_object(getThis());

#ifdef FAST_ZPP
    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_LONG(cmp_value)
        Z_PARAM_LONG(set_value)
    ZEND_PARSE_PARAMETERS_END();
#else
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ll", &cmp_value, &set_value) == FAILURE)
    {
        RETURN_FALSE;
    }
#endif

    RETURN_BOOL(sw_atomic_cmp_set(atomic, (sw_atomic_long_t) cmp_value, (sw_atomic_long_t) set_value));
}
