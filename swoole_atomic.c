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
#include "swoole_mmap.h"

static PHP_METHOD(swoole_atomic, __construct);
static PHP_METHOD(swoole_atomic, add);
static PHP_METHOD(swoole_atomic, sub);
static PHP_METHOD(swoole_atomic, get);
static PHP_METHOD(swoole_atomic, set);
static PHP_METHOD(swoole_atomic, cmpset);
static PHP_METHOD(swoole_atomic, wait);
static PHP_METHOD(swoole_atomic, wakeup);

static PHP_METHOD(swoole_atomic, fetchAdd);
static PHP_METHOD(swoole_atomic, addFetch);
static PHP_METHOD(swoole_atomic, fetchSub);
static PHP_METHOD(swoole_atomic, subFetch);
static PHP_METHOD(swoole_atomic, cmpAndSet);
static PHP_METHOD(swoole_atomic, fetchOr);
static PHP_METHOD(swoole_atomic, orFetch);
static PHP_METHOD(swoole_atomic, fetchXor);
static PHP_METHOD(swoole_atomic, xorFetch);
static PHP_METHOD(swoole_atomic, fetchAnd);
static PHP_METHOD(swoole_atomic, andFetch);
static PHP_METHOD(swoole_atomic, fetchNand);
static PHP_METHOD(swoole_atomic, nandFetch);
static PHP_METHOD(swoole_atomic, getValue);
static PHP_METHOD(swoole_atomic, setValue);

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
        sw_atomic_cmp_set(atomic, 1, 0);
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

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_atomic_mmap, 0, 0, 2)
    ZEND_ARG_INFO(0, mmap)
    ZEND_ARG_INFO(0, value)
    ZEND_ARG_INFO(0, offset)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_atomic_mmap_getValue, 0, 0, 1)
    ZEND_ARG_INFO(0, mmap)
    ZEND_ARG_INFO(0, offset)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_atomic_mmap_cmpset, 0, 0, 3)
    ZEND_ARG_INFO(0, mmap)
    ZEND_ARG_INFO(0, cmp_value)
    ZEND_ARG_INFO(0, new_value)
    ZEND_ARG_INFO(0, offset)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_atomic_wait, 0, 0, 0)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_atomic_waitup, 0, 0, 0)
    ZEND_ARG_INFO(0, count)
ZEND_END_ARG_INFO()

static zend_class_entry swoole_atomic_ce;
zend_class_entry *swoole_atomic_ce_ptr;
static zend_object_handlers swoole_atomic_handlers;

static zend_class_entry swoole_atomic_long_ce;
zend_class_entry *swoole_atomic_long_ce_ptr;
static zend_object_handlers swoole_atomic_long_handlers;

static const zend_function_entry swoole_atomic_methods[] =
{
    PHP_ME(swoole_atomic, __construct, arginfo_swoole_atomic_construct, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_atomic, add, arginfo_swoole_atomic_add, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_atomic, sub, arginfo_swoole_atomic_sub, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_atomic, get, arginfo_swoole_atomic_get, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_atomic, set, arginfo_swoole_atomic_set, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_atomic, wait, arginfo_swoole_atomic_wait, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_atomic, wakeup, arginfo_swoole_atomic_waitup, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_atomic, cmpset, arginfo_swoole_atomic_cmpset, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_atomic, fetchAdd, arginfo_swoole_atomic_mmap, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_atomic, fetchSub, arginfo_swoole_atomic_mmap, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_atomic, fetchOr, arginfo_swoole_atomic_mmap, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_atomic, fetchXor, arginfo_swoole_atomic_mmap, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_atomic, fetchAnd, arginfo_swoole_atomic_mmap, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_atomic, fetchNand, arginfo_swoole_atomic_mmap, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_atomic, addFetch, arginfo_swoole_atomic_mmap, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_atomic, subFetch, arginfo_swoole_atomic_mmap, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_atomic, orFetch, arginfo_swoole_atomic_mmap, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_atomic, xorFetch, arginfo_swoole_atomic_mmap, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_atomic, andFetch, arginfo_swoole_atomic_mmap, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_atomic, nandFetch, arginfo_swoole_atomic_mmap, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_atomic, cmpAndSet, arginfo_swoole_atomic_mmap_cmpset, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_atomic, getValue, arginfo_swoole_atomic_mmap_getValue, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_atomic, setValue, arginfo_swoole_atomic_mmap, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_FE_END
};

static const zend_function_entry swoole_atomic_long_methods[] =
{
    PHP_ME(swoole_atomic_long, __construct, arginfo_swoole_atomic_construct, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_atomic_long, add, arginfo_swoole_atomic_add, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_atomic_long, sub, arginfo_swoole_atomic_sub, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_atomic_long, get, arginfo_swoole_atomic_get, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_atomic_long, set, arginfo_swoole_atomic_set, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_atomic_long, cmpset, arginfo_swoole_atomic_cmpset, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

void swoole_atomic_init(int module_number)
{
    SWOOLE_INIT_CLASS_ENTRY(swoole_atomic, "Swoole\\Atomic", "swoole_atomic", NULL, swoole_atomic_methods);
    SWOOLE_SET_CLASS_SERIALIZABLE(swoole_atomic, zend_class_serialize_deny, zend_class_unserialize_deny);
    SWOOLE_SET_CLASS_CLONEABLE(swoole_atomic, zend_class_clone_deny);
    SWOOLE_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_atomic, zend_class_unset_property_deny);

    SWOOLE_INIT_CLASS_ENTRY(swoole_atomic_long, "Swoole\\Atomic\\Long", "swoole_atomic_long", NULL, swoole_atomic_long_methods);
    SWOOLE_SET_CLASS_SERIALIZABLE(swoole_atomic_long, zend_class_serialize_deny, zend_class_unserialize_deny);
    SWOOLE_SET_CLASS_CLONEABLE(swoole_atomic_long, zend_class_clone_deny);
    SWOOLE_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_atomic_long, zend_class_unset_property_deny);
}

PHP_METHOD(swoole_atomic, __construct)
{
    zend_long value = 0;

    ZEND_PARSE_PARAMETERS_START(0, 1)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(value)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    sw_atomic_t *atomic = SwooleG.memory_pool->alloc(SwooleG.memory_pool, sizeof(sw_atomic_t));
    if (atomic == NULL)
    {
        zend_throw_exception(swoole_exception_ce_ptr, "global memory allocation failure.", SW_ERROR_MALLOC_FAIL);
        RETURN_FALSE;
    }
    *atomic = (sw_atomic_t) value;
    swoole_set_object(getThis(), (void*) atomic);

    RETURN_TRUE;
}

PHP_METHOD(swoole_atomic, add)
{
    zend_long add_value = 1;
    sw_atomic_t *atomic = swoole_get_object(getThis());

    ZEND_PARSE_PARAMETERS_START(0, 1)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(add_value)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    RETURN_LONG(sw_atomic_add_fetch(atomic, (uint32_t) add_value));
}

PHP_METHOD(swoole_atomic, sub)
{
    zend_long sub_value = 1;
    sw_atomic_t *atomic = swoole_get_object(getThis());

    ZEND_PARSE_PARAMETERS_START(0, 1)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(sub_value)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    RETURN_LONG(sw_atomic_sub_fetch(atomic, (uint32_t) sub_value));
}

PHP_METHOD(swoole_atomic, get)
{
    sw_atomic_t *atomic = swoole_get_object(getThis());
    RETURN_LONG(*atomic);
}

PHP_METHOD(swoole_atomic, set)
{
    sw_atomic_t *atomic = swoole_get_object(getThis());
    zend_long set_value;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_LONG(set_value)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    *atomic = (uint32_t) set_value;
}

PHP_METHOD(swoole_atomic, cmpset)
{
    zend_long cmp_value, set_value;
    sw_atomic_t *atomic = swoole_get_object(getThis());

    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_LONG(cmp_value)
        Z_PARAM_LONG(set_value)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    RETURN_BOOL(sw_atomic_cmp_set(atomic, (sw_atomic_t) cmp_value, (sw_atomic_t) set_value));
}

PHP_METHOD(swoole_atomic, wait)
{
    double timeout = 1.0;
    sw_atomic_t *atomic = swoole_get_object(getThis());

    ZEND_PARSE_PARAMETERS_START(0, 1)
        Z_PARAM_OPTIONAL
        Z_PARAM_DOUBLE(timeout)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

#ifdef HAVE_FUTEX
    SW_CHECK_RETURN(swoole_futex_wait(atomic, timeout));
#else
    timeout = timeout <= 0 ? INT_MAX : timeout;
    int32_t i = (int32_t) sw_atomic_add_fetch(atomic, 1);
    while (timeout > 0)
    {
        if ((int32_t) *atomic < i)
        {
            RETURN_TRUE;
        }
        else
        {
            usleep(1000);
            timeout -= 0.001;
        }
    }
    RETURN_FALSE;
#endif
}

PHP_METHOD(swoole_atomic, wakeup)
{
    zend_long n = 1;
    sw_atomic_t *atomic = swoole_get_object(getThis());

    ZEND_PARSE_PARAMETERS_START(0, 1)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(n)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

#ifdef HAVE_FUTEX
    SW_CHECK_RETURN(swoole_futex_wakeup(atomic, (int ) n));
#else
    sw_atomic_fetch_sub(atomic, n);
    RETURN_TRUE;
#endif
}

static sw_atomic_t *get_atomic_from_mmap(INTERNAL_FUNCTION_PARAMETERS, zend_long *value)
{
    zval *zmmap;
    zend_long offset = 0;

    ZEND_PARSE_PARAMETERS_START(2, 3)
        Z_PARAM_ZVAL(zmmap)
        Z_PARAM_LONG(*value)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(offset)
    ZEND_PARSE_PARAMETERS_END_EX({return NULL;});

    return php_swoole_mmap_get_memory(zmmap, (size_t) offset, sizeof(sw_atomic_t));
}

PHP_METHOD(swoole_atomic, fetchAdd)
{
    zend_long value;
    sw_atomic_t *atomic = get_atomic_from_mmap(INTERNAL_FUNCTION_PARAM_PASSTHRU, &value);

    if (atomic == NULL)
    {
        RETURN_FALSE;
    }

    RETURN_LONG(sw_atomic_fetch_add(atomic, (sw_atomic_t) value));
}

PHP_METHOD(swoole_atomic, fetchSub)
{
    zend_long value;
    sw_atomic_t *atomic = get_atomic_from_mmap(INTERNAL_FUNCTION_PARAM_PASSTHRU, &value);

    if (atomic == NULL)
    {
        RETURN_FALSE;
    }

    RETURN_LONG(sw_atomic_fetch_sub(atomic, (sw_atomic_t) value));
}

PHP_METHOD(swoole_atomic, fetchOr)
{
    zend_long value;
    sw_atomic_t *atomic = get_atomic_from_mmap(INTERNAL_FUNCTION_PARAM_PASSTHRU, &value);

    if (atomic == NULL)
    {
        RETURN_FALSE;
    }

    RETURN_LONG(sw_atomic_fetch_or(atomic, (sw_atomic_t) value));
}

PHP_METHOD(swoole_atomic, fetchXor)
{
    zend_long value;
    sw_atomic_t *atomic = get_atomic_from_mmap(INTERNAL_FUNCTION_PARAM_PASSTHRU, &value);

    if (atomic == NULL)
    {
        RETURN_FALSE;
    }

    RETURN_LONG(sw_atomic_fetch_xor(atomic, (sw_atomic_t) value));
}

PHP_METHOD(swoole_atomic, fetchAnd)
{
    zend_long value;
    sw_atomic_t *atomic = get_atomic_from_mmap(INTERNAL_FUNCTION_PARAM_PASSTHRU, &value);

    if (atomic == NULL)
    {
        RETURN_FALSE;
    }

    RETURN_LONG(sw_atomic_fetch_and(atomic, (sw_atomic_t) value));
}

PHP_METHOD(swoole_atomic, fetchNand)
{
    zend_long value;
    sw_atomic_t *atomic = get_atomic_from_mmap(INTERNAL_FUNCTION_PARAM_PASSTHRU, &value);

    if (atomic == NULL)
    {
        RETURN_FALSE;
    }

    RETURN_LONG(sw_atomic_fetch_nand(atomic, (sw_atomic_t) value));
}

PHP_METHOD(swoole_atomic, addFetch)
{
    zend_long value;
    sw_atomic_t *atomic = get_atomic_from_mmap(INTERNAL_FUNCTION_PARAM_PASSTHRU, &value);

    if (atomic == NULL)
    {
        RETURN_FALSE;
    }

    RETURN_LONG(sw_atomic_add_fetch(atomic, (sw_atomic_t) value));
}

PHP_METHOD(swoole_atomic, subFetch)
{
    zend_long value;
    sw_atomic_t *atomic = get_atomic_from_mmap(INTERNAL_FUNCTION_PARAM_PASSTHRU, &value);

    if (atomic == NULL)
    {
        RETURN_FALSE;
    }

    RETURN_LONG(sw_atomic_sub_fetch(atomic, (sw_atomic_t) value));
}

PHP_METHOD(swoole_atomic, orFetch)
{
    zend_long value;
    sw_atomic_t *atomic = get_atomic_from_mmap(INTERNAL_FUNCTION_PARAM_PASSTHRU, &value);

    if (atomic == NULL)
    {
        RETURN_FALSE;
    }

    RETURN_LONG(sw_atomic_or_fetch(atomic, (sw_atomic_t) value));
}

PHP_METHOD(swoole_atomic, xorFetch)
{
    zend_long value;
    sw_atomic_t *atomic = get_atomic_from_mmap(INTERNAL_FUNCTION_PARAM_PASSTHRU, &value);

    if (atomic == NULL)
    {
        RETURN_FALSE;
    }

    RETURN_LONG(sw_atomic_xor_fetch(atomic, (sw_atomic_t) value));
}

PHP_METHOD(swoole_atomic, andFetch)
{
    zend_long value;
    sw_atomic_t *atomic = get_atomic_from_mmap(INTERNAL_FUNCTION_PARAM_PASSTHRU, &value);

    if (atomic == NULL)
    {
        RETURN_FALSE;
    }

    RETURN_LONG(sw_atomic_and_fetch(atomic, (sw_atomic_t) value));
}

PHP_METHOD(swoole_atomic, nandFetch)
{
    zend_long value;
    sw_atomic_t *atomic = get_atomic_from_mmap(INTERNAL_FUNCTION_PARAM_PASSTHRU, &value);

    if (atomic == NULL)
    {
        RETURN_FALSE;
    }

    RETURN_LONG(sw_atomic_nand_fetch(atomic, (sw_atomic_t) value));
}

PHP_METHOD(swoole_atomic, getValue)
{
    zval *zmmap;
    zend_long offset = 0;

    ZEND_PARSE_PARAMETERS_START(1, 2)
        Z_PARAM_ZVAL(zmmap)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(offset)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    sw_atomic_t *atomic = php_swoole_mmap_get_memory(zmmap, (size_t) offset, sizeof(sw_atomic_t));
    if (atomic == NULL)
    {
        RETURN_FALSE;
    }

    RETURN_LONG(*atomic);
}

PHP_METHOD(swoole_atomic, setValue)
{
    zend_long value;
    sw_atomic_t *atomic = get_atomic_from_mmap(INTERNAL_FUNCTION_PARAM_PASSTHRU, &value);

    if (atomic == NULL)
    {
        RETURN_FALSE;
    }

    *atomic = (sw_atomic_t) value;
    RETURN_TRUE;
}

PHP_METHOD(swoole_atomic, cmpAndSet)
{
    zval *zmmap;
    zend_long offset = 0;
    zend_long cmp_value;
    zend_long set_value;

    ZEND_PARSE_PARAMETERS_START(3, 4)
        Z_PARAM_ZVAL(zmmap)
        Z_PARAM_LONG(cmp_value)
        Z_PARAM_LONG(set_value)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(offset)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_NULL());

    sw_atomic_t *atomic = php_swoole_mmap_get_memory(zmmap, (size_t) offset, sizeof(sw_atomic_t));
    if (atomic == NULL)
    {
        RETURN_NULL();
    }

    RETURN_BOOL(sw_atomic_cmp_set(atomic, (sw_atomic_t) cmp_value, (sw_atomic_t) set_value));
}

PHP_METHOD(swoole_atomic_long, __construct)
{
    zend_long value = 0;

    ZEND_PARSE_PARAMETERS_START(0, 1)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(value)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    sw_atomic_long_t *atomic = SwooleG.memory_pool->alloc(SwooleG.memory_pool, sizeof(sw_atomic_long_t));
    if (atomic == NULL)
    {
        zend_throw_exception(swoole_exception_ce_ptr, "global memory allocation failure.", SW_ERROR_MALLOC_FAIL);
        RETURN_FALSE;
    }
    *atomic = (sw_atomic_long_t) value;
    swoole_set_object(getThis(), (void*) atomic);

    RETURN_TRUE;
}

PHP_METHOD(swoole_atomic_long, add)
{
    zend_long add_value = 1;
    sw_atomic_long_t *atomic = swoole_get_object(getThis());

    ZEND_PARSE_PARAMETERS_START(0, 1)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(add_value)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    RETURN_LONG(sw_atomic_add_fetch(atomic, (sw_atomic_long_t) add_value));
}

PHP_METHOD(swoole_atomic_long, sub)
{
    zend_long sub_value = 1;
    sw_atomic_long_t *atomic = swoole_get_object(getThis());

    ZEND_PARSE_PARAMETERS_START(0, 1)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(sub_value)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    RETURN_LONG(sw_atomic_sub_fetch(atomic, (sw_atomic_long_t) sub_value));
}

PHP_METHOD(swoole_atomic_long, get)
{
    sw_atomic_long_t *atomic = swoole_get_object(getThis());
    RETURN_LONG(*atomic);
}

PHP_METHOD(swoole_atomic_long, set)
{
    sw_atomic_long_t *atomic = swoole_get_object(getThis());
    zend_long set_value;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_LONG(set_value)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    *atomic = (sw_atomic_long_t) set_value;
}

PHP_METHOD(swoole_atomic_long, cmpset)
{
    zend_long cmp_value, set_value;
    sw_atomic_long_t *atomic = swoole_get_object(getThis());

    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_LONG(cmp_value)
        Z_PARAM_LONG(set_value)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    RETURN_BOOL(sw_atomic_cmp_set(atomic, (sw_atomic_long_t) cmp_value, (sw_atomic_long_t) set_value));
}
