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
  | Author: Tianfeng Han  <rango@swoole.com>                             |
  +----------------------------------------------------------------------+
*/

#include "php_swoole_private.h"
#include "swoole_memory.h"

#ifdef HAVE_FUTEX
#include <linux/futex.h>
#include <syscall.h>

static sw_inline int swoole_futex_wait(sw_atomic_t *atomic, double timeout) {
    if (sw_atomic_cmp_set(atomic, 1, 0)) {
        return SW_OK;
    }

    int ret;
    struct timespec _timeout;

    if (timeout > 0) {
        _timeout.tv_sec = (long) timeout;
        _timeout.tv_nsec = (timeout - _timeout.tv_sec) * 1000 * 1000 * 1000;
        ret = syscall(SYS_futex, atomic, FUTEX_WAIT, 0, &_timeout, nullptr, 0);
    } else {
        ret = syscall(SYS_futex, atomic, FUTEX_WAIT, 0, nullptr, nullptr, 0);
    }
    if (ret == SW_OK && sw_atomic_cmp_set(atomic, 1, 0)) {
        return SW_OK;
    } else {
        return SW_ERR;
    }
}

static sw_inline int swoole_futex_wakeup(sw_atomic_t *atomic, int n) {
    if (sw_atomic_cmp_set(atomic, 0, 1)) {
        return syscall(SYS_futex, atomic, FUTEX_WAKE, n, nullptr, nullptr, 0);
    } else {
        return SW_OK;
    }
}

#else
static sw_inline int swoole_atomic_wait(sw_atomic_t *atomic, double timeout) {
    if (sw_atomic_cmp_set(atomic, (sw_atomic_t) 1, (sw_atomic_t) 0)) {
        return SW_OK;
    }
    timeout = timeout <= 0 ? INT_MAX : timeout;
    int32_t i = (int32_t) sw_atomic_sub_fetch(atomic, 1);
    while (timeout > 0) {
        if ((int32_t) *atomic > i) {
            return SW_OK;
        } else {
            usleep(1000);
            timeout -= 0.001;
        }
    }
    sw_atomic_fetch_add(atomic, 1);
    return SW_ERR;
}

static sw_inline int swoole_atomic_wakeup(sw_atomic_t *atomic, int n) {
    if (1 == (int32_t) *atomic) {
        return SW_OK;
    }
    sw_atomic_fetch_add(atomic, n);
    return SW_OK;
}
#endif

zend_class_entry *swoole_atomic_ce;
static zend_object_handlers swoole_atomic_handlers;

zend_class_entry *swoole_atomic_long_ce;
static zend_object_handlers swoole_atomic_long_handlers;

struct AtomicObject {
    sw_atomic_t *ptr;
    zend_object std;
};

static sw_inline AtomicObject *php_swoole_atomic_fetch_object(zend_object *obj) {
    return (AtomicObject *) ((char *) obj - swoole_atomic_handlers.offset);
}

static sw_atomic_t *php_swoole_atomic_get_ptr(zval *zobject) {
    return php_swoole_atomic_fetch_object(Z_OBJ_P(zobject))->ptr;
}

void php_swoole_atomic_set_ptr(zval *zobject, sw_atomic_t *ptr) {
    php_swoole_atomic_fetch_object(Z_OBJ_P(zobject))->ptr = ptr;
}

static void php_swoole_atomic_free_object(zend_object *object) {
    sw_mem_pool()->free((void *) php_swoole_atomic_fetch_object(object)->ptr);
    zend_object_std_dtor(object);
}

static zend_object *php_swoole_atomic_create_object(zend_class_entry *ce) {
    AtomicObject *atomic = (AtomicObject *) zend_object_alloc(sizeof(AtomicObject), ce);
    if (atomic == nullptr) {
        zend_throw_exception(swoole_exception_ce, "global memory allocation failure", SW_ERROR_MALLOC_FAIL);
    }

    zend_object_std_init(&atomic->std, ce);
    object_properties_init(&atomic->std, ce);
    atomic->std.handlers = &swoole_atomic_handlers;
    atomic->ptr = (sw_atomic_t *) sw_mem_pool()->alloc(sizeof(sw_atomic_t));
    if (atomic->ptr == nullptr) {
        zend_throw_exception(swoole_exception_ce, "global memory allocation failure", SW_ERROR_MALLOC_FAIL);
    }

    return &atomic->std;
}

struct AtomicLongObject {
    sw_atomic_long_t *ptr;
    zend_object std;
};

static sw_inline AtomicLongObject *php_swoole_atomic_long_fetch_object(zend_object *obj) {
    return (AtomicLongObject *) ((char *) obj - swoole_atomic_long_handlers.offset);
}

static sw_atomic_long_t *php_swoole_atomic_long_get_ptr(zval *zobject) {
    return php_swoole_atomic_long_fetch_object(Z_OBJ_P(zobject))->ptr;
}

void php_swoole_atomic_long_set_ptr(zval *zobject, sw_atomic_long_t *ptr) {
    php_swoole_atomic_long_fetch_object(Z_OBJ_P(zobject))->ptr = ptr;
}

static void php_swoole_atomic_long_free_object(zend_object *object) {
    sw_mem_pool()->free((void *) php_swoole_atomic_long_fetch_object(object)->ptr);
    zend_object_std_dtor(object);
}

static zend_object *php_swoole_atomic_long_create_object(zend_class_entry *ce) {
    AtomicLongObject *atomic_long = (AtomicLongObject *) zend_object_alloc(sizeof(AtomicLongObject), ce);
    if (atomic_long == nullptr) {
        zend_throw_exception(swoole_exception_ce, "global memory allocation failure", SW_ERROR_MALLOC_FAIL);
    }

    zend_object_std_init(&atomic_long->std, ce);
    object_properties_init(&atomic_long->std, ce);
    atomic_long->std.handlers = &swoole_atomic_long_handlers;

    atomic_long->ptr = (sw_atomic_long_t *) sw_mem_pool()->alloc(sizeof(sw_atomic_long_t));
    if (atomic_long->ptr == nullptr) {
        zend_throw_exception(swoole_exception_ce, "global memory allocation failure", SW_ERROR_MALLOC_FAIL);
    }

    return &atomic_long->std;
}

SW_EXTERN_C_BEGIN
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
SW_EXTERN_C_END

// clang-format off

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

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_atomic_wakeup, 0, 0, 0)
    ZEND_ARG_INFO(0, count)
ZEND_END_ARG_INFO()

static const zend_function_entry swoole_atomic_methods[] =
{
    PHP_ME(swoole_atomic, __construct, arginfo_swoole_atomic_construct, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_atomic, add, arginfo_swoole_atomic_add, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_atomic, sub, arginfo_swoole_atomic_sub, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_atomic, get, arginfo_swoole_atomic_get, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_atomic, set, arginfo_swoole_atomic_set, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_atomic, wait, arginfo_swoole_atomic_wait, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_atomic, wakeup, arginfo_swoole_atomic_wakeup, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_atomic, cmpset, arginfo_swoole_atomic_cmpset, ZEND_ACC_PUBLIC)
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

// clang-format on

void php_swoole_atomic_minit(int module_number) {
    SW_INIT_CLASS_ENTRY(swoole_atomic, "Swoole\\Atomic", "swoole_atomic", nullptr, swoole_atomic_methods);
    SW_SET_CLASS_NOT_SERIALIZABLE(swoole_atomic);
    SW_SET_CLASS_CLONEABLE(swoole_atomic, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_atomic, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CUSTOM_OBJECT(
        swoole_atomic, php_swoole_atomic_create_object, php_swoole_atomic_free_object, AtomicObject, std);

    SW_INIT_CLASS_ENTRY(
        swoole_atomic_long, "Swoole\\Atomic\\Long", "swoole_atomic_long", nullptr, swoole_atomic_long_methods);
    SW_SET_CLASS_NOT_SERIALIZABLE(swoole_atomic_long);
    SW_SET_CLASS_CLONEABLE(swoole_atomic_long, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_atomic_long, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CUSTOM_OBJECT(swoole_atomic_long,
                               php_swoole_atomic_long_create_object,
                               php_swoole_atomic_long_free_object,
                               AtomicLongObject,
                               std);
}

PHP_METHOD(swoole_atomic, __construct) {
    sw_atomic_t *atomic = php_swoole_atomic_get_ptr(ZEND_THIS);
    zend_long value = 0;

    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 0, 1)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(value)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    *atomic = (sw_atomic_t) value;
}

PHP_METHOD(swoole_atomic, add) {
    sw_atomic_t *atomic = php_swoole_atomic_get_ptr(ZEND_THIS);
    zend_long add_value = 1;

    ZEND_PARSE_PARAMETERS_START(0, 1)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(add_value)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    RETURN_LONG(sw_atomic_add_fetch(atomic, (uint32_t) add_value));
}

PHP_METHOD(swoole_atomic, sub) {
    sw_atomic_t *atomic = php_swoole_atomic_get_ptr(ZEND_THIS);
    zend_long sub_value = 1;

    ZEND_PARSE_PARAMETERS_START(0, 1)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(sub_value)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    RETURN_LONG(sw_atomic_sub_fetch(atomic, (uint32_t) sub_value));
}

PHP_METHOD(swoole_atomic, get) {
    sw_atomic_t *atomic = php_swoole_atomic_get_ptr(ZEND_THIS);
    RETURN_LONG(*atomic);
}

PHP_METHOD(swoole_atomic, set) {
    sw_atomic_t *atomic = php_swoole_atomic_get_ptr(ZEND_THIS);
    zend_long set_value;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_LONG(set_value)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    *atomic = (uint32_t) set_value;
}

PHP_METHOD(swoole_atomic, cmpset) {
    sw_atomic_t *atomic = php_swoole_atomic_get_ptr(ZEND_THIS);
    zend_long cmp_value, set_value;

    ZEND_PARSE_PARAMETERS_START(2, 2)
    Z_PARAM_LONG(cmp_value)
    Z_PARAM_LONG(set_value)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    RETURN_BOOL(sw_atomic_cmp_set(atomic, (sw_atomic_t) cmp_value, (sw_atomic_t) set_value));
}

PHP_METHOD(swoole_atomic, wait) {
    sw_atomic_t *atomic = php_swoole_atomic_get_ptr(ZEND_THIS);
    double timeout = 1.0;

    ZEND_PARSE_PARAMETERS_START(0, 1)
    Z_PARAM_OPTIONAL
    Z_PARAM_DOUBLE(timeout)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

#ifdef HAVE_FUTEX
    SW_CHECK_RETURN(swoole_futex_wait(atomic, timeout));
#else
    SW_CHECK_RETURN(swoole_atomic_wait(atomic, timeout));
#endif
}

PHP_METHOD(swoole_atomic, wakeup) {
    sw_atomic_t *atomic = php_swoole_atomic_get_ptr(ZEND_THIS);
    zend_long n = 1;

    ZEND_PARSE_PARAMETERS_START(0, 1)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(n)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

#ifdef HAVE_FUTEX
    SW_CHECK_RETURN(swoole_futex_wakeup(atomic, (int) n));
#else
    SW_CHECK_RETURN(swoole_atomic_wakeup(atomic, n));
#endif
}

PHP_METHOD(swoole_atomic_long, __construct) {
    sw_atomic_long_t *atomic_long = php_swoole_atomic_long_get_ptr(ZEND_THIS);
    zend_long value = 0;

    ZEND_PARSE_PARAMETERS_START(0, 1)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(value)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    *atomic_long = (sw_atomic_long_t) value;
    RETURN_TRUE;
}

PHP_METHOD(swoole_atomic_long, add) {
    sw_atomic_long_t *atomic_long = php_swoole_atomic_long_get_ptr(ZEND_THIS);
    zend_long add_value = 1;

    ZEND_PARSE_PARAMETERS_START(0, 1)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(add_value)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    RETURN_LONG(sw_atomic_add_fetch(atomic_long, (sw_atomic_long_t) add_value));
}

PHP_METHOD(swoole_atomic_long, sub) {
    sw_atomic_long_t *atomic_long = php_swoole_atomic_long_get_ptr(ZEND_THIS);
    zend_long sub_value = 1;

    ZEND_PARSE_PARAMETERS_START(0, 1)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(sub_value)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    RETURN_LONG(sw_atomic_sub_fetch(atomic_long, (sw_atomic_long_t) sub_value));
}

PHP_METHOD(swoole_atomic_long, get) {
    sw_atomic_long_t *atomic_long = php_swoole_atomic_long_get_ptr(ZEND_THIS);
    RETURN_LONG(*atomic_long);
}

PHP_METHOD(swoole_atomic_long, set) {
    sw_atomic_long_t *atomic_long = php_swoole_atomic_long_get_ptr(ZEND_THIS);
    zend_long set_value;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_LONG(set_value)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    *atomic_long = (sw_atomic_long_t) set_value;
}

PHP_METHOD(swoole_atomic_long, cmpset) {
    sw_atomic_long_t *atomic_long = php_swoole_atomic_long_get_ptr(ZEND_THIS);
    zend_long cmp_value, set_value;

    ZEND_PARSE_PARAMETERS_START(2, 2)
    Z_PARAM_LONG(cmp_value)
    Z_PARAM_LONG(set_value)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    RETURN_BOOL(sw_atomic_cmp_set(atomic_long, (sw_atomic_long_t) cmp_value, (sw_atomic_long_t) set_value));
}
