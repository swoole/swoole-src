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

#include "php_swoole_cxx.h"
#include "php_swoole_thread.h"
#include "swoole_memory.h"

#ifdef SW_THREAD

BEGIN_EXTERN_C()
#include "stubs/php_swoole_thread_atomic_arginfo.h"
END_EXTERN_C()

zend_class_entry *swoole_thread_atomic_ce;
static zend_object_handlers swoole_thread_atomic_handlers;

zend_class_entry *swoole_thread_atomic_long_ce;
static zend_object_handlers swoole_thread_atomic_long_handlers;

struct AtomicResource : public ThreadResource {
    sw_atomic_t value;

    AtomicResource(zend_long _value) : ThreadResource() {
        value = _value;
    }

    ~AtomicResource() override { }
};

struct AtomicObject {
    AtomicResource *atomic;
    zend_object std;
};

static sw_inline AtomicObject *atomic_fetch_object(zend_object *obj) {
    return (AtomicObject *) ((char *) obj - swoole_thread_atomic_handlers.offset);
}

static sw_atomic_t *atomic_get_ptr(zval *zobject) {
    return &atomic_fetch_object(Z_OBJ_P(zobject))->atomic->value;
}

static void atomic_free_object(zend_object *object) {
    AtomicObject *o = atomic_fetch_object(object);
    if (o->atomic) {
        o->atomic->del_ref();
        o->atomic = nullptr;
    }
    zend_object_std_dtor(object);
}

static zend_object *atomic_create_object(zend_class_entry *ce) {
    AtomicObject *atomic = (AtomicObject *) zend_object_alloc(sizeof(AtomicObject), ce);
    zend_object_std_init(&atomic->std, ce);
    object_properties_init(&atomic->std, ce);
    atomic->std.handlers = &swoole_thread_atomic_handlers;

    return &atomic->std;
}

struct AtomicLongResource : public ThreadResource {
    sw_atomic_long_t value;

    AtomicLongResource(zend_long _value) : ThreadResource() {
        value = _value;
    }

    ~AtomicLongResource() override { }
};

struct AtomicLongObject {
    AtomicLongResource *atomic;
    zend_object std;
};

static sw_inline AtomicLongObject *atomic_long_fetch_object(zend_object *obj) {
    return (AtomicLongObject *) ((char *) obj - swoole_thread_atomic_long_handlers.offset);
}

static sw_atomic_long_t *atomic_long_get_ptr(zval *zobject) {
    return &atomic_long_fetch_object(Z_OBJ_P(zobject))->atomic->value;
}

static void atomic_long_free_object(zend_object *object) {
    AtomicLongObject *o = atomic_long_fetch_object(object);
    if (o->atomic) {
        o->atomic->del_ref();
        o->atomic = nullptr;
    }
    zend_object_std_dtor(object);
}

static zend_object *atomic_long_create_object(zend_class_entry *ce) {
    AtomicLongObject *atomic_long = (AtomicLongObject *) zend_object_alloc(sizeof(AtomicLongObject), ce);
    zend_object_std_init(&atomic_long->std, ce);
    object_properties_init(&atomic_long->std, ce);
    atomic_long->std.handlers = &swoole_thread_atomic_long_handlers;
    return &atomic_long->std;
}

ThreadResource *php_swoole_thread_atomic_cast(zval *zobject) {
    return atomic_fetch_object(Z_OBJ_P(zobject))->atomic;
}

ThreadResource *php_swoole_thread_atomic_long_cast(zval *zobject) {
    return atomic_long_fetch_object(Z_OBJ_P(zobject))->atomic;
}

void php_swoole_thread_atomic_create(zval *return_value, ThreadResource *resource) {
    auto obj = atomic_create_object(swoole_thread_atomic_ce);
    auto ao = (AtomicObject *) atomic_fetch_object(obj);
    ao->atomic = static_cast<AtomicResource *>(resource);
    ZVAL_OBJ(return_value, obj);
}

void php_swoole_thread_atomic_long_create(zval *return_value, ThreadResource *resource) {
    auto obj = atomic_long_create_object(swoole_thread_atomic_long_ce);
    auto ao = (AtomicLongObject *) atomic_long_fetch_object(obj);
    ao->atomic = static_cast<AtomicLongResource *>(resource);
    ZVAL_OBJ(return_value, obj);
}

SW_EXTERN_C_BEGIN
static PHP_METHOD(swoole_thread_atomic, __construct);
static PHP_METHOD(swoole_thread_atomic, add);
static PHP_METHOD(swoole_thread_atomic, sub);
static PHP_METHOD(swoole_thread_atomic, get);
static PHP_METHOD(swoole_thread_atomic, set);
static PHP_METHOD(swoole_thread_atomic, cmpset);
static PHP_METHOD(swoole_thread_atomic, wait);
static PHP_METHOD(swoole_thread_atomic, wakeup);

static PHP_METHOD(swoole_thread_atomic_long, __construct);
static PHP_METHOD(swoole_thread_atomic_long, add);
static PHP_METHOD(swoole_thread_atomic_long, sub);
static PHP_METHOD(swoole_thread_atomic_long, get);
static PHP_METHOD(swoole_thread_atomic_long, set);
static PHP_METHOD(swoole_thread_atomic_long, cmpset);
SW_EXTERN_C_END

// clang-format off
static const zend_function_entry swoole_thread_atomic_methods[] =
{
    PHP_ME(swoole_thread_atomic, __construct, arginfo_class_Swoole_Thread_Atomic___construct, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_atomic, add,         arginfo_class_Swoole_Thread_Atomic_add,         ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_atomic, sub,         arginfo_class_Swoole_Thread_Atomic_sub,         ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_atomic, get,         arginfo_class_Swoole_Thread_Atomic_get,         ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_atomic, set,         arginfo_class_Swoole_Thread_Atomic_set,         ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_atomic, wait,        arginfo_class_Swoole_Thread_Atomic_wait,        ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_atomic, wakeup,      arginfo_class_Swoole_Thread_Atomic_wakeup,      ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_atomic, cmpset,      arginfo_class_Swoole_Thread_Atomic_cmpset,      ZEND_ACC_PUBLIC)
    PHP_FE_END
};

static const zend_function_entry swoole_thread_atomic_long_methods[] =
{
    PHP_ME(swoole_thread_atomic_long, __construct, arginfo_class_Swoole_Thread_Atomic_Long___construct, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_atomic_long, add,         arginfo_class_Swoole_Thread_Atomic_Long_add,         ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_atomic_long, sub,         arginfo_class_Swoole_Thread_Atomic_Long_sub,         ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_atomic_long, get,         arginfo_class_Swoole_Thread_Atomic_Long_get,         ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_atomic_long, set,         arginfo_class_Swoole_Thread_Atomic_Long_set,         ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_atomic_long, cmpset,      arginfo_class_Swoole_Thread_Atomic_Long_cmpset,      ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

void php_swoole_thread_atomic_minit(int module_number) {
    SW_INIT_CLASS_ENTRY(swoole_thread_atomic, "Swoole\\Thread\\Atomic", nullptr, swoole_thread_atomic_methods);
    swoole_thread_atomic_ce->ce_flags |= ZEND_ACC_FINAL | ZEND_ACC_NOT_SERIALIZABLE;
    SW_SET_CLASS_CLONEABLE(swoole_thread_atomic, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_thread_atomic, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CUSTOM_OBJECT(swoole_thread_atomic,
                               atomic_create_object,
                               atomic_free_object,
                               AtomicObject,
                               std);

    SW_INIT_CLASS_ENTRY(
        swoole_thread_atomic_long, "Swoole\\Thread\\Atomic\\Long", nullptr, swoole_thread_atomic_long_methods);
    swoole_thread_atomic_long_ce->ce_flags |= ZEND_ACC_FINAL | ZEND_ACC_NOT_SERIALIZABLE;
    SW_SET_CLASS_CLONEABLE(swoole_thread_atomic_long, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_thread_atomic_long, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CUSTOM_OBJECT(swoole_thread_atomic_long,
                               atomic_long_create_object,
                               atomic_long_free_object,
                               AtomicLongObject,
                               std);
}

PHP_METHOD(swoole_thread_atomic, __construct) {
    auto o = atomic_fetch_object(Z_OBJ_P(ZEND_THIS));
    zend_long value = 0;

    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 0, 1)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(value)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (o->atomic) {
        zend_throw_error(NULL, "Constructor of %s can only be called once", SW_Z_OBJCE_NAME_VAL_P(ZEND_THIS));
        return;
    }
    o->atomic = new AtomicResource(value);
}

PHP_METHOD(swoole_thread_atomic, add) {
    sw_atomic_t *atomic = atomic_get_ptr(ZEND_THIS);
    zend_long add_value = 1;

    ZEND_PARSE_PARAMETERS_START(0, 1)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(add_value)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    RETURN_LONG(sw_atomic_add_fetch(atomic, (uint32_t) add_value));
}

PHP_METHOD(swoole_thread_atomic, sub) {
    sw_atomic_t *atomic = atomic_get_ptr(ZEND_THIS);
    zend_long sub_value = 1;

    ZEND_PARSE_PARAMETERS_START(0, 1)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(sub_value)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    RETURN_LONG(sw_atomic_sub_fetch(atomic, (uint32_t) sub_value));
}

PHP_METHOD(swoole_thread_atomic, get) {
    sw_atomic_t *atomic = atomic_get_ptr(ZEND_THIS);
    RETURN_LONG(*atomic);
}

PHP_METHOD(swoole_thread_atomic, set) {
    sw_atomic_t *atomic = atomic_get_ptr(ZEND_THIS);
    zend_long set_value;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_LONG(set_value)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    *atomic = (uint32_t) set_value;
}

PHP_METHOD(swoole_thread_atomic, cmpset) {
    sw_atomic_t *atomic = atomic_get_ptr(ZEND_THIS);
    zend_long cmp_value, set_value;

    ZEND_PARSE_PARAMETERS_START(2, 2)
    Z_PARAM_LONG(cmp_value)
    Z_PARAM_LONG(set_value)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    RETURN_BOOL(sw_atomic_cmp_set(atomic, (sw_atomic_t) cmp_value, (sw_atomic_t) set_value));
}

PHP_METHOD(swoole_thread_atomic, wait) {
    sw_atomic_t *atomic = atomic_get_ptr(ZEND_THIS);
    double timeout = 1.0;

    ZEND_PARSE_PARAMETERS_START(0, 1)
    Z_PARAM_OPTIONAL
    Z_PARAM_DOUBLE(timeout)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    SW_CHECK_RETURN(sw_atomic_futex_wait(atomic, timeout));
}

PHP_METHOD(swoole_thread_atomic, wakeup) {
    sw_atomic_t *atomic = atomic_get_ptr(ZEND_THIS);
    zend_long n = 1;

    ZEND_PARSE_PARAMETERS_START(0, 1)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(n)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    SW_CHECK_RETURN(sw_atomic_futex_wakeup(atomic, (int) n));
}

PHP_METHOD(swoole_thread_atomic_long, __construct) {
    auto o = atomic_long_fetch_object(Z_OBJ_P(ZEND_THIS));
    zend_long value = 0;

    ZEND_PARSE_PARAMETERS_START(0, 1)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(value)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (o->atomic) {
        zend_throw_error(NULL, "Constructor of %s can only be called once", SW_Z_OBJCE_NAME_VAL_P(ZEND_THIS));
        RETURN_FALSE;
    }
    o->atomic = new AtomicLongResource(value);
}

PHP_METHOD(swoole_thread_atomic_long, add) {
    sw_atomic_long_t *atomic_long = atomic_long_get_ptr(ZEND_THIS);
    zend_long add_value = 1;

    ZEND_PARSE_PARAMETERS_START(0, 1)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(add_value)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    RETURN_LONG(sw_atomic_add_fetch(atomic_long, (sw_atomic_long_t) add_value));
}

PHP_METHOD(swoole_thread_atomic_long, sub) {
    sw_atomic_long_t *atomic_long = atomic_long_get_ptr(ZEND_THIS);
    zend_long sub_value = 1;

    ZEND_PARSE_PARAMETERS_START(0, 1)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(sub_value)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    RETURN_LONG(sw_atomic_sub_fetch(atomic_long, (sw_atomic_long_t) sub_value));
}

PHP_METHOD(swoole_thread_atomic_long, get) {
    sw_atomic_long_t *atomic_long = atomic_long_get_ptr(ZEND_THIS);
    RETURN_LONG(*atomic_long);
}

PHP_METHOD(swoole_thread_atomic_long, set) {
    sw_atomic_long_t *atomic_long = atomic_long_get_ptr(ZEND_THIS);
    zend_long set_value;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_LONG(set_value)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    *atomic_long = (sw_atomic_long_t) set_value;
}

PHP_METHOD(swoole_thread_atomic_long, cmpset) {
    sw_atomic_long_t *atomic_long = atomic_long_get_ptr(ZEND_THIS);
    zend_long cmp_value, set_value;

    ZEND_PARSE_PARAMETERS_START(2, 2)
    Z_PARAM_LONG(cmp_value)
    Z_PARAM_LONG(set_value)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    RETURN_BOOL(sw_atomic_cmp_set(atomic_long, (sw_atomic_long_t) cmp_value, (sw_atomic_long_t) set_value));
}

#endif
