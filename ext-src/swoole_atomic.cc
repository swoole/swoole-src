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

BEGIN_EXTERN_C()
#include "stubs/php_swoole_atomic_arginfo.h"
END_EXTERN_C()

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

#ifdef SW_THREAD
struct AtomicResource: public ThreadResource {
    sw_atomic_t *ptr_;
    AtomicResource(): ThreadResource() {
        ptr_ = new sw_atomic_t;
    }
    ~AtomicResource() {
        delete ptr_;
    }
};
#endif

struct AtomicObject {
    sw_atomic_t *ptr;
#ifdef SW_THREAD
    AtomicResource *res;
#endif
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
#ifdef SW_THREAD
    AtomicObject *o = php_swoole_atomic_fetch_object(object);
    zend_long resource_id = zend::object_get_long(object, ZEND_STRL("id"));
    if (o->res && php_swoole_thread_resource_free(resource_id, o->res)) {
        delete o->res;
        o->res = nullptr;
        o->ptr = nullptr;
    }
#else
    sw_mem_pool()->free((void *) php_swoole_atomic_fetch_object(object)->ptr);
#endif
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

#ifndef SW_THREAD
    atomic->ptr = (sw_atomic_t *) sw_mem_pool()->alloc(sizeof(sw_atomic_t));
    if (atomic->ptr == nullptr) {
        zend_throw_exception(swoole_exception_ce, "global memory allocation failure", SW_ERROR_MALLOC_FAIL);
    }
#endif

    return &atomic->std;
}

#ifdef SW_THREAD
struct AtomicLongResource: public ThreadResource {
    sw_atomic_long_t *ptr_;
    AtomicLongResource(): ThreadResource() {
        ptr_ = new sw_atomic_long_t;
    }
    ~AtomicLongResource() {
        delete ptr_;
    }
};
#endif

struct AtomicLongObject {
    sw_atomic_long_t *ptr;
#ifdef SW_THREAD
    AtomicLongResource *res;
#endif
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
#ifdef SW_THREAD
    AtomicLongObject *o = php_swoole_atomic_long_fetch_object(object);
    zend_long resource_id = zend::object_get_long(object, ZEND_STRL("id"));
    if (o->res && php_swoole_thread_resource_free(resource_id, o->res)) {
        delete o->res;
        o->res = nullptr;
        o->ptr = nullptr;
    }
#else
    sw_mem_pool()->free((void *) php_swoole_atomic_long_fetch_object(object)->ptr);
#endif

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

#ifndef SW_THREAD
    atomic_long->ptr = (sw_atomic_long_t *) sw_mem_pool()->alloc(sizeof(sw_atomic_long_t));
    if (atomic_long->ptr == nullptr) {
        zend_throw_exception(swoole_exception_ce, "global memory allocation failure", SW_ERROR_MALLOC_FAIL);
    }
#endif

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
#ifdef SW_THREAD
static PHP_METHOD(swoole_atomic, __wakeup);
#endif

static PHP_METHOD(swoole_atomic_long, __construct);
static PHP_METHOD(swoole_atomic_long, add);
static PHP_METHOD(swoole_atomic_long, sub);
static PHP_METHOD(swoole_atomic_long, get);
static PHP_METHOD(swoole_atomic_long, set);
static PHP_METHOD(swoole_atomic_long, cmpset);
#ifdef SW_THREAD
static PHP_METHOD(swoole_atomic_long, __wakeup);
#endif
SW_EXTERN_C_END

// clang-format off

static const zend_function_entry swoole_atomic_methods[] =
{
    PHP_ME(swoole_atomic, __construct, arginfo_class_Swoole_Atomic___construct, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_atomic, add,         arginfo_class_Swoole_Atomic_add,         ZEND_ACC_PUBLIC)
    PHP_ME(swoole_atomic, sub,         arginfo_class_Swoole_Atomic_sub,         ZEND_ACC_PUBLIC)
    PHP_ME(swoole_atomic, get,         arginfo_class_Swoole_Atomic_get,         ZEND_ACC_PUBLIC)
    PHP_ME(swoole_atomic, set,         arginfo_class_Swoole_Atomic_set,         ZEND_ACC_PUBLIC)
    PHP_ME(swoole_atomic, wait,        arginfo_class_Swoole_Atomic_wait,        ZEND_ACC_PUBLIC)
    PHP_ME(swoole_atomic, wakeup,      arginfo_class_Swoole_Atomic_wakeup,      ZEND_ACC_PUBLIC)
    PHP_ME(swoole_atomic, cmpset,      arginfo_class_Swoole_Atomic_cmpset,      ZEND_ACC_PUBLIC)
#ifdef SW_THREAD
    PHP_ME(swoole_atomic, __wakeup,     arginfo_class_Swoole_Atomic___wakeup,      ZEND_ACC_PUBLIC)
#endif
    PHP_FE_END
};

static const zend_function_entry swoole_atomic_long_methods[] =
{
    PHP_ME(swoole_atomic_long, __construct, arginfo_class_Swoole_Atomic_Long___construct, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_atomic_long, add,         arginfo_class_Swoole_Atomic_Long_add,         ZEND_ACC_PUBLIC)
    PHP_ME(swoole_atomic_long, sub,         arginfo_class_Swoole_Atomic_Long_sub,         ZEND_ACC_PUBLIC)
    PHP_ME(swoole_atomic_long, get,         arginfo_class_Swoole_Atomic_Long_get,         ZEND_ACC_PUBLIC)
    PHP_ME(swoole_atomic_long, set,         arginfo_class_Swoole_Atomic_Long_set,         ZEND_ACC_PUBLIC)
    PHP_ME(swoole_atomic_long, cmpset,      arginfo_class_Swoole_Atomic_Long_cmpset,      ZEND_ACC_PUBLIC)
#ifdef SW_THREAD
    PHP_ME(swoole_atomic_long, __wakeup,    arginfo_class_Swoole_Atomic_Long___wakeup,    ZEND_ACC_PUBLIC)
#endif
    PHP_FE_END
};

// clang-format on

void php_swoole_atomic_minit(int module_number) {
    SW_INIT_CLASS_ENTRY(swoole_atomic, "Swoole\\Atomic", nullptr, swoole_atomic_methods);
#ifndef SW_THREAD
    SW_SET_CLASS_NOT_SERIALIZABLE(swoole_atomic);
#endif
    SW_SET_CLASS_CLONEABLE(swoole_atomic, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_atomic, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CUSTOM_OBJECT(
        swoole_atomic, php_swoole_atomic_create_object, php_swoole_atomic_free_object, AtomicObject, std);

    SW_INIT_CLASS_ENTRY(swoole_atomic_long, "Swoole\\Atomic\\Long", nullptr, swoole_atomic_long_methods);
#ifndef SW_THREAD
    SW_SET_CLASS_NOT_SERIALIZABLE(swoole_atomic_long);
#endif
    SW_SET_CLASS_CLONEABLE(swoole_atomic_long, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_atomic_long, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CUSTOM_OBJECT(swoole_atomic_long,
                               php_swoole_atomic_long_create_object,
                               php_swoole_atomic_long_free_object,
                               AtomicLongObject,
                               std);
}

PHP_METHOD(swoole_atomic, __construct) {
    auto o = php_swoole_atomic_fetch_object(Z_OBJ_P(ZEND_THIS));
    zend_long value = 0;

    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 0, 1)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(value)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

#ifdef SW_THREAD
    if (o->ptr) {
        zend_throw_error(NULL, "Constructor of %s can only be called once", SW_Z_OBJCE_NAME_VAL_P(ZEND_THIS));
        RETURN_FALSE;
    }
    o->res = new AtomicResource();
    auto resource_id = php_swoole_thread_resource_insert(o->res);
    zend_update_property_long(swoole_atomic_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("id"), resource_id);
    o->ptr = o->res->ptr_;
#endif

    *o->ptr = (sw_atomic_t) value;
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

#ifdef SW_THREAD
static PHP_METHOD(swoole_atomic, __wakeup) {
    auto o = php_swoole_atomic_fetch_object(Z_OBJ_P(ZEND_THIS));
    zend_long resource_id = zend::object_get_long(ZEND_THIS, ZEND_STRL("id"));
    o->res = static_cast<AtomicResource *>(php_swoole_thread_resource_fetch(resource_id));
    if (!o->res) {
        zend_throw_exception(swoole_exception_ce, EMSG_NO_RESOURCE, ECODE_NO_RESOURCE);
        return;
    }
    o->ptr = o->res->ptr_;
}
#endif

PHP_METHOD(swoole_atomic_long, __construct) {
    auto o = php_swoole_atomic_long_fetch_object(Z_OBJ_P(ZEND_THIS));
    zend_long value = 0;

    ZEND_PARSE_PARAMETERS_START(0, 1)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(value)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

#ifdef SW_THREAD
    if (o->ptr) {
        zend_throw_error(NULL, "Constructor of %s can only be called once", SW_Z_OBJCE_NAME_VAL_P(ZEND_THIS));
        RETURN_FALSE;
    }
    o->res = new AtomicLongResource();
    auto resource_id = php_swoole_thread_resource_insert(o->res);
    zend_update_property_long(swoole_atomic_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("id"), resource_id);
    o->ptr = o->res->ptr_;
#endif

    *o->ptr = (sw_atomic_long_t) value;
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

#ifdef SW_THREAD
static PHP_METHOD(swoole_atomic_long, __wakeup) {
    auto o = php_swoole_atomic_long_fetch_object(Z_OBJ_P(ZEND_THIS));
    zend_long resource_id = zend::object_get_long(ZEND_THIS, ZEND_STRL("id"));
    o->res = static_cast<AtomicLongResource *>(php_swoole_thread_resource_fetch(resource_id));
    if (!o->res) {
        zend_throw_exception(swoole_exception_ce, EMSG_NO_RESOURCE, ECODE_NO_RESOURCE);
        return;
    }
    o->ptr = o->res->ptr_;
}
#endif
