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
#include "swoole_lock.h"

BEGIN_EXTERN_C()
#include "stubs/php_swoole_coroutine_lock_arginfo.h"
END_EXTERN_C()

using swoole::CoroutineLock;

static zend_class_entry *swoole_coroutine_lock_ce;
static zend_object_handlers swoole_coroutine_lock_handlers;

struct CoLockObject {
    CoroutineLock *lock;
    bool shared;
    zend_object std;
};

static sw_inline CoLockObject *co_lock_fetch_object(zend_object *obj) {
    return (CoLockObject *) ((char *) obj - swoole_coroutine_lock_handlers.offset);
}

static CoroutineLock *co_lock_get_ptr(zval *zobject) {
    return co_lock_fetch_object(Z_OBJ_P(zobject))->lock;
}

static CoroutineLock *co_lock_get_and_check_ptr(zval *zobject) {
    CoroutineLock *lock = co_lock_get_ptr(zobject);
    if (UNEXPECTED(!lock)) {
        swoole_fatal_error(SW_ERROR_WRONG_OPERATION, "must call constructor first");
    }
    return lock;
}

void co_lock_set_ptr(zval *zobject, CoroutineLock *ptr) {
    co_lock_fetch_object(Z_OBJ_P(zobject))->lock = ptr;
}

static void co_lock_free_object(zend_object *object) {
    CoLockObject *o = co_lock_fetch_object(object);
    if (o->lock && !o->shared) {
        delete o->lock;
    }
    zend_object_std_dtor(object);
}

static zend_object *co_lock_create_object(zend_class_entry *ce) {
    CoLockObject *lock = (CoLockObject *) zend_object_alloc(sizeof(CoLockObject), ce);
    zend_object_std_init(&lock->std, ce);
    object_properties_init(&lock->std, ce);
    lock->std.handlers = &swoole_coroutine_lock_handlers;
    return &lock->std;
}

SW_EXTERN_C_BEGIN
static PHP_METHOD(swoole_coroutine_lock, __construct);
static PHP_METHOD(swoole_coroutine_lock, lock);
static PHP_METHOD(swoole_coroutine_lock, unlock);
SW_EXTERN_C_END

// clang-format off
static const zend_function_entry swoole_coroutine_lock_methods[] =
{
    PHP_ME(swoole_coroutine_lock, __construct,  arginfo_class_Swoole_Coroutine_Lock___construct,  ZEND_ACC_PUBLIC)
    PHP_ME(swoole_coroutine_lock, lock,         arginfo_class_Swoole_Coroutine_Lock_lock,         ZEND_ACC_PUBLIC)
    PHP_ME(swoole_coroutine_lock, unlock,       arginfo_class_Swoole_Coroutine_Lock_unlock,       ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

void php_swoole_coroutine_lock_minit(int module_number) {
    SW_INIT_CLASS_ENTRY(swoole_coroutine_lock, "Swoole\\Coroutine\\Lock", nullptr, swoole_coroutine_lock_methods);
    SW_SET_CLASS_NOT_SERIALIZABLE(swoole_coroutine_lock);
    SW_SET_CLASS_CLONEABLE(swoole_coroutine_lock, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_coroutine_lock, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CUSTOM_OBJECT(
        swoole_coroutine_lock, co_lock_create_object, co_lock_free_object, CoLockObject, std);
    zend_declare_property_long(swoole_coroutine_lock_ce, ZEND_STRL("errCode"), 0, ZEND_ACC_PUBLIC);
}

static PHP_METHOD(swoole_coroutine_lock, __construct) {
    CoroutineLock *lock = co_lock_get_ptr(ZEND_THIS);
    if (lock != nullptr) {
        zend_throw_error(NULL, "Constructor of %s can only be called once", SW_Z_OBJCE_NAME_VAL_P(ZEND_THIS));
        RETURN_FALSE;
    }

    zend_bool shared = false;

    ZEND_PARSE_PARAMETERS_START(0, 1)
    Z_PARAM_OPTIONAL
    Z_PARAM_BOOL(shared)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    lock = new CoroutineLock(shared);
    co_lock_set_ptr(ZEND_THIS, lock);
    RETURN_TRUE;
}

static PHP_METHOD(swoole_coroutine_lock, lock) {
    zend_long operation = LOCK_EX;

    ZEND_PARSE_PARAMETERS_START(0, 1)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(operation)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    CoroutineLock *lock = co_lock_get_and_check_ptr(ZEND_THIS);
    SW_LOCK_CHECK_RETURN(lock->lock(operation));
}

static PHP_METHOD(swoole_coroutine_lock, unlock) {
    CoroutineLock *lock = co_lock_get_and_check_ptr(ZEND_THIS);
    SW_LOCK_CHECK_RETURN(lock->unlock());
}
