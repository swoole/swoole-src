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
#include "swoole_util.h"
#include "swoole_timer.h"

#include <sys/file.h>

BEGIN_EXTERN_C()
#include "stubs/php_swoole_lock_arginfo.h"
END_EXTERN_C()

using swoole::Lock;
using swoole::Mutex;
#ifdef HAVE_SPINLOCK
using swoole::SpinLock;
#endif
#ifdef HAVE_RWLOCK
using swoole::RWLock;
#endif

static zend_class_entry *swoole_lock_ce;
static zend_object_handlers swoole_lock_handlers;

struct LockObject {
    Lock *lock;
    zend_object std;
};

static sw_inline LockObject *lock_fetch_object(zend_object *obj) {
    return reinterpret_cast<LockObject *>(reinterpret_cast<char *>(obj) - swoole_lock_handlers.offset);
}

static Lock *lock_get_ptr(const zval *zobject) {
    return lock_fetch_object(Z_OBJ_P(zobject))->lock;
}

static Lock *lock_get_and_check_ptr(const zval *zobject) {
    Lock *lock = lock_get_ptr(zobject);
    if (UNEXPECTED(!lock)) {
        swoole_fatal_error(SW_ERROR_WRONG_OPERATION, "must call constructor first");
    }
    return lock;
}

static void lock_set_ptr(const zval *zobject, Lock *ptr) {
    lock_fetch_object(Z_OBJ_P(zobject))->lock = ptr;
}

static void lock_free_object(zend_object *object) {
    zend_object_std_dtor(object);
}

static zend_object *lock_create_object(zend_class_entry *ce) {
    auto *lock = static_cast<LockObject *>(zend_object_alloc(sizeof(LockObject), ce));
    zend_object_std_init(&lock->std, ce);
    object_properties_init(&lock->std, ce);
    lock->std.handlers = &swoole_lock_handlers;
    return &lock->std;
}

SW_EXTERN_C_BEGIN
static PHP_METHOD(swoole_lock, __construct);
static PHP_METHOD(swoole_lock, lock);
static PHP_METHOD(swoole_lock, unlock);
SW_EXTERN_C_END

// clang-format off
static constexpr zend_function_entry swoole_lock_methods[] =
{
    PHP_ME(swoole_lock, __construct,  arginfo_class_Swoole_Lock___construct,  ZEND_ACC_PUBLIC)
    PHP_ME(swoole_lock, lock,         arginfo_class_Swoole_Lock_lock,         ZEND_ACC_PUBLIC)
    PHP_ME(swoole_lock, unlock,       arginfo_class_Swoole_Lock_unlock,       ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

void php_swoole_lock_minit(int module_number) {
    SW_INIT_CLASS_ENTRY(swoole_lock, "Swoole\\Lock", nullptr, swoole_lock_methods);
    SW_SET_CLASS_NOT_SERIALIZABLE(swoole_lock);
    SW_SET_CLASS_CLONEABLE(swoole_lock, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_lock, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CUSTOM_OBJECT(swoole_lock, lock_create_object, lock_free_object, LockObject, std);

    zend_declare_class_constant_long(swoole_lock_ce, ZEND_STRL("MUTEX"), Lock::MUTEX);
#ifdef HAVE_RWLOCK
    zend_declare_class_constant_long(swoole_lock_ce, ZEND_STRL("RWLOCK"), Lock::RW_LOCK);
#endif
#ifdef HAVE_SPINLOCK
    zend_declare_class_constant_long(swoole_lock_ce, ZEND_STRL("SPINLOCK"), Lock::SPIN_LOCK);
#endif
    zend_declare_property_long(swoole_lock_ce, ZEND_STRL("errCode"), 0, ZEND_ACC_PUBLIC);

    SW_REGISTER_LONG_CONSTANT("SWOOLE_MUTEX", Lock::MUTEX);
#ifdef HAVE_RWLOCK
    SW_REGISTER_LONG_CONSTANT("SWOOLE_RWLOCK", Lock::RW_LOCK);
#endif
#ifdef HAVE_SPINLOCK
    SW_REGISTER_LONG_CONSTANT("SWOOLE_SPINLOCK", Lock::SPIN_LOCK);
#endif
}

static PHP_METHOD(swoole_lock, __construct) {
    Lock *lock = lock_get_ptr(ZEND_THIS);
    if (lock != nullptr) {
        zend_throw_error(nullptr, "Constructor of %s can only be called once", SW_Z_OBJCE_NAME_VAL_P(ZEND_THIS));
        RETURN_FALSE;
    }

    zend_long type = Lock::MUTEX;

    ZEND_PARSE_PARAMETERS_START(0, 1)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(type)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    switch (type) {
#ifdef HAVE_SPINLOCK
    case Lock::SPIN_LOCK:
        lock = new SpinLock(true);
        break;
#endif
#ifdef HAVE_RWLOCK
    case Lock::RW_LOCK:
        lock = new RWLock(true);
        break;
#endif
    case Lock::MUTEX:
        lock = new Mutex(true);
        break;
    default:
        zend_throw_exception(swoole_exception_ce, "lock type[%d] is not support", type);
        RETURN_FALSE;
        break;
    }
    lock_set_ptr(ZEND_THIS, lock);
    RETURN_TRUE;
}

static PHP_METHOD(swoole_lock, lock) {
    zend_long operation = LOCK_EX;
    double timeout = -1;

    ZEND_PARSE_PARAMETERS_START(0, 2)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(operation)
    Z_PARAM_DOUBLE(timeout)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    Lock *lock = lock_get_and_check_ptr(ZEND_THIS);
    SW_LOCK_CHECK_RETURN(lock->lock(operation, swoole::sec2msec(timeout)));
}

static PHP_METHOD(swoole_lock, unlock) {
    Lock *lock = lock_get_and_check_ptr(ZEND_THIS);
    SW_LOCK_CHECK_RETURN(lock->unlock());
}
