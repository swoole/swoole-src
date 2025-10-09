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
#include "php_swoole_thread.h"
#include "swoole_lock.h"
#include "swoole_timer.h"

#ifdef SW_THREAD

BEGIN_EXTERN_C()
#include "stubs/php_swoole_thread_lock_arginfo.h"
END_EXTERN_C()

using swoole::Lock;
using swoole::Mutex;
#ifdef HAVE_SPINLOCK
using swoole::SpinLock;
#endif
#ifdef HAVE_RWLOCK
using swoole::RWLock;
#endif

zend_class_entry *swoole_thread_lock_ce;
static zend_object_handlers swoole_thread_lock_handlers;

struct LockResource : public ThreadResource {
    Lock *lock_;
    LockResource(int type) : ThreadResource() {
        switch (type) {
#ifdef HAVE_SPINLOCK
        case Lock::SPIN_LOCK:
            lock_ = new SpinLock(false);
            break;
#endif
#ifdef HAVE_RWLOCK
        case Lock::RW_LOCK:
            lock_ = new RWLock(false);
            break;
#endif
        case Lock::MUTEX:
        default:
            lock_ = new Mutex(false);
            break;
        }
    }
    ~LockResource() override {
        delete lock_;
    }
};

struct ThreadLockObject {
    LockResource *lock;
    zend_object std;
};

static sw_inline ThreadLockObject *thread_lock_fetch_object(zend_object *obj) {
    return reinterpret_cast<ThreadLockObject *>(reinterpret_cast<char *>(obj) - swoole_thread_lock_handlers.offset);
}

static Lock *thread_lock_get_ptr(const zval *zobject) {
    return thread_lock_fetch_object(Z_OBJ_P(zobject))->lock->lock_;
}

static Lock *thread_lock_get_and_check_ptr(const zval *zobject) {
    Lock *lock = thread_lock_get_ptr(zobject);
    if (!lock) {
        php_swoole_fatal_error(E_ERROR, "must call constructor first");
    }
    return lock;
}

static void thread_lock_free_object(zend_object *object) {
    ThreadLockObject *o = thread_lock_fetch_object(object);
    if (o->lock) {
        o->lock->del_ref();
        o->lock = nullptr;
    }
    zend_object_std_dtor(object);
}

static zend_object *thread_lock_create_object(zend_class_entry *ce) {
    auto lock = static_cast<ThreadLockObject *>(zend_object_alloc(sizeof(ThreadLockObject), ce));
    zend_object_std_init(&lock->std, ce);
    object_properties_init(&lock->std, ce);
    lock->std.handlers = &swoole_thread_lock_handlers;
    return &lock->std;
}

ThreadResource *php_swoole_thread_lock_cast(const zval *zobject) {
    return thread_lock_fetch_object(Z_OBJ_P(zobject))->lock;
}

void php_swoole_thread_lock_create(zval *return_value, ThreadResource *resource) {
    auto obj = thread_lock_create_object(swoole_thread_lock_ce);
    auto lo = (ThreadLockObject *) thread_lock_fetch_object(obj);
    lo->lock = static_cast<LockResource *>(resource);
    ZVAL_OBJ(return_value, obj);
}

SW_EXTERN_C_BEGIN
static PHP_METHOD(swoole_thread_lock, __construct);
static PHP_METHOD(swoole_thread_lock, lock);
static PHP_METHOD(swoole_thread_lock, unlock);
SW_EXTERN_C_END

// clang-format off
static const zend_function_entry swoole_thread_lock_methods[] =
{
    PHP_ME(swoole_thread_lock, __construct,  arginfo_class_Swoole_Thread_Lock___construct,  ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_lock, lock,         arginfo_class_Swoole_Thread_Lock_lock,         ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_lock, unlock,       arginfo_class_Swoole_Thread_Lock_unlock,       ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

void php_swoole_thread_lock_minit(int module_number) {
    SW_INIT_CLASS_ENTRY(swoole_thread_lock, "Swoole\\Thread\\Lock", nullptr, swoole_thread_lock_methods);
    swoole_thread_lock_ce->ce_flags |= ZEND_ACC_FINAL | ZEND_ACC_NOT_SERIALIZABLE;
    SW_SET_CLASS_CLONEABLE(swoole_thread_lock, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_thread_lock, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CUSTOM_OBJECT(
        swoole_thread_lock, thread_lock_create_object, thread_lock_free_object, ThreadLockObject, std);

    zend_declare_class_constant_long(swoole_thread_lock_ce, ZEND_STRL("MUTEX"), Lock::MUTEX);
#ifdef HAVE_RWLOCK
    zend_declare_class_constant_long(swoole_thread_lock_ce, ZEND_STRL("RWLOCK"), Lock::RW_LOCK);
#endif
#ifdef HAVE_SPINLOCK
    zend_declare_class_constant_long(swoole_thread_lock_ce, ZEND_STRL("SPINLOCK"), Lock::SPIN_LOCK);
#endif
    zend_declare_property_long(swoole_thread_lock_ce, ZEND_STRL("errCode"), 0, ZEND_ACC_PUBLIC);
}

static PHP_METHOD(swoole_thread_lock, __construct) {
    auto o = thread_lock_fetch_object(Z_OBJ_P(ZEND_THIS));
    if (o->lock != nullptr) {
        zend_throw_error(nullptr, "Constructor of %s can only be called once", SW_Z_OBJCE_NAME_VAL_P(ZEND_THIS));
        RETURN_FALSE;
    }

    zend_long type = swoole::Lock::MUTEX;

    ZEND_PARSE_PARAMETERS_START(0, 1)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(type)
    ZEND_PARSE_PARAMETERS_END();

    o->lock = new LockResource(type);
}

static PHP_METHOD(swoole_thread_lock, lock) {
    zend_long operation = LOCK_EX;
    double timeout = -1;

    ZEND_PARSE_PARAMETERS_START(0, 2)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(operation)
    Z_PARAM_DOUBLE(timeout)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    Lock *lock = thread_lock_get_and_check_ptr(ZEND_THIS);
    if (timeout > 0 && !in_range(lock->get_type(), {Lock::RW_LOCK, Lock::MUTEX})) {
        zend_throw_exception(swoole_exception_ce, "only `mutex` and `rwlock` supports timeout", -2);
        RETURN_FALSE;
    }
    SW_LOCK_CHECK_RETURN(lock->lock(operation, swoole::sec2msec(timeout)));
}

static PHP_METHOD(swoole_thread_lock, unlock) {
    Lock *lock = thread_lock_get_and_check_ptr(ZEND_THIS);
    SW_LOCK_CHECK_RETURN(lock->unlock());
}

#endif
