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

static sw_inline LockObject *php_swoole_lock_fetch_object(zend_object *obj) {
    return (LockObject *) ((char *) obj - swoole_lock_handlers.offset);
}

static Lock *php_swoole_lock_get_ptr(zval *zobject) {
    return php_swoole_lock_fetch_object(Z_OBJ_P(zobject))->lock;
}

static Lock *php_swoole_lock_get_and_check_ptr(zval *zobject) {
    Lock *lock = php_swoole_lock_get_ptr(zobject);
    if (!lock) {
        php_swoole_fatal_error(E_ERROR, "you must call Lock constructor first");
    }
    return lock;
}

void php_swoole_lock_set_ptr(zval *zobject, Lock *ptr) {
    php_swoole_lock_fetch_object(Z_OBJ_P(zobject))->lock = ptr;
}

static void php_swoole_lock_free_object(zend_object *object) {
    LockObject *o = php_swoole_lock_fetch_object(object);
    if (o->lock) {
        delete o->lock;
    }
    zend_object_std_dtor(object);
}

static zend_object *php_swoole_lock_create_object(zend_class_entry *ce) {
    LockObject *lock = (LockObject *) zend_object_alloc(sizeof(LockObject), ce);
    zend_object_std_init(&lock->std, ce);
    object_properties_init(&lock->std, ce);
    lock->std.handlers = &swoole_lock_handlers;
    return &lock->std;
}

SW_EXTERN_C_BEGIN
static PHP_METHOD(swoole_lock, __construct);
static PHP_METHOD(swoole_lock, __destruct);
static PHP_METHOD(swoole_lock, lock);
static PHP_METHOD(swoole_lock, lockwait);
static PHP_METHOD(swoole_lock, trylock);
static PHP_METHOD(swoole_lock, lock_read);
static PHP_METHOD(swoole_lock, trylock_read);
static PHP_METHOD(swoole_lock, unlock);
static PHP_METHOD(swoole_lock, destroy);
SW_EXTERN_C_END

// clang-format off
ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_lock_construct, 0, 0, 0)
    ZEND_ARG_INFO(0, type)
    ZEND_ARG_INFO(0, filename)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_lock_lockwait, 0, 0, 0)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

static const zend_function_entry swoole_lock_methods[] =
{
    PHP_ME(swoole_lock, __construct, arginfo_swoole_lock_construct, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_lock, __destruct, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_lock, lock, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_lock, lockwait, arginfo_swoole_lock_lockwait, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_lock, trylock, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_lock, lock_read, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_lock, trylock_read, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_lock, unlock, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_lock, destroy, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

void php_swoole_lock_minit(int module_number) {
    SW_INIT_CLASS_ENTRY(swoole_lock, "Swoole\\Lock", "swoole_lock", nullptr, swoole_lock_methods);
    SW_SET_CLASS_NOT_SERIALIZABLE(swoole_lock);
    SW_SET_CLASS_CLONEABLE(swoole_lock, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_lock, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CUSTOM_OBJECT(
        swoole_lock, php_swoole_lock_create_object, php_swoole_lock_free_object, LockObject, std);

    zend_declare_class_constant_long(swoole_lock_ce, ZEND_STRL("FILELOCK"), Lock::FILE_LOCK);
    zend_declare_class_constant_long(swoole_lock_ce, ZEND_STRL("MUTEX"), Lock::MUTEX);
    zend_declare_class_constant_long(swoole_lock_ce, ZEND_STRL("SEM"), Lock::SEM);
#ifdef HAVE_RWLOCK
    zend_declare_class_constant_long(swoole_lock_ce, ZEND_STRL("RWLOCK"), Lock::RW_LOCK);
#endif
#ifdef HAVE_SPINLOCK
    zend_declare_class_constant_long(swoole_lock_ce, ZEND_STRL("SPINLOCK"), Lock::SPIN_LOCK);
#endif
    zend_declare_property_long(swoole_lock_ce, ZEND_STRL("errCode"), 0, ZEND_ACC_PUBLIC);

    SW_REGISTER_LONG_CONSTANT("SWOOLE_FILELOCK", Lock::FILE_LOCK);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_MUTEX", Lock::MUTEX);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_SEM", Lock::SEM);
#ifdef HAVE_RWLOCK
    SW_REGISTER_LONG_CONSTANT("SWOOLE_RWLOCK", Lock::RW_LOCK);
#endif
#ifdef HAVE_SPINLOCK
    SW_REGISTER_LONG_CONSTANT("SWOOLE_SPINLOCK", Lock::SPIN_LOCK);
#endif
}

static PHP_METHOD(swoole_lock, __construct) {
    Lock *lock = php_swoole_lock_get_ptr(ZEND_THIS);
    if (lock != nullptr) {
        php_swoole_fatal_error(E_ERROR, "Constructor of %s can only be called once", SW_Z_OBJCE_NAME_VAL_P(ZEND_THIS));
    }

    zend_long type = Lock::MUTEX;
    char *filelock;
    size_t filelock_len = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "|ls", &type, &filelock, &filelock_len) == FAILURE) {
        RETURN_FALSE;
    }

    switch (type) {
    case Lock::FILE_LOCK:
    case Lock::SEM:
        zend_throw_exception(
            swoole_exception_ce, "FileLock and SemLock is no longer supported, please use mutex lock", errno);
        RETURN_FALSE;
        break;
#ifdef HAVE_SPINLOCK
    case Lock::SPIN_LOCK:
        lock = new SpinLock(1);
        break;
#endif
#ifdef HAVE_RWLOCK
    case Lock::RW_LOCK:
        lock = new RWLock(1);
        break;
#endif
    case Lock::MUTEX:
    default:
        lock = new Mutex(Mutex::PROCESS_SHARED);
        break;
    }
    php_swoole_lock_set_ptr(ZEND_THIS, lock);
    RETURN_TRUE;
}

static PHP_METHOD(swoole_lock, __destruct) {}

static PHP_METHOD(swoole_lock, lock) {
    Lock *lock = php_swoole_lock_get_and_check_ptr(ZEND_THIS);
    SW_LOCK_CHECK_RETURN(lock->lock());
}

static PHP_METHOD(swoole_lock, lockwait) {
    double timeout = 1.0;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "d", &timeout) == FAILURE) {
        RETURN_FALSE;
    }
    Lock *lock = php_swoole_lock_get_and_check_ptr(ZEND_THIS);
    if (lock->get_type() != Lock::MUTEX) {
        zend_throw_exception(swoole_exception_ce, "only mutex supports lockwait", -2);
        RETURN_FALSE;
    }
    Mutex *mutex = dynamic_cast<Mutex *>(lock);
    if (mutex == nullptr) {
        zend_throw_exception(swoole_exception_ce, "wrong lock type", -3);
        RETURN_FALSE;
    }
    SW_LOCK_CHECK_RETURN(mutex->lock_wait((int) timeout * 1000));
}

static PHP_METHOD(swoole_lock, unlock) {
    Lock *lock = php_swoole_lock_get_and_check_ptr(ZEND_THIS);
    SW_LOCK_CHECK_RETURN(lock->unlock());
}

static PHP_METHOD(swoole_lock, trylock) {
    Lock *lock = php_swoole_lock_get_and_check_ptr(ZEND_THIS);
    SW_LOCK_CHECK_RETURN(lock->trylock());
}

static PHP_METHOD(swoole_lock, trylock_read) {
    Lock *lock = php_swoole_lock_get_and_check_ptr(ZEND_THIS);
    SW_LOCK_CHECK_RETURN(lock->trylock_rd());
}

static PHP_METHOD(swoole_lock, lock_read) {
    Lock *lock = php_swoole_lock_get_and_check_ptr(ZEND_THIS);
    SW_LOCK_CHECK_RETURN(lock->lock_rd());
}

static PHP_METHOD(swoole_lock, destroy) {
    Lock *lock = php_swoole_lock_get_and_check_ptr(ZEND_THIS);
    delete lock;
    php_swoole_lock_set_ptr(ZEND_THIS, nullptr);
}
