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
#include "swoole_memory.h"
#include "swoole_lock.h"

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

static zend_class_entry *swoole_thread_lock_ce;
static zend_object_handlers swoole_thread_lock_handlers;

#ifdef SW_THREAD
struct LockResource : public ThreadResource {
    Lock *lock_;
    LockResource(int type) : ThreadResource() {
        switch (type) {
#ifdef HAVE_SPINLOCK
        case Lock::SPIN_LOCK:
            lock_ = new SpinLock(0);
            break;
#endif
#ifdef HAVE_RWLOCK
        case Lock::RW_LOCK:
            lock_ = new RWLock(0);
            break;
#endif
        case Lock::MUTEX:
        default:
            lock_ = new Mutex(0);
            break;
        }
    }
    ~LockResource() {
        delete lock_;
    }
};
#endif

struct LockObject {
    LockResource *lock;
    zend_object std;
};

static sw_inline LockObject *php_swoole_thread_lock_fetch_object(zend_object *obj) {
    return (LockObject *) ((char *) obj - swoole_thread_lock_handlers.offset);
}

static Lock *php_swoole_thread_lock_get_ptr(zval *zobject) {
    return php_swoole_thread_lock_fetch_object(Z_OBJ_P(zobject))->lock->lock_;
}

static Lock *php_swoole_thread_lock_get_and_check_ptr(zval *zobject) {
    Lock *lock = php_swoole_thread_lock_get_ptr(zobject);
    if (!lock) {
        php_swoole_fatal_error(E_ERROR, "must call constructor first");
    }
    return lock;
}

static void php_swoole_thread_lock_free_object(zend_object *object) {
    LockObject *o = php_swoole_thread_lock_fetch_object(object);
    zend_long resource_id = zend::object_get_long(object, ZEND_STRL("id"));
    if (o->lock && php_swoole_thread_resource_free(resource_id, o->lock)) {
        delete o->lock;
        o->lock = nullptr;
    }
    zend_object_std_dtor(object);
}

static zend_object *php_swoole_thread_lock_create_object(zend_class_entry *ce) {
    LockObject *lock = (LockObject *) zend_object_alloc(sizeof(LockObject), ce);
    zend_object_std_init(&lock->std, ce);
    object_properties_init(&lock->std, ce);
    lock->std.handlers = &swoole_thread_lock_handlers;
    return &lock->std;
}

SW_EXTERN_C_BEGIN
static PHP_METHOD(swoole_thread_lock, __construct);
static PHP_METHOD(swoole_thread_lock, __destruct);
static PHP_METHOD(swoole_thread_lock, lock);
static PHP_METHOD(swoole_thread_lock, lockwait);
static PHP_METHOD(swoole_thread_lock, trylock);
static PHP_METHOD(swoole_thread_lock, lock_read);
static PHP_METHOD(swoole_thread_lock, trylock_read);
static PHP_METHOD(swoole_thread_lock, unlock);
static PHP_METHOD(swoole_thread_lock, destroy);
#ifdef SW_THREAD
static PHP_METHOD(swoole_thread_lock, __wakeup);
#endif
SW_EXTERN_C_END

// clang-format off
static const zend_function_entry swoole_thread_lock_methods[] =
{
    PHP_ME(swoole_thread_lock, __construct,  arginfo_class_Swoole_Thread_Lock___construct,  ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_lock, __destruct,   arginfo_class_Swoole_Thread_Lock___destruct,   ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_lock, lock,         arginfo_class_Swoole_Thread_Lock_lock,         ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_lock, lockwait,     arginfo_class_Swoole_Thread_Lock_locakwait,    ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_lock, trylock,      arginfo_class_Swoole_Thread_Lock_trylock,      ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_lock, lock_read,    arginfo_class_Swoole_Thread_Lock_lock_read,    ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_lock, trylock_read, arginfo_class_Swoole_Thread_Lock_trylock_read, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_lock, unlock,       arginfo_class_Swoole_Thread_Lock_unlock,       ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_lock, __wakeup,     arginfo_class_Swoole_Thread_Lock___wakeup,      ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

void php_swoole_thread_lock_minit(int module_number) {
    SW_INIT_CLASS_ENTRY(swoole_thread_lock, "Swoole\\Thread\\Lock", nullptr, swoole_thread_lock_methods);
    zend_declare_property_long(swoole_thread_lock_ce, ZEND_STRL("id"), 0, ZEND_ACC_PUBLIC);
    SW_SET_CLASS_CLONEABLE(swoole_thread_lock, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_thread_lock, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CUSTOM_OBJECT(
        swoole_thread_lock, php_swoole_thread_lock_create_object, php_swoole_thread_lock_free_object, LockObject, std);

    zend_declare_class_constant_long(swoole_thread_lock_ce, ZEND_STRL("MUTEX"), Lock::MUTEX);
#ifdef HAVE_RWLOCK
    zend_declare_class_constant_long(swoole_thread_lock_ce, ZEND_STRL("RWLOCK"), Lock::RW_LOCK);
#endif
#ifdef HAVE_SPINLOCK
    zend_declare_class_constant_long(swoole_thread_lock_ce, ZEND_STRL("SPINLOCK"), Lock::SPIN_LOCK);
#endif
    zend_declare_property_long(swoole_thread_lock_ce, ZEND_STRL("errCode"), 0, ZEND_ACC_PUBLIC);
#ifdef SW_THREAD
    zend_declare_property_long(swoole_thread_lock_ce, ZEND_STRL("id"), 0, ZEND_ACC_PUBLIC | ZEND_ACC_READONLY);
#endif
}

static PHP_METHOD(swoole_thread_lock, __construct) {
    auto o = php_swoole_thread_lock_fetch_object(Z_OBJ_P(ZEND_THIS));
    if (o->lock != nullptr) {
        zend_throw_error(NULL, "Constructor of %s can only be called once", SW_Z_OBJCE_NAME_VAL_P(ZEND_THIS));
        RETURN_FALSE;
    }

    zend_long type = swoole::Lock::MUTEX;

    ZEND_PARSE_PARAMETERS_START(0, 1)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(type)
    ZEND_PARSE_PARAMETERS_END();

    o->lock = new LockResource(type);
    auto resource_id = php_swoole_thread_resource_insert(o->lock);
    zend_update_property_long(swoole_thread_lock_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("id"), resource_id);
    RETURN_TRUE;
}

static PHP_METHOD(swoole_thread_lock, __destruct) {}

static PHP_METHOD(swoole_thread_lock, lock) {
    Lock *lock = php_swoole_thread_lock_get_and_check_ptr(ZEND_THIS);
    SW_LOCK_CHECK_RETURN(lock->lock());
}

static PHP_METHOD(swoole_thread_lock, lockwait) {
    double timeout = 1.0;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "d", &timeout) == FAILURE) {
        RETURN_FALSE;
    }
    Lock *lock = php_swoole_thread_lock_get_and_check_ptr(ZEND_THIS);
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

static PHP_METHOD(swoole_thread_lock, unlock) {
    Lock *lock = php_swoole_thread_lock_get_and_check_ptr(ZEND_THIS);
    SW_LOCK_CHECK_RETURN(lock->unlock());
}

static PHP_METHOD(swoole_thread_lock, trylock) {
    Lock *lock = php_swoole_thread_lock_get_and_check_ptr(ZEND_THIS);
    SW_LOCK_CHECK_RETURN(lock->trylock());
}

static PHP_METHOD(swoole_thread_lock, trylock_read) {
    Lock *lock = php_swoole_thread_lock_get_and_check_ptr(ZEND_THIS);
    SW_LOCK_CHECK_RETURN(lock->trylock_rd());
}

static PHP_METHOD(swoole_thread_lock, lock_read) {
    Lock *lock = php_swoole_thread_lock_get_and_check_ptr(ZEND_THIS);
    SW_LOCK_CHECK_RETURN(lock->lock_rd());
}

static PHP_METHOD(swoole_thread_lock, __wakeup) {
    auto o = php_swoole_thread_lock_fetch_object(Z_OBJ_P(ZEND_THIS));
    zend_long resource_id = zend::object_get_long(ZEND_THIS, ZEND_STRL("id"));
    o->lock = static_cast<LockResource *>(php_swoole_thread_resource_fetch(resource_id));
    if (!o->lock) {
        zend_throw_exception(swoole_exception_ce, EMSG_NO_RESOURCE, ECODE_NO_RESOURCE);
        return;
    }
}
