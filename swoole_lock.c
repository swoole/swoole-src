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

static PHP_METHOD(swoole_lock, __construct);
static PHP_METHOD(swoole_lock, __destruct);
static PHP_METHOD(swoole_lock, lock);
static PHP_METHOD(swoole_lock, lockwait);
static PHP_METHOD(swoole_lock, trylock);
static PHP_METHOD(swoole_lock, lock_read);
static PHP_METHOD(swoole_lock, trylock_read);
static PHP_METHOD(swoole_lock, unlock);
static PHP_METHOD(swoole_lock, destroy);

static zend_class_entry *swoole_lock_ce;
static zend_object_handlers swoole_lock_handlers;

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

void swoole_lock_init(int module_number)
{
    SW_INIT_CLASS_ENTRY(swoole_lock, "Swoole\\Lock", "swoole_lock", NULL, swoole_lock_methods);
    SW_SET_CLASS_SERIALIZABLE(swoole_lock, zend_class_serialize_deny, zend_class_unserialize_deny);
    SW_SET_CLASS_CLONEABLE(swoole_lock, zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_lock, sw_zend_class_unset_property_deny);
    // SW_SET_CLASS_CREATE_WITH_ITS_OWN_HANDLERS(swoole_lock);

    zend_declare_class_constant_long(swoole_lock_ce, ZEND_STRL("FILELOCK"), SW_FILELOCK);
    zend_declare_class_constant_long(swoole_lock_ce, ZEND_STRL("MUTEX"), SW_MUTEX);
    zend_declare_class_constant_long(swoole_lock_ce, ZEND_STRL("SEM"), SW_SEM);
#ifdef HAVE_RWLOCK
    zend_declare_class_constant_long(swoole_lock_ce, ZEND_STRL("RWLOCK"), SW_RWLOCK);
#endif
#ifdef HAVE_SPINLOCK
    zend_declare_class_constant_long(swoole_lock_ce, ZEND_STRL("SPINLOCK"), SW_SPINLOCK);
#endif
    zend_declare_property_long(swoole_lock_ce, ZEND_STRL("errCode"), 0, ZEND_ACC_PUBLIC);

    SW_REGISTER_LONG_CONSTANT("SWOOLE_FILELOCK", SW_FILELOCK);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_MUTEX", SW_MUTEX);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_SEM", SW_SEM);
#ifdef HAVE_RWLOCK
    SW_REGISTER_LONG_CONSTANT("SWOOLE_RWLOCK", SW_RWLOCK);
#endif
#ifdef HAVE_SPINLOCK
    SW_REGISTER_LONG_CONSTANT("SWOOLE_SPINLOCK", SW_SPINLOCK);
#endif
}

static PHP_METHOD(swoole_lock, __construct)
{
    swoole_php_fatal_error(
        E_DEPRECATED, "Class %s is deprecated, it will be removed in v4.5.0",
        ZSTR_VAL(swoole_lock_ce->name)
    );

    long type = SW_MUTEX;
    char *filelock;
    size_t filelock_len = 0;
    int ret;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "|ls", &type, &filelock, &filelock_len) == FAILURE)
    {
        RETURN_FALSE;
    }

    swLock *lock = SwooleG.memory_pool->alloc(SwooleG.memory_pool, sizeof(swLock));
    if (lock == NULL)
    {
        zend_throw_exception(swoole_exception_ce, "global memory allocation failure", SW_ERROR_MALLOC_FAIL);
        RETURN_FALSE;
    }

    switch(type)
    {
#ifdef HAVE_RWLOCK
    case SW_RWLOCK:
        ret = swRWLock_create(lock, 1);
        break;
#endif
    case SW_FILELOCK:
        if (filelock_len == 0)
        {
            zend_throw_exception(swoole_exception_ce, "filelock requires file name of the lock", SW_ERROR_INVALID_PARAMS);
            RETURN_FALSE;
        }
        int fd;
        if ((fd = open(filelock, O_RDWR | O_CREAT, 0666)) < 0)
        {
            zend_throw_exception_ex(swoole_exception_ce, errno, "open file[%s] failed. Error: %s [%d]", filelock, strerror(errno), errno);
            RETURN_FALSE;
        }
        ret = swFileLock_create(lock, fd);
        break;
#ifdef SEM_UNDO
    case SW_SEM:
        ret = swSem_create(lock, IPC_PRIVATE);
        break;
#endif
#ifdef HAVE_SPINLOCK
    case SW_SPINLOCK:
        ret = swSpinLock_create(lock, 1);
        break;
#endif
    case SW_MUTEX:
    default:
        ret = swMutex_create(lock, 1);
        break;
    }
    if (ret < 0)
    {
        zend_throw_exception(swoole_exception_ce, "failed to create lock", errno);
        RETURN_FALSE;
    }
    swoole_set_object(getThis(), lock);
    RETURN_TRUE;
}

static PHP_METHOD(swoole_lock, __destruct)
{
    SW_PREVENT_USER_DESTRUCT();

    swLock *lock = swoole_get_object(getThis());
    if (lock)
    {
        swoole_set_object(getThis(), NULL);
    }
}

static PHP_METHOD(swoole_lock, lock)
{
    swLock *lock = swoole_get_object(getThis());
    SW_LOCK_CHECK_RETURN(lock->lock(lock));
}

static PHP_METHOD(swoole_lock, lockwait)
{
    double timeout = 1.0;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "d", &timeout) == FAILURE)
    {
        RETURN_FALSE;
    }
    swLock *lock = swoole_get_object(getThis());
    if (lock->type != SW_MUTEX)
    {
        zend_throw_exception(swoole_exception_ce, "only mutex supports lockwait", -2);
        RETURN_FALSE;
    }
    SW_LOCK_CHECK_RETURN(swMutex_lockwait(lock, (int)timeout * 1000));
}

static PHP_METHOD(swoole_lock, unlock)
{
    swLock *lock = swoole_get_object(getThis());
    SW_LOCK_CHECK_RETURN(lock->unlock(lock));
}

static PHP_METHOD(swoole_lock, trylock)
{
    swLock *lock = swoole_get_object(getThis());
    if (lock->trylock == NULL)
    {
        swoole_php_error(E_WARNING, "lock[type=%d] can't use trylock", lock->type);
        RETURN_FALSE;
    }
    SW_LOCK_CHECK_RETURN(lock->trylock(lock));
}

static PHP_METHOD(swoole_lock, trylock_read)
{
    swLock *lock = swoole_get_object(getThis());
    if (lock->trylock_rd == NULL)
    {
        swoole_php_error(E_WARNING, "lock[type=%d] can't use trylock_read", lock->type);
        RETURN_FALSE;
    }
    SW_LOCK_CHECK_RETURN(lock->trylock_rd(lock));
}

static PHP_METHOD(swoole_lock, lock_read)
{
    swLock *lock = swoole_get_object(getThis());
    if (lock->lock_rd == NULL)
    {
        swoole_php_error(E_WARNING, "lock[type=%d] can't use lock_read", lock->type);
        RETURN_FALSE;
    }
    SW_LOCK_CHECK_RETURN(lock->lock_rd(lock));
}

static PHP_METHOD(swoole_lock, destroy)
{
    swLock *lock = swoole_get_object(getThis());
    lock->free(lock);
}
