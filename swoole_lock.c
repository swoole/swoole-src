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
static PHP_METHOD(swoole_lock, trylock);
static PHP_METHOD(swoole_lock, lock_read);
static PHP_METHOD(swoole_lock, trylock_read);
static PHP_METHOD(swoole_lock, unlock);

static zend_class_entry swoole_lock_ce;
static zend_class_entry *swoole_lock_class_entry_ptr;

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_lock_construct, 0, 0, 0)
    ZEND_ARG_INFO(0, type)
    ZEND_ARG_INFO(0, filename)
ZEND_END_ARG_INFO()

static const zend_function_entry swoole_lock_methods[] =
{
    PHP_ME(swoole_lock, __construct, arginfo_swoole_lock_construct, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_ME(swoole_lock, __destruct, arginfo_swoole_void, ZEND_ACC_PUBLIC | ZEND_ACC_DTOR)
    PHP_ME(swoole_lock, lock, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_lock, trylock, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_lock, lock_read, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_lock, trylock_read, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_lock, unlock, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

void swoole_lock_init(int module_number TSRMLS_DC)
{
    SWOOLE_INIT_CLASS_ENTRY(swoole_lock_ce, "swoole_lock", "Swoole\\Lock", swoole_lock_methods);
    swoole_lock_class_entry_ptr = zend_register_internal_class(&swoole_lock_ce TSRMLS_CC);
    SWOOLE_CLASS_ALIAS(swoole_lock, "Swoole\\Lock");

    REGISTER_LONG_CONSTANT("SWOOLE_FILELOCK", SW_FILELOCK, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SWOOLE_MUTEX", SW_MUTEX, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SWOOLE_SEM", SW_SEM, CONST_CS | CONST_PERSISTENT);
#ifdef HAVE_RWLOCK
    REGISTER_LONG_CONSTANT("SWOOLE_RWLOCK", SW_RWLOCK, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef HAVE_SPINLOCK
    REGISTER_LONG_CONSTANT("SWOOLE_SPINLOCK", SW_SPINLOCK, CONST_CS | CONST_PERSISTENT);
#endif
}

static PHP_METHOD(swoole_lock, __construct)
{
    long type = SW_MUTEX;
    char *filelock;
    zend_size_t filelock_len = 0;
    int ret;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|ls", &type, &filelock, &filelock_len) == FAILURE)
    {
        RETURN_FALSE;
    }

    swLock *lock = SwooleG.memory_pool->alloc(SwooleG.memory_pool, sizeof(swLock));
    if (lock == NULL)
    {
        zend_throw_exception(swoole_exception_class_entry_ptr, "alloc global memory failed.", SW_ERROR_MALLOC_FAIL TSRMLS_CC);
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
        if (filelock_len <= 0)
        {
            zend_throw_exception(swoole_exception_class_entry_ptr, "filelock require lock file name.", SW_ERROR_INVALID_PARAMS TSRMLS_CC);
            RETURN_FALSE;
        }
        int fd;
        if ((fd = open(filelock, O_RDWR | O_CREAT, 0666)) < 0)
        {
            zend_throw_exception_ex(swoole_exception_class_entry_ptr, errno TSRMLS_CC, "open file[%s] failed. Error: %s [%d]", filelock, strerror(errno), errno);
            RETURN_FALSE;
        }
        ret = swFileLock_create(lock, fd);
        break;
    case SW_SEM:
        ret = swSem_create(lock, IPC_PRIVATE);
        break;
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
        zend_throw_exception(swoole_exception_class_entry_ptr, "create lock failed.", errno TSRMLS_CC);
        RETURN_FALSE;
    }
    swoole_set_object(getThis(), lock);
    RETURN_TRUE;
}

static PHP_METHOD(swoole_lock, __destruct)
{
    swLock *lock = swoole_get_object(getThis());
    if (lock)
    {
        lock->free(lock);
        swoole_set_object(getThis(), NULL);
    }
}

static PHP_METHOD(swoole_lock, lock)
{
    swLock *lock = swoole_get_object(getThis());
    SW_LOCK_CHECK_RETURN(lock->lock(lock));
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
        swoole_php_error(E_WARNING, "lock[type=%d] cannot use trylock", lock->type);
        RETURN_FALSE;
    }
    SW_LOCK_CHECK_RETURN(lock->trylock(lock));
}

static PHP_METHOD(swoole_lock, trylock_read)
{
    swLock *lock = swoole_get_object(getThis());
    if (lock->trylock_rd == NULL)
    {
        swoole_php_error(E_WARNING, "lock[type=%d] cannot use trylock_read", lock->type);
        RETURN_FALSE;
    }
    SW_LOCK_CHECK_RETURN(lock->trylock_rd(lock));
}

static PHP_METHOD(swoole_lock, lock_read)
{
    swLock *lock = swoole_get_object(getThis());
    if (lock->lock_rd == NULL)
    {
        swoole_php_error(E_WARNING, "lock[type=%d] cannot use lock_read", lock->type);
        RETURN_FALSE;
    }
    SW_LOCK_CHECK_RETURN(lock->lock_rd(lock));
}
