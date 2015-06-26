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
zend_class_entry *swoole_lock_class_entry_ptr;

static const zend_function_entry swoole_lock_methods[] =
{
    PHP_ME(swoole_lock, __construct, NULL, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_ME(swoole_lock, __destruct, NULL, ZEND_ACC_PUBLIC | ZEND_ACC_DTOR)
    PHP_ME(swoole_lock, lock, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_lock, trylock, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_lock, lock_read, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_lock, trylock_read, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_lock, unlock, NULL, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

void swoole_lock_init(int module_number TSRMLS_DC)
{
    INIT_CLASS_ENTRY(swoole_lock_ce, "swoole_lock", swoole_lock_methods);
    swoole_lock_class_entry_ptr = zend_register_internal_class(&swoole_lock_ce TSRMLS_CC);

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

PHP_METHOD(swoole_lock, __construct)
{
    long type = SW_MUTEX;
    char *filelock;
    zend_size_t filelock_len = 0;
    int ret;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|ls", &type, &filelock, &filelock_len) == FAILURE)
    {
        RETURN_FALSE;
    }
    swLock *lock = emalloc(sizeof(swLock));
    if (lock == NULL)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "alloc failed.");
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
            php_error_docref(NULL TSRMLS_CC, E_ERROR, "filelock require lock file name.");
            RETURN_FALSE;
        }
        int fd;
        if ((fd = open(filelock, O_RDWR | O_CREAT, 0666)) < 0)
        {
            php_error_docref(NULL TSRMLS_CC, E_WARNING, "open file[%s] failed. Error: %s [%d]", filelock, strerror(errno), errno);
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
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "create lock failed");
        RETURN_FALSE;
    }
    swoole_set_object(getThis(), lock);
    RETURN_TRUE;
}

PHP_METHOD(swoole_lock, __destruct)
{
    swLock *lock = swoole_get_object(getThis());
    lock->free(lock);
    efree(lock);
}

PHP_METHOD(swoole_lock, lock)
{
    swLock *lock = swoole_get_object(getThis());
    SW_LOCK_CHECK_RETURN(lock->lock(lock));
}

PHP_METHOD(swoole_lock, unlock)
{
    swLock *lock = swoole_get_object(getThis());
    SW_LOCK_CHECK_RETURN(lock->unlock(lock));
}

PHP_METHOD(swoole_lock, trylock)
{
    swLock *lock = swoole_get_object(getThis());
    if (lock->trylock == NULL)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "lock[type=%d] can not trylock", lock->type);
        RETURN_FALSE;
    }
    SW_LOCK_CHECK_RETURN(lock->trylock(lock));
}

PHP_METHOD(swoole_lock, trylock_read)
{
    swLock *lock = swoole_get_object(getThis());
    if (lock->trylock_rd == NULL)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "lock[type=%d] can not trylock_read", lock->type);
        RETURN_FALSE;
    }
    SW_LOCK_CHECK_RETURN(lock->trylock(lock));
}

PHP_METHOD(swoole_lock, lock_read)
{
    swLock *lock = swoole_get_object(getThis());
    if (lock->lock_rd == NULL)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "lock[type=%d] can not lock_read", lock->type);
        RETURN_FALSE;
    }
    SW_LOCK_CHECK_RETURN(lock->trylock(lock));
}
