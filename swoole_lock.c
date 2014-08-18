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
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
  +----------------------------------------------------------------------+
*/

#include "php_swoole.h"

PHP_METHOD(swoole_lock, __construct)
{
	long type = SW_MUTEX;
	char *filelock;
	int filelock_len = 0;
	int ret;

#ifdef ZTS
    if (sw_thread_ctx == NULL)
    {
        TSRMLS_SET_CTX(sw_thread_ctx);
    }
#endif

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|ls", &type, &filelock, &filelock_len) == FAILURE)
	{
		RETURN_FALSE;
	}
	swLock *lock = SwooleG.memory_pool->alloc(SwooleG.memory_pool, sizeof(swLock));
	if (lock == NULL)
	{
	    php_error_docref(NULL TSRMLS_CC, E_WARNING, "alloc failed.");
		RETURN_FALSE;
	}

	switch(type)
	{
	case SW_RWLOCK:
		ret = swRWLock_create(lock, 1);
		break;
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
		ret = swSem_create(lock, IPC_PRIVATE, 1);
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
	zval *zres;
	MAKE_STD_ZVAL(zres);

	ZEND_REGISTER_RESOURCE(zres, lock, le_swoole_lock);
	zend_update_property(swoole_lock_class_entry_ptr, getThis(), ZEND_STRL("_lock"), zres TSRMLS_CC);

	zval_ptr_dtor(&zres);
	RETURN_TRUE;
}

void swoole_destory_lock(zend_rsrc_list_entry *rsrc TSRMLS_DC)
{
	swLock *lock = (swLock *) rsrc->ptr;
	lock->free(lock);
}

PHP_METHOD(swoole_lock, lock)
{
	zval **zres;
	swLock *lock;
	if (zend_hash_find(Z_OBJPROP_P(getThis()), SW_STRL("_lock"), (void **) &zres) == SUCCESS)
	{
		ZEND_FETCH_RESOURCE(lock, swLock*, zres, -1, SW_RES_CLIENT_NAME, le_swoole_lock);
	}
	else
	{
		RETURN_FALSE;
	}
	SW_LOCK_CHECK_RETURN(lock->lock(lock));
}

PHP_METHOD(swoole_lock, unlock)
{
	zval **zres;
	swLock *lock;
	if (zend_hash_find(Z_OBJPROP_P(getThis()), SW_STRL("_lock"), (void **) &zres) == SUCCESS)
	{
		ZEND_FETCH_RESOURCE(lock, swLock*, zres, -1, SW_RES_CLIENT_NAME, le_swoole_lock);
	}
	else
	{
		RETURN_FALSE;
	}
	SW_LOCK_CHECK_RETURN(lock->unlock(lock));
}

PHP_METHOD(swoole_lock, trylock)
{
	zval **zres;
	swLock *lock;
	if (zend_hash_find(Z_OBJPROP_P(getThis()), SW_STRL("_lock"), (void **) &zres) == SUCCESS)
	{
		ZEND_FETCH_RESOURCE(lock, swLock*, zres, -1, SW_RES_CLIENT_NAME, le_swoole_lock);
	}
	else
	{
		RETURN_FALSE;
	}
	if (lock->trylock == NULL)
	{
	    php_error_docref(NULL TSRMLS_CC, E_WARNING, "lock[type=%d] can not trylock", lock->type);
		RETURN_FALSE;
	}
	SW_LOCK_CHECK_RETURN(lock->trylock(lock));
}

PHP_METHOD(swoole_lock, trylock_read)
{
	zval **zres;
	swLock *lock;
	if (zend_hash_find(Z_OBJPROP_P(getThis()), SW_STRL("_lock"), (void **) &zres) == SUCCESS)
	{
		ZEND_FETCH_RESOURCE(lock, swLock*, zres, -1, SW_RES_CLIENT_NAME, le_swoole_lock);
	}
	else
	{
		RETURN_FALSE;
	}
	if(lock->trylock_rd == NULL)
	{
	    php_error_docref(NULL TSRMLS_CC, E_WARNING, "lock[type=%d] can not trylock_read", lock->type);
		RETURN_FALSE;
	}
	SW_LOCK_CHECK_RETURN(lock->trylock(lock));
}

PHP_METHOD(swoole_lock, lock_read)
{
	zval **zres;
	swLock *lock;
	if (zend_hash_find(Z_OBJPROP_P(getThis()), SW_STRL("_lock"), (void **) &zres) == SUCCESS)
	{
		ZEND_FETCH_RESOURCE(lock, swLock*, zres, -1, SW_RES_CLIENT_NAME, le_swoole_lock);
	}
	else
	{
		RETURN_FALSE;
	}
	if (lock->lock_rd == NULL)
	{
	    php_error_docref(NULL TSRMLS_CC, E_WARNING, "lock[type=%d] can not lock_read", lock->type);
		RETURN_FALSE;
	}
	SW_LOCK_CHECK_RETURN(lock->trylock(lock));
}
