#include "swoole.h"

int swMutex_lock(swLock *lock);
int swMutex_unlock(swLock *lock);
int swMutex_trylock(swLock *lock);
int swMutex_free(swLock *lock);

int swMutex_create(swLock *lock, int use_in_process)
{
	int ret;
	bzero(lock, sizeof(swLock));
	lock->type = SW_MUTEX;
	pthread_mutexattr_init(&lock->object.mutex.attr);
	if (use_in_process == 1)
	{
		pthread_mutexattr_setpshared(&lock->object.mutex.attr, PTHREAD_PROCESS_SHARED);
	}
	if ((ret = pthread_mutex_init(&lock->object.mutex._lock, &lock->object.mutex.attr)) < 0)
	{
		swWarn("swMutex_create fail. Error: %s [%d]", strerror(errno), errno);
		return SW_ERR;
	}
	lock->lock = swMutex_lock;
	lock->unlock = swMutex_unlock;
	lock->trylock = swMutex_trylock;
	lock->free = swMutex_free;
	return SW_OK;
}

int swMutex_lock(swLock *lock)
{
	return pthread_mutex_lock(&lock->object.mutex._lock);
}

int swMutex_unlock(swLock *lock)
{
	return pthread_mutex_unlock(&lock->object.mutex._lock);
}

int swMutex_trylock(swLock *lock)
{
	return pthread_mutex_trylock(&lock->object.mutex._lock);
}

int swMutex_free(swLock *lock)
{
	return pthread_mutex_destroy(&lock->object.mutex._lock);
}
