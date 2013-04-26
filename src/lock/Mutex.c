#include "swoole.h"

int swMutex_create(swMutex *this)
{
	int ret;
	pthread_mutexattr_setpshared(&this->attr, PTHREAD_PROCESS_SHARED);
	if((ret = pthread_mutex_init(&this->rwlock, &this->attr)) < 0)
	{
		return -1;
	}
	this->lock = swMutex_lock;
	this->unlock = swMutex_unlock;
	this->trylock = swMutex_trylock;
	return 0;
}

int swMutex_lock(swMutex *this)
{
	return pthread_mutex_lock(&this->rwlock);
}

int swMutex_unlock(swMutex *this)
{
	return pthread_mutex_unlock(&this->rwlock);
}

int swMutex_trylock(swMutex *this)
{
	return pthread_mutex_trylock(&this->rwlock);
}
