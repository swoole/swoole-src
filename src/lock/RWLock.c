#include "swoole.h"

int swRWLock_create(swRWLock *this, int use_in_process)
{
	int ret;
	bzero(this, sizeof(swRWLock));
	if(use_in_process == 1)
	{
		pthread_rwlockattr_setpshared(&this->attr, PTHREAD_PROCESS_SHARED);
	}
	if((ret = pthread_rwlock_init(&this->rwlock, &this->attr)) < 0)
	{
		return -1;
	}
	this->lock_rd = swRWLock_lock_rd;
	this->lock = swRWLock_lock_rw;
	this->unlock = swRWLock_unlock;
	this->trylock = swRWLock_trylock_rw;
	this->trylock_rd = swRWLock_trylock_rd;
	return 0;
}

int swRWLock_lock_rd(swRWLock *this)
{
	return pthread_rwlock_rdlock(&this->rwlock);
}

int swRWLock_lock_rw(swRWLock *this)
{
	return pthread_rwlock_wrlock(&this->rwlock);
}

int swRWLock_unlock(swRWLock *this)
{
	return pthread_rwlock_unlock(&this->rwlock);
}

int swRWLock_trylock_rd(swRWLock *this)
{
	return pthread_rwlock_tryrdlock(&this->rwlock);
}

int swRWLock_trylock_rw(swRWLock *this)
{
	return pthread_rwlock_trywrlock(&this->rwlock);
}
