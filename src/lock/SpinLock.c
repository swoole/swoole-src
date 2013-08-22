#include "swoole.h"

int swSpinLock_create(swSpinLock *object, int use_in_process)
{
	int ret;
	bzero(object, sizeof(swSpinLock));

	if((ret = pthread_spin_init(&object->lock_t, use_in_process)) < 0)
	{
		return -1;
	}
	object->lock = swSpinLock_lock;
	object->unlock = swSpinLock_unlock;
	object->trylock = swSpinLock_trylock;
	object->free = swSpinLock_free;
	return 0;
}

int swSpinLock_lock(swSpinLock *object)
{
	return pthread_spin_lock(&object->lock_t);
}

int swSpinLock_unlock(swSpinLock *object)
{
	return pthread_spin_unlock(&object->lock_t);
}

int swSpinLock_trylock(swSpinLock *object)
{
	return pthread_spin_trylock(&object->lock_t);
}

int swSpinLock_free(swSpinLock *object)
{
	return pthread_spin_destroy(&object->lock_t);
}
