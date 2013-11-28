#include "swoole.h"

#ifdef HAVE_SPINLOCK

static int swSpinLock_lock(swLock *lock);
static int swSpinLock_unlock(swLock *lock);
static int swSpinLock_trylock(swLock *lock);
static int swSpinLock_free(swLock *lock);

int swSpinLock_create(swLock *lock, int use_in_process)
{
	int ret;
	bzero(lock, sizeof(swLock));
	lock->type = SW_SPINLOCK;
	if ((ret = pthread_spin_init(&lock->object.spinlock.lock_t, use_in_process)) < 0)
	{
		return -1;
	}
	lock->lock = swSpinLock_lock;
	lock->unlock = swSpinLock_unlock;
	lock->trylock = swSpinLock_trylock;
	lock->free = swSpinLock_free;
	return 0;
}

static int swSpinLock_lock(swLock *lock)
{
	return pthread_spin_lock(&lock->object.spinlock.lock_t);
}

static int swSpinLock_unlock(swLock *lock)
{
	return pthread_spin_unlock(&lock->object.spinlock.lock_t);
}

static int swSpinLock_trylock(swLock *lock)
{
	return pthread_spin_trylock(&lock->object.spinlock.lock_t);
}

static int swSpinLock_free(swLock *lock)
{
	return pthread_spin_destroy(&lock->object.spinlock.lock_t);
}

#endif
