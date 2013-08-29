#include "swoole.h"

int swAtomicLock_create(swAtomicLock *object, int Atomic)
{
	bzero(object, sizeof(swAtomicLock));
	object->lock_t = Atomic;
	object->lock = swAtomicLock_lock;
	object->unlock = swAtomicLock_unlock;
	object->trylock = swAtomicLock_trylock;
	return SW_OK;
}

int swAtomicLock_lock(swAtomicLock *object)
{
	atomic_t *lock = &object->lock_t;
	uint32_t i, n;
	while (1)
	{
		if (*lock == 0 && sw_atomic_cmp_set(lock, 0, 1))
		{
			return SW_OK;
		}
		if (SW_CPU_NUM > 1)
		{
			for (n = 1; n < object->lock_t; n <<= 1)
			{
				for (i = 0; i < n; i++)
				{
					sw_atomic_cpu_pause();
				}

				if (*lock == 0 && sw_atomic_cmp_set(lock, 0, 1))
				{
					return SW_OK;
				}
			}
		}
		swYield();
	}
	return SW_ERR;
}

int swAtomicLock_unlock(swAtomicLock *object)
{
	return object->lock_t = 0;
}

int swAtomicLock_trylock(swAtomicLock *object)
{
	atomic_t *lock = &object->lock_t;
	return (*(lock) == 0 && sw_atomic_cmp_set(lock, 0, 1));
}
