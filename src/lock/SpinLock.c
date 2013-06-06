#include "swoole.h"

int swSpinLock_create(swSpinLock *this, int spin)
{
	bzero(this, sizeof(swSpinLock));
	this->spin = spin;
	this->lock = swSpinLock_lock;
	this->unlock = swSpinLock_unlock;
	this->trylock = swSpinLock_trylock;
	return SW_OK;
}

int swSpinLock_lock(swSpinLock *this)
{
	atomic_t *lock = &this->lock_t;
	uint32_t i, n;
	while (1)
	{
		if (*lock == 0 && sw_atomic_cmp_set(lock, 0, 1))
		{
			return SW_OK;
		}
		if (SW_CPU_NUM > 1)
		{
			for (n = 1; n < this->spin; n <<= 1)
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

int swSpinLock_unlock(swSpinLock *this)
{
	return this->lock_t = 0;
}

int swSpinLock_trylock(swSpinLock *this)
{
	atomic_t *lock = &this->lock_t;
	return (*(lock) == 0 && sw_atomic_cmp_set(lock, 0, 1));
}
