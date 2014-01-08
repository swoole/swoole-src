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

#include "swoole.h"

int swAtomicLock_create(swLock *lock, int spin)
{
	bzero(lock, sizeof(swLock));
	lock->type = SW_ATOMLOCK;
	lock->object.atomlock.spin = spin;
	lock->lock = swAtomicLock_lock;
	lock->unlock = swAtomicLock_unlock;
	lock->trylock = swAtomicLock_trylock;
	return SW_OK;
}

int swAtomicLock_lock(swLock *lock)
{
	atomic_t *atomic = &lock->object.atomlock.lock_t;
	uint32_t i, n;
	while (1)
	{
		if (*atomic == 0 && sw_atomic_cmp_set(atomic, 0, 1))
		{
			return SW_OK;
		}
		if (SW_CPU_NUM > 1)
		{
			for (n = 1; n < lock->object.atomlock.spin; n <<= 1)
			{
				for (i = 0; i < n; i++)
				{
					sw_atomic_cpu_pause();
				}

				if (*atomic == 0 && sw_atomic_cmp_set(atomic, 0, 1))
				{
					return SW_OK;
				}
			}
		}
		swYield();
	}
	return SW_ERR;
}

int swAtomicLock_unlock(swLock *lock)
{
	return lock->object.atomlock.lock_t = 0;
}

int swAtomicLock_trylock(swLock *lock)
{
	atomic_t *atomic = &lock->object.atomlock.lock_t;
	return (*(atomic) == 0 && sw_atomic_cmp_set(atomic, 0, 1));
}
