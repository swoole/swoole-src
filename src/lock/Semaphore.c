#include "swoole.h"
#include <sys/sem.h>

static int swSem_lock(swLock *lock);
static int swSem_unlock(swLock *lock);
static int swSem_free(swLock *lock);

int swSem_create(swLock *lock, key_t key, int n)
{
	int ret;
	assert(key != 0);
	lock->type = SW_SEM;
	if ((ret = semget(key, n, IPC_CREAT | 0666)) < 0)
	{
		return SW_ERR;
	}
	lock->object.sem.semid = ret;
	lock->object.sem.lock_num = 0;

	lock->lock = swSem_lock;
	lock->unlock = swSem_unlock;
	lock->free = swSem_free;
	return SW_OK;
}

static int swSem_lock(swLock *lock)
{
	struct sembuf sem;
	sem.sem_flg = SEM_UNDO;
	sem.sem_num = lock->object.sem.lock_num;
	sem.sem_op = 1;
	return semop(lock->object.sem.semid, &sem, 1);
}

static int swSem_unlock(swLock *lock)
{
	struct sembuf sem;
	sem.sem_flg = SEM_UNDO;
	sem.sem_num = lock->object.sem.lock_num;
	sem.sem_op = -1;
	return semop(lock->object.sem.semid, &sem, 1);
}

static int swSem_free(swLock *lock)
{
	return semctl(lock->object.sem.semid, 0, IPC_RMID);
}
