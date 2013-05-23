#include "swoole.h"
#include <sys/sem.h>

int swSem_create(swSem *this, key_t key, int n)
{
	int ret;
	assert(key != 0);
	if ((ret = semget(key, n, IPC_CREAT | 0666)) < 0)
	{
		return SW_ERR;
	}
	this->semid = ret;
	this->lock = swSem_lock;
	this->unlock = swSem_unlock;
	this->lock_num = 0;
	return SW_OK;
}

int swSem_lock(swSem *this)
{
	struct sembuf sem;
	sem.sem_flg = SEM_UNDO;
	sem.sem_num = this->lock_num;
	sem.sem_op = 1;
	return semop(this->semid, &sem, 1);
}

int swSem_unlock(swSem *this)
{
	struct sembuf sem;
	sem.sem_flg = SEM_UNDO;
	sem.sem_num = this->lock_num;
	sem.sem_op = -1;
	return semop(this->semid, &sem, 1);
}
