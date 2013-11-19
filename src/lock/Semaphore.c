#include "swoole.h"
#include <sys/sem.h>

int swSem_create(swSem *object, key_t key, int n)
{
	int ret;
	assert(key != 0);
	if ((ret = semget(key, n, IPC_CREAT | 0666)) < 0)
	{
		return SW_ERR;
	}
	object->semid = ret;
	object->lock = swSem_lock;
	object->unlock = swSem_unlock;
	object->free = swSem_free;
	object->lock_num = 0;
	return SW_OK;
}

int swSem_lock(swSem *object)
{
	struct sembuf sem;
	sem.sem_flg = SEM_UNDO;
	sem.sem_num = object->lock_num;
	sem.sem_op = 1;
	return semop(object->semid, &sem, 1);
}

int swSem_unlock(swSem *object)
{
	struct sembuf sem;
	sem.sem_flg = SEM_UNDO;
	sem.sem_num = object->lock_num;
	sem.sem_op = -1;
	return semop(object->semid, &sem, 1);
}

int swSem_free(swSem *object)
{
	return semctl(object->semid, 0, IPC_RMID);
}
