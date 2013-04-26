#include "swoole.h"
#include <sys/sem.h>

int swSem_create(swSem *this, key_t key, int n)
{
	int ret;
	assert(key != 0);
	if ((ret = semget(key, 1, IPC_EXCL | IPC_CREAT | 0666)) < 0)
	{
		return -1;
	}
	this->semid = ret;
	this->lock = swSem_lock;
	this->unlock = swSem_unlock;
	return 0;
}

int swSem_lock(swSem *this)
{
	static struct sembuf buf =
	{ 0, -1, SEM_UNDO };
	return semop(this->semid, &buf, 1);
}

int swSem_unlock(swSem *this)
{
	static struct sembuf buf =
	{ 0, 1, SEM_UNDO };
	return semop(this->semid, &buf, 1);
}
