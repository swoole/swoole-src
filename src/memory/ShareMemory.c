#include "swoole.h"
#include "memory.h"

void *swShareMemory_mmap_create(swShareMemory_mmap *object, int size, char *mapfile)
{
	void *mem;
	int tmpfd = 0;
	int flag = MAP_SHARED;

#ifdef MAP_ANONYMOUS
	flag |= MAP_ANONYMOUS;
#else
	if(mapfile == NULL)
	{
		mapfile = "/dev/zero";
	}
	if((tmpfd = open(mapfile, O_RDWR)) < 0)
	{
		return NULL;
	}
	strncpy(object->mapfile, mapfile, SW_SHM_MMAP_FILE_LEN);
	object->tmpfd = tmpfd;
#endif

	if((mem = mmap(NULL, size, PROT_READ|PROT_WRITE, flag, tmpfd, 0)) < 0)
	{
		return NULL;
	}
	else
	{
		object->size = size;
		object->mem = mem;
		return mem;
	}
}

int swShareMemory_mmap_free(swShareMemory_mmap *object)
{
	return munmap(object->mem, object->size);
}

void *swShareMemory_sysv_create(swShareMemory_sysv *object, int size, int key)
{
	int shmid;
	void *mem;
	if(key == 0)
	{
		key = IPC_PRIVATE;
	}
    if ((shmid = shmget(key, size, SHM_R|SHM_W|IPC_CREAT)) < 0)
    {
        return NULL;
    }
    if ((mem = shmat(shmid, NULL, 0)) < 0)
    {
        return NULL;
    }
    else
    {
    	object->key = key;
    	object->shmid = shmid;
    	object->size = size;
    	object->mem = mem;
    	return mem;
    }
}

int swShareMemory_sysv_free(swShareMemory_sysv *object, int rm)
{
	int ret = shmdt(object->mem);
	if(rm == 1)
	{
		shmctl(object->shmid, IPC_RMID, NULL);
	}
	return ret;
}
