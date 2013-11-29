#include "swoole.h"
#include "memory.h"

void* sw_shm_malloc(size_t size)
{
	swShareMemory object;
	void *mem;
	//object对象需要保存在头部
	size += sizeof(swShareMemory);
	mem = swShareMemory_mmap_create(&object, size, NULL);
	if (mem == NULL)
	{
		return NULL;
	}
	else
	{
		memcpy(mem, &object, sizeof(swShareMemory));
		return mem + sizeof(swShareMemory);
	}
}

void* sw_shm_calloc(size_t num, size_t _size)
{
	swShareMemory object;
	void *mem;
	void *ret_mem;
	//object对象需要保存在头部
	int size = sizeof(swShareMemory) + (num * _size);
	mem = swShareMemory_mmap_create(&object, size, NULL);
	if (mem == NULL)
	{
		return NULL;
	}
	else
	{
		memcpy(mem, &object, sizeof(swShareMemory));
		ret_mem = mem + sizeof(swShareMemory);
		//calloc需要初始化
		bzero(ret_mem, size - sizeof(swShareMemory));
		return ret_mem;
	}
}

void sw_shm_free(void *ptr)
{
	//object对象在头部，如果释放了错误的对象可能会发生段错误
	swShareMemory *object = ptr - sizeof(swShareMemory);
#ifdef SW_DEBUG
	char check = ptr + object->size; //尝试访问
#endif
	swShareMemory_mmap_free(object);
}

void* sw_shm_realloc(void *ptr, size_t new_size)
{
	swShareMemory *object = ptr - sizeof(swShareMemory);
#ifdef SW_DEBUG
	char check = ptr + object->size; //尝试访问
#endif
	void *new_ptr;
	new_ptr = sw_shm_malloc(new_size);
	if(new_ptr==NULL)
	{
		return NULL;
	}
	else
	{
		memcpy(new_ptr, ptr, object->size);
		sw_shm_free(ptr);
		return new_ptr;
	}
}

void *swShareMemory_mmap_create(swShareMemory *object, int size, char *mapfile)
{
	void *mem;
	int tmpfd = -1;
	int flag = MAP_SHARED;
	bzero(object, sizeof(swShareMemory));

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

	mem = mmap(NULL, size, PROT_READ | PROT_WRITE, flag, tmpfd, 0);
	if ((int)mem < 0)
	{
		swWarn("mmap fail. Error: %s[%d]", strerror(errno), errno);
		return NULL;
	}
	else
	{
		object->size = size;
		object->mem = mem;
		return mem;
	}
}

int swShareMemory_mmap_free(swShareMemory *object)
{
	return munmap(object->mem, object->size);
}

void *swShareMemory_sysv_create(swShareMemory *object, int size, int key)
{
	int shmid;
	void *mem;
	bzero(object, sizeof(swShareMemory));

	if (key == 0)
	{
		key = IPC_PRIVATE;
	}
	if ((shmid = shmget(key, size, SHM_R | SHM_W | IPC_CREAT)) < 0)
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

int swShareMemory_sysv_free(swShareMemory *object, int rm)
{
	int ret = shmdt(object->mem);
	if (rm == 1)
	{
		shmctl(object->shmid, IPC_RMID, NULL);
	}
	return ret;
}
