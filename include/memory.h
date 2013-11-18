/*
 * memory.h
 *
 *  Created on: 2013-4-25
 *      Author: htf
 */

#ifndef SW_MEMORY_H_
#define SW_MEMORY_H_

#include <sys/mman.h>
#include <sys/ipc.h>
#include <sys/shm.h>

#define SW_SHM_MMAP_FILE_LEN  64
typedef struct _swShareMemory_mmap
{
	int size;
	char mapfile[SW_SHM_MMAP_FILE_LEN];
	int tmpfd;
	int key;
	int shmid;
	void *mem;
} swShareMemory;

void *swShareMemory_mmap_create(swShareMemory *object, int size, char *mapfile);
void *swShareMemory_sysv_create(swShareMemory *object, int size, int key);
int swShareMemory_sysv_free(swShareMemory *object, int rm);
int swShareMemory_mmap_free(swShareMemory *object);

typedef struct _swMemoryPoolSlab
{
	char tag; //1表示被占用 0未使用
	struct _swMemoryPoolSlab *next;
	struct _swMemoryPoolSlab *pre;
	void *data; //读写区
} swMemoryPoolSlab;

typedef struct _swMemoryPool
{
	swMemoryPoolSlab *head;
	swMemoryPoolSlab *tail;
	int block_size; //每次扩容的长度
	int memory_limit; //最大内存占用
	int memory_usage; //内存使用量
	int slab_size; //每个slab的长度
	char shared; //是否使用共享内存
} swMemoryPool;

typedef struct _swAllocator {
	void *object;
	void* (*alloc)(struct _swAllocator *alloc, int size);
	void (*free)(struct _swAllocator *alloc, void *ptr);
	void (*destroy)(struct _swAllocator *alloc);
} swAllocator;

typedef struct _swMemoryGlobal
{
	int size;  //总容量
	void *mem; //剩余内存的指针
	int offset; //内存分配游标
	char shared;
	int pagesize;
	void *root_page;
	void *cur_page;
} swMemoryGlobal;

/**
 * 内存池
 */
int swMemoryPool_create(swMemoryPool *pool, int memory_limit, int slab_size);
void swMemoryPool_free(swMemoryPool *pool, void *data);
void* swMemoryPool_alloc(swMemoryPool *pool);

/**
 * 全局内存,程序生命周期内只分配/释放一次
 */
swAllocator* swMemoryGlobal_create(int pagesize, char shared);

/**
 * 共享内存分配
 */
void* sw_shm_malloc(size_t size);
void sw_shm_free(void *ptr);
void* sw_shm_calloc(size_t num, size_t _size);
void* sw_shm_realloc(void *ptr, size_t new_size);

#endif /* SW_MEMORY_H_ */
