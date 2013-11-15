#include "swoole.h"

static int swMemoryPool_expand(swMemoryPool *pool);
static void swMemoryPool_print_slab(swMemoryPoolSlab *slab);
static void swMemoryPool_print_slab(swMemoryPoolSlab *slab);

static void *swMemoryGlobal_alloc(swAllocator *allocator, int size);
static void swMemoryGlobal_free(swAllocator *allocator, void *ptr);
static void swMemoryGlobal_destroy(swAllocator *allocator);

swAllocator* swMemoryGlobal_create(int size, char shared)
{
	void *mem = (shared == 1) ? sw_shm_malloc(size) : sw_malloc(size);
	if (mem == NULL)
	{
		return NULL;
	}
	bzero(mem, size);
	swMemoryGlobal *gm = mem;
	mem += sizeof(swMemoryGlobal);

	gm->size = (size - sizeof(swAllocator) - sizeof(swMemoryGlobal));
	gm->shared = shared;

	swAllocator *allocator = mem;
	mem += sizeof(swAllocator);

	//赋值到gm
	gm->mem = mem;

	allocator->object = gm;
	allocator->alloc = swMemoryGlobal_alloc;
	allocator->destroy = swMemoryGlobal_destroy;
	allocator->free = swMemoryGlobal_free;
	return allocator;
}

static void *swMemoryGlobal_alloc(swAllocator *allocator, int size)
{
	swMemoryGlobal *gm = allocator->object;
	if(gm->offset + size > gm->size)
	{
		return NULL;
	}
	void *mem = gm->mem + gm->offset;
	gm->offset += size;
//	swWarn("swMemoryGlobal_alloc total=%d", gm->offset);
	return mem;
}

static void swMemoryGlobal_free(swAllocator *allocator, void *ptr)
{
	swWarn("swMemoryGlobal Allocator no free.");
}

static void swMemoryGlobal_destroy(swAllocator *allocator)
{
	swMemoryGlobal *gm = allocator->object;
	if(gm->shared)
	{
		sw_shm_free(gm->mem);
	}
	else
	{
		sw_free(gm->mem);
	}
}

/**
 * 固定尺寸随机释放的内存池
 */
int swMemoryPool_create(swMemoryPool *pool, int memory_limit, int slab_size)
{
	pool->head = NULL;
	pool->tail = NULL;
	pool->memory_limit = memory_limit;
	pool->slab_size = slab_size; //固定大小
	pool->memory_usage = 0;
	pool->block_size = (sizeof(swMemoryPoolSlab) + pool->slab_size) * SW_MEMORY_POOL_SLAB_PAGE;
	//扩展内存
	if (swMemoryPool_expand(pool) < 0)
	{
		return -1;
	}
	return 0;
}

int swMemoryPool_expand(swMemoryPool *pool)
{
	void *mem = (pool->shared == 1) ? sw_shm_malloc(pool->block_size) : sw_malloc(pool->block_size);
	if (mem == NULL)
	{
		return -1;
	}
	pool->memory_usage += pool->block_size;
//	int i = 0;
	swMemoryPoolSlab *slab;
	void *cur = mem;
	void *max = mem + pool->block_size;

//	printf("Memory Expand.\n");
	do
	{
		slab = (swMemoryPoolSlab *) cur;
		slab->data = (slab + 1);
		slab->tag = 0;
		if (pool->head != NULL)
		{
			pool->head->pre = slab;
			slab->next = pool->head;
		}
		//第一次运行
		else
		{
			pool->tail = slab;
		}
		pool->head = slab; //放到头部
		cur += (sizeof(swMemoryPoolSlab) + pool->slab_size);
		slab->pre = (swMemoryPoolSlab *) cur;
	} while (cur < max);

	return 0;
}

void* swMemoryPool_alloc(swMemoryPool *pool)
{
	swMemoryPoolSlab *slab;
	alloc_start: slab = pool->head;
	//有可分配块
	if (slab->tag == 0)
	{
		slab->tag = 1; //标记为已使用
		pool->head = slab->next; //将下一个内存块作为待分配区
		slab->next->pre = NULL;
		pool->tail->next = slab; //将自己加入到队尾

		slab->next = NULL;
		slab->pre = pool->tail; //将slab的pre指定为队尾

		pool->tail = slab; //将自己加入到队尾
		return slab->data;
	}
	//需要扩容
	else if (pool->memory_limit > pool->memory_usage)
	{
		if (swMemoryPool_expand(pool) < 0)
		{
			return NULL;
		}
		goto alloc_start;
	}
	else
	{
		return NULL;
	}
}

void swMemoryPool_print(swMemoryPool *pool)
{
	int line = 0;
	swMemoryPoolSlab *slab = pool->head;
//	printf("swMemoryPool_print: head=%p\n", slab);
	printf("===============================%s=================================\n", __FUNCTION__);
	while (slab != NULL)
	{
		if (slab->next == slab)
		{
			printf("-------------------@@@@@@@@@@@@@@@@@@@@@@----------------\n");

		}
		printf("#%d\t", line);
		swMemoryPool_print_slab(slab);

		slab = slab->next;
		line++;
		if (line > 100)
			break;
	}
}

void swMemoryPool_print_slab(swMemoryPoolSlab *slab)
{
	printf("Slab[%p]\t", slab);
	printf("pre=%p\t", slab->pre);
	printf("next=%p\t", slab->next);
	printf("tag=%d\t", slab->tag);
	printf("data=%p\n", slab->data);
}

void swMemoryPool_free(swMemoryPool *pool, void *data)
{
//	printf("Memory free.\n");
	swMemoryPoolSlab *slab;

	slab = data - sizeof(swMemoryPoolSlab);
	slab->tag = 0;

	//队头 AB
	if (slab->pre == NULL)
	{
		//直接返回
		return;
	}
	//队尾 DE
	if (slab->next == NULL)
	{
		slab->pre->next = NULL; //将上一个设为队尾
	}
	//中间区域 BCD
	else
	{
		//BCD 连接BD
		slab->pre->next = slab->next;
		slab->next->pre = slab->pre;
//		printf("slab=%p\tslab->pre->next=%p|slab->next->pre=%p\n", slab, slab->pre->next, slab->next->pre);
	}
	slab->pre = NULL;
	slab->next = pool->head; //加入待分配区
	pool->head->pre = slab; //队头的上级指为当前
	pool->head = slab; //将自己设为队头
}

