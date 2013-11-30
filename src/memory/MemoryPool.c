#include "swoole.h"

#define SW_PAGE_SIZE  256

static int swMemoryPool_expand(swMemoryPool *pool);
static void swMemoryPool_print_slab(swMemoryPoolSlab *slab);
static void swMemoryPool_print_slab(swMemoryPoolSlab *slab);

static void *swMemoryGlobal_alloc(swAllocator *allocator, int size);
static void swMemoryGlobal_free(swAllocator *allocator, void *ptr);
static void swMemoryGlobal_destroy(swAllocator *allocator);
static void* swMemoryGlobal_new_page(swMemoryGlobal *gm);

swAllocator* swMemoryGlobal_create(int pagesize, char shared)
{
	swMemoryGlobal gm, *gm_ptr;
	assert(pagesize >= SW_PAGE_SIZE);
	bzero(&gm, sizeof(swMemoryGlobal));
	gm.shared = shared;
	gm.pagesize = pagesize;
	void *first_page = swMemoryGlobal_new_page(&gm);
	if (first_page == NULL)
	{
		return NULL;
	}
	//分配内存需要加锁
	if(swMutex_create(&gm.lock, 1) < 0)
	{
		return NULL;
	}
	//root
	gm.root_page = first_page;
	gm.cur_page = first_page;

	gm_ptr = (swMemoryGlobal *) gm.mem;
	gm.offset += sizeof(swMemoryGlobal);

	swAllocator *allocator = (swAllocator *) (gm.mem + gm.offset);
	gm.offset += sizeof(swAllocator);

	allocator->object = gm_ptr;
	allocator->alloc = swMemoryGlobal_alloc;
	allocator->destroy = swMemoryGlobal_destroy;
	allocator->free = swMemoryGlobal_free;

	memcpy(gm_ptr, &gm, sizeof(gm));
	return allocator;
}

/**
 * 使用前8个字节保存next指针
 */
static void* swMemoryGlobal_new_page(swMemoryGlobal *gm)
{
	void *page = (gm->shared == 1) ? sw_shm_malloc(gm->pagesize) : sw_malloc(gm->pagesize);
	if (page == NULL)
	{
		return NULL;
	}
	bzero(page, gm->pagesize);
	//将next设置为NULL
	((void **)page)[0] = NULL;

	gm->offset = 0;
	gm->size = gm->pagesize - sizeof(void*);
	gm->mem = page + sizeof(void*);
	return page;
}

static void *swMemoryGlobal_alloc(swAllocator *allocator, int size)
{
	swMemoryGlobal *gm = allocator->object;
	gm->lock.lock(&gm->lock);
	if(size > gm->pagesize)
	{
		swWarn("swMemoryGlobal_alloc: alloc %d bytes not allow. Max size=%d", size, gm->pagesize);
		return NULL;
	}

	if(gm->offset + size > gm->size)
	{
		//没有足够的内存,再次申请
		swTrace("swMemoryGlobal_alloc new page: size=%d|offset=%d|alloc=%d", gm->size, gm->offset, size);
		void *page = swMemoryGlobal_new_page(gm);
		if(page==NULL)
		{
			swWarn("swMemoryGlobal_alloc alloc memory error.");
			return NULL;
		}
		//将next指向新申请的内存块
		((void **)gm->cur_page)[0] = page;
		gm->cur_page = page;
	}
	void *mem = gm->mem + gm->offset;
	gm->offset += size;
	gm->lock.unlock(&gm->lock);
	return mem;
}

static void swMemoryGlobal_free(swAllocator *allocator, void *ptr)
{
	swWarn("swMemoryGlobal Allocator no free.");
}

static void swMemoryGlobal_destroy(swAllocator *allocator)
{
	swMemoryGlobal *gm = allocator->object;
	void *page = gm->root_page;
	void *next =((void **)page)[0];
	while(next != NULL)
	{
		next = ((void **)next)[0];
		sw_shm_free(page);
		swTrace("swMemoryGlobal free=%p", next);
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

