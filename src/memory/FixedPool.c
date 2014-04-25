#include "swoole.h"

typedef struct _swFixedPool_slice
{
	uint8_t lock;
	struct _swFixedPool_slice *next;
	struct _swFixedPool_slice *pre;
	char data[0];

} swFixedPool_slice;

typedef struct _swFixedPool
{
	void *memory;
	size_t size;

	swFixedPool_slice *head;
	swFixedPool_slice *tail;

	/**
	 * total memory size
	 */
	uint32_t slice_num;

	/**
	 * memory usage
	 */
	uint32_t slice_use;

	/**
	 * Fixed slice size
	 */
	uint32_t slice_size;

	/**
	 * use shared memory
	 */
	uint8_t shared;

} swFixedPool;

static void swFixedPool_init(swFixedPool *object);
static void* swFixedPool_alloc(swMemoryPool *pool, uint32_t size);
static void swFixedPool_free(swMemoryPool *pool, void *ptr);
static void swFixedPool_destroy(swMemoryPool *pool);

void swFixedPool_debug_slice(swFixedPool_slice *slice);

/**
 * create new FixedPool, random alloc/free fixed size memory
 */
swMemoryPool* swFixedPool_new(uint32_t slice_num, uint32_t slice_size, uint8_t shared)
{
	size_t size = slice_size * slice_num;
	size_t alloc_size = size + sizeof(swFixedPool) + sizeof(swMemoryPool);
	void *memory = (shared == 1) ? sw_shm_malloc(alloc_size) : sw_malloc(alloc_size);

	swFixedPool *object = memory;
	memory += sizeof(swFixedPool);
	bzero(object, sizeof(swFixedPool));

	object->shared = shared;
	object->slice_num = slice_num;
	object->slice_size = slice_size;
	object->size = size;

	swMemoryPool *pool = memory;
	memory += sizeof(swMemoryPool);
	pool->object = object;
	pool->alloc = swFixedPool_alloc;
	pool->free = swFixedPool_free;
	pool->destroy = swFixedPool_destroy;

	object->memory = memory;

	/**
	 * init linked list
	 */
	swFixedPool_init(object);

	return pool;
}

/**
 * linked list
 */
static void swFixedPool_init(swFixedPool *object)
{
	swFixedPool_slice *slice;
	void *cur = object->memory;
	void *max = object->memory + object->size;

	do
	{
		slice = (swFixedPool_slice *) cur;
		bzero(slice, sizeof(swFixedPool_slice));

		if (object->head != NULL)
		{
			object->head->pre = slice;
			slice->next = object->head;
		}
		else
		{
			object->tail = slice;
		}

		object->head = slice;
		cur += (sizeof(swFixedPool_slice) + object->slice_size);
		slice->pre = (swFixedPool_slice *) cur;
	} while (cur < max);
}

static void* swFixedPool_alloc(swMemoryPool *pool, uint32_t size)
{
	swFixedPool *object = pool->object;
	swFixedPool_slice *slice;

	slice = object->head;

	if (slice->lock == 0)
	{
		slice->lock = 1;
		/**
		 * move next slice to head (idle list)
		 */
		object->head = slice->next;
		slice->next->pre = NULL;

		/*
		 * move this slice to tail (busy list)
		 */
		object->tail->next = slice;
		slice->next = NULL;
		slice->pre = object->tail;
		object->tail = slice;

		return slice->data;
	}
	else
	{
		return NULL;
	}
}

static void swFixedPool_free(swMemoryPool *pool, void *ptr)
{
	swFixedPool *object = pool->object;
	swFixedPool_slice *slice;

	slice = ptr - sizeof(swFixedPool_slice);
	slice->lock = 0;

	//list head, AB
	if (slice->pre == NULL)
	{
		return;
	}
	//list tail, DE
	if (slice->next == NULL)
	{
		slice->pre->next = NULL;
	}
	//middle BCD
	else
	{
		slice->pre->next = slice->next;
		slice->next->pre = slice->pre;
	}
	slice->pre = NULL;
	slice->next = object->head;
	object->head->pre = slice;
	object->head = slice;
}

static void swFixedPool_destroy(swMemoryPool *pool)
{
	swFixedPool *object = pool->object;
	if (object->shared)
	{
		sw_shm_free(object);
	}
	else
	{
		sw_free(object);
	}
}


void swFixedPool_debug(swMemoryPool *pool)
{
	int line = 0;
	swFixedPool *object = pool->object;
	swFixedPool_slice *slice = object->head;

	printf("===============================%s=================================\n", __FUNCTION__);
	while (slice != NULL)
	{
		if (slice->next == slice)
		{
			printf("-------------------@@@@@@@@@@@@@@@@@@@@@@----------------\n");

		}
		printf("#%d\t", line);
		swFixedPool_debug_slice(slice);

		slice = slice->next;
		line++;
		if (line > 100)
			break;
	}
}

void swFixedPool_debug_slice(swFixedPool_slice *slice)
{
	printf("Slab[%p]\t", slice);
	printf("pre=%p\t", slice->pre);
	printf("next=%p\t", slice->next);
	printf("tag=%d\t", slice->lock);
	printf("data=%p\n", slice->data);
}
