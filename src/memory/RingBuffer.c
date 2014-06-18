#include "swoole.h"

typedef struct _swRingBuffer
{
	uint8_t shared;
	size_t size;
	volatile off_t alloc_offset;
	volatile off_t collect_offset;
	volatile uint32_t free_n;
	void *memory;

} swRingBuffer;

typedef struct _swRingBuffer_item
{
	volatile uint32_t lock;
	volatile uint32_t length;
} swRingBuffer_head;

static void swRingBuffer_destory(swMemoryPool *pool);
SWINLINE static void swRingBuffer_collect(swRingBuffer *object);
static void* swRingBuffer_alloc(swMemoryPool *pool, uint32_t size);
static void swRingBuffer_free(swMemoryPool *pool, void *ptr);

swMemoryPool *swRingBuffer_new(size_t size, uint8_t shared)
{
	size_t malloc_size = size + sizeof(swRingBuffer) + sizeof(swMemoryPool);
	void *mem = (shared == 1) ? sw_shm_malloc(malloc_size) : sw_malloc(malloc_size);
	if (mem == NULL)
	{
		swWarn("malloc(%ld) failed.", size);
		return NULL;
	}
	swRingBuffer *object = mem;
	mem += sizeof(swRingBuffer);
	bzero(object, sizeof(swRingBuffer));
	object->size = size;
	object->shared = shared;

	swMemoryPool *pool = mem;
	mem += sizeof(swMemoryPool);
	pool->object = object;
	pool->destroy = swRingBuffer_destory;
	pool->free = swRingBuffer_free;
	pool->alloc = swRingBuffer_alloc;

	object->memory = mem;
	return pool;
}

SWINLINE static void swRingBuffer_collect(swRingBuffer *object)
{
	int i;
	swRingBuffer_head *item;

	swTraceLog(SW_TRACE_MEMORY, "collect_offset=%ld, free_n=%d", object->collect_offset, object->free_n);

	for(i = 0; i<SW_RINGBUFFER_COLLECT_N; i++)
	{
		item = (swRingBuffer_head *) (object->memory + object->collect_offset);

		swTraceLog(SW_TRACE_MEMORY, "collect_offset=%d, item_length=%d, lock=%d", object->collect_offset, item->length, item->lock);

		//can collect
		if (item->lock == 0)
		{
			object->collect_offset += (sizeof(swRingBuffer_head) + item->length);
			if (object->free_n > 0)
			{
				object->free_n --;
			}
			if (object->collect_offset >= object->size)
			{
				object->collect_offset = 0;
			}
		}
		else
		{
			break;
		}
	}
}

static void* swRingBuffer_alloc(swMemoryPool *pool, uint32_t size)
{
	swRingBuffer *object = pool->object;
	swRingBuffer_head *item;
	size_t n;
	uint8_t try_collect = 0;
	void *ret_mem = NULL;

	swTraceLog(SW_TRACE_MEMORY, "[0] alloc_offset=%ld|collect_offset=%ld", object->alloc_offset, object->collect_offset);

	start_alloc:

	if (object->alloc_offset < object->collect_offset)
	{
		head_alloc:
		item = object->memory + object->alloc_offset;
		/**
		 * 剩余内存的长度
		 */
		n = object->collect_offset - object->alloc_offset;
		/**
		 * 剩余内存可供本次分配,必须是>size
		 */
		if ((n - sizeof(swRingBuffer_head)) > size)
		{
			goto do_alloc;
		}
		/**
		 * 内存不足,已尝试回收过
		 */
		else if (try_collect == 1)
		{
			swWarn("alloc_offset=%ld|collect_offset=%ld", object->alloc_offset, object->collect_offset);
			return NULL;
		}
		//try collect memory, then try head_alloc
		else
		{
			try_collect = 1;
			swRingBuffer_collect(object);
			goto start_alloc;
		}
	}
	else
	{
		//tail_alloc:
		n = object->size - object->alloc_offset;
		item = object->memory + object->alloc_offset;

		swTraceLog(SW_TRACE_MEMORY, "[1] size=%ld, ac_size=%d, n_size=%ld", object->size, size, n);

		if ((n - sizeof(swRingBuffer_head)) >= size)
		{
			goto do_alloc;
		}
		else
		{
			//unlock
			item->lock = 0;
			item->length = n - sizeof(swRingBuffer_head);

			//goto head
			object->alloc_offset = 0;

			swTraceLog(SW_TRACE_MEMORY, "switch to head_alloc. ac_size=%d, n_size=%ld", size, n);

			goto head_alloc;
		}
	}

	do_alloc:
	item->lock = 1;
	item->length = size;
	ret_mem = (void*) (object->memory + object->alloc_offset + sizeof(swRingBuffer_head));

	/**
	 * 内存游标向后移动
	 */
	object->alloc_offset += size + sizeof(swRingBuffer_head);

	if (object->free_n > 0)
	{
		swRingBuffer_collect(object);
	}

	return ret_mem;
}

static void swRingBuffer_free(swMemoryPool *pool, void *ptr)
{
	swRingBuffer *object = pool->object;
	swRingBuffer_head *item = ptr - sizeof(swRingBuffer_head);
	item->lock = 0;
	object->free_n ++;
}

static void swRingBuffer_destory(swMemoryPool *pool)
{
	swRingBuffer *object = pool->object;
	if (object->shared)
	{
		sw_shm_free(object);
	}
	else
	{
		sw_free(object);
	}
}
