#include <stdlib.h>
#include "swoole.h"
#include "RingMempool.h"

inline int swRingMempool_init(swRingMempool *pool, void *mem, int size)
{
	pool->size = size;
	pool->mem = mem;
	pool->head = 0;
	pool->tail = 0;
	return 0;
}
void* swRingMempool_alloc(swRingMempool *pool, int size)
{
	swRingMempool_head *item;
	//超过最大尺寸
	if(size > SWRINGMEM_ITEM_MAXSIZE)
	{
		return NULL;
	}
	//tail已翻转
	if(pool->tag == 1 && pool->head - pool->tail < size)
	{
		return NULL;
	}
	else if(pool->tag == 0 && pool->size - pool->tail < size)
	{
		if(pool->head < size)
		{
			return NULL;
		}
		else
		{
			pool->tail = 0;
			pool->tag = 1;
		}
	}

	pool->tail += (size + sizeof(swRingMempool_head));
	item = pool->mem + pool->tail;
	item->length = size;
	return (void *) (item + sizeof(swRingMempool_head));
}

inline void swRingMempool_free(swRingMempool *pool, void *ptr)
{
	//翻转
	if(ptr < pool->mem + pool->head)
	{
		pool->head = 0;
		pool->tag = 0;
	}
	pool->head += (((swRingMempool_head *)ptr)->length + sizeof(swRingMempool_head));
}

inline void swRingMempool_resize(swRingMempool *pool, void *ptr, int size)
{
	swRingMempool_head *item = ptr;
	pool->tail -= (item->length - size);
	item->length = size;
}
