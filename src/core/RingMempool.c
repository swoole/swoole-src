#include <stdlib.h>
#include "swoole.h"
#include "RingMempool.h"


int swRingMempool_init(swRingMempool *pool, int size, int item_len)
{
	void *mem_ptr = sw_calloc(size, item_len + sizeof(swRingMempool_head));
	if (mem_ptr == NULL)
	{
		return -1;
	}
	pool->cur_key = 0;
	pool->size = size;
	pool->item_len = item_len;
	pool->mem = mem_ptr;
	return 0;
}
swRingMempool_head* swRingMempool_alloc(swRingMempool *pool)
{
	int item_key = 0;
	swRingMempool_head *head;
	//达到末尾
	if (pool->cur_key < pool->size)
	{
		item_key = pool->cur_key;
	}
	else
	{
		item_key = 0;
	}
	head = pool->mem+(item_key*(pool->item_len+sizeof(swRingMempool_head)));
	//数据未释放
	if (head->tag == 1)
	{
		return NULL;
	}
	pool->cur_key++;
	//标记为已用
	head->tag = 1;
	head->item_key = item_key;
	return head;
}
