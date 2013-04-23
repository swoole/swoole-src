#include <stdio.h>
#include "swoole.h"
#include "RingQueue.h"

#ifdef SW_USE_RINGQUEUE_TS

int swRingQueue_init(swRingQueue *queue, int buffer_size)
{
	queue->size = buffer_size;
	queue->flags = (char *)malloc(queue->size);
	if (queue->flags == NULL)
	{
		return -1;
	}
	queue->data = (void **)calloc(queue->size, sizeof(void*));
	if (queue->data == NULL)
	{
		return -1;
	}
	queue->head = 0;
	queue->tail = 0;
	memset(queue->flags, 0, queue->size);
	memset(queue->data, 0, queue->size * sizeof(void*));
	return 0;
}

int swRingQueue_push(swRingQueue *queue, void * ele)
{
	if (!(queue->num < queue->size))
	{
		return -1;
	}
	int cur_tail_index = queue->tail;
	char * cur_tail_flag_index = queue->flags + cur_tail_index;
	//TODO Scheld
	while (!sw_atomic_cmp_set(cur_tail_flag_index, 0, 1))
	{
		cur_tail_index = queue->tail;
		cur_tail_flag_index = queue->flags + cur_tail_index;
	}

	// 两个入队线程之间的同步
	//TODO 取模操作可以优化
	int update_tail_index = (cur_tail_index + 1) % queue->size;

	// 如果已经被其他的线程更新过，则不需要更新；
	// 否则，更新为 (cur_tail_index+1) % size;
	sw_atomic_cmp_set(&queue->tail, cur_tail_index, update_tail_index);

	// 申请到可用的存储空间
	*(queue->data + cur_tail_index) = ele;

	sw_atomic_fetch_add(cur_tail_flag_index, 1);
	sw_atomic_fetch_add(&queue->num, 1);
	return 0;
}

int swRingQueue_pop(swRingQueue *queue, void **ele)
{
	if (!(queue->num > 0))
		return -1;
	int cur_head_index = queue->head;
	char * cur_head_flag_index = queue->flags + cur_head_index;

	while (!sw_atomic_cmp_set(cur_head_flag_index, 2, 3))
	{
		cur_head_index = queue->head;
		cur_head_flag_index = queue->flags + cur_head_index;
	}
	//TODO 取模操作可以优化
	int update_head_index = (cur_head_index + 1) % queue->size;
	sw_atomic_cmp_set(&queue->head, cur_head_index, update_head_index);
	*ele = *(queue->data + cur_head_index);

	sw_atomic_fetch_sub(cur_head_flag_index, 3);
	sw_atomic_fetch_sub(&queue->num, 1);
	return 0;
}
#else

int swRingQueue_init(swRingQueue * p_queue, int buffer_size)
{
	p_queue->data = sw_calloc(buffer_size, sizeof(void*));
	if(p_queue->data == NULL)
	{
		swError("malloc fail\n");
		return -1;
	}
	p_queue->size = buffer_size;
	p_queue->head = 0;
	p_queue->tail = 0;
	p_queue->tag = 0;
	return 0;
}

int swRingQueue_push(swRingQueue * p_queue, void *push_data)
{
	if (swRingQueue_full(p_queue))
	{
		return -1;
	}

	p_queue->data[p_queue->tail] = push_data;
	p_queue->tail = (p_queue->tail + 1) % p_queue->size;

	/* 这个时候一定队列满了*/
	if (p_queue->tail == p_queue->head)
	{
		p_queue->tag = 1;
	}
	return p_queue->tag;
}

int swRingQueue_pop(swRingQueue * p_queue, void **pop_data)
{
	if (swRingQueue_empty(p_queue))
	{
		return -1;
	}

	*pop_data = p_queue->data[p_queue->head];
	p_queue->head = (p_queue->head + 1) % p_queue->size;

	/* 这个时候一定队列空了*/
	if (p_queue->tail == p_queue->head)
	{
		p_queue->tag = 0;
	}
	return p_queue->tag;
}
#endif
