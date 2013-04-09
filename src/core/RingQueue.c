#include <stdio.h>
#include "swoole.h"
#include "RingQueue.h"

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
