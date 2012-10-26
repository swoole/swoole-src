#include <stdio.h>
#include "RingBuffer.h"

int swRingBuffer_init(swRingBuffer * p_queue)
{
	p_queue->size = SW_BUFFER_LEN;
	p_queue->head = 0;
	p_queue->tail = 0;
	p_queue->tag = 0;
	return 0;
}

int swRingBuffer_push(swRingBuffer * p_queue, void *push_data)
{
	if (swRingBuffer_full(p_queue))
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

int swRingBuffer_pop(swRingBuffer * p_queue, void **pop_data)
{
	if (swRingBuffer_empty(p_queue))
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
