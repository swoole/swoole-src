#ifndef _SW_RINGQUEUE_H_
#define _SW_RINGQUEUE_H_

typedef struct _swRingQueue
{
	int head; /* 头部，出队列方向*/
	int tail; /* 尾部，入队列方向*/
	int tag; /* 为空还是为满的标志位*/
	int size; /* 队列总尺寸 */
	void **data; /* 队列空间 */
} swRingQueue;

extern int swRingQueue_init(swRingQueue *, int);
extern int swRingQueue_push(swRingQueue *, void *);
extern int swRingQueue_pop(swRingQueue *, void **);

#define swRingQueue_empty(q) ((q->head == q->tail) && (q->tag == 0))
#define swRingQueue_full(q) ((q->head == q->tail) && (q->tag == 1))
#endif 
