#include "swoole.h"

#define SW_QUEUERING_MIN_MEM    (1024*64)   //最小内存分配

#define swQueueRing_debug(q) printf("RingBuffer: num=%d|head=%d|tail=%d\n", \
q->num, \
q->head,\
q->tail);

#define swQueueRing_empty(q) ((q->head == q->tail) && (q->tag == 0))
#define swQueueRing_full(q) ((q->head == q->tail) && (q->tag == 1))

typedef struct _swQueueRing_item {
	int length;
	char data[0];
} swQueueRing_item;

typedef struct _swQueueRing
{
	int head;    //头部，出队列方向
	int tail;    //尾部，入队列方向
	int size;    //队列总尺寸
	int tag;
	int num;
	int maxlen;
	void *mem;   //内存块
	swMutex lock;
	swPipe notify_fd;
} swQueueRing;

int swQueueRing_pop(swQueue *q, swQueue_data *out, int buffer_length);
int swQueueRing_push(swQueue *q, swQueue_data *in, int data_length);
int swQueueRing_out(swQueue *q, swQueue_data *out, int buffer_length);
int swQueueRing_in(swQueue *q, swQueue_data *in, int data_length);
int swQueueRing_wait(swQueue *q);
int swQueueRing_notify(swQueue *q);
void swQueueRing_free(swQueue *q);

int swQueueRing_create(swQueue *q, int size, int maxlen)
{
	assert(size > SW_QUEUERING_MIN_MEM);
	int ret;
	void *mem = sw_shm_malloc(size);
	if(mem == NULL)
	{
		swWarn("malloc fail\n");
		return SW_ERR;
	}
	swQueueRing *object = mem;
	mem += sizeof(swQueueRing);

	bzero(object, sizeof(swQueueRing));

	//允许溢出
	object->size = size - maxlen;
	object->mem = mem;
	object->head = 0;
	object->tail = 0;
	object->maxlen = maxlen;
	object->tag = 0;

	//初始化锁
	if(swMutex_create(&object->lock, 1) < 0)
	{
		swWarn("mutex init fail\n");
		return SW_ERR;
	}

#ifdef HAVE_EVENTFD
	ret = swPipeEventfd_create(&object->notify_fd, 1, 1);
#else
	ret = swPipeBase_create(&object->notify_fd, 1);
#endif
	if(ret < 0)
	{
		swWarn("notify_fd init fail\n");
		return SW_ERR;
	}

	q->object = object;
	q->in = swQueueRing_push;
	q->out = swQueueRing_pop;
	q->free = swQueueRing_free;
	q->notify = swQueueRing_notify;
	q->wait = swQueueRing_wait;
	return SW_OK;
}

int swQueueRing_in(swQueue *q, swQueue_data *in, int data_length)
{
	swQueueRing *object = q->object;
	assert(data_length < object->maxlen);

	//队列满了
	if (swQueueRing_full(object))
	{
		swWarn("queue full\n");
		return SW_ERR;
	}
	swQueueRing_item *item;
	int msize = sizeof(item->length) + data_length;

	if (object->tail < object->head)
	{
		if((object->head - object->tail) < msize)
		{
			//空间不足
			return SW_ERR;
		}
		object->tail += msize;
		item = object->mem + object->tail;
	}
	//这里tail必然小于size,无需判断,因为每次分配完会计算超过size后转到开始
	else
	{
		object->tail += msize;
		item = object->mem + object->tail;

		if(object->tail >= object->size)
		{
			object->tail = 0;
		}
	}
	object->num ++;
	item->length = data_length;
	memcpy(item->data, in->mdata, data_length);

	if (object->tail == object->head)
	{
		object->tag = 1;
	}
	return SW_OK;
}

int swQueueRing_out(swQueue *q, swQueue_data *out, int buffer_length)
{
	swQueueRing *object = q->object;
	//队列为空
	if (swQueueRing_empty(object))
	{
		swWarn("queue empty");
		return SW_ERR;
	}
	swQueueRing_item *item = object->mem + object->head;
	memcpy(out->mdata, item->data, item->length);
	object->head += (item->length + sizeof(item->length));
	if(object->head >= object->size)
	{
		object->head = 0;
	}
	object->num--;
	/* 这个时候一定队列空了*/
	if (object->tail == object->head)
	{
		object->tag = 0;
	}
	return item->length;
}

int swQueueRing_wait(swQueue *q)
{
	swQueueRing *object = q->object;
	uint64_t flag;
	return object->notify_fd.read(&object->notify_fd, &flag, sizeof(flag));
}

int swQueueRing_notify(swQueue *q)
{
	swQueueRing *object = q->object;
	uint64_t flag = 1;
	return object->notify_fd.write(&object->notify_fd, &flag, sizeof(flag));
}

int swQueueRing_push(swQueue *q, swQueue_data *in, int data_length)
{
	swQueueRing *object = q->object;
	if (object->lock.trylock(&object->lock) < 0)
	{
		return SW_ERR;
	}
	int ret = swQueueRing_in(q, in, data_length);
	object->lock.unlock(&object->lock);
	swQueueRing_debug(object);
	return ret;
}

void swQueueRing_free(swQueue *q)
{
	swQueueRing *object = q->object;
	object->lock.free(&object->lock);
	object->notify_fd.close(&object->notify_fd);
	sw_shm_free(object);
	q->object = NULL;
}

int swQueueRing_pop(swQueue *q, swQueue_data *out, int buffer_length)
{
	swQueueRing *object = q->object;
	if (object->lock.trylock(&object->lock) < 0)
	{
		return SW_ERR;
	}
	int n = swQueueRing_out(q, out, buffer_length);
	object->lock.unlock(&object->lock);
	return n;
}

