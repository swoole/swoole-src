#include "swoole.h"

#define SW_CHAN_MAX_ELEM    65535   //单个元素最大可分配内存
#define SW_CHAN_MIN_MEM     65535*2 //最小内存分配
#if defined(SW_CHAN_DEBUG) && SW_CHAN_DEBUG == 1
#define swQueueRing_debug(chan) swWarn("swQueue.\nelem_num\t%d\
\nelem_size\t%d\nmem_use_num\t%d\nmem_size\t%d\nelem_tail\t%d\nelem_head\t%d\nmem_current\t%d\n", \
chan->elem_num, \
chan->elem_size,\
chan->mem_use_num,\
chan->mem_size,\
chan->elem_tail,\
chan->elem_head,\
chan->mem_cur);
#else
#define swQueueRing_debug(chan)
#endif

typedef struct _swQueueRing_item {
	int length;
	char data[0];
} swQueueRing_item;

typedef struct _swQueueRing
{
	int head;    //头部，出队列方向
	int tail;    //尾部，入队列方向
	int tag;     //为空还是为满的标志位
	int size;    //队列总尺寸
	void *mem;   //内存块
	int m_index; //内存分配游标
	int cap;     //剩余容量
	int m_max;   //内存边界,不得超过此边界
	swMutex lock;
	swPipe notify_fd;
	swQueueRing_item *items[0]; //队列空间
} swQueueRing;

int swQueueRing_pop(swQueue *q, swQueue_data *out, int buffer_length);
int swQueueRing_push(swQueue *q, swQueue_data *in, int data_length);
int swQueueRing_out(swQueue *q, swQueue_data *out, int buffer_length);
int swQueueRing_in(swQueue *q, swQueue_data *in, int data_length);
int swQueueRing_create(swQueue *q, int mem_size, int qlen);
int swQueueRing_wait(swQueue *q);
int swQueueRing_notify(swQueue *q);
void swQueueRing_free(swQueue *q);

int swQueueRing_create(swQueue *q, int mem_size, int qlen)
{
	int ret;
	void *mem = sw_shm_malloc(mem_size);
	if(mem == NULL)
	{
		swWarn("malloc fail\n");
		return SW_ERR;
	}
	swQueueRing *object = mem;
	mem += (sizeof(swQueueRing) + sizeof(void*)*mem_size);

	bzero(object, sizeof(swQueueRing));
	object->size = qlen;
	object->mem = mem;
	object->m_max = object->cap = (mem_size - (sizeof(swQueueRing) + sizeof(void*)*mem_size));

	//初始化锁
	if(swMutex_create(&object->lock, 1) < 0)
	{
		swWarn("mutex init fail\n");
		return SW_ERR;
	}

#ifdef HAVE_EVENTFD
	ret = swPipeEventfd_create(&object->notify_fd, 1, 0);
#else
	ret = swPipeBase_create(&object->notify_fd, 1);
#endif

	if(ret < 0)
	{
		swWarn("mutex init fail\n");
		return SW_ERR;
	}
	q->in = swQueueRing_in;
	q->out = swQueueRing_out;
	q->free = swQueueRing_free;
	return SW_OK;
}

int swQueueRing_in(swQueue *q, swQueue_data *in, int data_length)
{
	swQueueRing *object = q->object;
	//队列已满
	if ((object->head == object->tail) && (object->tag == 1))
	{
		swTrace("ringqueue full\n");
		return SW_ERR;
	}
	int msize = sizeof(int) + data_length;

	//游标到达快尾
	if(object->m_index + msize > object->m_max)
	{
		//边界区域内存不够此次分配，所以从容量中减去
		object->cap -= (object->m_max - object->m_index);
		//尝试从头开始分配
		object->m_index = 0;
	}

	//内存容量不足或者没有连续的内存块
	if(object->cap < msize )
	{
		swTrace("ringqueue no enough memory\n");
		return SW_ERR;
	}

	swQueueRing_item *item = object->mem + object->m_index;
	object->m_index += msize;   //游标向后
	object->cap -= data_length; //减去容量

	item->length = data_length;
	memcpy(item->data, in->mdata, data_length);

	object->items[object->tail] = item;
	object->tail = (object->tail + 1) % object->size;

	/* 这个时候一定队列满了*/
	if (object->tail == object->head)
	{
		object->tag = 1;
	}
	return object->tag;
}

int swQueueRing_out(swQueue *q, swQueue_data *out, int buffer_length)
{
	swQueueRing *object = q->object;
	if ((object->head == object->tail) && (object->tag == 0))
	{
		swTrace("queue empty\n");
		return -1;
	}
	swQueueRing_item *item = object->items[object->head];
	memcpy(out->mdata, item->data, item->length);

	object->cap += item->length + sizeof(int);
	object->head = (object->head + 1) % object->size;

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
	return ret;
}

void swQueueRing_free(swQueue *q)
{
	swQueueRing *object = q->object;
	object->lock.free(&object->lock);
	object->notify_fd.close(&object->notify_fd);
	sw_shm_free(object);
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

