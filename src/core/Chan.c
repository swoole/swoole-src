#include "swoole.h"

#define SW_CHAN_MAX_ELEM    65535   //单个元素最大可分配内存
#define SW_CHAN_MIN_MEM     65535*2 //最小内存分配
#if defined(SW_CHAN_DEBUG) && SW_CHAN_DEBUG == 1
#define swChan_debug(chan) swWarn("swChan.\nelem_num\t%d\
\nelem_size\t%d\nmem_use_num\t%d\nmem_size\t%d\nelem_tail\t%d\nelem_head\t%d\nmem_current\t%d\n", \
chan->elem_num, \
chan->elem_size,\
chan->mem_use_num,\
chan->mem_size,\
chan->elem_tail,\
chan->elem_head,\
chan->mem_cur);
#else
#define swChan_debug(chan)
#endif

/**
 * @elem_size 每个item内存块的长度
 * @elem_max item最多个数
 */
int swChan_create(swChan **chan_addr, void *mem, int mem_size, int elem_max, int elem_size)
{
	int slab_size, ret;
	bzero(mem, sizeof(swChan)); //初始化内存块
	if (mem_size <= 0 || mem == NULL || mem_size < SW_CHAN_MIN_MEM)
	{
		swWarn("error: mem_size <= %d or mem == NULL\n", SW_CHAN_MIN_MEM);
		return SW_ERR;
	}
	*chan_addr = mem;
	swChan *chan = *chan_addr;
	mem += sizeof(swChan); //去掉swChan结构占用的部分
	if (swMutex_create(&chan->lock, 1) < 0)
	{
		swWarn("create mutex fail.\n");
		return SW_ERR;
	}
	if (elem_max == 0)
	{
		elem_max = 65535;
	}
#ifdef HAVE_EVENTFD
	ret =  swPipeEventfd_create(&chan->notify_fd, 1, 1);
#else
	ret =  swPipeBase_create(&chan->notify_fd, 1);
#endif
	if(ret < 0)
	{
		swWarn("create eventfd fail.\n");
		return SW_ERR;
	}
	slab_size = sizeof(swChanElem)*elem_max;
	chan->elem_max = elem_max;
	chan->mem_size = mem_size - slab_size - sizeof(swChan);//允许溢出
	chan->elems = (swChanElem *) mem;
	chan->mem = mem + slab_size;
	swMemPool_create(&chan->pool, chan->mem, chan->mem_size, elem_size);
	return SW_OK;
}

int swChan_wait(swChan *chan)
{
	uint64_t flag;
	return chan->notify_fd.read(&chan->notify_fd, &flag, sizeof(flag));
}

int swChan_notify(swChan *chan)
{
	uint64_t flag = 1;
	return chan->notify_fd.write(&chan->notify_fd, &flag, sizeof(flag));
}

int swChan_push(swChan *chan, void *buf, int size)
{
	if (chan->lock.trylock(&chan->lock) < 0)
	{
		return SW_ERR;
	}
	int ret = swChan_push_nolock(chan, buf, size);
	chan->lock.unlock(&chan->lock);
	return ret;
}

swChanElem* swChan_pop(swChan *chan)
{
	if (chan->lock.trylock(&chan->lock) < 0)
	{
		return NULL;
	}
	swChanElem *elem = swChan_pop_nolock(chan);
	chan->lock.unlock(&chan->lock);
	return elem;
}

int swChan_push_nolock(swChan *chan, void *buf, int buf_len)
{
	swChanElem *elem;
	if (chan->elem_num == chan->elem_max)
	{
		swChan_debug(chan);
		return SW_ERR;
	}
	elem = &(chan->elems[chan->elem_tail]);
	elem->ptr = swMemPool_fetch(&chan->pool);
	//内存不足
	if(elem->ptr == NULL)
	{
		return SW_ERR;
	}
	elem->size = buf_len;
	chan->elem_num++;
	chan->elem_tail = (chan->elem_tail + 1) % chan->elem_max;
	memcpy(elem->ptr, buf, buf_len);
	return SW_OK;
}

swChanElem* swChan_pop_nolock(swChan *chan)
{
	swChanElem *elem;
	//当前通道中没有数据
	if (chan->elem_num == 0)
	{
		swChan_debug(chan);
		return NULL;
	}
	if(chan->elem_head >= chan->elem_max)
	{
		chan->elem_head = 0;
	}
	elem = &(chan->elems[chan->elem_head]);
	chan->elem_num--;
	chan->elem_head++;
	return elem;
}
