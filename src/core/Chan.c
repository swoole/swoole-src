#include "swoole.h"

#define SW_CHAN_MAX_ELEM    65535   //单个元素最大可分配内存
#define SW_CHAN_MIN_MEM     65535*2 //最小内存分配
#if defined(SW_CHAN_DEBUG) && SW_CHAN_DEBUG == 1
#define swChan_debug(chan) swWarn("swChanr Error.\nelem_num\t%d\
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

int swChan_create(swChan **chan_addr, void *mem, int mem_size, int elem_size)
{
	int slab_size;
	if (mem_size <= 0 || mem == NULL || mem_size < SW_CHAN_MIN_MEM)
	{
		swWarn("error: mem_size <= %d or mem == NULL\n", SW_CHAN_MIN_MEM);
		return SW_ERR;
	}
	*chan_addr = mem;
	swChan *chan = *chan_addr;

	mem += sizeof(swChan);
	if (swMutex_create(&chan->lock, 1) < 0)
	{
		swWarn("create mutex fail.\n");
		return SW_ERR;
	}
	if (elem_size == 0)
	{
		elem_size = 65535;
	}
	slab_size = sizeof(swChanElem)*elem_size;
	chan->elem_size = elem_size;
	chan->mem_size = mem_size - slab_size - sizeof(swChan) - SW_CHAN_MAX_ELEM; //允许溢出
	chan->elems = (swChanElem *) mem;
	chan->mem = mem + slab_size;
	return SW_OK;
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
		return NULL ;
	}
	swChanElem *elem = swChan_pop_nolock(chan);
	chan->lock.unlock(&chan->lock);
	return elem;
}

int swChan_push_nolock(swChan *chan, void *buf, int size)
{
	swChanElem *elem;
	if (chan->elem_num == chan->elem_size || chan->mem_use_num >= chan->mem_size)
	{
		swChan_debug(chan);
		return SW_ERR;
	}
	if (chan->mem_cur >= chan->mem_size)
	{
		chan->mem_cur = 0;
	}
	elem = &(chan->elems[chan->elem_tail]);
	elem->ptr = chan->mem + chan->mem_cur;
	elem->size = size;

	chan->elem_num++;
	chan->mem_use_num += size;
	chan->elem_tail = (chan->elem_tail + 1) % chan->elem_size;
	chan->mem_cur += size;

	memcpy(elem->ptr, buf, size);
	return SW_OK;
}

swChanElem* swChan_pop_nolock(swChan *chan)
{
	swChanElem *elem;
	if (chan->elem_num == 0)
	{
		swChan_debug(chan);
		return NULL ;
	}
	elem = &(chan->elems[chan->elem_head]);
	chan->elem_num--;
	chan->mem_use_num -= elem->size;
	chan->elem_head++;
	return elem;
}
