#include "swoole.h"
#include "chan.h"

int swChan_create(swChan *chan, void *mem, int mem_size, int elem_size)
{
	if (mem_size <= 0 || mem == NULL || mem_size < SW_CHAN_MIN_MEM)
	{
		swWarn("error: mem_size <= %d or mem == NULL\n", SW_CHAN_MIN_MEM);
		return SW_ERR;
	}
	bzero(chan, sizeof(swChan));
	if (swMutex_create(&chan->lock, 1) < 0)
	{
		swWarn("create mutex fail.\n");
		return SW_ERR;
	}
	if (elem_size == 0)
	{
		elem_size = 65535;
	}
	chan->elems = sw_calloc(elem_size, sizeof(swChanElem));
	if (chan->elems == NULL )
	{
		swWarn("error: malloc fail.\n");
		return SW_ERR;
	}
	chan->elem_size = elem_size;
	chan->mem_size = mem_size - SW_CHAN_MAX_ELEM; //允许溢出
	chan->mem = mem;
	return SW_OK;
}

void swChan_destroy(swChan *chan)
{
	sw_free(chan->elems);
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
