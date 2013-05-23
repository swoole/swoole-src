/*
 * chan.h
 *
 *  Created on: 2013-5-23
 *      Author: tianfeng
 */

#ifndef CHAN_H_
#define CHAN_H_

#define SW_CHAN_MAX_ELEM    128   //单个元素最大可分配内存
#define SW_CHAN_MIN_MEM     128*2 //最小内存分配

typedef struct _swChanElem
{
	int size;
	void *ptr;
} swChanElem;

typedef struct _swChan
{
	void *lock;
	void *mem;
	int mem_size;
	int mem_use_num;
	int mem_cur;

	int elem_size;
	int elem_num;
	int elem_tail;
	int elem_head;
	swChanElem *elems;
} swChan;

int swChan_create(swChan *chan, void *mem, int mem_size, int elem_num);
void swChan_destroy(swChan *chan);
int swChan_push(swChan *chan, void *buf, int size);
swChanElem* swChan_pop(swChan *chan);

#define swChan_debug(chan) swWarn("swChanr Error.\nelem_num\t%d\nelem_size\t%d\nmem_use_num\t%d\nmem_size\t%d\nelem_tail\t%d\nelem_head\t%d\nmem_current\t%d\n", \
chan->elem_num, \
chan->elem_size,\
chan->mem_use_num,\
chan->mem_size,\
chan->elem_tail,\
chan->elem_head,\
chan->mem_cur);

#endif /* CHAN_H_ */
