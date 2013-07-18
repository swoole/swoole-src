#include "swoole.h"

void swMemPool_create(swMemPool *p, void *mem, int size, int item_size)
{
	p->size = size;
	p->mem = mem;
	p->item_size = item_size;
	p->cur = 0;
	bzero(mem, size);
}

void* swMemPool_fetch(swMemPool *p)
{
	if(p->cur + p->item_size + 1 > p->size)
	{
		p->cur = 0;
	}
	//in use
	if(*(char*)(p->mem + p->cur) == 1)
	{
		return NULL;
	}
	else
	{
		//将要分配出去的内存
		void *m = p->mem + p->cur;
		*(char*)m = 1;
		//向后移动
		p->cur += (p->item_size + 1);
		return m+1;
	}
}

