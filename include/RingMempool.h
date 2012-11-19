#ifndef _SW_RINGMEMPOOL_H_
#define _SW_RINGMEMPOOL_H_

typedef struct _swRingMempool
{
	int cur_key; /* 头部，出队列方向*/
	int size; /* 队列总尺寸 */
	int item_len;
	void *mem; /* 队列空间 */
} swRingMempool;

typedef struct _swRingMempool_head
{
	char tag;
	int item_key;
} swRingMempool_head;

extern int swRingMempool_init(swRingMempool *, int size, int item_len);
extern swRingMempool_head* swRingMempool_alloc(swRingMempool *poll);
#define swRingMempool_free(pool,item) (((swRingMempool_head *)item)->tag = 0)
#define swRingMempool_data(pool,item) ((char*)item+sizeof(swRingMempool_head))
#endif
