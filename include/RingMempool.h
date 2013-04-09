#ifndef _SW_RINGMEMPOOL_H_
#define _SW_RINGMEMPOOL_H_
#define SWRINGMEM_ITEM_MAXSIZE 65525

typedef struct _swRingMempool
{
	int size;
	int head;
	int tail;
	char tag;
	void *mem;

} swRingMempool;

typedef struct _swRingMempool_head
{
	int length;
} swRingMempool_head;

inline int swRingMempool_init(swRingMempool *pool, void *mem, int size);
void* swRingMempool_alloc(swRingMempool *pool, int size);
inline void swRingMempool_free(swRingMempool *pool, void *ptr);
inline void swRingMempool_resize(swRingMempool *pool, void *ptr, int size);
#endif
