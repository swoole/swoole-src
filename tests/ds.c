#include <string.h>
#include "swoole.h"
#include "Server.h"
#include "hashtable.h"
#include "RingMempool.h"
#include <netinet/tcp.h>
#include "tests.h"

typedef struct _swHashTable_FdInfo
{
	int fd;
	int key;
	UT_hash_handle hh;
} swHashTable_FdInfo;

swUnitTest(chan_test)
{

	int ret, i;
	//int size = 1024 * 1024 * 8; //8M
	int size = 1024 * 200;
	swChanElem *elem;
	char buf[128];
	//void *mem = malloc(size);

	swShareMemory mm;
	swChan *chan;
	void *mem = swShareMemory_mmap_create(&mm, size, NULL );
	if (mem == NULL )
	{
		printf("malloc memory fail.\n");
		return 0;
	}
	else
	{
		printf("malloc memory OK.mem_addr=%p\n", mem);
	}

	ret = swChan_create(&chan, mem, size, 64);
	if (ret < 0)
	{
		printf("swChan_create fail.\n");
		return 0;
	}

	buf[127] = '\0';
	memset(buf, 'c', 127);

	int pid = fork();

	if (pid > 0)
	{
		swBreakPoint();
		for (i = 0; i < 7; i++)
		{
			//n = snprintf(buf, 128, "hello world.i=%d", i);
			ret = swChan_push(chan, buf, 128);
			if (ret < 0)
			{
				printf("swChan_push fail.\n");
				return 0;
			}
		}
		printf(
				"#swChan_pop---------------------------\nmem_addr\t%p\nelem_num\t%d\
				\nelem_size\t%d\nmem_use_num\t%d\nmem_size\t%d\nelem_tail\t%d\nelem_head\t%d\nmem_current\t%d\n",
				chan->mem, chan->elem_num, chan->elem_size, chan->mem_use_num, chan->mem_size, chan->elem_tail,
				chan->elem_head, chan->mem_cur);
		printf("chan_test OK.\n");
		pause();
	}
	else
	{
		sleep(1);
		swBreakPoint();
		for (i = 0; i < 7; i++)
		{
			elem = swChan_pop(chan);
			if (elem == NULL )
			{
				printf("swChan_pop fail.\n");
			}
			else
			{
				printf("Data=%s\n", (char *) elem->ptr);
			}
		}
		printf(
				"#swChan_pop---------------------------\nmem_addr\t%p\nelem_num\t%d\
				\nelem_size\t%d\nmem_use_num\t%d\nmem_size\t%d\nelem_tail\t%d\nelem_head\t%d\nmem_current\t%d\n",
				chan->mem, chan->elem_num, chan->elem_size, chan->mem_use_num, chan->mem_size, chan->elem_tail,
				chan->elem_head, chan->mem_cur);
		pause();
	}
	return 0;
}

/**
 * HashTable Test
 */
swUnitTest(ds_test2)
{
	swHashTable_FdInfo *ht = NULL;
	swHashTable_FdInfo *pkt, *tmp;
	int i;

	for (i = 0; i < 10; i++)
	{
		pkt = (swHashTable_FdInfo *) malloc(sizeof(swHashTable_FdInfo));
		pkt->key = i;
		pkt->fd = i * 34;
		HASH_ADD_INT(ht, key, pkt);
	}
	i = 7;
	HASH_FIND_INT(ht, &i, tmp);
	if (tmp != NULL)
	{

		printf("The key(%d) exists in hash. Fd = %d\n", i, tmp->fd);
	}
	return 0;
}

swUnitTest(ds_test1)
{
	swRingMempool pool;
	void *mem = malloc(1024 * 1024);
	void *item1, *item2, *item3, *item4, *item5;
	swRingMempool_init(&pool, mem, 1024 * 1024);

	item1 = swRingMempool_alloc(&pool, 20);
	sprintf(item1, "123456789");
	swRingMempool_resize(&pool, item1, strlen(item1) + 1);

	item2 = swRingMempool_alloc(&pool, 20);
	sprintf(item2, "12345678901");
	swRingMempool_resize(&pool, item2, strlen(item2) + 1);

	item3 = swRingMempool_alloc(&pool, 6);
	sprintf(item3, "12345");
	swRingMempool_resize(&pool, item3, strlen(item3) + 1);

	p_str(item1);
	p_str(item2);
	p_str(item3);

	item4 = swRingMempool_alloc(&pool, 20);
	if (item4 == NULL)
	{
		printf("Alloc fail\n");
	}
	swRingMempool_free(&pool, item1);
	swRingMempool_free(&pool, item2);

	item4 = swRingMempool_alloc(&pool, 20);
	if (item4 == NULL)
	{
		printf("Alloc fail\n");
		exit(1);
	}
	sprintf(item4, "hello world3.I'm death");
	swRingMempool_resize(&pool, item4, strlen(item4) + 1);
	p_str(item4);
	p_str(item3);
	swRingMempool_free(&pool, item3);
	swRingMempool_free(&pool, item4);

	item5 = swRingMempool_alloc(&pool, 20);
	sprintf(item5, "END");
	p_str(item5);
	pause();
	return 0;
}
