#include <string.h>
#include "swoole.h"
#include "Server.h"
#include "hashtable.h"
#include <netinet/tcp.h>
#include "tests.h"

typedef struct _swHashTable_FdInfo
{
	int fd;
	int key;
	UT_hash_handle hh;
} swHashTable_FdInfo;

swUnitTest(type_test1)
{
	char eof[] = SW_DATA_EOF;
	printf("SW_DATA_STREAM_EOF = %s\n", eof);
	return 0;
}

swUnitTest(chan_test)
{
	int ret, i;
	//int size = 1024 * 1024 * 8; //8M
	int size = 1024 * 200; //共享内存大小

	swMemoryGlobal gm;
	swMemoryGlobal_create(&gm, 4096, 1);

	char buf[128];

//	swShareMemory mm;
//	swChanElem *elem;
//	swChan *chan = swMemoryGlobal_alloc(&gm, sizeof(swChan));
//	void *ele_mem = swMemoryGlobal_alloc(&gm, size);
//
//	ret = swChan_create(chan, mem, size, 200, 128);
//	if (ret < 0)
//	{
//		printf("swChan_create fail.\n");
//		return 0;
//	}
//	buf[127] = '\0';
//	memset(buf, 'c', 127);
//
//	int pid = fork();
//
//	if (pid > 0)
//	{
//		printf("parent\n");
//		for (i = 0; i < 1000; i++)
//		{
//			//n = snprintf(buf, 128, "hello world.i=%d", i);
//			ret = swChan_push(chan, buf, 128);
//			if (ret < 0)
//			{
//				printf("[%d]swChan_push fail.\n", i);
//				return 0;
//			}
//			else
//			{
//				printf("[%d]swChan_push ok.\n", i);
//			}
//		}
//		printf(
//				"[parent]#swChan_pop---------------------------\nmem_addr\t%p\nelem_num\t%d\
//				\nelem_size\t%d\nmem_size\t%d\nelem_tail\t%d\nelem_head\t%d\n",
//				chan->mem, chan->elem_num, chan->elem_max,  chan->mem_size, chan->elem_tail,
//				chan->elem_head);
//		printf("chan_test OK.\n");
//		pause();
//	}
//	else
//	{
//		sleep(1);
//		printf("child\n");
//		swBreakPoint();
//		for (i = 0; i < 70; i++)
//		{
//			elem = swChan_pop(chan);
//			if (elem == NULL )
//			{
//				printf("swChan_pop fail.\n");
//			}
//			else
//			{
//				printf("Data=%s\n", (char *) elem->ptr);
//			}
//		}
//		printf(
//				"[parent]#swChan_pop---------------------------\nmem_addr\t%p\nelem_num\t%d\
//								\nelem_size\t%d\nmem_size\t%d\nelem_tail\t%d\nelem_head\t%d\n",
//								chan->mem, chan->elem_num, chan->elem_max,  chan->mem_size, chan->elem_tail,
//								chan->elem_head);
//		pause();
//	}
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
