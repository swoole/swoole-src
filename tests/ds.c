#include <string.h>
#include "swoole.h"
#include "Server.h"
#include "hashtable.h"
#include "RingMempool.h"
#include <netinet/tcp.h>
#include "tests.h"

/**
 * HashTable Test
 */
void ds_test2()
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
}

int ds_test1(int argc, char **argv)
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
